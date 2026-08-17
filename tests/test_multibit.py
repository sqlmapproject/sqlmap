#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Multi-bit blind inference (lib/techniques/blind/multibit.py).

Row multiplexing turns "which rows came back" into a whole bit vector per response, so it is only
safe as long as its gates hold: it runs on demand only ('--multi-bit'), it must decline on pages that
cannot superpose (pagination), on rows that carry no unique marker, and on values the 8-bit channel
cannot carry - and it must NEVER hand back a value it could not prove against the target.

Driven offline against a real SQLite engine: the module's own predicates (the <bitmap>/<bitcol> atoms
from queries.xml) are evaluated by sqlite3 over a synthetic listing table and the result is rendered
as a page, exactly the way a vulnerable listing endpoint would. Only multibit._page is mocked, so
discovery, bit-plane mapping, calibration, reading and confirmation all run for real.
"""

import os
import sqlite3
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms, reset_dbms
bootstrap()

from lib.core.data import conf, kb, queries
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.settings import MULTIBIT_MAX_FAILURES
from lib.core.settings import MULTIBIT_NARROW
from lib.core.settings import MULTIBIT_WIDEN
from plugins.dbms.sqlite import SQLiteMap    # registers the SQLite escaper used by the read-back
import lib.techniques.blind.multibit as multibit

assert SQLiteMap

ROWS = 96
SMALL = 15                                          # a real shop listing, far short of the 128 wide window
_SAID = (multibit.singleTimeWarnMessage, multibit.singleTimeLogMessage)   # hint() speaks through both

def tearDownModule():
    reset_dbms()

class _Target(object):
    """A vulnerable listing endpoint: renders the rows its (injected) predicate selects."""

    def __init__(self, secret, limit=None, unique=True, junkEvery=0, column="id", rows=ROWS, shown=None, widenable=True):
        self.db = sqlite3.connect(":memory:", check_same_thread=False)   # '--threads' reads it from several
        self.lock = threading.Lock()
        self.db.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, cat INTEGER, name TEXT)")
        for i in range(1, rows + 1):
            self.db.execute("INSERT INTO products VALUES (?,?,?)", (i, i, "Item-%03d" % i))
        self.db.execute("CREATE TABLE v (s TEXT)")
        self.db.execute("INSERT INTO v VALUES (?)", (secret,))
        self.column = column                        # name the per-row link uses for the identifier
        self.shown = shown                          # rows the page shows on its own (narrow mode's width)
        self.limit = limit                          # rows rendered per response (pagination)
        self.unique = unique                        # per-row markers, or identical rows
        self.junkEvery = junkEvery                  # every Nth response is a gateway error
        self.widenable = widenable                  # whether an OR payload can reach past the page's own rows
        self.requests = 0

    def secret(self, value):
        """Point the target at another value, keeping the row channel (and its profile) intact."""

        self.db.execute("UPDATE v SET s=?", (value,))

        return value

    def page(self, expression, mode="widen"):
        with self.lock:
            self.requests += 1
            requests = self.requests

        if self.junkEvery and requests % self.junkEvery == 0:
            return "<html><body><h1>502 Bad Gateway</h1></body></html>"

        if mode != "widen":                         # AND-ed onto the live value: only the page's own rows
            expression = "%s<=%d AND (%s)" % (self.column, self.shown or ROWS, expression)
        elif not self.widenable:                    # a filter in a subquery the injected OR cannot escape
            return "<html><body>Database error</body></html>"

        try:
            with self.lock:
                rows = self.db.execute("SELECT %s,name FROM products WHERE %s ORDER BY id" % (self.column, expression)).fetchall()
        except Exception:
            return "<html><body>Database error</body></html>"

        if self.limit:
            rows = rows[:self.limit]

        out = ["<html><body>"]

        for rid, name in rows:
            if self.unique:
                out.append('<div class="item"><a href="/product.php?%s=%d">%s</a></div>' % (self.column, rid, name))
            else:
                out.append('<div class="item"><a href="/product.php">product</a></div>')

        out.append("</body></html>")

        return "\n".join(out)

class MultibitTest(unittest.TestCase):
    def setUp(self):
        self._saved = dict((_, conf.get(_)) for _ in ("multiBit", "firstChar", "lastChar", "hostname", "path", "verbose", "eta", "api", "noEscape", "threads"))
        self._savedKb = dict((_, kb.get(_)) for _ in ("multibit", "multibitHinted", "nullConnection", "technique", "injection", "bruteMode", "multiThreadMode", "originalPage"))
        self._savedPage = multibit._page
        self._savedInjection = (kb.injection.place, kb.injection.parameter, kb.injection.data)

        conf.multiBit = True                        # opt-in: nothing here runs without the switch
        conf.firstChar = conf.lastChar = None
        conf.hostname, conf.path, conf.verbose = "test", "/", 0
        conf.eta = conf.api = conf.noEscape = False
        conf.threads = 1

        kb.multibit = {}
        kb.multibitHinted = False
        kb.nullConnection = None
        kb.originalPage = None                      # force discovery through the (mocked) request path
        kb.bruteMode = kb.multiThreadMode = False
        kb.technique = PAYLOAD.TECHNIQUE.BOOLEAN
        kb.injection.place, kb.injection.parameter = "GET", "cat"
        kb.injection.data = {PAYLOAD.TECHNIQUE.BOOLEAN: {}}
        kb.data.processChar = None

        set_dbms("SQLite")

    def tearDown(self):
        for key, value in self._saved.items():
            conf[key] = value
        for key, value in self._savedKb.items():
            kb[key] = value
        # kb.injection is restored by identity above, so its members have to be put back one by one
        kb.injection.place, kb.injection.parameter, kb.injection.data = self._savedInjection
        multibit._page = self._savedPage
        multibit.singleTimeWarnMessage, multibit.singleTimeLogMessage = _SAID

    def _attempt(self, secret, length=None, **kwargs):
        target = _Target(secret, **kwargs)
        multibit._page = target.page

        return self._read(target, secret, length), target

    def _read(self, target, secret, length=None):
        """Extracts the target's CURRENT value, so a case can chain several through one channel."""

        multibit._page = target.page

        return multibit.attempt("SELECT s FROM v", lambda idx: secret[idx - 1:idx], length)

    def test_extracts_and_beats_single_bit(self):
        secret = "sqlmap-multi-bit-channel-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        value, target = self._attempt(secret, len(secret))

        self.assertEqual(value, secret)
        # single-bit would need 8 requests per character just to read it
        self.assertLess(target.requests, 8 * len(secret))

    def test_extracts_without_known_length(self):
        secret = "no-length-known-here-but-still-exact"
        value, _ = self._attempt(secret)

        self.assertEqual(value, secret)

    def test_declines_when_too_few_rows_are_rendered(self):
        # not even two bits plus a canary, so there is nothing to multiplex
        value, target = self._attempt("this must never come back", 25, limit=2)

        self.assertIsNone(value)
        self.assertLess(target.requests, 40)        # and it must find that out cheaply

    def test_page_that_cannot_be_widened_falls_back_to_its_own_rows(self):
        # a fixed filter in a subquery the injected OR cannot escape: the whole-table channel does not
        # calibrate, and the five rows the page itself renders still carry four bits per request
        secret = "five rows still beat one bit"
        value, _ = self._attempt(secret, len(secret), limit=5, widenable=False)

        self.assertEqual(value, secret)
        self.assertEqual(list(kb.multibit.values())[0]["mode"], MULTIBIT_NARROW)

    def test_small_table_is_usable(self):
        # a listing with far fewer rows than the 128 wide identifier window leaves the high bit planes
        # empty; the shared row markup must not then be placed at a row that does not exist (it would
        # become the canary, and "no rows selected" would be indistinguishable from a junk response)
        secret = "fifteen products are enough to carry this"
        value, _ = self._attempt(secret, len(secret), rows=SMALL)

        self.assertEqual(value, secret)

    def test_pagination_wider_than_the_channel_is_still_usable(self):
        # a page that renders 10 rows can still carry a channel that only ever addresses 9 of them -
        # rejecting it would throw the technique away on most real listings
        secret = "ten rendered rows are enough"
        value, _ = self._attempt(secret, len(secret), limit=10)

        self.assertEqual(value, secret)

    def test_declines_when_rows_carry_no_unique_marker(self):
        value, _ = self._attempt("indistinguishable rows", 22, unique=False)

        self.assertIsNone(value)

    def test_declines_on_non_ascii_value(self):
        # 8 bits cannot carry it, so the read-back must catch it rather than return mojibake
        value, _ = self._attempt(u"stra\u017enji dio", 12)

        self.assertIsNone(value)

    def test_junk_responses_never_produce_a_wrong_value(self):
        secret = "junk-tolerant-extraction-must-stay-exact"

        for every in (3, 5, 7, 11):
            value, _ = self._attempt(secret, len(secret), junkEvery=every)
            self.assertIn(value, (secret, None), "junkEvery=%d produced %r" % (every, value))

    def test_unprovable_value_does_not_condemn_the_channel(self):
        # the unescaper stands down on data matching EXCLUDE_UNESCAPE, so this value cannot be proven
        # back - but that is the value's problem, not the channel's, and must not latch it off
        value, _ = self._attempt("no way to escape CREATE TABLE x (a int)", 36)

        self.assertIsNone(value)
        self.assertNotEqual(list(kb.multibit.values()), [False])

    def test_first_value_that_cannot_settle_the_cross_check_keeps_the_channel(self):
        # the cross-check compares the FIRST character of whatever value comes first; an empty one, a
        # non-ASCII one, and one whose codepoint has an ASCII low byte (U+0141 -> 0x41 'A') all settle
        # nothing, and none of them may condemn a channel that calibrated cleanly
        for first in ("", u"\u017eaba pod vodom", u"\u0141ukasz Nowak here"):
            target = _Target(first)
            self.assertIsNone(self._read(target, first, len(first) or None))

            good = target.secret("plain ascii value that must still come back")
            self.assertEqual(self._read(target, good, len(good)), good, "condemned after %r" % first)

    def test_null_values_do_not_condemn_the_channel(self):
        # a NULL column has no length, so the read-back's length probe comes back unselected no matter
        # what the channel did - i.e. exactly the way a channel dropping rows fails it. That is the
        # data's doing, and a handful of NULLs in one dump must not retire a working channel
        first = "first value is perfectly readable ascii"
        target = _Target(first)
        self.assertEqual(self._read(target, first, len(first)), first)

        for _ in range(MULTIBIT_MAX_FAILURES + 1):
            target.secret(None)
            self.assertIsNone(self._read(target, ""))

        good = target.secret("and the channel is still fine afterwards")
        self.assertEqual(self._read(target, good, len(good)), good)

    def test_unreadable_value_mid_run_keeps_the_channel(self):
        target = _Target("first value is perfectly readable ascii")
        self.assertEqual(self._read(target, "first value is perfectly readable ascii", 39), "first value is perfectly readable ascii")

        bad = target.secret(u"\u0141ukasz")          # reads back as "Aukasz" - right length, wrong char
        self.assertIsNone(self._read(target, bad, len(bad)))

        good = target.secret("and the channel is still fine afterwards")
        self.assertEqual(self._read(target, good, len(good)), good)

    def test_row_identifier_may_share_the_injected_parameter_name(self):
        # a shop injectable through ?cat= can perfectly well render per-row ?cat= links; the candidate
        # is picked because its values VARY, not because of what it is called
        secret = "same name as the injection point is fine"
        value, _ = self._attempt(secret, len(secret), column="cat")

        self.assertEqual(value, secret)

    def test_atoms_are_wellformed_for_every_supported_dbms(self):
        # only the SQLite path is executed above; the others must at least produce balanced, fully
        # substituted SQL - including the negative shift a later window produces ("id--67" would be a
        # comment, so it has to come out parenthesized)
        for dbms in (DBMS.MYSQL, DBMS.PGSQL, DBMS.MSSQL, DBMS.ORACLE, DBMS.SQLITE):
            set_dbms(dbms)
            expressions = (multibit._bitcol("id", 5, 3),
                           queries[dbms].bitmap.query % ("SELECT s FROM v", "id", "(-67)", 8, "id", "(-67)", 8))

            for expression in expressions:
                self.assertNotIn("--", expression, dbms)
                self.assertNotIn("%s", expression, dbms)
                self.assertNotIn("%d", expression, dbms)
                self.assertEqual(expression.count("("), expression.count(")"), dbms)

    def test_nothing_runs_without_the_switch(self):
        conf.multiBit = False
        value, target = self._attempt("not to be read", 14)

        self.assertIsNone(value)
        self.assertEqual(target.requests, 0)

    def test_resumed_partial_value_is_left_to_bisection(self):
        # a resumed value starts mid-string, and multi-bit reads from the first character: it would
        # re-read what is already cached and then fail its own length read-back
        target = _Target("resuming this one is bisection's job")
        multibit._page = target.page

        self.assertIsNone(multibit.attempt("SELECT s FROM v", lambda idx: 'x', 35, None, True))
        self.assertEqual(target.requests, 0)

    def test_threaded_read_matches_the_serial_one(self):
        # the chunks sit at known positions, so they are independent; the value must come out identical
        secret = "threaded reads must assemble in position order, not in completion order"

        conf.threads = 4
        value, _ = self._attempt(secret, len(secret))

        self.assertEqual(value, secret)

    def test_profile_is_per_injection_point(self):
        secret = "first parameter value here padded out"
        value, _ = self._attempt(secret, len(secret))
        self.assertEqual(value, secret)
        self.assertEqual(len(kb.multibit), 1)

        kb.injection.parameter = "other"
        value, _ = self._attempt(secret, len(secret))
        self.assertEqual(value, secret)
        self.assertEqual(len(kb.multibit), 2)

    def test_identifiers_ignore_site_chrome(self):
        # a single-product DETAIL page: one real row (a hidden form field), but the only REPEATED
        # markup is the nav menu, the currency switcher and the security-level links - all site
        # chrome. That must yield NO candidates, so the page is ruled out for free and the risk-3
        # question can never fire on it (the exact failure this trigger replaces)
        page = """
        <!doctype html><html><head><title>x</title></head><body>
        <header><div class='acct'>
        <a href='/setcurr.php?c=USD'>USD</a><a href='/setcurr.php?c=EUR'>EUR</a>
        <a href='/setlevel.php?l=low'>low</a><a href='/setlevel.php?l=high'>high</a>
        </div></header>
        <nav><a href='/category.php?cat=1'>A</a><a href='/category.php?cat=2'>B</a>
        <a href='/category.php?cat=3'>C</a><a href='/category.php?cat=4'>D</a>
        <a href='/category.php?cat=5'>E</a></nav>
        <main><div class='product'><h2>Quantum USB Cable</h2>
        <p class='price'>$9.99</p><p class='desc'>Transfers data before you even plug it in.</p>
        <a class='btn' href='/cart.php?add=1'>add to cart</a></div>
        <form method='post'><input type='hidden' name='product_id' value='1'>
        <label>name<input name='author'></label></form></main>
        <footer><p>demo shop</p></footer></body></html>
        """

        self.assertEqual(multibit._identifiers(page), {})

    def test_identifiers_find_repeated_row_forms(self):
        # row identity hides in whatever markup the listing repeats: query strings, path segments,
        # data attributes and hidden form fields all count - but only when the value VARIES
        page = "".join(
            "<div class='item'><a href='/product/%d'>p</a><span data-pid='%d'>%d</span>" % (_, _, _) +
            "<input type='hidden' name='product_id' value='%d'>" % _ +
            "<a href='details.php?sku=%d'>x</a></div>" % _
            for _ in range(1, 6)) + "<div class='once'><a href='/cart.php?add=7'>y</a></div>"

        found = multibit._identifiers(page)

        self.assertEqual(found.get("product"), set(range(1, 6)))
        self.assertEqual(found.get("pid"), set(range(1, 6)))
        self.assertEqual(found.get("product_id"), set(range(1, 6)))
        self.assertEqual(found.get("sku"), set(range(1, 6)))
        self.assertNotIn("add", found)              # a single value is page furniture, not a row id

    def test_the_switch_takes_the_whole_table(self):
        # the switch IS the permission, so discovery goes for the wide channel first - no question,
        # whatever '--risk' says
        secret = "the switch is the permission to widen"
        value, _ = self._attempt(secret, len(secret))

        self.assertEqual(value, secret)
        self.assertEqual(list(kb.multibit.values())[0]["mode"], MULTIBIT_WIDEN)

    def _hint(self):
        """hint() with everything it could say captured - a nudge is INFO, an unusable back-end a WARNING."""

        said = []
        multibit.singleTimeWarnMessage = lambda message: said.append(message)
        multibit.singleTimeLogMessage = lambda message, level=None, flag=None: said.append(message)
        multibit.hint()

        return said

    def test_hint_costs_nothing_and_states_the_width(self):
        # the nudge towards the switch is drawn from the page sqlmap already has, never from a probe
        conf.multiBit = False                       # the nudge is for a run that did NOT ask for it
        kb.originalPage = "".join("<div class='item'><a href='/product.php?id=%d'>p</a></div>" % _ for _ in range(1, 13))

        said = self._hint()

        self.assertEqual(len(said), 1)
        self.assertIn("12 rows", said[0])
        self.assertIn("--multi-bit", said[0])

    def test_hint_stays_quiet_on_a_page_that_renders_no_rows(self):
        # the old trigger announced "the target lists rows" on the nav menu of a single-product DETAIL
        # page and asked the user to accept risk 3; the nudge may only follow REPEATED CONTENT markup
        conf.multiBit = False
        kb.originalPage = ("<html><body>"
                           "<header><a href='/setcurr.php?c=USD'>USD</a><a href='/setcurr.php?c=EUR'>EUR</a></header>"
                           "<nav><a href='/category.php?cat=1'>A</a><a href='/category.php?cat=2'>B</a>"
                           "<a href='/category.php?cat=3'>C</a></nav>"
                           "<main><div class='product'><h2>Quantum USB Cable</h2><p class='price'>$9.99</p>"
                           "<input type='hidden' name='product_id' value='1'></div></main></body></html>")

        self.assertEqual(self._hint(), [])

    def test_switch_on_an_unsupported_backend_says_so(self):
        # the bit arithmetic exists for five back-ends; asking for the switch on any other one has to
        # say why nothing happens instead of silently doing nothing
        set_dbms(DBMS.FIREBIRD)

        said = self._hint()

        self.assertEqual(len(said), 1)
        self.assertIn("not supported", said[0])

    def test_hint_stays_quiet_when_an_inband_channel_is_available(self):
        # UNION or error-based beats any row channel, so nudging towards this one would be noise
        conf.multiBit = False
        kb.originalPage = "".join("<div class='item'><a href='/product.php?id=%d'>p</a></div>" % _ for _ in range(1, 13))
        kb.injection.data[PAYLOAD.TECHNIQUE.UNION] = {}

        self.assertEqual(self._hint(), [])

if __name__ == "__main__":
    unittest.main()
