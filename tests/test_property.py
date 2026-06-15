#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Property/fuzz tests for the pure parsers and transforms. Where the other test
files pin specific examples, these assert INVARIANTS over hundreds of randomized
(but deterministic, cross-version-identical - see _testutils.Rng) inputs, which is
the cheap net for the edge-bug class that example tests miss (commas inside quoted
literals / nested parens, NUL / 0xff / astral code points in codecs, etc.).

Property families:
  - codec/serializer pairs round-trip: decode(encode(x)) == x
  - structure transforms preserve their contract (flat/de-arrayized/permutation)
  - string transforms hold their stated invariant (ASCII-only, no newlines, ...)
  - random helpers respect length / alphabet / range bounds
  - splitFields/zeroDepthSearch partition faithfully and never cut inside a group
  - a batch of transforms never raise on arbitrary input

On failure _testutils.for_all prints the exact offending input + its case index so
it reproduces on any interpreter.
"""

import os
import string
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, for_all, set_dbms
bootstrap()

from extra.cloak.cloak import cloak, decloak
from lib.core.common import (escapeJsonValue, filterStringValue, flattenValue, isListLike, normalizeUnicode,
                             prioritySortColumns, randomInt, randomRange, randomStr, safeSQLIdentificatorNaming,
                             sanitizeStr, splitFields, unArrayizeValue, unsafeSQLIdentificatorNaming, urldecode,
                             urlencode, zeroDepthSearch)
from lib.core.convert import (base64pickle, base64unpickle, decodeBase64, decodeHex, dejsonize, encodeBase64,
                              encodeHex, getBytes, getConsoleLength, getOrds, getText, htmlEscape, htmlUnescape,
                              jsonize, stdoutEncode)
from lib.core.data import kb
from lib.utils.safe2bin import safecharencode


# --- input strategies (draw ONLY through rng: randint / choice / sample / blob) ---

# deliberately loaded with structural metacharacters + tricky code points
_TEXT = [u"a", u"Z", u"7", u" ", u",", u"'", u'"', u"(", u")", u"\\", u";",
         u"\n", u"\t", u"\x00", u"\x7f", u"\xe9", u"\u0107", u"\u4e2d", u"\U0001F600", u" FROM "]


def gen_text(rng):
    return u"".join(rng.choice(_TEXT) for _ in range(rng.randint(0, 24)))


def gen_ascii(rng):
    return u"".join(rng.choice(string.printable) for _ in range(rng.randint(0, 20)))


def gen_blob(rng):
    return rng.blob(rng.randint(0, 32))


def gen_json(rng):
    # JSON-safe only: tuples become lists and non-str keys are coerced, so exclude them here
    if rng.randint(0, 4) == 0:
        return [gen_json(rng) for _ in range(rng.randint(0, 3))]
    if rng.randint(0, 4) == 0:
        return dict((u"k%d" % j, gen_json(rng)) for j in range(rng.randint(0, 3)))
    return rng.choice([0, 1, -1, 2 ** 31, 1.5, -0.25, True, False, None, u"", u"x", u"\u0107", u'a"b,c'])


def gen_pickle(rng):
    kind = rng.randint(0, 9)
    if kind < 5:
        return rng.choice([0, -7, 2 ** 40, 3.5, True, False, None, u"\u0107x", b"\x00\xff", u""])
    if kind < 7:
        return [gen_pickle(rng) for _ in range(rng.randint(0, 3))]
    if kind < 8:
        return tuple(gen_pickle(rng) for _ in range(rng.randint(0, 3)))
    if kind < 9:
        return set(rng.choice([1, 2, 3, u"a", u"b"]) for _ in range(rng.randint(0, 3)))
    return dict((u"k%d" % j, gen_pickle(rng)) for j in range(rng.randint(0, 2)))


def gen_columns(rng):
    return [rng.choice([u"id", u"userid", u"name", u"password", u"a", u"created_id", u"x_id_y", u"data"])
            for _ in range(rng.randint(0, 6))]


def gen_ident(rng):
    # clean (round-trippable) identifier names: letters/digits/underscore, optional dot/space
    chars = string.ascii_letters + string.digits + u"_"
    name = u"".join(rng.choice(chars) for _ in range(rng.randint(1, 10)))
    if rng.randint(0, 3) == 0:
        name += rng.choice([u".col", u" alias", u"_2"])
    return name


# well-formed field lists: balanced parens, properly closed/escaped quotes
_TOKENS = [u"foo", u"bar", u"id", u"a b", u"1", u"*", u"max(a)", u"COALESCE(a, b, c)", u"func(x, y)"]
_QUOTED = [u"a,b", u"x, y", u"f(1, 2)", u"o''k", u"plain", u""]


def gen_sql_fields(rng):
    parts = []
    for _ in range(rng.randint(1, 5)):
        t = rng.randint(0, 9)
        if t < 5:
            parts.append(rng.choice(_TOKENS))
        elif t < 8:
            q = rng.choice([u"'", u'"'])
            parts.append(q + rng.choice(_QUOTED) + q)
        else:
            parts.append(u"g(%s, %s)" % (rng.choice(_TOKENS), rng.choice(_TOKENS)))
    return u", ".join(parts)


class TestCodecRoundTrips(unittest.TestCase):
    def test_base64(self):
        for_all(self, gen_blob, lambda b: decodeBase64(encodeBase64(b)) == b, label="base64")

    def test_hex(self):
        for_all(self, gen_blob, lambda b: decodeHex(encodeHex(b)) == b, label="hex")

    def test_getbytes_gettext(self):
        # unsafe=False -> plain UTF-8 (no \xNN escape interpretation), so it is a clean round-trip
        for_all(self, gen_text, lambda s: getText(getBytes(s, unsafe=False)) == s, label="bytes-text")

    def test_json(self):
        for_all(self, gen_json, lambda v: dejsonize(jsonize(v)) == v, label="json")

    def test_pickle(self):
        for_all(self, gen_pickle, lambda v: base64unpickle(base64pickle(v)) == v, label="pickle")

    def test_html_escape(self):
        for_all(self, gen_text, lambda s: htmlUnescape(htmlEscape(s)) == s, label="html")

    def test_cloak(self):
        for_all(self, gen_blob, lambda b: decloak(data=cloak(data=b)) == b, label="cloak")


class TestStructureTransforms(unittest.TestCase):
    def test_unarrayize_never_listlike(self):
        # the whole point of unArrayizeValue is that the result is a scalar, never a list/tuple
        # (gen_pickle includes sets - they used to crash here; see test_unarrayize_set regression)
        for_all(self, gen_pickle, lambda v: not isListLike(unArrayizeValue(v)), label="unarrayize")

    def test_flatten_is_flat(self):
        for_all(self, gen_pickle, lambda v: all(not isListLike(x) for x in flattenValue([v])), label="flatten")

    def test_unarrayize_set(self):
        # regression: a 1-element set is list-like but not subscriptable; unArrayizeValue must
        # de-arrayize it rather than crash on value[0]
        self.assertEqual(unArrayizeValue(set(["x"])), "x")
        self.assertEqual(unArrayizeValue(set()), None)
        self.assertEqual(unArrayizeValue(["1"]), "1")   # ordinary fast-path still works

    def test_prioritysort_is_permutation(self):
        # sorting must not invent/drop columns, and must be idempotent
        def prop(cols):
            out = prioritySortColumns(cols)
            return sorted(out) == sorted(cols) and prioritySortColumns(out) == out
        for_all(self, gen_columns, prop, label="prioritysort")


class TestStringTransforms(unittest.TestCase):
    def test_normalize_unicode_is_ascii(self):
        for_all(self, gen_text, lambda s: all(ord(c) < 128 for c in normalizeUnicode(s)), label="normalize-ascii")

    def test_sanitizestr_strips_newlines(self):
        for_all(self, gen_text, lambda s: "\n" not in sanitizeStr(s) and "\r" not in sanitizeStr(s), label="sanitizestr")

    def test_filterstringvalue_charset(self):
        allowed = set("0123456789abcdef")
        for_all(self, gen_text, lambda s: set(filterStringValue(s, r"[0-9a-f]")) <= allowed, label="filterstring")

    def test_escapejson_no_control_char(self):
        # control chars and bare quotes must be escaped away (output is JSON-string-body safe re: those)
        for_all(self, gen_text, lambda s: all(c >= " " for c in escapeJsonValue(s)), label="escapejson-invariant")

    def test_escapejson_json_roundtrip(self):
        # escapeJsonValue(s) embedded in a JSON string must parse back to s - for ALL text,
        # including backslash (the F1 fix; this used to fail on '\')
        import json
        for_all(self, gen_text, lambda s: json.loads(u'"%s"' % escapeJsonValue(s)) == s, label="escapejson-roundtrip")

    def test_escapejson_backslash(self):
        # regression for F1: backslash is now escaped, so the round-trip holds
        import json
        self.assertEqual(json.loads(u'"%s"' % escapeJsonValue(u"a\\b")), u"a\\b")

    def test_getords_length(self):
        for_all(self, gen_text, lambda s: len(getOrds(s)) == len(s) and all(isinstance(o, int) for o in getOrds(s)), label="getords")

    def test_consolelength_ascii(self):
        for_all(self, gen_ascii, lambda s: getConsoleLength(s) == len(s), label="consolelength")


class TestRandomHelpers(unittest.TestCase):
    def test_randomstr_length_and_alphabet(self):
        for_all(self, lambda r: r.randint(0, 16),
                lambda n: len(randomStr(n)) == n and set(randomStr(n)) <= set(string.ascii_letters), label="randomstr")

    def test_randomstr_lowercase(self):
        for_all(self, lambda r: r.randint(0, 16),
                lambda n: set(randomStr(n, lowercase=True)) <= set(string.ascii_lowercase), label="randomstr-lower")

    def test_randomint_digits(self):
        for_all(self, lambda r: r.randint(1, 8), lambda n: len(str(randomInt(n))) == n, label="randomint")

    def test_randomrange_bounds(self):
        def prop(_):
            a = _[0]
            b = _[0] + _[1]
            return a <= randomRange(a, b) <= b
        for_all(self, lambda r: (r.randint(-50, 50), r.randint(0, 100)), prop, label="randomrange")


class TestSplitterInvariants(unittest.TestCase):
    def test_reconstruction(self):
        # Faithful partition: rejoining the 0-depth split reconstructs the input modulo the only
        # transform splitFields applies - dropping a single space after an unquoted delimiter. So
        # nothing other than spaces may be lost/added/reordered. (Space-insensitive so it survives
        # the quote-aware normalization: spaces inside 'literals' are kept, comma-trailing ones are
        # not; either way no non-space content changes.)
        for_all(self, gen_text, lambda s: u",".join(splitFields(s)).replace(u" ", u"") == s.replace(u" ", u""), label="split-reconstruct-text")
        for_all(self, gen_sql_fields, lambda s: u",".join(splitFields(s)).replace(u" ", u"") == s.replace(u" ", u""), label="split-reconstruct-sql")

    def test_quoted_literal_spaces_preserved(self):
        # the I3 contract: a ", " inside a quoted literal must NOT be collapsed (the whole literal
        # survives intact as a single field)
        for_all(self, lambda r: u"%s, '%s, %s', %s" % (r.choice([u"a", u"id"]), r.choice([u"x", u"p q"]), r.choice([u"y", u"z"]), r.choice([u"b", u"c"])),
                lambda s: u"'%s'" % s.split(u"'")[1] in splitFields(s), label="split-quote-preserve")

    def test_never_cuts_inside_parens(self):
        # on well-formed input no field may carry unbalanced parens (i.e. a split never lands inside a group)
        for_all(self, gen_sql_fields, lambda s: all(f.count(u"(") == f.count(u")") for f in splitFields(s)), label="split-balanced")

    def test_zerodepth_indices_are_real_commas(self):
        def prop(s):
            idx = zeroDepthSearch(s, ",")
            return all(s[i] == u"," for i in idx) and idx == sorted(idx) and len(set(idx)) == len(idx)
        for_all(self, gen_text, prop, label="zerodepth-commas-text")
        for_all(self, gen_sql_fields, prop, label="zerodepth-commas-sql")


class TestIdentifierRoundTrip(unittest.TestCase):
    def setUp(self):
        self._saved = kb.get("forcedDbms")
        set_dbms("MySQL")   # identifier quoting is DBMS-specific; pin a case-preserving back-end

    def tearDown(self):
        kb.forcedDbms = self._saved

    def test_safe_unsafe_roundtrip(self):
        for_all(self, gen_ident, lambda n: unsafeSQLIdentificatorNaming(safeSQLIdentificatorNaming(n)) == n, label="identifier")


class TestRobustness(unittest.TestCase):
    # total functions: must never raise on arbitrary text (return value unconstrained)
    def test_urlencode_urldecode(self):
        for_all(self, gen_text, lambda s: (urlencode(s), urldecode(s)) and True, label="urlcodec")

    def test_safecharencode(self):
        for_all(self, gen_text, lambda s: safecharencode(s) is not None or s == u"", label="safecharencode")

    def test_stdoutencode(self):
        for_all(self, gen_text, lambda s: stdoutEncode(s) is not None or s == u"", label="stdoutencode")


if __name__ == "__main__":
    unittest.main()
