#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Tamper scripts (all ~70): contract, robustness on a payload battery, known
transforms, and documented fragile cases.

NOTE (flagged for author - real minor bugs surfaced by this suite):
  * tamper/percentage.py raises UnboundLocalError on empty/None payload
    (retVal is only assigned inside `if payload:`; missing `retVal = payload` init).
  * tamper/escapequotes.py raises AttributeError on None payload (no guard).
  68/70 tampers handle ""/None gracefully; these two are inconsistent. Pinned below
  as KNOWN_FRAGILE so the suite stays green and a fix is a conscious change.
"""

import os
import glob
import importlib
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, ROOT
bootstrap()

from thirdparty import six

TAMPERS = sorted(os.path.basename(f)[:-3] for f in glob.glob(os.path.join(ROOT, "tamper", "*.py"))
                 if not f.endswith("__init__.py"))

# realistic, non-empty payloads (incl. unicode via escape, and a long one)
PAYLOADS = [
    "1 AND 2=2",
    "1 UNION SELECT NULL,NULL-- -",
    "1 AND (SELECT 1 FROM dual)>0",
    "1 AND '1'='1",
    "admin'-- -",
    u"1 AND name='caf\xe9'",
    "1 AND " + "A" * 64,   # modest "longer" payload
]

KNOWN_FRAGILE = set()  # percentage/escapequotes empty/None crashes were FIXED by the author; now covered below
# Intentionally expensive by design (generates 4.2M parameters per call to flood Lua-Nginx
# WAFs) -> ~6s/call. NOT a bug; excluded from execution to keep the unit suite fast.
HEAVY = {"luanginxmore"}

# Project contract for falsy input: tamper("") == "" and tamper(None) is None
# (the common idiom `if payload: ...; return payload` passes "" and None through unchanged).
# These tampers legitimately deviate for None: they initialize `retVal = ""` and only reassign
# it inside `if payload:`, so any falsy payload (both "" AND None) returns "" -- i.e. None is
# normalized to "" instead of being passed through. tamper("") == "" still holds for them.
NONE_RETURNS_EMPTY = {
    "sp_password",        # retVal = ""; reassigned only inside `if payload:`
    "space2dash",         # retVal = ""; reassigned only inside `if payload:`
    "space2hash",         # retVal = ""; reassigned only inside `if payload:`
    "space2morehash",     # retVal = ""; reassigned only inside `if payload:`
    "space2mssqlhash",    # retVal = ""; reassigned only inside `if payload:`
    "space2mysqldash",    # retVal = ""; reassigned only inside `if payload:`
}


class TestTamperRobustness(unittest.TestCase):
    def test_no_crash_returns_string(self):
        for name in TAMPERS:
            if name in HEAVY:
                continue
            mod = importlib.import_module("tamper.%s" % name)
            for p in PAYLOADS:
                try:
                    r = mod.tamper(p)
                except Exception as ex:
                    self.fail("tamper '%s' crashed on %r: %s" % (name, p[:25], ex))
                self.assertTrue(isinstance(r, six.string_types),
                                msg="tamper '%s' returned %s for %r" % (name, type(r).__name__, p[:25]))


class TestTamperEmptyNoneHandling(unittest.TestCase):
    def test_graceful_on_empty_and_none(self):
        # Assert the actual return contract on falsy input, not merely "does not raise":
        #   tamper("") == ""  and  tamper(None) is None
        # (NONE_RETURNS_EMPTY tampers normalize None to "" -- see comment on that set.)
        for name in TAMPERS:
            if name in KNOWN_FRAGILE or name in HEAVY:
                continue
            mod = importlib.import_module("tamper.%s" % name)

            try:
                empty_result = mod.tamper("")
            except Exception as ex:
                self.fail("tamper '%s' crashed on %r: %s" % (name, "", ex))
            self.assertEqual(empty_result, "",
                             msg="tamper '%s' returned %r for '' (expected '')" % (name, empty_result))

            try:
                none_result = mod.tamper(None)
            except Exception as ex:
                self.fail("tamper '%s' crashed on %r: %s" % (name, None, ex))
            if name in NONE_RETURNS_EMPTY:
                self.assertEqual(none_result, "",
                                 msg="tamper '%s' returned %r for None (expected '' per NONE_RETURNS_EMPTY)" % (name, none_result))
            else:
                self.assertIsNone(none_result,
                                  msg="tamper '%s' returned %r for None (expected None)" % (name, none_result))

    def test_previously_fragile_now_fixed(self):
        # regression pin: percentage/escapequotes used to crash on empty/None; now must be graceful
        import tamper.percentage as _p
        import tamper.escapequotes as _e
        self.assertEqual(_p.tamper(""), "")
        self.assertIsNone(_p.tamper(None))
        self.assertEqual(_e.tamper(""), "")
        self.assertIsNone(_e.tamper(None))


class TestKnownTransforms(unittest.TestCase):
    # authoritative input->output taken from each tamper's own doctest
    CASES = {
        "space2comment":  ("SELECT id FROM users", "SELECT/**/id/**/FROM/**/users"),
        "between":        ("1 AND A > B--", "1 AND A NOT BETWEEN 0 AND B--"),
        "charencode":     ("SELECT FIELD FROM%20TABLE",
                           "%53%45%4C%45%43%54%20%46%49%45%4C%44%20%46%52%4F%4D%20%54%41%42%4C%45"),
        "apostrophemask": ("1 AND '1'='1", "1 AND %EF%BC%871%EF%BC%87=%EF%BC%871"),
        "equaltolike":    ("SELECT * FROM users WHERE id=1", "SELECT * FROM users WHERE id LIKE 1"),
        "percentage":     ("SELECT FIELD FROM TABLE", "%S%E%L%E%C%T %F%I%E%L%D %F%R%O%M %T%A%B%L%E"),
        # additional deterministic transforms (verified stable across repeated calls)
        "space2plus":                ("1 AND 2>1", "1+AND+2>1"),
        "unionalltounion":           ("1 UNION ALL SELECT 2", "1 UNION SELECT 2"),
        "halfversionedmorekeywords": ("1 AND 2>1", "1/*!0AND 2>1"),
        "versionedkeywords":         ("1 AND 2>1", "1/*!AND*/2>1"),
        "appendnullbyte":            ("1", "1%00"),
        "base64encode":              ("1 AND 1=1", "MSBBTkQgMT0x"),
        "greatest":                  ("1 AND A>B", "1 AND GREATEST(A,B+1)=A"),
        "ifnull2ifisnull":           ("IFNULL(a,b)", "IF(ISNULL(a),b,a)"),
        "symboliclogical":           ("1 AND 2 OR 3", "1 %26%26 2 %7C%7C 3"),
        "bluecoat":                  ("1 AND 2=2", "1 AND%092 LIKE 2"),
        "apostrophenullencode":      ("'", "%00%27"),
    }

    def test_transforms(self):
        for name, (inp, expected) in self.CASES.items():
            mod = importlib.import_module("tamper.%s" % name)
            self.assertEqual(mod.tamper(inp), expected, msg="tamper '%s'(%r)" % (name, inp))


class TestTamperCount(unittest.TestCase):
    def test_expected_count(self):
        # there are currently 70 tamper scripts; floor at 70 so an accidental deletion (or a glob
        # that silently stops matching) fails loudly rather than passing on a shrunken set
        self.assertGreaterEqual(len(TAMPERS), 70, msg="expected >=70 tampers, found %d" % len(TAMPERS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
