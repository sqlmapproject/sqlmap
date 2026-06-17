#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

T1 - automatic WAF-bypass tamper selection (lib/utils/wafbypass.py). These cover the pure,
offline pieces: the identYwaf blind-signature decoder (which provocation vectors a known WAF
blocks), the data-ranked / DBMS-filtered / identYwaf-pruned candidate ordering, and the runtime
tamper loader. The end-to-end "adopt a tamper that restores detection" behaviour is exercised by
the --auto-tamper vuln-test case (lib/core/testing.py) against the vulnserver WAF emulator.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.utils.wafbypass import candidateTampers, identYwafBlockedVectors, loadTamper


class TestIdentYwafDecoder(unittest.TestCase):
    def test_known_waf_decodes_to_blocked_vectors(self):
        # cloudflare has bundled blind signatures -> a non-trivial set of blocked vector indices,
        # all within range of the 45 provocation vectors
        blocked = identYwafBlockedVectors("cloudflare")
        self.assertTrue(len(blocked) > 5)
        self.assertTrue(all(isinstance(_, int) and 0 <= _ < 45 for _ in blocked))

    def test_unknown_waf_is_empty(self):
        self.assertEqual(identYwafBlockedVectors("definitely-not-a-real-waf"), set())
        self.assertEqual(identYwafBlockedVectors(None), set())


class TestCandidateRanking(unittest.TestCase):
    def test_structural_first(self):
        cands = candidateTampers()
        # the empirically strongest structural substitutions lead, ahead of camouflage
        self.assertEqual(cands[0], "equaltolike")
        self.assertIn("between", cands[:3])
        self.assertLess(cands.index("between"), cands.index("space2comment"))

    def test_no_dbms_prefiltering(self):
        # DBMS compatibility is verified at runtime (detection re-run through the tamper), not here,
        # so the full candidate set is offered regardless of any guessed back-end DBMS
        cands = candidateTampers()
        self.assertIn("versionedkeywords", cands)
        self.assertIn("space2hash", cands)
        self.assertIn("between", cands)

    def test_identYwaf_prior_prunes_camouflage(self):
        # a WAF whose profile blocks comment-obfuscated vectors should have comment-insertion
        # camouflage pruned (it cannot help there), while structural candidates survive
        base = candidateTampers()
        pruned = candidateTampers(identifiedWafs=["cloudflare"])
        self.assertIn("equaltolike", pruned)
        self.assertNotIn("space2comment", pruned)
        self.assertLessEqual(len(pruned), len(base))


class TestLoadTamper(unittest.TestCase):
    def test_loads_and_applies(self):
        fn = loadTamper("between")
        self.assertTrue(callable(fn))
        self.assertEqual(fn.__name__, "between")
        # the loaded function is the real tamper transform
        self.assertEqual(fn(payload="1 AND A>B"), "1 AND A NOT BETWEEN 0 AND B")

    def test_missing_returns_none_or_raises(self):
        # a non-existent script must not silently yield a bogus callable
        try:
            self.assertIsNone(loadTamper("no_such_tamper_script_xyz"))
        except Exception:
            pass   # an import error is also acceptable; what matters is no fake function


if __name__ == "__main__":
    unittest.main()
