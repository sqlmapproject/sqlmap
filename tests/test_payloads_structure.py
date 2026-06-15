#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Structural invariants of the injection payload/boundary definitions
(data/xml/payloads/*.xml -> conf.tests, data/xml/boundaries.xml -> conf.boundaries).

These XML files ARE the detection engine: every test/boundary loaded here is
something sqlmap will fire at a target. The fields are pure data, so the right
tests are shape/range invariants - a malformed level, an unknown technique, a
duplicate title, or a test missing its request payload would silently break or
skew detection.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.parse.payloads import loadBoundaries, loadPayloads
from lib.core.data import conf
from lib.core.enums import PAYLOAD
from lib.core.common import getPublicTypeMembers

# load once for the module
loadBoundaries()
loadPayloads()

TECHNIQUES = set(v for _, v in getPublicTypeMembers(PAYLOAD.TECHNIQUE))   # {1..6}
WHERES = set(v for _, v in getPublicTypeMembers(PAYLOAD.WHERE))           # {1,2,3}


class TestLoaded(unittest.TestCase):
    # floors well below the current counts (~340 tests, ~54 boundaries) - high enough to catch a
    # truncated/partially-loaded XML set (not just "> 0"), low enough to survive normal additions
    def test_payloads_loaded(self):
        self.assertGreaterEqual(len(conf.tests), 200, msg="only %d tests loaded" % len(conf.tests))

    def test_boundaries_loaded(self):
        self.assertGreaterEqual(len(conf.boundaries), 30, msg="only %d boundaries loaded" % len(conf.boundaries))


class TestTestEntries(unittest.TestCase):
    def setUp(self):
        # guard against vacuous passes: if payloads failed to load, every loop below
        # would iterate zero times and pass silently
        self.assertTrue(conf.tests, "conf.tests is empty - payloads failed to load")

    def test_required_fields_present(self):
        for t in conf.tests:
            for field in ("title", "stype", "clause", "where", "level", "risk", "request", "response"):
                self.assertIn(field, t, msg="test %r missing field %r" % (t.get("title"), field))

    def test_title_non_empty(self):
        for t in conf.tests:
            self.assertTrue(t.title and t.title.strip(), msg="empty test title")

    def test_titles_unique(self):
        titles = [t.title for t in conf.tests]
        self.assertEqual(len(titles), len(set(titles)), msg="duplicate test titles exist")

    def test_stype_is_known_technique(self):
        for t in conf.tests:
            self.assertIn(t.stype, TECHNIQUES, msg="test %r has unknown stype %r" % (t.title, t.stype))

    def test_level_and_risk_in_range(self):
        for t in conf.tests:
            self.assertIn(t.level, (1, 2, 3, 4, 5), msg="test %r bad level %r" % (t.title, t.level))
            self.assertIn(t.risk, (1, 2, 3), msg="test %r bad risk %r" % (t.title, t.risk))

    def test_request_has_payload(self):
        for t in conf.tests:
            self.assertIn("payload", t.request, msg="test %r request has no payload" % t.title)

    def test_where_values_valid(self):
        for t in conf.tests:
            for w in t.where:
                self.assertIn(w, WHERES, msg="test %r has bad where %r" % (t.title, w))


class TestBoundaryEntries(unittest.TestCase):
    def setUp(self):
        self.assertTrue(conf.boundaries, "conf.boundaries is empty - boundaries failed to load")

    def test_required_fields_present(self):
        for b in conf.boundaries:
            for field in ("level", "clause", "where", "ptype"):
                self.assertIn(field, b, msg="boundary missing field %r" % field)

    def test_level_in_range(self):
        for b in conf.boundaries:
            self.assertIn(b.level, (1, 2, 3, 4, 5), msg="boundary bad level %r" % b.level)

    def test_where_values_valid(self):
        for b in conf.boundaries:
            for w in b.where:
                self.assertIn(w, WHERES, msg="boundary bad where %r" % w)

    def test_clause_is_list_like(self):
        for b in conf.boundaries:
            self.assertTrue(isinstance(b.clause, (list, tuple)), msg="boundary clause not list-like")


if __name__ == "__main__":
    unittest.main(verbosity=2)
