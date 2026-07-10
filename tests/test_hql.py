#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Offline, deterministic tests for the HQL/JPQL (Hibernate ORM) injection engine. Mock
oracles stand in for the HTTP/ORM layer so detection, fingerprinting, entity leakage,
blind attribute enumeration, value extraction and output formatting can be exercised
without a live Hibernate target.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.techniques.hql.inject as hql


class TestHelpers(unittest.TestCase):
    def test_ratio(self):
        self.assertGreater(hql._ratio("abc", "abc"), 0.9)
        self.assertLess(hql._ratio("abc", "xyz"), 0.5)

    def test_is_error(self):
        self.assertTrue(hql._isError("org.hibernate.query.SyntaxException: token recognition error at: '''"))
        self.assertTrue(hql._isError("org.hibernate.query.sqm.UnknownEntityException: Could not resolve root entity 'Ghost'"))
        self.assertFalse(hql._isError("normal page content"))

    def test_backend_from_error(self):
        self.assertEqual(hql._backendFromError("org.hibernate.query.SemanticException: boom"), "Hibernate")
        self.assertIsNotNone(hql._backendFromError("org.eclipse.persistence.exceptions.JPQLException"))
        self.assertIsNone(hql._backendFromError("plain page"))

    def test_entity_from_error(self):
        self.assertEqual(hql._entityFromError("Could not resolve attribute 'zzz' of 'lab.App$Member'"), "lab.App$Member")
        self.assertEqual(hql._entityFromError("Could not resolve root entity 'Ghost'"), "Ghost")
        self.assertIsNone(hql._entityFromError("nothing here"))

    def test_short_entity(self):
        self.assertEqual(hql._shortEntity("lab.App$Member"), "Member")
        self.assertEqual(hql._shortEntity("com.acme.model.User"), "User")
        self.assertEqual(hql._shortEntity("User"), "User")


class TestBoundary(unittest.TestCase):
    def test_wrap_string(self):
        b = hql.Boundary("' OR ", " OR '1'='2", True)
        self.assertEqual(hql._wrap("SEN", b, "1=1"), "SEN' OR 1=1 OR '1'='2")

    def test_base_sentinel_vs_numeric(self):
        self.assertEqual(hql._base(hql.Boundary("' OR ", " OR '1'='2", True), "x"), hql.SENTINEL)
        self.assertEqual(hql._base(hql.Boundary(" OR ", "", False), "5"), "-1")

    def test_scalar_casts_attribute(self):
        expr = hql._scalar("Member", "id", "LENGTH(%s)", "id")
        self.assertIn("CAST(_h.id AS string)", expr)
        self.assertIn("FROM Member _h", expr)
        self.assertIn("MIN(_h2.id)", expr)


class TestDetection(unittest.TestCase):
    def setUp(self):
        self.original = hql._send

    def tearDown(self):
        hql._send = self.original

    def test_boolean_detection(self):
        # TRUE payloads return rows, FALSE payloads return an empty (but stable) page
        def mock(place, parameter, value):
            if "OR '1'='1" in value or "OR 1=1" in value:
                return "<html><body><div>alice</div><div>bob</div></body></html>"
            return "<html><body></body></html>"
        hql._send = mock
        template, payload, boundary = hql._detectBoolean("GET", "name")
        self.assertIsNotNone(template)
        self.assertIn("OR '1'='1", payload)
        self.assertTrue(boundary.sentinel)

    def test_no_detection_when_static(self):
        hql._send = lambda place, parameter, value: "<html>same</html>"
        template, _, _ = hql._detectBoolean("GET", "name")
        self.assertIsNone(template)


def _recordOracle(record, entity="Member"):
    """Build a truth(predicate) that answers the LENGTH/SUBSTRING/EXISTS predicates
    the engine emits, evaluated against an in-memory record dict."""

    def truth(predicate):
        # entity brute / attribute existence
        m = re.search(r"FROM (\w+) _h", predicate)
        if m and m.group(1) != entity:
            return False
        # entity brute: EXISTS(SELECT 1 FROM <entity> _h)
        if re.search(r"EXISTS\(SELECT 1 FROM \w+ _h\)", predicate):
            return True
        # attribute existence: EXISTS(SELECT _h.<attr> FROM <entity> _h)
        m = re.search(r"SELECT _h\.(\w+) FROM", predicate)
        if m:
            return m.group(1) in record
        # length: LENGTH(CAST(_h.<attr> AS string)) ... >= N
        if "LENGTH" in predicate:
            m = re.search(r"CAST\(_h\.(\w+) AS string\)", predicate)
            n = re.search(r">=(\d+)", predicate)
            if m and n:
                return len(str(record.get(m.group(1), ""))) >= int(n.group(1))
        # char: SUBSTRING(CAST(_h.<attr> AS string),<pos>,1) ... ='<c>'
        if "SUBSTRING" in predicate:
            m = re.search(r"SUBSTRING\(CAST\(_h\.(\w+) AS string\),(\d+),1\)", predicate)
            c = re.search(r"='(.)'\s*$", predicate)
            if m and c:
                attr, pos, ch = m.group(1), int(m.group(2)), c.group(1)
                value = str(record.get(attr, ""))
                return pos <= len(value) and value[pos - 1] == ch
        return False

    return truth


class TestExtraction(unittest.TestCase):
    def setUp(self):
        self.record = {"id": "1", "name": "alice", "secret": "s3cr3t-alice", "role": "admin"}
        self.truth = _recordOracle(self.record)

    def test_brute_entities(self):
        self.assertEqual(hql._bruteEntities(self.truth), ["Member"])

    def test_enum_fields(self):
        fields = hql._enumFields(self.truth, "Member")
        for expected in ("id", "name", "secret", "role"):
            self.assertIn(expected, fields)

    def test_infer_string_value(self):
        self.assertEqual(hql._inferValue(self.truth, "Member", "name", "id"), "alice")

    def test_infer_secret_with_symbols(self):
        self.assertEqual(hql._inferValue(self.truth, "Member", "secret", "id"), "s3cr3t-alice")

    def test_infer_numeric_via_cast(self):
        self.assertEqual(hql._inferValue(self.truth, "Member", "id", "id"), "1")

    def test_infer_absent_attribute_empty(self):
        self.assertEqual(hql._inferValue(self.truth, "Member", "nope", "id"), "")


def _multiOracle(records):
    """Row-aware oracle: honors the "_h2.<pin> > <after>" walk bound by selecting the
    smallest-id record strictly greater than `after`."""

    def pick(predicate):
        m = re.search(r"_h2\.\w+>(\d+)", predicate)
        after = int(m.group(1)) if m else None
        cands = [r for r in records if after is None or int(r["id"]) > after]
        return min(cands, key=lambda r: int(r["id"])) if cands else None

    def truth(predicate):
        if re.search(r"EXISTS\(SELECT 1 FROM \w+ _h\)", predicate):
            return True
        m = re.search(r"EXISTS\(SELECT _h\.(\w+) FROM", predicate)
        if m:
            return m.group(1) in records[0]
        rec = pick(predicate)
        if rec is None:
            return False
        if "LENGTH" in predicate:
            m = re.search(r"CAST\(_h\.(\w+) AS string\)", predicate)
            n = re.search(r">=(\d+)", predicate)
            if m and n:
                return len(str(rec.get(m.group(1), ""))) >= int(n.group(1))
        if "SUBSTRING" in predicate:
            m = re.search(r"SUBSTRING\(CAST\(_h\.(\w+) AS string\),(\d+),1\)", predicate)
            c = re.search(r"='(.)'\s*$", predicate)
            if m and c:
                value = str(rec.get(m.group(1), ""))
                pos = int(m.group(2))
                return pos <= len(value) and value[pos - 1] == c.group(1)
        return False

    return truth


class TestMultiRow(unittest.TestCase):
    def setUp(self):
        self.records = [
            {"id": "1", "name": "alice", "role": "admin"},
            {"id": "2", "name": "bob", "role": "user"},
            {"id": "5", "name": "carol", "role": "staff"},
        ]
        self.truth = _multiOracle(self.records)

    def _walk(self, fields, pin):
        rows, after = [], None
        for _ in range(20):
            pinValue = hql._inferValue(self.truth, "Member", pin, pin, after)
            if not pinValue:
                break
            record = {pin: pinValue}
            for field in fields:
                if field != pin:
                    record[field] = hql._inferValue(self.truth, "Member", field, pin, after)
            rows.append(record)
            if not re.match(r"\A\d+\Z", pinValue):
                break
            after = pinValue
        return rows

    def test_walks_all_rows_in_order(self):
        rows = self._walk(["id", "name", "role"], "id")
        self.assertEqual([r["name"] for r in rows], ["alice", "bob", "carol"])
        self.assertEqual([r["id"] for r in rows], ["1", "2", "5"])
        self.assertEqual(rows[2]["role"], "staff")


class TestGrid(unittest.TestCase):
    def test_grid(self):
        out = hql._grid(["id", "name"], [["1", "alice"]])
        self.assertIn("alice", out)
        self.assertIn("+--", out)


if __name__ == "__main__":
    unittest.main()
