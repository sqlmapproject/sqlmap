#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Payload assembly helpers in lib/core/agent.py.

These are the (mostly) DBMS-independent string transforms that wrap, fold and
clean a payload on its way to the wire: prefix/suffix, payload delimiters,
field extraction, CONCAT folding, and RAND-marker cleanup. All values below
were probed from real output, not assumed.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.agent import agent
from lib.core.enums import DBMS
from lib.core.settings import PAYLOAD_DELIMITER


class TestPayloadDelimiters(unittest.TestCase):
    def test_add(self):
        self.assertEqual(agent.addPayloadDelimiters("1 AND 1=1"),
                         "%s1 AND 1=1%s" % (PAYLOAD_DELIMITER, PAYLOAD_DELIMITER))

    def test_remove(self):
        wrapped = "%spayload%s" % (PAYLOAD_DELIMITER, PAYLOAD_DELIMITER)
        self.assertEqual(agent.removePayloadDelimiters(wrapped), "payload")

    def test_remove_none_is_none(self):
        self.assertIsNone(agent.removePayloadDelimiters(None))

    def test_roundtrip(self):
        for p in ["1=1", "1 AND SLEEP(5)", "' OR '1'='1", "", "a%sb" % "x"]:
            self.assertEqual(agent.removePayloadDelimiters(agent.addPayloadDelimiters(p)), p,
                             msg="delimiter round-trip for %r" % p)


class TestPrefixSuffix(unittest.TestCase):
    def test_prefix_default_pads_space(self):
        # with no configured prefix, a single leading space is prepended
        self.assertEqual(agent.prefixQuery("1=1"), " 1=1")

    def test_suffix_default_identity(self):
        self.assertEqual(agent.suffixQuery("1=1"), "1=1")


class TestGetFields(unittest.TestCase):
    def test_extracts_select_list(self):
        # getFields(query) returns an 8-tuple; the fields-bearing slots are:
        #   [0],[1] = regex match objects for the SELECT/expression (must be found, not None)
        #   [5]     = parsed field list, [6] = raw fields string
        # (asserting the match objects guards against a refactor that silently shifts the tuple)
        result = agent.getFields("SELECT a,b FROM t")
        self.assertIsNotNone(result[0], msg="getFields did not match the SELECT")
        self.assertEqual(result[5], ["a", "b"])
        self.assertEqual(result[6], "a,b")


class TestConcatQuery(unittest.TestCase):
    def test_mysql_concat_folding(self):
        set_dbms(DBMS.MYSQL)
        q = agent.concatQuery("SELECT a FROM t")
        # folds the field through CONCAT with the start/stop delimiters and keeps the FROM
        self.assertTrue(q.startswith("CONCAT("), msg=q)
        self.assertIn("IFNULL(CAST(a AS NCHAR),' ')", q)
        self.assertTrue(q.endswith("FROM t"), msg=q)


class TestCleanupPayload(unittest.TestCase):
    def test_randnum_marker_replaced_with_digits(self):
        out = agent.cleanupPayload("SELECT [RANDNUM]")
        self.assertNotIn("[RANDNUM]", out, msg="marker not replaced: %r" % out)   # actually substituted
        self.assertTrue(out.startswith("SELECT "), msg=out)
        self.assertTrue(out.split()[-1].isdigit(), msg=out)   # ...and replaced with a concrete number


if __name__ == "__main__":
    unittest.main(verbosity=2)
