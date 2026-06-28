#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit coverage for lib/utils/brute.py.

tableExists / columnExists are driven with conf.direct=True and the external
collaborators (inject.checkBooleanExpression, getFileItems, runThreads,
getPageWordSet) monkeypatched so the check runs synchronously, deterministically
and offline; plus _addPageTextWords.

Any global conf/kb/Backend state that a call reads or writes is snapshotted in
setUp and restored in tearDown so test ordering is irrelevant.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.data import conf, kb
from lib.core.enums import DBMS

import lib.utils.brute as brute
from lib.request import inject


class DbmsStateMixin(object):
    """Snapshot/restore the Backend/kb DBMS-forcing state so set_dbms() does not leak."""

    def setUp(self):
        self._forcedDbms = kb.forcedDbms
        self._sticky = kb.stickyDBMS
        self._batch = conf.batch
        conf.batch = True

    def tearDown(self):
        kb.forcedDbms = self._forcedDbms
        kb.stickyDBMS = self._sticky
        conf.batch = self._batch


class TestBrute(DbmsStateMixin, unittest.TestCase):
    """Drive tableExists / columnExists with all external collaborators stubbed.

    conf.direct=True skips the time/stacked recommendation prompt. checkBooleanExpression,
    getFileItems and runThreads are monkeypatched so the check runs synchronously,
    deterministically and offline. getPageWordSet is neutralized so the wordlist is
    just what the stub returns.
    """

    def setUp(self):
        DbmsStateMixin.setUp(self)
        self._saved_conf = {k: conf.get(k) for k in
                            ("direct", "db", "tbl", "threads", "api", "verbose")}
        self._choices = kb.choices
        self._cachedTables = kb.data.get("cachedTables")
        self._cachedColumns = kb.data.get("cachedColumns")
        self._brute = kb.brute
        self._origPage = kb.originalPage

        # stub the collaborators
        self._orig_cbe = inject.checkBooleanExpression
        self._orig_brute_cbe = brute.inject.checkBooleanExpression
        self._orig_getFileItems = brute.getFileItems
        self._orig_runThreads = brute.runThreads
        self._orig_getPageWordSet = brute.getPageWordSet

        from lib.core.datatype import AttribDict
        kb.choices = AttribDict(keycheck=False)
        kb.choices.tableExists = None
        kb.choices.columnExists = None
        kb.data.cachedTables = {}
        kb.data.cachedColumns = {}
        kb.brute = AttribDict({"tables": [], "columns": []})
        kb.originalPage = None

        conf.direct = True
        conf.db = None
        conf.threads = 1
        conf.api = False
        conf.verbose = 0

        # runThreads -> just call the worker once synchronously
        def _fakeRunThreads(numThreads, threadFunction, *args, **kwargs):
            kb.threadContinue = True
            threadFunction()
        brute.runThreads = _fakeRunThreads
        # no page words injected into the wordlist
        brute.getPageWordSet = lambda page: set()
        # wordlist file -> small fixed list
        brute.getFileItems = lambda *a, **k: ["users", "logs", "secret_t"]

    def tearDown(self):
        for k, v in self._saved_conf.items():
            conf[k] = v
        kb.choices = self._choices
        if self._cachedTables is None:
            kb.data.pop("cachedTables", None)
        else:
            kb.data.cachedTables = self._cachedTables
        if self._cachedColumns is None:
            kb.data.pop("cachedColumns", None)
        else:
            kb.data.cachedColumns = self._cachedColumns
        kb.brute = self._brute
        kb.originalPage = self._origPage
        brute.inject.checkBooleanExpression = self._orig_brute_cbe
        brute.getFileItems = self._orig_getFileItems
        brute.runThreads = self._orig_runThreads
        brute.getPageWordSet = self._orig_getPageWordSet
        DbmsStateMixin.tearDown(self)

    def test_table_exists_collects_true_results(self):
        set_dbms(DBMS.MYSQL)

        def _cbe(expression, expectingNone=True):
            # initial sanity probe (random table) -> must be False, otherwise the
            # function raises SqlmapDataException; then only "users" exists.
            return "users" in expression
        brute.inject.checkBooleanExpression = _cbe

        result = brute.tableExists("/nonexistent/tables.txt")
        # cachedTables keyed by conf.db (None here) holds the discovered table
        self.assertIn(None, result)
        self.assertIn("users", result[None])
        self.assertNotIn("logs", result.get(None, []))
        # also recorded in kb.brute.tables as (db, table)
        self.assertIn((None, "users"), kb.brute.tables)

    def test_table_exists_invalid_results_raises(self):
        from lib.core.exception import SqlmapDataException
        set_dbms(DBMS.MYSQL)
        # the initial random-table probe returns True -> "invalid results" guard
        brute.inject.checkBooleanExpression = lambda *a, **k: True
        with self.assertRaises(SqlmapDataException):
            brute.tableExists("/nonexistent/tables.txt")

    def test_column_exists_requires_table(self):
        from lib.core.exception import SqlmapMissingMandatoryOptionException
        set_dbms(DBMS.MYSQL)
        conf.tbl = None
        # the sanity probe is False so we reach the missing-table guard
        brute.inject.checkBooleanExpression = lambda *a, **k: False
        with self.assertRaises(SqlmapMissingMandatoryOptionException):
            brute.columnExists("/nonexistent/columns.txt")

    def test_column_exists_collects_and_types(self):
        set_dbms(DBMS.MYSQL)
        conf.tbl = "users"
        brute.getFileItems = lambda *a, **k: ["id", "name"]

        calls = {"n": 0}

        def _cbe(expression, expectingNone=True):
            calls["n"] += 1
            # initial sanity probe uses two random strings (no real column name)
            if "id" not in expression and "name" not in expression:
                return False
            # MySQL numeric-type follow-up: `not checkBooleanExpression(... REGEXP '[^0-9]')`.
            # 'id' is numeric (no non-digit chars => probe False => numeric);
            # 'name' is non-numeric (has non-digit chars => probe True => non-numeric).
            if "REGEXP" in expression:
                return "name" in expression
            # plain existence check (EXISTS(SELECT <col> FROM <tbl>)) => both columns exist
            return True
        brute.inject.checkBooleanExpression = _cbe

        result = brute.columnExists("/nonexistent/columns.txt")
        self.assertIn(None, result)
        cols = result[None]["users"]
        # column names are run through safeSQLIdentificatorNaming, so the MySQL
        # reserved word "name" comes back backtick-quoted
        from lib.core.common import safeSQLIdentificatorNaming, getText
        self.assertEqual(cols.get(getText(safeSQLIdentificatorNaming("id"))), "numeric")
        self.assertEqual(cols.get(getText(safeSQLIdentificatorNaming("name"))), "non-numeric")

    def test_add_page_text_words_filters(self):
        # restore the real getPageWordSet for this one and drive it directly
        brute.getPageWordSet = self._orig_getPageWordSet
        kb.originalPage = u"<html>admin password 1abc xy verylongword</html>"
        words = brute._addPageTextWords()
        # words <= 2 chars or starting with a digit are dropped
        self.assertIn("admin", words)
        self.assertIn("password", words)
        self.assertNotIn("xy", words)
        self.assertNotIn("1abc", words)


if __name__ == "__main__":
    unittest.main(verbosity=2)
