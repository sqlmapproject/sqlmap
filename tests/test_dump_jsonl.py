#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

JSONL output of the per-table dumper (Dump.dbTableValues in lib/core/dump.py).

--dump-format=JSONL writes one self-describing JSON object per row to a
<host>/dump/<db>/<table>.jsonl file, streaming-safe (one independent line per
row, no surrounding array/header/footer). These tests pin the contract that an
automated consumer relies on: column order preserved (so it matches the CSV
column order and is reproducible on Python 2's unordered dict), the DB-NULL
marker (" ") mapped to JSON null exactly like --report-json, the empty string
left intact (NOT collapsed to null), and a strict one-object-per-line layout.
"""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest

from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import Backend
from lib.core.data import conf, kb
from lib.core.dump import Dump
from lib.core.enums import DUMP_FORMAT


class _JsonlDumpCase(unittest.TestCase):
    def setUp(self):
        self._saved = dict((k, conf.get(k)) for k in ("dumpFormat", "dumpPath", "dumpFile", "col", "api", "reportCollector", "limitStart", "limitStop", "csvDel", "forceDbms", "dbms"))
        self._savedKb = dict((k, kb.get(k)) for k in ("forcedDbms", "dbms"))
        # A DBMS leaked from an earlier test (e.g. one that uppercases identifiers) would change
        # both the on-disk filename and the JSON keys, so pin a neutral, case-preserving back-end.
        conf.forceDbms = conf.dbms = None
        kb.dbms = None
        Backend.forceDbms("MySQL")
        self.tmp = tempfile.mkdtemp(prefix="sqlmap-jsonl-test")
        conf.dumpFormat = DUMP_FORMAT.JSONL
        conf.dumpPath = self.tmp
        conf.dumpFile = None
        conf.col = None
        conf.api = False
        conf.reportCollector = None
        conf.limitStart = conf.limitStop = None
        conf.csvDel = ","
        self.d = Dump()
        self.d._write = lambda *a, **k: None    # silence the console table

    def tearDown(self):
        for k, v in self._saved.items():
            conf[k] = v
        for k, v in self._savedKb.items():
            kb[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _dump(self, table_values):
        self.d.dbTableValues(table_values)
        db = table_values["__infos__"]["db"] or "All"
        path = os.path.join(self.tmp, db, "%s.jsonl" % table_values["__infos__"]["table"])
        # sqlmap writes the dump file as UTF-8; read it the same way (not the platform default,
        # which is cp1252 on Windows CI and would mojibake multibyte values)
        with io.open(path, encoding="utf-8") as f:
            content = f.read()
        return content

    def _rows(self, content):
        return [json.loads(line) for line in content.splitlines() if line.strip()]


class TestJsonlContract(_JsonlDumpCase):
    def test_one_object_per_row(self):
        content = self._dump({
            "__infos__": {"count": 2, "db": "testdb", "table": "users"},
            "id": {"length": 2, "values": ["1", "2"]},
            "name": {"length": 6, "values": ["luther", "fluffy"]},
        })
        # exactly N non-empty lines, each terminated by a newline, each a standalone object
        lines = content.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(content.endswith("\n"))
        rows = self._rows(content)
        self.assertEqual(rows[0], {"id": "1", "name": "luther"})
        self.assertEqual(rows[1], {"id": "2", "name": "fluffy"})

    def test_no_header_or_footer(self):
        # unlike CSV (header row) / HTML (doc scaffold), JSONL must be pure data lines
        content = self._dump({
            "__infos__": {"count": 1, "db": "testdb", "table": "t"},
            "id": {"length": 2, "values": ["1"]},
        })
        lines = [l for l in content.splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0]), {"id": "1"})

    def test_db_null_becomes_json_null(self):
        # sqlmap stores a DB NULL as a single space (" "); the machine format must emit JSON null,
        # consistent with --report-json. An empty string is a real value and must stay "".
        content = self._dump({
            "__infos__": {"count": 1, "db": "testdb", "table": "t"},
            "a": {"length": 1, "values": [" "]},     # DB NULL marker
            "b": {"length": 1, "values": [""]},       # genuine empty string
            "c": {"length": 1, "values": ["x"]},
        })
        row = self._rows(content)[0]
        self.assertIsNone(row["a"])
        self.assertEqual(row["b"], "")
        self.assertEqual(row["c"], "x")

    def test_missing_value_is_null(self):
        # a column whose values list is short for this row index must serialize as null, not crash
        content = self._dump({
            "__infos__": {"count": 2, "db": "testdb", "table": "t"},
            "id": {"length": 2, "values": ["1", "2"]},
            "lagging": {"length": 4, "values": ["only-one"]},   # missing index 1
        })
        rows = self._rows(content)
        self.assertEqual(rows[0], {"id": "1", "lagging": "only-one"})
        self.assertEqual(rows[1], {"id": "2", "lagging": None})

    def test_column_order_matches_csv(self):
        # The serialized byte stream must keep the (priority-sorted) column order so output is
        # reproducible - even on Python 2 where a plain dict would not - and that order must be
        # the SAME one CSV uses. Build the input as an OrderedDict so the expectation is fixed,
        # then dump the identical data as both JSONL and CSV and compare the column sequences.
        def table():
            tv = OrderedDict()
            tv["__infos__"] = {"count": 1, "db": "testdb", "table": "t"}
            tv["zebra"] = {"length": 1, "values": ["1"]}
            tv["alpha"] = {"length": 1, "values": ["2"]}
            tv["middle"] = {"length": 1, "values": ["3"]}
            return tv

        jsonl_line = [l for l in self._dump(table()).splitlines() if l.strip()][0]
        jsonl_order = [k for k, _ in json.loads(jsonl_line, object_pairs_hook=lambda p: p)]

        conf.dumpFormat = DUMP_FORMAT.CSV
        csv_path = os.path.join(self.tmp, "testdb", "t.csv")
        if os.path.exists(csv_path):
            os.remove(csv_path)
        self.d.dbTableValues(table())
        with io.open(csv_path, encoding="utf-8") as f:
            csv_header = f.read().splitlines()[0]
        csv_order = [c.strip() for c in csv_header.split(conf.csvDel)]

        self.assertEqual(jsonl_order, csv_order)

    def test_unicode_value_not_escaped(self):
        # ensure_ascii=False keeps multibyte data readable; it must round-trip through json.loads
        content = self._dump({
            "__infos__": {"count": 1, "db": "testdb", "table": "t"},
            "name": {"length": 6, "values": [u"\u0107evap"]},
        })
        self.assertEqual(self._rows(content)[0]["name"], u"\u0107evap")


if __name__ == "__main__":
    unittest.main()
