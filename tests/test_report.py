#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

JSON scan report collector/assembler (lib/utils/api.py), shared by the REST API
endpoint /scan/<id>/data and the CLI --report-json writer.

The whole point of the feature is that both produce the SAME structure, so these
tests pin the shared contract: the per-content_type merge (partial -> complete),
the assembled {success, data:[{status,type,type_name,value}], error} shape, the
partRun fallback for untyped output, and the meta-wrapped file written to disk.
A regression here is a divergence between the API and the report - the exact bug
this design exists to prevent.
"""

import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.utils.api as api
from lib.core.data import conf, kb
from lib.core.enums import CONTENT_TYPE, CONTENT_STATUS


class _CollectorCase(unittest.TestCase):
    def setUp(self):
        self.c = api.setupReportCollector()
        self._saved_partRun = kb.get("partRun")

    def tearDown(self):
        kb.partRun = self._saved_partRun
        try:
            self.c.disconnect()
        except Exception:
            pass

    def _store(self, value, content_type, status=CONTENT_STATUS.COMPLETE):
        api._storeData(self.c, api.REPORT_TASKID, value, status, content_type)


class TestAssembledShape(_CollectorCase):
    def test_structure_and_typename(self):
        self._store("MySQL >= 5.0.12", CONTENT_TYPE.DBMS_FINGERPRINT)
        result = api._assembleData(self.c, api.REPORT_TASKID)
        self.assertEqual(result["success"], True)
        self.assertEqual(result["error"], [])
        self.assertEqual(len(result["data"]), 1)
        entry = result["data"][0]
        self.assertEqual(sorted(entry.keys()), ["status", "type", "type_name", "value"])
        self.assertEqual(entry["type"], CONTENT_TYPE.DBMS_FINGERPRINT)
        self.assertEqual(entry["type_name"], "DBMS_FINGERPRINT")     # int -> readable name
        self.assertEqual(entry["value"], "MySQL >= 5.0.12")

    def test_structured_values_preserved(self):
        # dict / list / bool must survive as native JSON types (not stringified) - this is what
        # makes the report machine-consumable, exactly like the API
        self._store({"url": "http://h/?id=1", "data": None}, CONTENT_TYPE.TARGET)
        self._store(["a", "b", "c"], CONTENT_TYPE.DBS)
        self._store(True, CONTENT_TYPE.IS_DBA)
        by_type = {d["type"]: d["value"] for d in api._assembleData(self.c, api.REPORT_TASKID)["data"]}
        self.assertEqual(by_type[CONTENT_TYPE.TARGET], {"url": "http://h/?id=1", "data": None})
        self.assertEqual(by_type[CONTENT_TYPE.DBS], ["a", "b", "c"])
        self.assertIs(by_type[CONTENT_TYPE.IS_DBA], True)


class TestMergeSemantics(_CollectorCase):
    def test_complete_replaces_partials(self):
        # the API appends IN_PROGRESS chunks then a COMPLETE replaces them; final value is COMPLETE
        self._store("roo", CONTENT_TYPE.CURRENT_USER, CONTENT_STATUS.IN_PROGRESS)
        self._store("t@localhost", CONTENT_TYPE.CURRENT_USER, CONTENT_STATUS.COMPLETE)
        data = api._assembleData(self.c, api.REPORT_TASKID)["data"]
        self.assertEqual(len(data), 1)                      # one row, not two
        self.assertEqual(data[0]["value"], "t@localhost")
        self.assertEqual(data[0]["status"], CONTENT_STATUS.COMPLETE)

    def test_inprogress_chunks_accumulate(self):
        self._store("foo", CONTENT_TYPE.BANNER, CONTENT_STATUS.IN_PROGRESS)
        self._store("bar", CONTENT_TYPE.BANNER, CONTENT_STATUS.IN_PROGRESS)
        data = api._assembleData(self.c, api.REPORT_TASKID)["data"]
        self.assertEqual(data[0]["value"], "foobar")        # appended


class TestPartRunFallback(_CollectorCase):
    def test_untyped_output_tagged_via_partrun(self):
        # untyped output during a part-run (e.g. the fingerprint line) is tagged by kb.partRun -
        # this is how DBMS_FINGERPRINT is captured with no explicit content_type
        kb.partRun = "getFingerprint"
        self._store("back-end DBMS: MySQL >= 5.1", None)    # content_type=None
        data = api._assembleData(self.c, api.REPORT_TASKID)["data"]
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["type"], CONTENT_TYPE.DBMS_FINGERPRINT)
        self.assertEqual(data[0]["value"], "back-end DBMS: MySQL >= 5.1")

    def test_untyped_output_without_partrun_is_ignored(self):
        kb.partRun = None
        self._store("just a log line", None)
        self.assertEqual(api._assembleData(self.c, api.REPORT_TASKID)["data"], [])


class TestSanitize(unittest.TestCase):
    """The shared assembler strips internal plumbing (matchRatio/trueCode/falseCode/templatePayload/
    where/conf) from TECHNIQUES and restructures DUMP_TABLE (drop __infos__ wrapper + per-column
    'length'), so neither the API nor the report leaks consumer-irrelevant internals. Deterministic
    (no run variance), unlike the live API-vs-report comparison."""

    def test_techniques_internals_stripped_and_named(self):
        injection = {
            "place": "GET", "parameter": "id", "ptype": 1, "dbms": "MySQL",
            "conf": {"string": "x", "regexp": None},          # internal -> must be dropped
            "data": {"1": {"title": "boolean", "payload": "id=1 AND 1=1", "vector": "AND [INFERENCE]",
                           "comment": "", "where": 1, "matchRatio": 0.74, "trueCode": 200,
                           "falseCode": 200, "templatePayload": None},
                     "6": {"title": "union", "payload": "id=1 UNION ...", "vector": "...", "comment": ""}},
        }
        injection["ptype"] = 1
        injection["clause"] = [1, 8, 9]
        injection["prefix"] = ""
        injection["suffix"] = ""
        original = json.loads(json.dumps(injection))   # deep copy to prove no mutation
        out = api._sanitizeScanData(CONTENT_TYPE.TECHNIQUES, [injection])[0]
        # detection/construction internals dropped
        for field in ("conf", "ptype", "clause", "prefix", "suffix"):
            self.assertNotIn(field, out)
        # data is now an ordered LIST (not a map keyed by opaque ids), each entry named
        self.assertIsInstance(out["data"], list)
        self.assertEqual([t["technique"] for t in out["data"]], ["boolean-based blind", "UNION query"])
        first = out["data"][0]
        self.assertEqual(sorted(first.keys()), ["comment", "payload", "technique", "title", "vector"])
        self.assertEqual(first["payload"], "id=1 AND 1=1")    # consumer-relevant fields preserved
        self.assertEqual(out["dbms"], "MySQL")
        # input not mutated (operates on a copy - must not corrupt live kb.injections)
        self.assertEqual(injection, original)

    def test_dump_table_restructured_and_unquoted(self):
        value = {
            "__infos__": {"db": "`master`", "table": "users", "count": 3},
            "id": {"length": 2, "values": ["1", "2", "3"]},
            "`name`": {"length": 9, "values": ["alice", " ", ""]},   # backtick id; " " is a DB NULL, "" is empty
        }
        out = api._sanitizeScanData(CONTENT_TYPE.DUMP_TABLE, value)
        self.assertEqual(sorted(out.keys()), ["columns", "count", "db", "table"])
        self.assertNotIn("__infos__", out)
        self.assertEqual(out["db"], "master")                 # quoting stripped (context-free)
        self.assertEqual(out["table"], "users")
        self.assertEqual(out["count"], 3)
        # columns flattened to value lists (no 'length'), identifiers unquoted
        self.assertEqual(out["columns"]["id"], ["1", "2", "3"])
        self.assertNotIn("`name`", out["columns"])
        # DB NULL (" ") -> JSON null; genuine empty string ("") preserved
        self.assertEqual(out["columns"]["name"], ["alice", None, ""])

    def test_schema_listing_identifiers_cleaned(self):
        # TABLES/COLUMNS/SCHEMA/COUNT must have their identifiers unquoted too (consistency with
        # DUMP_TABLE) - a regression here is the exact "X cleaned but Y not" inconsistency to avoid
        tables = api._sanitizeScanData(CONTENT_TYPE.TABLES, {"`master`": ["users", "`order`"]})
        self.assertEqual(tables, {"master": ["users", "order"]})
        columns = api._sanitizeScanData(CONTENT_TYPE.COLUMNS,
                                        {"`master`": {"users": {"id": "int", "`name`": "varchar(500)"}}})
        self.assertEqual(columns, {"master": {"users": {"id": "int", "name": "varchar(500)"}}})
        schema = api._sanitizeScanData(CONTENT_TYPE.SCHEMA, {"sys": {"w": {"`events`": "varchar(128)"}}})
        self.assertEqual(schema, {"sys": {"w": {"events": "varchar(128)"}}})
        count = api._sanitizeScanData(CONTENT_TYPE.COUNT, {"`master`": {"5": ["users"]}})
        self.assertEqual(count, {"master": {"5": ["users"]}})

    def test_identifier_unquoting_is_context_free(self):
        # all DBMS quote styles handled without Backend context (so CLI and API server agree)
        self.assertEqual(api._cleanIdentifier("`tbl`"), "tbl")     # MySQL
        self.assertEqual(api._cleanIdentifier('"tbl"'), "tbl")     # PostgreSQL/Oracle
        self.assertEqual(api._cleanIdentifier("[tbl]"), "tbl")     # MSSQL
        self.assertEqual(api._cleanIdentifier("plain"), "plain")

    def test_other_types_pass_through(self):
        # non-TECHNIQUES/DUMP_TABLE values are returned unchanged
        self.assertEqual(api._sanitizeScanData(CONTENT_TYPE.CURRENT_USER, "root@%"), "root@%")
        self.assertEqual(api._sanitizeScanData(CONTENT_TYPE.DBS, ["a", "b"]), ["a", "b"])
        self.assertIs(api._sanitizeScanData(CONTENT_TYPE.IS_DBA, True), True)


class TestErrors(_CollectorCase):
    def test_errors_captured(self):
        self.c.execute("INSERT INTO errors VALUES(NULL, ?, ?)", (api.REPORT_TASKID, "something failed"))
        result = api._assembleData(self.c, api.REPORT_TASKID)
        self.assertEqual(result["error"], ["something failed"])


class TestWriteReportJson(_CollectorCase):
    def test_file_is_valid_json_with_meta(self):
        self._store("admin", CONTENT_TYPE.CURRENT_USER)
        saved_url = conf.get("url")
        conf.url = "http://target/?id=1"
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            api.writeReportJson(self.c, path)
            with io.open(path, encoding="utf-8") as f:   # explicit UTF-8 + closed handle (no ResourceWarning, no cp1252 on Windows)
                loaded = json.load(f)
            # core shape == API /scan/<id>/data, plus a meta wrapper
            self.assertEqual(sorted(loaded.keys()), ["data", "error", "meta", "success"])
            self.assertEqual(loaded["data"][0]["value"], "admin")
            self.assertEqual(loaded["data"][0]["type_name"], "CURRENT_USER")
            self.assertEqual(loaded["meta"]["url"], "http://target/?id=1")
            self.assertEqual(loaded["meta"]["api_version"], 2)   # MAJOR-only integer, for compatibility checks
            self.assertIn("sqlmap_version", loaded["meta"])
            self.assertIn("timestamp", loaded["meta"])
        finally:
            conf.url = saved_url
            os.remove(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
