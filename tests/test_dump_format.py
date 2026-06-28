#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Output formatting of the result dumper (lib/core/dump.py) and the SQLite
replication backend (lib/core/replication.py).

dump.Dump turns extracted DB structures (schemas, table/column listings, row
counts, single facts, user lists) into the human-readable ASCII tables printed
to the console, and serializes per-table row data to CSV / HTML / SQLite files.
None of that needs a live target, network or DBMS: the console renderers route
every line through Dump._write (overridden here to capture instead of print),
and the file renderers just write to a path we point at a temp dir. These tests
pin the rendered layout/escaping contracts so a formatting regression is caught
without an end-to-end scan.
"""

import io
import os
import shutil
import sys
import tempfile
import unittest

from collections import OrderedDict as _PlainOrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import Backend
from lib.core.data import conf, kb
from lib.core.dump import Dump
from lib.core.enums import DUMP_FORMAT
from lib.core.replication import Replication


# --- console-rendering tests (no files): capture every Dump._write line --------------------------

class _CaptureCase(unittest.TestCase):
    """Base for the console renderers: pins a neutral case-preserving DBMS, disables api/report
    side channels, and replaces Dump._write with an in-memory capture so nothing hits stdout."""

    _CONF_KEYS = ("api", "reportCollector", "dumpFormat", "col", "csvDel", "dumpPath", "dumpFile",
                  "limitStart", "limitStop", "forceDbms", "dbms")
    _KB_KEYS = ("forcedDbms", "dbms")

    def setUp(self):
        self._saved = dict((k, conf.get(k)) for k in self._CONF_KEYS)
        self._savedKb = dict((k, kb.get(k)) for k in self._KB_KEYS)
        conf.forceDbms = conf.dbms = None
        kb.dbms = None
        Backend.forceDbms("MySQL")
        conf.api = False
        conf.reportCollector = None
        conf.col = None
        conf.csvDel = ","
        self.lines = []
        self.d = Dump()
        self.d._write = self._capture

    def tearDown(self):
        for k, v in self._saved.items():
            conf[k] = v
        for k, v in self._savedKb.items():
            kb[k] = v

    def _capture(self, data, newline=True, console=True, content_type=None):
        # mirror Dump._write's own line-vs-space join so multi-call lines reassemble faithfully
        self.lines.append("%s%s" % (data, "\n" if newline else " "))

    def text(self):
        return "".join(self.lines)


class TestStringAndLister(_CaptureCase):
    def test_string_scalar_quoted(self):
        # a plain string fact is rendered as "header: 'value'"
        self.d.string("current user", "root@localhost")
        self.assertIn("current user: 'root@localhost'", self.text())

    def test_string_multiline_block(self):
        # a value containing a newline switches to the fenced ---\n...\n--- block form
        self.d.string("banner", "line1\nline2")
        out = self.text()
        self.assertIn("banner:\n---\nline1\nline2\n---", out)

    def test_string_singleton_list_unwrapped(self):
        # a one-element list is unwrapped to the scalar form (not the lister "[N]:" form)
        self.d.string("current database", ["testdb"])
        out = self.text()
        self.assertIn("current database: 'testdb'", out)
        self.assertNotIn("[1]", out)

    def test_lister_sorts_and_counts(self):
        # lister prints a "[count]:" header, one "[*] item" per element, sorted case-insensitively
        self.d.lister("available databases", ["mysql", "Alpha", "zebra"])
        out = self.text()
        self.assertIn("available databases [3]:", out)
        body = out[out.index("[3]:"):]
        # case-insensitive ascending: Alpha, mysql, zebra
        self.assertLess(body.index("[*] Alpha"), body.index("[*] mysql"))
        self.assertLess(body.index("[*] mysql"), body.index("[*] zebra"))

    def test_lister_dedupes(self):
        # the sort path also de-duplicates (set()) before listing
        self.d.lister("database management system users", ["root", "root", "guest"])
        out = self.text()
        self.assertIn("database management system users [2]:", out)
        self.assertEqual(out.count("[*] root"), 1)

    def test_lister_unsorted_preserves_order(self):
        # sort=False (e.g. rFile) keeps insertion order
        self.d.lister("files saved to", ["/z", "/a", "/m"], sort=False)
        out = self.text()
        self.assertLess(out.index("[*] /z"), out.index("[*] /a"))
        self.assertLess(out.index("[*] /a"), out.index("[*] /m"))


class TestCurrentDb(_CaptureCase):
    def test_label_default_dbms(self):
        # MySQL is not in the schema/owner special-cased lists -> plain "current database"
        self.d.currentDb("testdb")
        self.assertIn("current database: 'testdb'", self.text())

    def test_label_schema_dbms(self):
        # Oracle is in the schema-equivalent list -> the label is annotated accordingly
        Backend.forceDbms("Oracle")
        self.d.currentDb("SYSTEM")
        out = self.text()
        self.assertIn("equivalent to schema on Oracle", out)
        self.assertIn("SYSTEM", out)


class TestDbTables(_CaptureCase):
    def test_table_listing_box(self):
        self.d.dbTables({"testdb": ["users", "logs"]})
        out = self.text()
        self.assertIn("Database: testdb", out)
        self.assertIn("[2 tables]", out)
        self.assertIn("| users", out)
        self.assertIn("| logs", out)
        # box borders present
        self.assertIn("+", out)

    def test_single_table_singular(self):
        self.d.dbTables({"testdb": ["only"]})
        self.assertIn("[1 table]", self.text())

    def test_no_tables(self):
        self.d.dbTables({})
        self.assertIn("No tables found", self.text())

    def test_box_width_matches_longest_table(self):
        # the border length tracks the longest table name (+2 padding)
        self.d.dbTables({"testdb": ["a", "elephant"]})
        out = self.text()
        # "elephant" is 8 chars -> a border line of 8+2 = 10 dashes exists
        self.assertIn("+%s+" % ("-" * 10), out)


class TestDbTableColumns(_CaptureCase):
    def test_typed_columns_two_column_box(self):
        self.d.dbTableColumns({"testdb": {"users": {"id": "int", "name": "varchar(50)"}}})
        out = self.text()
        self.assertIn("Database: testdb", out)
        self.assertIn("Table: users", out)
        self.assertIn("[2 columns]", out)
        self.assertIn("| Column", out)
        self.assertIn("| Type", out)
        self.assertIn("int", out)
        self.assertIn("varchar(50)", out)

    def test_typeless_columns_single_box(self):
        # when no column carries a type, only the Column box is rendered (no Type header)
        self.d.dbTableColumns({"testdb": {"users": {"id": None, "name": None}}})
        out = self.text()
        self.assertIn("| Column", out)
        self.assertNotIn("| Type", out)

    def test_mixed_types_still_show_type_header(self):
        # even if the alphabetically-last column is type-less, a Type column must appear
        self.d.dbTableColumns({"testdb": {"t": {"aaa": "int", "zzz": None}}})
        self.assertIn("| Type", self.text())


class TestDbTablesCount(_CaptureCase):
    def test_count_box_sorted_desc(self):
        self.d.dbTablesCount({"testdb": {5: ["small"], 100: ["big"]}})
        out = self.text()
        self.assertIn("Database: testdb", out)
        self.assertIn("| Table", out)
        self.assertIn("| Entries", out)
        # higher count first (reverse sort)
        self.assertLess(out.index("big"), out.index("small"))
        self.assertIn("100", out)


class TestUserSettings(_CaptureCase):
    def test_privileges_listed_with_admin_flag(self):
        # userSettings accepts (settingsDict, adminsSet); admins get an "(administrator)" tag
        settings = ({"root": ["ALL"], "guest": ["SELECT"]}, set(["root"]))
        self.d.userSettings("database management system users privileges", settings, "privilege")
        out = self.text()
        self.assertIn("[*] root (administrator)", out)
        self.assertIn("[*] guest", out)
        self.assertNotIn("guest (administrator)", out)
        self.assertIn("privilege: ALL", out)
        self.assertIn("privilege: SELECT", out)


# --- file-rendering tests (CSV / HTML / SQLite): point output at a temp dir ----------------------

class _FileDumpCase(unittest.TestCase):
    _CONF_KEYS = ("dumpFormat", "dumpPath", "dumpFile", "col", "api", "reportCollector",
                  "limitStart", "limitStop", "csvDel", "forceDbms", "dbms")
    _KB_KEYS = ("forcedDbms", "dbms")

    def setUp(self):
        self._saved = dict((k, conf.get(k)) for k in self._CONF_KEYS)
        self._savedKb = dict((k, kb.get(k)) for k in self._KB_KEYS)
        conf.forceDbms = conf.dbms = None
        kb.dbms = None
        Backend.forceDbms("MySQL")
        self.tmp = tempfile.mkdtemp(prefix="sqlmap-dumpfmt-test")
        conf.dumpPath = self.tmp
        conf.dumpFile = None
        conf.col = None
        conf.api = False
        conf.reportCollector = None
        conf.limitStart = conf.limitStop = None
        conf.csvDel = ","
        self.d = Dump()
        self.d._write = lambda *a, **k: None   # silence the console table

    def tearDown(self):
        for k, v in self._saved.items():
            conf[k] = v
        for k, v in self._savedKb.items():
            kb[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _path(self, table_values, ext):
        db = table_values["__infos__"]["db"] or "All"
        return os.path.join(self.tmp, db, "%s.%s" % (table_values["__infos__"]["table"], ext))

    def _dump(self, table_values, fmt, ext):
        conf.dumpFormat = fmt
        self.d.dbTableValues(table_values)
        with io.open(self._path(table_values, ext), encoding="utf-8") as f:
            return f.read()


class TestCsvDump(_FileDumpCase):
    def _sample(self):
        return _PlainOrderedDict([
            ("__infos__", {"count": 2, "db": "testdb", "table": "users"}),
            ("id", {"length": 2, "values": ["1", "2"]}),
            ("name", {"length": 6, "values": ["luther", "fluffy"]}),
        ])

    def test_header_and_rows(self):
        content = self._dump(self._sample(), DUMP_FORMAT.CSV, "csv")
        lines = [l for l in content.splitlines() if l.strip()]
        self.assertEqual(lines[0].split(","), ["id", "name"])
        self.assertEqual(lines[1].split(","), ["1", "luther"])
        self.assertEqual(lines[2].split(","), ["2", "fluffy"])

    def test_delimiter_in_value_is_quoted(self):
        # RFC-4180: a value containing the delimiter must be wrapped in quotes
        tv = _PlainOrderedDict([
            ("__infos__", {"count": 1, "db": "testdb", "table": "t"}),
            ("a", {"length": 8, "values": ["x,y"]}),
            ("b", {"length": 1, "values": ["z"]}),
        ])
        content = self._dump(tv, DUMP_FORMAT.CSV, "csv")
        self.assertIn('"x,y"', content)

    def test_null_and_blank_markers(self):
        # the display replacements apply to CSV too: DB NULL (" ") -> NULL, empty ("") -> <blank>
        tv = _PlainOrderedDict([
            ("__infos__", {"count": 1, "db": "testdb", "table": "t"}),
            ("a", {"length": 4, "values": [" "]}),
            ("b", {"length": 7, "values": [""]}),
            ("c", {"length": 1, "values": ["x"]}),
        ])
        content = self._dump(tv, DUMP_FORMAT.CSV, "csv")
        row = [l for l in content.splitlines() if l.strip()][1]
        self.assertEqual(row.split(","), ["NULL", "<blank>", "x"])

    def test_custom_delimiter(self):
        conf.csvDel = ";"
        content = self._dump(self._sample(), DUMP_FORMAT.CSV, "csv")
        self.assertEqual(content.splitlines()[0].split(";"), ["id", "name"])


class TestHtmlDump(_FileDumpCase):
    def _sample(self):
        return _PlainOrderedDict([
            ("__infos__", {"count": 1, "db": "testdb", "table": "users"}),
            ("id", {"length": 2, "values": ["1"]}),
            ("name", {"length": 6, "values": ["luther"]}),
        ])

    def test_html_scaffold_and_cells(self):
        content = self._dump(self._sample(), DUMP_FORMAT.HTML, "html")
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("<title>testdb.users</title>", content)
        self.assertIn("<th", content)
        self.assertIn(">id</th>", content)
        self.assertIn(">name</th>", content)
        self.assertIn("<td>1</td>", content)
        self.assertIn("<td>luther</td>", content)
        self.assertIn("</table>", content)
        self.assertIn("</html>", content)

    def test_html_escapes_markup(self):
        # a value with HTML metacharacters must be escaped, not emitted raw
        tv = _PlainOrderedDict([
            ("__infos__", {"count": 1, "db": "testdb", "table": "t"}),
            ("payload", {"length": 16, "values": ["<script>x</script>"]}),
        ])
        content = self._dump(tv, DUMP_FORMAT.HTML, "html")
        self.assertNotIn("<td><script>x</script></td>", content)
        self.assertIn("&lt;", content)


class TestSqliteDump(_FileDumpCase):
    def test_rows_and_inferred_types(self):
        tv = _PlainOrderedDict([
            ("__infos__", {"count": 2, "db": "testdb", "table": "people"}),
            ("id", {"length": 2, "values": ["1", "2"]}),       # all ints -> INTEGER
            ("ratio", {"length": 4, "values": ["1.5", "2.0"]}),  # floats -> REAL
            ("name", {"length": 6, "values": ["alice", " "]}),   # text with a NULL marker
        ])
        conf.dumpFormat = DUMP_FORMAT.SQLITE
        self.d.dbTableValues(tv)

        import sqlite3
        dbfile = os.path.join(self.tmp, "testdb.sqlite3")
        self.assertTrue(os.path.exists(dbfile))
        conn = sqlite3.connect(dbfile)
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, ratio, name FROM people ORDER BY id")
            rows = cur.fetchall()
            self.assertEqual(rows[0], (1, 1.5, "alice"))
            # the DB NULL marker (" ") was stored as a real NULL, not the "NULL" text
            self.assertEqual(rows[1], (2, 2.0, None))
            # column affinities inferred from the values
            cur.execute("PRAGMA table_info(people)")
            types = {name: ctype for (_cid, name, ctype, _nn, _dv, _pk) in cur.fetchall()}
            self.assertEqual(types["id"], "INTEGER")
            self.assertEqual(types["ratio"], "REAL")
            self.assertEqual(types["name"], "TEXT")
        finally:
            conn.close()


# --- replication backend tests (pure sqlite3, no network/DBMS) -----------------------------------

class TestReplication(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sqlmap-repl-test")
        self.path = os.path.join(self.tmp, "out.sqlite3")
        self.repl = Replication(self.path)

    def tearDown(self):
        try:
            self.repl.connection.close()
        except Exception:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_create_insert_select_roundtrip(self):
        t = self.repl.createTable("t", [("id", Replication.INTEGER), ("name", Replication.TEXT)])
        t.beginTransaction()
        t.insert(["1", "alice"])
        t.insert(["2", "bob"])
        t.endTransaction()
        rows = sorted(t.select())
        self.assertEqual(rows, [(1, "alice"), (2, "bob")])

    def test_select_with_condition(self):
        t = self.repl.createTable("t", [("id", Replication.INTEGER), ("name", Replication.TEXT)])
        t.insert(["1", "alice"])
        t.insert(["2", "bob"])
        self.assertEqual(t.select("name = 'bob'"), [(2, "bob")])

    def test_insert_wrong_arity_raises(self):
        from lib.core.exception import SqlmapValueException
        t = self.repl.createTable("t", [("id", Replication.INTEGER), ("name", Replication.TEXT)])
        with self.assertRaises(SqlmapValueException):
            t.insert(["only-one-value"])

    def test_typeless_table(self):
        t = self.repl.createTable("t", ["a", "b"], typeless=True)
        t.insert(["x", "y"])
        self.assertEqual(t.select(), [("x", "y")])

    def test_datatype_str(self):
        self.assertEqual(str(Replication.TEXT), "TEXT")
        self.assertEqual(str(Replication.INTEGER), "INTEGER")
        self.assertIn("DataType", repr(Replication.REAL))


if __name__ == "__main__":
    unittest.main(verbosity=2)
