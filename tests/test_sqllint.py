#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit tests + atom-level SQL coverage for lib/utils/sqllint.py.

Two concerns:

  1. Linter self-test - a curated set of well-formed fragments/statements that
     must NOT flag, malformed ones that MUST flag, and the cross-dialect edge
     cases the linter has learned (==, ::, $/backtick identifiers, LIKE() as a
     function, HSQLDB "LIMIT off lim", ...). Guards the linter from regressions.

  2. Atom-level SQL coverage - every SQL-bearing template in data/xml/queries.xml
     and data/xml/payloads.xml, across ALL back-end DBMSes, must lint structurally
     clean. This is a coverage gate over the *building blocks* of every query
     sqlmap emits. The composed/runtime layer (agent.py wrapping these atoms into
     wire payloads) is exercised faithfully by the separate payload-lint walk; a
     0-flag result here means the catalog itself is sound in all 30 dialects.

A regression (a newly malformed catalog entry, OR a genuinely new valid dialect
construct the linter does not yet understand) makes the relevant test fail with a
pointer to the offending template.

stdlib unittest only; Python 2.7 and 3.x; pure-ASCII.
"""

import os
import re
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.utils.sqllint import checkSanity

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# well-formed fragments/statements that must NOT flag
GOOD = (
    "1 AND 1=1",
    "1) AND 5108=5108 AND (7936=7936",
    "1)) OR 1=1-- -",
    "1' AND '1'='1",
    "1 UNION ALL SELECT NULL,NULL,CONCAT(0x71,0x62,0x71)-- -",
    "1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7176,(SELECT database()),0x71)x FROM information_schema.tables GROUP BY x)a)",
    "1 AND ORD(MID((SELECT IFNULL(CAST(username AS NCHAR),0x20) FROM users ORDER BY id LIMIT 0,1),1,1))>64",
    "1 AND EXTRACTVALUE(1,CONCAT(0x5c,0x7e,(SELECT version())))",
    "SELECT name FROM users WHERE id=1 ORDER BY id",
    "SELECT count(*) FROM t WHERE x=1",
    "1 WAITFOR DELAY '0:0:5'",
)

# cross-dialect valid constructs the linter must accept (regression guards for
# the exact false positives that adversarial/catalog runs exposed and fixed)
DIALECT_GOOD = (
    "1 AND id==1",                                               # SQLite '==' equality
    "SELECT 1 WHERE (SELECT 1)::text = '1'",                     # PostgreSQL '::' cast
    "SELECT 1 WHERE 9223=LIKE(CHAR(65),UPPER(HEX(1)))",         # SQLite LIKE() function
    "SELECT NAME FROM SYSMASTER:SYSDATABASES",                   # Informix 'db:table'
    "SELECT $ZVERSION",                                          # InterSystems Cache system var
    "SELECT `col` FROM `directory` LIMIT 0,1",                  # MySQL backtick identifiers
    "SELECT LIMIT 0 1 DISTINCT(user) FROM INFORMATION_SCHEMA.SYSTEM_USERS",  # HSQLDB space-LIMIT
    "SELECT TOP 1 name FROM master..sysdatabases",              # MSSQL TOP + db..table
    "CONCAT('\\',0x71,(SELECT 1))",                             # backslash-literal string (ANSI)
    "SELECT a FROM t WHERE x=1 UNION SELECT b FROM u WHERE y=2",  # two WHEREs across UNION (legal)
    "SELECT a FROM (SELECT b FROM t WHERE c=1) z WHERE d=2",     # subquery WHERE + outer WHERE (different scopes)
    "SELECT a FROM t WHERE x IN (SELECT c FROM d WHERE e=1) AND f=2",  # WHERE with a WHERE'd subquery
)

# malformed fragments/statements that MUST flag
BAD = (
    "(SELECT id 1 FROM users)",                                 # missing separator
    "1 AND 1=(SELECT id 1 FROM users' WHERE tablename='foobar')",  # stray quote in scope
    "1UNION SELECT NULL",                                        # digit glued to word
    "1 AND 5108=5108AND 1=1",                                    # digit glued to keyword
    "1 AND 1 = = 1",                                             # doubled operator
    "1 AND AND 1=1",                                             # doubled keyword operator
    "1 UNION SELECT NULL,,NULL",                                 # empty list item
    "1 AND (1=1)(2=2)",                                          # adjacent groups
    "SELECT count() FROM t WHERE id=)",                          # operator before ')'
    "SELECT a,b, FROM t",                                        # dangling comma before clause
    "1 AND (SELECT [DELIMITER_START]x[DELIMITER_STOP] FROM t)",   # leftover templating marker
    "1 [ORIGVALUE] AND 1=1",                                     # leftover ORIGVALUE marker
    "1 UNI1ON ALL SELECT NULL,NULL",                             # digit-corrupted UNION
    "1 UrNION ALL SELECT NULL",                                  # char-inserted UNION
    "SEL2ECT x.z FROM t",                                        # digit-corrupted SELECT
    "1 ORD2ER BY 1",                                             # digit-corrupted ORDER
    "1 UNIN ALL SELECT NULL",                                    # deletion-typo UNION
    "1 UNOIN ALL SELECT NULL",                                   # transposition-typo UNION
    "SELCT a FROM t",                                            # deletion-typo SELECT
    "1 UNION ALLSELECT NULL",                                    # glued keyword after UNION
    "1 AND ORD(MID((SELECT COUNT(x FROM t),1,1))>64",            # unbalanced parentheses (dropped ')')
    "1 UNION ALL SELECT ,CONCAT(0x71,a,0x71) FROM t",            # comma right after SELECT
    "SELECT OWNER,OBJECT_NAME FROM SYS.ALL_OBJECTS WHERE OBJECT_TYPE IN ('TABLE','VIEW') WHERE OWNER IN ('APPU')",  # double WHERE (mis-appended schema filter)
    "SELECT tabschema,tabname FROM syscat.tables WHERE type IN ('T','V') WHERE tabschema IN ('DB2INST1')",  # double WHERE (DB2)
    "SELECT a FROM t WHERE x=1 HAVING c>1 HAVING d<2",           # duplicate HAVING
)

# cross-dialect valid constructs the near-keyword / comma / digit-glue rules must
# NOT flag (regression guards for false positives the real-identifier stress found)
DIALECT_GOOD_HARD = (
    "SELECT 4images_users FROM t",                              # digit-STARTED identifier (not '1UNION')
    "SELECT a,group,b FROM t",                                  # column literally named 'group'
    "SELECT a,order FROM t",                                    # column literally named 'order'
    "1 UNION SELECT orders FROM t",                             # 'orders' near ORDER but a real table
)

# queries.xml: attributes that carry SQL (not regexes/markers)
_SQL_ATTRS = ("query", "query2", "query3", "count", "count2", "count3",
              "condition", "condition2", "condition3",
              "keyset_where", "keyset_next", "keyset_first", "keyset_by", "keyset_ordered", "rowid")
_SKIP_TAGS = ("limitregexp", "comment")


def _materialize(s):
    """Substitute sqlmap's template markers with structurally-neutral values so a
    catalog template becomes lintable SQL (mirrors what agent.py fills in)."""
    s = s.replace("[QUERY]", "SELECT 1").replace("[UNION]", "UNION SELECT NULL")
    s = s.replace("[INFERENCE]", "1=1")
    s = re.sub(r"\[RANDNUM\d*\]", "1", s)
    s = re.sub(r"\[RANDSTR\d*\]", "abc", s)
    s = s.replace("[SLEEPTIME]", "1").replace("[DELAYED]", "1")
    for _ in ("[DELIMITER_START]", "[DELIMITER_STOP]", "[COLSTART]", "[COLSTOP]"):
        s = s.replace(_, "0x71")
    s = s.replace("[ORIGVALUE]", "1").replace("[CHAR]", "NULL").replace("[GENERIC_SQL_COMMENT]", "-- -")
    s = s.replace("[SINGLE_QUOTE]", "'").replace("[DOUBLE_QUOTE]", '"').replace("[DB]", "db")
    s = s.replace("[SPACE_REPLACE]", " ").replace("[HASH_REPLACE]", "#")
    s = s.replace("[DOLLAR_REPLACE]", "$").replace("[AT_REPLACE]", "@")
    s = re.sub(r"\[[A-Z][A-Z0-9_]*\]", "1", s)
    s = s.replace("%d", "1").replace("%s", "col").replace("%%", "%")
    return s


def _queries_atoms():
    """{dbms: sorted list of SQL atom strings} from queries.xml."""
    retVal = {}
    root = ET.parse(os.path.join(ROOT, "data", "xml", "queries.xml")).getroot()
    for dbms in root.iter("dbms"):
        atoms = set()
        for el in dbms.iter():
            if el.tag in _SKIP_TAGS:
                continue
            for attr in _SQL_ATTRS:
                raw = el.get(attr)
                if raw and not raw.strip().isdigit():
                    atoms.add(raw)
        retVal[dbms.get("value")] = sorted(atoms)
    return retVal


def _payload_atoms():
    """[(file, stype-title, sql)] from data/xml/payloads/*.xml."""
    import glob
    retVal = []
    for path in sorted(glob.glob(os.path.join(ROOT, "data", "xml", "payloads", "*.xml"))):
        name = os.path.basename(path)
        for test in ET.parse(path).getroot().iter("test"):
            title = (test.findtext("title") or "").strip()
            for tag in ("payload", "vector", "comparison"):
                for el in test.iter(tag):
                    raw = (el.text or "").strip()
                    if raw:
                        retVal.append((name, title, raw))
    return retVal


class TestLinterSelf(unittest.TestCase):
    def test_well_formed_pass(self):
        for sql in GOOD + DIALECT_GOOD + DIALECT_GOOD_HARD:
            self.assertEqual(checkSanity(sql), [], "false positive on valid SQL: %r" % sql)

    def test_malformed_flag(self):
        for sql in BAD:
            self.assertTrue(checkSanity(sql), "missed malformed SQL: %r" % sql)

    def test_nonascii_identifier(self):
        # a non-ASCII column name (Turkish dotless-i U+0131) must lex as an identifier, not stray
        self.assertEqual(checkSanity(u"SELECT \u0131d,ad FROM users"), [])


class TestCatalogCoverage(unittest.TestCase):
    def test_queries_xml_clean(self):
        atoms = _queries_atoms()
        total = 0
        for dbms, items in atoms.items():
            for raw in items:
                total += 1
                issues = checkSanity(_materialize(raw))
                self.assertEqual(issues, [],
                                 "queries.xml [%s] malformed atom: %r -> %s" % (dbms, raw, issues))
        self.assertGreater(total, 1000)   # sanity: the catalog was actually walked

    def test_payloads_xml_clean(self):
        items = _payload_atoms()
        for name, title, raw in items:
            issues = checkSanity(_materialize(raw))
            self.assertEqual(issues, [],
                             "%s malformed payload atom (%s): %r -> %s" % (name, title, raw, issues))
        self.assertGreater(len(items), 500)


if __name__ == "__main__":
    unittest.main(verbosity=2)
