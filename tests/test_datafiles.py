#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Repo / data-file invariants - the cheap structural guards that catch whole
bug classes seen this session: tamper contract, per-DBMS query-tag coverage,
errors.xml regex compilation, XML well-formedness, and source ASCII-safety
(the py2 'no coding header' constraint).
"""

import os
import re
import sys
import glob
import importlib
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, ROOT
bootstrap()


class TestTamperContract(unittest.TestCase):
    def test_every_tamper_has_contract(self):
        names = [os.path.basename(f)[:-3] for f in glob.glob(os.path.join(ROOT, "tamper", "*.py"))
                 if not f.endswith("__init__.py")]
        self.assertGreater(len(names), 50)  # sanity: we expect ~70
        for name in names:
            mod = importlib.import_module("tamper.%s" % name)
            self.assertTrue(callable(getattr(mod, "tamper", None)), msg="%s: no tamper()" % name)
            self.assertTrue(hasattr(mod, "__priority__"), msg="%s: no __priority__" % name)
            # dependencies() is OPTIONAL (e.g. randomcomments omits it); if present it must be callable
            dep = getattr(mod, "dependencies", None)
            self.assertTrue(dep is None or callable(dep), msg="%s: non-callable dependencies" % name)

    def test_every_tamper_priority_is_valid(self):
        # __priority__ must be one of the PRIORITY enum values (or None) - a typo'd priority
        # silently mis-orders the tamper chain (_setTamperingFunctions sorts on it)
        from lib.core.enums import PRIORITY
        valid = set(v for n, v in vars(PRIORITY).items() if not n.startswith("_"))
        names = [os.path.basename(f)[:-3] for f in glob.glob(os.path.join(ROOT, "tamper", "*.py"))
                 if not f.endswith("__init__.py")]
        for name in names:
            mod = importlib.import_module("tamper.%s" % name)
            priority = getattr(mod, "__priority__", None)
            self.assertTrue(priority is None or priority in valid,
                            msg="%s: __priority__ %r is not a PRIORITY value" % (name, priority))


class TestQueriesXmlCoverage(unittest.TestCase):
    CORE_TAGS = ("cast", "substring", "length", "count", "inference", "comment")

    def test_every_dbms_has_core_tags(self):
        tree = ET.parse(os.path.join(ROOT, "data", "xml", "queries.xml"))
        dbmses = tree.findall(".//dbms")
        self.assertGreaterEqual(len(dbmses), 25)
        for dbms in dbmses:
            present = set(child.tag for child in dbms.iter())
            missing = [t for t in self.CORE_TAGS if t not in present]
            self.assertEqual(missing, [], msg="%s missing core tags: %s" % (dbms.get("value"), missing))


class TestErrorsXmlCompile(unittest.TestCase):
    def test_all_error_regexes_compile(self):
        tree = ET.parse(os.path.join(ROOT, "data", "xml", "errors.xml"))
        regexes = [e.get("regexp") for e in tree.findall(".//error")]
        self.assertGreater(len(regexes), 100)
        for rgx in regexes:
            try:
                re.compile(rgx)
            except re.error as ex:
                self.fail("errors.xml regex does not compile: %r (%s)" % (rgx, ex))


class TestXmlWellFormed(unittest.TestCase):
    def test_core_xml_parses(self):
        for rel in ("queries.xml", "boundaries.xml", "errors.xml",
                    os.path.join("payloads", "boolean_blind.xml"),
                    os.path.join("payloads", "union_query.xml")):
            path = os.path.join(ROOT, "data", "xml", rel)
            ET.parse(path)  # raises on malformed

    def test_banner_xml_parses(self):
        for path in glob.glob(os.path.join(ROOT, "data", "xml", "banner", "*.xml")):
            ET.parse(path)  # raises on malformed


class TestSourceAsciiSafety(unittest.TestCase):
    # sqlmap source files carry NO coding header, so any non-ASCII byte breaks py2 parsing.
    # This guards the exact regression introduced (and fixed) earlier this session.
    CODING_RE = re.compile(b"coding[:=]\\s*([-\\w.]+)")

    def test_lib_and_plugins_are_ascii(self):
        offenders = []
        for base in ("lib", "plugins"):
            for path in glob.glob(os.path.join(ROOT, base, "**", "*.py"), recursive=True) if sys.version_info >= (3, 5) \
                    else self._walk(os.path.join(ROOT, base)):
                with open(path, "rb") as f:
                    head = f.read(256)
                    data = head + f.read()
                if self.CODING_RE.search(head):  # explicit coding header -> non-ASCII allowed
                    continue
                try:
                    data.decode("ascii")
                except UnicodeDecodeError:
                    offenders.append(os.path.relpath(path, ROOT))
        self.assertEqual(offenders, [], msg="non-ASCII source w/o coding header (breaks py2): %s" % offenders)

    @staticmethod
    def _walk(top):
        for dirpath, _, files in os.walk(top):
            for fn in files:
                if fn.endswith(".py"):
                    yield os.path.join(dirpath, fn)


class TestSettingsIntegrity(unittest.TestCase):
    def test_milestone_and_version(self):
        from lib.core.settings import HASHDB_MILESTONE_VALUE, VERSION
        self.assertTrue(HASHDB_MILESTONE_VALUE)
        self.assertTrue(re.match(r"^\d+\.\d+\.\d+", VERSION), msg="unexpected VERSION %r" % VERSION)


if __name__ == "__main__":
    unittest.main(verbosity=2)
