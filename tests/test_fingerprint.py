#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

DBMS version/fork fingerprinting (plugins/dbms/<dbms>/fingerprint.py). Each
plugin's getFingerprint()/checkDbms() probes the backend with a cascade of
boolean expressions (inject.checkBooleanExpression) and version reads
(inject.getValue). Those are the network seam: stubbing them lets the dialect's
whole detection cascade run offline. We drive every targeted plugin with the
oracle pinned both True and False so opposite branches of the cascade execute.
"""

import importlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.data import conf, kb
from lib.core.common import Backend

# (display name, fingerprint module, handler package)
TARGETS = [
    ("MySQL", "plugins.dbms.mysql.fingerprint", "plugins.dbms.mysql"),
    ("PostgreSQL", "plugins.dbms.postgresql.fingerprint", "plugins.dbms.postgresql"),
    ("Microsoft SQL Server", "plugins.dbms.mssqlserver.fingerprint", "plugins.dbms.mssqlserver"),
    ("Oracle", "plugins.dbms.oracle.fingerprint", "plugins.dbms.oracle"),
    ("IBM DB2", "plugins.dbms.db2.fingerprint", "plugins.dbms.db2"),
    ("Microsoft Access", "plugins.dbms.access.fingerprint", "plugins.dbms.access"),
    ("Firebird", "plugins.dbms.firebird.fingerprint", "plugins.dbms.firebird"),
    ("Sybase", "plugins.dbms.sybase.fingerprint", "plugins.dbms.sybase"),
    ("SAP MaxDB", "plugins.dbms.maxdb.fingerprint", "plugins.dbms.maxdb"),
    ("HSQLDB", "plugins.dbms.hsqldb.fingerprint", "plugins.dbms.hsqldb"),
    ("H2", "plugins.dbms.h2.fingerprint", "plugins.dbms.h2"),
    ("Presto", "plugins.dbms.presto.fingerprint", "plugins.dbms.presto"),
    ("Vertica", "plugins.dbms.vertica.fingerprint", "plugins.dbms.vertica"),
    ("Informix", "plugins.dbms.informix.fingerprint", "plugins.dbms.informix"),
    ("InterSystems Cache", "plugins.dbms.cache.fingerprint", "plugins.dbms.cache"),
    ("MonetDB", "plugins.dbms.monetdb.fingerprint", "plugins.dbms.monetdb"),
    ("Altibase", "plugins.dbms.altibase.fingerprint", "plugins.dbms.altibase"),
    ("ClickHouse", "plugins.dbms.clickhouse.fingerprint", "plugins.dbms.clickhouse"),
    ("CrateDB", "plugins.dbms.cratedb.fingerprint", "plugins.dbms.cratedb"),
    ("Cubrid", "plugins.dbms.cubrid.fingerprint", "plugins.dbms.cubrid"),
    ("Mckoi", "plugins.dbms.mckoi.fingerprint", "plugins.dbms.mckoi"),
    ("Virtuoso", "plugins.dbms.virtuoso.fingerprint", "plugins.dbms.virtuoso"),
    ("Raima Database Manager", "plugins.dbms.raima.fingerprint", "plugins.dbms.raima"),
    ("eXtremeDB", "plugins.dbms.extremedb.fingerprint", "plugins.dbms.extremedb"),
    ("FrontBase", "plugins.dbms.frontbase.fingerprint", "plugins.dbms.frontbase"),
    ("Apache Derby", "plugins.dbms.derby.fingerprint", "plugins.dbms.derby"),
    ("MimerSQL", "plugins.dbms.mimersql.fingerprint", "plugins.dbms.mimersql"),
]


def _handler_cls(pkg):
    main = importlib.import_module(pkg)
    return [getattr(main, n) for n in dir(main) if n.endswith("Map")][0]


# Dialects whose non-extensive getFingerprint emits Format.getDbms() (i.e.
# "<name> <version>") rather than a hard-coded DBMS.* constant, so the version
# that flowed through (Backend.setVersionList(["1.0"])) actually appears in the
# output. (In the test harness Backend.getDbms() is None because set_dbms uses
# forceDbms, so for these the dialect NAME is absent but "1.0" is load-bearing.)
ACTVER_DBMS = frozenset((
    "MySQL", "Microsoft SQL Server", "Firebird", "HSQLDB",
))

# Dialects whose getFingerprint has a fork concept: with the oracle pinned True
# the first fork-detection branch fires (MySQL->MariaDB, PostgreSQL->CockroachDB,
# Oracle->DM8, Cache->Iris, H2->Apache Ignite, Presto->Trino) and the output
# gains a " (... fork)" suffix. Pinned False, no fork is emitted.
FORK_DBMS = frozenset((
    "MySQL", "PostgreSQL", "Oracle", "InterSystems Cache", "H2", "Presto",
))

# Dialects whose getFingerprint genuinely needs more extraction state under
# conf.extensiveFp and raises a narrow KeyError before completing.
EXTENSIVE_RAISERS = frozenset((
    "SAP MaxDB",
))


class TestFingerprint(unittest.TestCase):
    def setUp(self):
        self._saved = {k: conf.get(k) for k in ("batch", "extensiveFp", "api", "dbms", "forceDbms")}
        self._kb = {k: kb.get(k) for k in ("dbmsVersion", "forcedDbms", "dbms", "stickyDBMS",
                                           "resolutionDbms", "os", "osVersion", "osSP")}
        conf.batch = True
        conf.extensiveFp = False
        conf.api = False

    def tearDown(self):
        for k, v in self._saved.items():
            conf[k] = v
        for k, v in self._kb.items():
            kb[k] = v

    def _drive(self, name, modpath, pkg, oracle):
        set_dbms(name)
        Backend.setVersionList(["1.0"])
        mod = importlib.import_module(modpath)
        if hasattr(mod, "inject"):
            mod.inject.checkBooleanExpression = lambda e, *a, **k: oracle
            mod.inject.getValue = lambda q, *a, **k: "1.0"
        handler = _handler_cls(pkg)()
        fp = handler.getFingerprint()
        self.assertIsInstance(fp, str)

        # Real content: the dialect's own identity must have flowed into the
        # output, not merely the constant "back-end DBMS: " prefix.
        if name in ACTVER_DBMS:
            # Format.getDbms() embedded the version list -> "1.0" must appear.
            self.assertIn("1.0", fp,
                          "%s fp lost the version that flowed through: %r" % (name, fp))
        else:
            # the dialect name (DBMS.* constant) must appear verbatim.
            self.assertIn(Backend.getForcedDbms(), fp,
                          "%s fp lost its dialect name: %r" % (name, fp))

        # Fork detection: with the oracle pinned True the first fork branch
        # fires for the fork-bearing dialects; pinned False none do. This is the
        # only thing distinguishing the True/False runs for those dialects.
        if name in FORK_DBMS:
            if oracle:
                self.assertIn("fork)", fp,
                              "%s did not emit a fork label with oracle=True: %r" % (name, fp))
            else:
                self.assertNotIn("fork)", fp,
                                 "%s emitted a fork label with oracle=False: %r" % (name, fp))
        else:
            # dialects with no fork concept never emit a fork label
            self.assertNotIn("fork)", fp)

        # checkDbms walks the dialect's detection cascade end-to-end; it must
        # return a real boolean verdict (True/False), never None or a raise.
        verdict = handler.checkDbms()
        self.assertIn(verdict, (True, False),
                      "%s checkDbms() returned a non-bool: %r" % (name, verdict))
        return fp

    def test_fingerprint_oracle_true(self):
        for name, modpath, pkg in TARGETS:
            self._drive(name, modpath, pkg, True)

    def test_fingerprint_oracle_false(self):
        for name, modpath, pkg in TARGETS:
            self._drive(name, modpath, pkg, False)

    def test_fingerprint_extensive(self):
        # conf.extensiveFp drives the deeper comment-/version-/dbms-check cascades
        # (getFingerprint past the early return) - much more code per dialect.
        # In this mode every dialect's output is built around an
        # "active fingerprint: <Format.getDbms()>" line, so that header is the
        # real content proof; the version "1.0" rides along for the ACTVER set.
        conf.extensiveFp = True
        try:
            for name, modpath, pkg in TARGETS:
                for oracle in (True, False):
                    set_dbms(name)
                    Backend.setVersionList(["1.0"])
                    mod = importlib.import_module(modpath)
                    if hasattr(mod, "inject"):
                        mod.inject.checkBooleanExpression = lambda e, *a, **k: oracle
                        mod.inject.getValue = lambda q, *a, **k: "1.0"
                    handler = _handler_cls(pkg)()
                    if name in EXTENSIVE_RAISERS:
                        # this dialect genuinely needs extra extraction state under
                        # extensiveFp; assert it gets exactly that far and no further.
                        with self.assertRaises(KeyError):
                            handler.getFingerprint()
                        continue
                    fp = handler.getFingerprint()
                    self.assertIsInstance(fp, str)
                    self.assertIn("active fingerprint:", fp,
                                  "%s extensiveFp produced no active-fingerprint line: %r" % (name, fp))
                    if name in ACTVER_DBMS:
                        self.assertIn("1.0", fp,
                                      "%s extensiveFp lost the version: %r" % (name, fp))
        finally:
            conf.extensiveFp = False


def _make(name, modpath, pkg):
    def _t(self):
        # _drive already asserts real, dialect-specific content (version/name +
        # fork label + a boolean checkDbms verdict) for both oracle states.
        self._drive(name, modpath, pkg, True)
        self._drive(name, modpath, pkg, False)
    return _t


# one named test per DBMS for clearer reporting
for _name, _mod, _pkg in TARGETS:
    setattr(TestFingerprint, "test_fp_%s" % _pkg.split(".")[-1], _make(_name, _mod, _pkg))


if __name__ == "__main__":
    unittest.main()
