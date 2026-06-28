#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Optional-dependency probe (lib/utils/deps.py, the --dependencies feature).
checkDependencies() attempts to import every supported DBMS driver and warns
on the ones missing; it must never raise regardless of what's installed.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.utils.deps as deps
from lib.utils.deps import checkDependencies


class _RecordingLogger(object):
    """Captures every (level, message) emitted while installed as deps.logger."""

    def __init__(self):
        self.records = []

    def warning(self, msg, *args):
        self.records.append(("warning", msg % args if args else msg))

    def info(self, msg, *args):
        self.records.append(("info", msg % args if args else msg))

    def debug(self, msg, *args):
        self.records.append(("debug", msg % args if args else msg))

    def error(self, msg, *args):
        self.records.append(("error", msg % args if args else msg))

    def messages(self, level=None):
        return [m for (lvl, m) in self.records if level is None or lvl == level]


class TestCheckDependencies(unittest.TestCase):
    def setUp(self):
        self._real_logger = deps.logger
        self.rec = _RecordingLogger()
        deps.logger = self.rec

    def tearDown(self):
        deps.logger = self._real_logger

    def test_missing_driver_warns_with_library_name(self):
        # 'kinterbasdb' (Firebird driver) is essentially never installed, so the
        # probe must hit the except branch and emit a warning naming the library.
        try:
            __import__("kinterbasdb")
            self.skipTest("kinterbasdb is unexpectedly installed")
        except ImportError:
            pass

        checkDependencies()

        warnings = self.rec.messages("warning")
        self.assertTrue(warnings, msg="no warnings captured for a missing driver")
        # the Firebird entry must name its third-party library in a warning
        self.assertTrue(
            any("kinterbasdb" in w for w in warnings),
            msg="missing Firebird driver did not produce a library-naming warning: %r" % warnings,
        )

    def test_all_present_emits_all_installed_info(self):
        # force every __import__ to succeed so no library is ever recorded as
        # missing; the empty-missing-set branch must emit the summary info line.
        try:
            import __builtin__ as builtins  # py2 real builtin module
        except ImportError:
            import builtins  # py3

        class _FakeModule(object):
            __version__ = "999.0.0"

        real_import = builtins.__import__

        def _always_succeed(name, *args, **kwargs):
            try:
                return real_import(name, *args, **kwargs)
            except Exception:
                return _FakeModule()

        builtins.__import__ = _always_succeed
        try:
            checkDependencies()
        finally:
            builtins.__import__ = real_import

        infos = self.rec.messages("info")
        self.assertTrue(
            any("all dependencies are installed" in m for m in infos),
            msg="all-present path did not emit the summary info: %r" % infos,
        )
        # and with nothing missing there must be no missing-library warnings
        self.assertFalse(
            any("third-party library" in w and "requires" in w for w in self.rec.messages("warning")),
            msg="unexpected missing-library warning when all imports succeed",
        )

    def test_returns_none(self):
        # contract: the probe is purely advisory and never returns a value
        self.assertIsNone(checkDependencies())


if __name__ == "__main__":
    unittest.main()
