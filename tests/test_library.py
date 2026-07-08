#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit coverage for the library facade (import sqlmap; sqlmap.scan(...)).

The facade drives the engine out-of-process through a generated configuration file (the same '-c'
mechanism the REST API uses) and reads back a '--report-json' report. These tests stub
subprocess.Popen to (a) capture the argv/config sqlmap.scan() builds from its keyword options and
(b) feed back a canned report - keeping the test fast, offline and network-free (no real scan runs).

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import json
import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlmap


class _FakePopen(object):
    """Stub that records argv/config and writes a canned report to the config's 'reportJson' path."""

    captured = {}
    returncode = 0

    def __init__(self, argv, **kwargs):
        _FakePopen.captured["argv"] = argv
        _FakePopen.captured["kwargs"] = kwargs
        with open(argv[argv.index("-c") + 1]) as f:
            config = f.read()
        _FakePopen.captured["config"] = config
        report = re.search(r"(?im)^reportjson\s*=\s*(.+)$", config).group(1).strip()
        with open(report, "w") as f:
            json.dump({"success": True, "data": [{"type_name": "BANNER", "value": "3.45.1"}], "error": []}, f)

    def wait(self, timeout=None):
        return 0

    def poll(self):
        return 0

    def kill(self):
        pass


class TestLibraryFacade(unittest.TestCase):
    def setUp(self):
        self._realPopen = subprocess.Popen
        subprocess.Popen = _FakePopen
        _FakePopen.captured = {}

    def tearDown(self):
        subprocess.Popen = self._realPopen

    def test_requires_a_target(self):
        subprocess.Popen = self._realPopen  # never reached; guard fires first
        self.assertRaises(sqlmap.SqlmapError, sqlmap.scan)

    def test_rejects_unknown_option(self):
        # a command line switch spelling (rather than a conf option name) must be rejected loudly
        self.assertRaises(sqlmap.SqlmapError, sqlmap.scan, "http://target/?id=1", current_user=True)

    def test_options_go_through_config(self):
        result = sqlmap.scan("http://target/vuln.php?id=1", technique="BEU", dumpTable=True,
                             tbl="users", level=3, getBanner=True, raw=["--fresh-queries"])
        argv = _FakePopen.captured["argv"]
        config = _FakePopen.captured["config"]
        # driven via a generated config file, stdin ignored, engine plumbing set - no arg escaping
        self.assertIn("-c", argv)
        self.assertIn("--ignore-stdin", argv)
        self.assertIn("--fresh-queries", argv)                  # raw escape hatch stays on the CLI
        # options land in the config using sqlmap's own (conf) names (ConfigParser lowercases keys)
        self.assertTrue(re.search(r"(?im)^url\s*=\s*http://target/vuln.php\?id=1$", config))
        self.assertTrue(re.search(r"(?im)^technique\s*=\s*BEU$", config))
        self.assertTrue(re.search(r"(?im)^tbl\s*=\s*users$", config))
        self.assertTrue(re.search(r"(?im)^level\s*=\s*3$", config))
        self.assertTrue(re.search(r"(?im)^dumptable\s*=\s*True$", config))
        self.assertTrue(re.search(r"(?im)^getbanner\s*=\s*True$", config))
        self.assertTrue(re.search(r"(?im)^batch\s*=\s*True$", config))
        self.assertTrue(re.search(r"(?im)^outputdir\s*=", config))     # each run isolated on disk
        # file descriptors are not leaked to the engine (matches the REST API subprocess)
        self.assertFalse(_FakePopen.captured["kwargs"].get("close_fds") and os.name == "nt")
        # canned report is returned verbatim
        self.assertTrue(result["success"])
        self.assertEqual(result["data"][0]["value"], "3.45.1")

    def test_scan_from_request_uses_request_file(self):
        sqlmap.scanFromRequest("/tmp/req.txt", technique="U")
        config = _FakePopen.captured["config"]
        self.assertTrue(re.search(r"(?im)^requestfile\s*=\s*/tmp/req.txt$", config))
        self.assertTrue(re.search(r"(?im)^technique\s*=\s*U$", config))

    def test_missing_report_raises(self):
        class _NoReportPopen(_FakePopen):
            def __init__(self, argv, **kwargs):
                _FakePopen.captured["argv"] = argv  # write nothing -> no report file
        subprocess.Popen = _NoReportPopen
        self.assertRaises(sqlmap.SqlmapError, sqlmap.scan, "http://target/?id=1")


class TestReportErrorCapture(unittest.TestCase):
    """
    The library tells failure modes apart (unreachable vs nothing-found) because a CLI --report-json
    run now records error/critical log messages into the report 'error' array, like the REST API.
    """

    def test_errors_reach_the_report(self):
        import logging
        from lib.core.data import logger
        from lib.utils.api import setupReportCollector, _assembleData, ReportErrorRecorder, REPORT_TASKID

        # represent a normal run: the shared test bootstrap silences the logger (CRITICAL+1), which would
        # otherwise gate the ERROR record before it reaches the recorder (order-dependent flakiness)
        saved_level = logger.level
        logger.setLevel(logging.ERROR)
        # mute the existing console handler(s) so the deliberate ERROR below does not leak to the
        # unittest output; the recorder added by setupReportCollector next still captures it
        muted = [(handler, handler.level) for handler in logger.handlers]
        for handler, _ in muted:
            handler.setLevel(logging.CRITICAL + 1)
        collector = setupReportCollector()
        try:
            logger.error("boom %s", "here")
            result = _assembleData(collector, REPORT_TASKID)
            self.assertTrue(any("boom here" in _ for _ in result["error"]))
        finally:
            logger.setLevel(saved_level)
            for handler, level in muted:
                handler.setLevel(level)
            for handler in list(logger.handlers):
                if isinstance(handler, ReportErrorRecorder):
                    logger.removeHandler(handler)
            collector.disconnect()


if __name__ == "__main__":
    unittest.main(verbosity=2)
