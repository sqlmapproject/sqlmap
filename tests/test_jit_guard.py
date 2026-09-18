#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

The last branch of main()'s unhandled-exception chain in sqlmap.py: when the
experimental Python JIT is turned on, a crash gets the tier-2 advisory (Reference:
'https://github.com/python/cpython/issues/156319') instead of the automatic
issue-creation prompt - but the traceback is still printed, so a genuine sqlmap
bug is not swallowed.

Driven through a subprocess because it is main()'s own except chain under test.
"""

import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Forces a crash inside init(), i.e. the same place #6117 landed, without needing a target.
# NOTE: the injected fault must raise on Python 2 as well - 'a' < 128 does NOT (Python 2 orders
# mismatched types by type name and quietly returns a bool), which let a broken run reach the
# network on the PyPy-2.7 job instead of the exception handler under test.
# codeIsModified() is neutralized because its branch sits earlier in the chain and would
# otherwise win on any working tree with uncommitted edits (or a stale txt/checksum.md5).
DRIVER = """
import sys
sys.path.insert(0, %r)
sys.argv = ["sqlmap.py", "-u", "http://127.0.0.1/?id=1", "--batch"]
import sqlmap
import lib.core.option
sqlmap.codeIsModified = lambda: False
lib.core.option.loadPayloads = lambda: iter([])()
sqlmap.main()
""" % ROOT

ADVISORY = "experimental Python JIT compiler is turned on"
TRACEBACK = "TypeError"
PROMPT = "automatically create a new (anonymized) issue"


def _run(jit):
    env = dict(os.environ)
    env["PYTHON_JIT"] = jit
    proc = subprocess.Popen([sys.executable, "-c", DRIVER], cwd=ROOT, env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    out = proc.communicate(input=b"")[0]
    return out.decode("utf-8", "replace")


def _jitEnabled(jit):
    """Whether the guard in sqlmap.py would consider the JIT enabled (mirrors its condition)."""
    code = ("import sys, os; print(sys._jit.is_enabled() if hasattr(sys, '_jit') "
            "else (sys.version_info >= (3, 13) and os.environ.get('PYTHON_JIT') == '1'))")
    env = dict(os.environ)
    env["PYTHON_JIT"] = jit
    return subprocess.check_output([sys.executable, "-c", code], env=env).strip() == b"True"


class TestJitGuard(unittest.TestCase):
    def test_advisory_replaces_issue_prompt_but_keeps_traceback(self):
        if not _jitEnabled('1'):
            self.skipTest("interpreter does not report the JIT as enabled")

        out = _run('1')
        self.assertIn(ADVISORY, out)
        self.assertIn(TRACEBACK, out)          # a real bug must still be visible in full
        self.assertNotIn(PROMPT, out)          # ... but not auto-filed while the JIT is on

    def test_normal_path_is_untouched_without_jit(self):
        if _jitEnabled('0'):
            self.skipTest("JIT stays enabled with PYTHON_JIT=0 on this build")

        out = _run('0')
        self.assertNotIn(ADVISORY, out)
        self.assertIn(TRACEBACK, out)
        self.assertIn(PROMPT, out)


# Tool id 3 is unused by CPython's own well-known ids (DEBUGGER=0, COVERAGE=1, PROFILER=2, OPTIMIZER=5)
_TEST_TOOL_ID = 3

_MONITORING_DRIVER = """
import sys
sys.path.insert(0, %r)
sys.monitoring.use_tool_id(%d, "test-tool")
sys.monitoring.set_events(%d, sys.monitoring.events.PY_START)
import sqlmap
print(sys.monitoring.get_tool(%d))
print(sys.monitoring.get_events(%d))
""" % (ROOT, _TEST_TOOL_ID, _TEST_TOOL_ID, _TEST_TOOL_ID, _TEST_TOOL_ID)


class TestMonitoringGuard(unittest.TestCase):
    """
    The other half of the cpython#156319 mitigation: the tier-2 corruption needs BOTH the JIT and
    an active sys.monitoring tool (debugger/profiler/coverage) at once. sqlmap has no legitimate
    reason to run a scan with one attached, so it silences any already-registered tool's events as
    the very first thing at import time (Reference: 'https://github.com/python/cpython/issues/156319').
    """

    def test_active_tool_is_silenced_but_not_unregistered(self):
        if not hasattr(sys, "monitoring"):
            self.skipTest("interpreter has no sys.monitoring (needs 3.12+)")

        out = subprocess.check_output([sys.executable, "-c", _MONITORING_DRIVER], cwd=ROOT)
        tool, events = out.decode("utf-8").strip().splitlines()

        self.assertEqual(tool, "test-tool")    # still registered - its own owner can still free it
        self.assertEqual(events, "0")          # events cleared to NO_EVENTS, so nothing fires


if __name__ == "__main__":
    unittest.main()
