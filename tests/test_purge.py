#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Secure directory purge (lib/utils/purge.py, the --purge feature): multi-pass
overwrite + truncation + removal of a directory's content. Driven against a
throwaway temp tree so the real output dir is never touched.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.utils.purge as purge_mod
from lib.utils.purge import purge


class _RecordingLogger(object):
    """Captures every (level, message) emitted while installed as purge.logger."""

    def __init__(self):
        self.records = []

    def _add(self, level):
        return lambda msg, *a: self.records.append((level, msg % a if a else msg))

    def __getattr__(self, name):
        if name in ("warning", "info", "debug", "error", "critical"):
            return self._add(name)
        raise AttributeError(name)

    def messages(self, level=None):
        return [m for (lvl, m) in self.records if level is None or lvl == level]


class TestPurge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sqlmap_purge_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_overwrites_and_truncates_file_contents(self):
        # a couple of files + a nested subdir with a (non-empty) file
        plaintexts = {
            os.path.join(self.tmp, "a.txt"): "secret data",
            os.path.join(self.tmp, "sub", "b.txt"): "more secret data",
        }
        with open(os.path.join(self.tmp, "a.txt"), "w") as f:
            f.write(plaintexts[os.path.join(self.tmp, "a.txt")])
        with open(os.path.join(self.tmp, "empty.bin"), "w") as f:
            pass
        os.mkdir(os.path.join(self.tmp, "sub"))
        with open(os.path.join(self.tmp, "sub", "b.txt"), "w") as f:
            f.write(plaintexts[os.path.join(self.tmp, "sub", "b.txt")])

        # neutralise the final rmtree so the overwrite/truncate work product remains
        # observable on disk; the files are renamed, so locate them by walking the tree.
        real_rmtree = purge_mod.shutil.rmtree
        purge_mod.shutil.rmtree = lambda *a, **k: None
        try:
            purge(self.tmp)
        finally:
            purge_mod.shutil.rmtree = real_rmtree

        # collect every surviving regular file (names are randomised by purge)
        survivors = []
        for root, _dirs, files in os.walk(self.tmp):
            for name in files:
                survivors.append(os.path.join(root, name))

        # the originally non-empty files still exist (rmtree was a no-op) but the
        # multi-pass overwrite + truncation reduced each to size 0 and the original
        # plaintext is gone.
        nonempty = [p for p in survivors if os.path.getsize(p) > 0]
        self.assertEqual(nonempty, [], msg="files were not truncated to zero: %r" % nonempty)

        blob = b"".join(open(p, "rb").read() for p in survivors)
        for secret in plaintexts.values():
            self.assertNotIn(secret.encode("utf-8"), blob,
                             msg="original plaintext %r survived the purge" % secret)

    def test_purges_nested_content(self):
        # full purge (including rmtree) wipes the whole tree
        with open(os.path.join(self.tmp, "a.txt"), "w") as f:
            f.write("secret data")
        sub = os.path.join(self.tmp, "sub")
        os.mkdir(sub)
        with open(os.path.join(sub, "b.txt"), "w") as f:
            f.write("more secret data")

        purge(self.tmp)

        self.assertFalse(os.path.exists(self.tmp))

    def test_nonexistent_directory_is_noop(self):
        missing = os.path.join(self.tmp, "does_not_exist")

        real_logger = purge_mod.logger
        rec = _RecordingLogger()
        purge_mod.logger = rec
        try:
            # must not raise; the guard branch logs a skip warning and returns
            purge(missing)
        finally:
            purge_mod.logger = real_logger

        self.assertFalse(os.path.exists(missing))
        self.assertTrue(
            any("skipping purging" in w and "does not exist" in w for w in rec.messages("warning")),
            msg="nonexistent-directory guard did not log its warning: %r" % rec.records,
        )


if __name__ == "__main__":
    unittest.main()
