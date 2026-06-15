#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Wordlist iterator (lib/core/wordlist.py).

Backs dictionary attacks (--common-tables, password cracking, brute force): a
lazy iterator that streams words across one or more files (and zip archives)
without loading them into RAM. Tested for ordering, multi-file chaining,
rewind, and end-of-stream behavior over real temp files.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.wordlist import Wordlist


def _mkfile(lines):
    fd, path = tempfile.mkstemp()
    os.write(fd, ("\n".join(lines) + "\n").encode("utf-8"))
    os.close(fd)
    return path


def _w(s):
    # Wordlist yields native str on py2 but bytes on py3 (words are fed straight into HTTP payloads)
    return s.encode("utf-8") if sys.version_info[0] >= 3 else s


def _drain(w):
    out = []
    try:
        while True:
            out.append(next(w))
    except StopIteration:
        pass
    return out


class TestWordlist(unittest.TestCase):
    def setUp(self):
        self.paths = []
        self.wordlists = []

    def tearDown(self):
        for w in self.wordlists:        # close open file handles (else ResourceWarning on py3)
            try:
                w.closeFP()
            except Exception:
                pass
        for p in self.paths:
            if os.path.exists(p):
                os.remove(p)

    def _mk(self, lines):
        p = _mkfile(lines)
        self.paths.append(p)
        return p

    def _wl(self, files):
        w = Wordlist(files)
        self.wordlists.append(w)
        return w

    def test_single_file_order(self):
        w = self._wl([self._mk(["alpha", "beta", "gamma"])])
        self.assertEqual(_drain(w), [_w("alpha"), _w("beta"), _w("gamma")])

    def test_multiple_files_chained(self):
        w = self._wl([self._mk(["a", "b"]), self._mk(["c", "d"])])
        self.assertEqual(_drain(w), [_w("a"), _w("b"), _w("c"), _w("d")])

    def test_rewind_restarts(self):
        w = self._wl([self._mk(["one", "two"])])
        self.assertEqual(next(w), _w("one"))
        self.assertEqual(next(w), _w("two"))
        w.rewind()
        self.assertEqual(next(w), _w("one"))

    def test_end_raises_stopiteration(self):
        w = self._wl([self._mk(["only"])])
        self.assertEqual(next(w), _w("only"))
        self.assertRaises(StopIteration, lambda: next(w))


if __name__ == "__main__":
    unittest.main(verbosity=2)
