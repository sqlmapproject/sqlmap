#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Assorted request-shaping helpers in lib/core/common.py:
chunkSplitPostData (HTTP chunked-transfer evasion), randomizeParameterValue
(tamper/cache-buster), getHostHeader (Host header derivation).

chunkSplitPostData uses random chunk sizes, so its output is asserted
structurally (reassembles to the original, terminates correctly) rather than
byte-for-byte; randomizeParameterValue is asserted via its invariants.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import chunkSplitPostData, randomizeParameterValue, getHostHeader


def _dechunk(data):
    """Reassemble an HTTP/1.1 chunked body back into its payload."""
    out = []
    i = 0
    while i < len(data):
        nl = data.index("\r\n", i)
        size = int(data[i:nl].split(";")[0], 16)   # size; optional chunk-extension
        start = nl + 2
        out.append(data[start:start + size])
        i = start + size + 2                         # skip chunk data + trailing CRLF
        if size == 0:
            break
    return "".join(out)


class TestChunkSplit(unittest.TestCase):
    def test_reassembles_to_original(self):
        for payload in ("a=1&b=2", "x" * 50, "single=value", ""):
            self.assertEqual(_dechunk(chunkSplitPostData(payload)), payload,
                             msg="chunk reassembly failed for %r" % payload)

    def test_terminates_with_zero_chunk(self):
        self.assertTrue(chunkSplitPostData("a=1&b=2").endswith("0\r\n\r\n"))


class TestRandomizeParameterValue(unittest.TestCase):
    def test_length_preserved(self):
        for v in ("abc123", "value", "42", "MixedCASE99"):
            self.assertEqual(len(randomizeParameterValue(v)), len(v), msg="length changed for %r" % v)

    def test_char_class_preserved(self):
        # letters stay letters, digits stay digits (positionally)
        src = "abc123XYZ789"
        out = randomizeParameterValue(src)
        for a, b in zip(src, out):
            self.assertEqual(a.isdigit(), b.isdigit(), msg="char class changed: %r -> %r" % (a, b))
            self.assertEqual(a.isalpha(), b.isalpha(), msg="char class changed: %r -> %r" % (a, b))


class TestGetHostHeader(unittest.TestCase):
    def test_with_port(self):
        self.assertEqual(getHostHeader("http://h:8080/p"), "h:8080")

    def test_without_port(self):
        self.assertEqual(getHostHeader("http://example.com/path"), "example.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
