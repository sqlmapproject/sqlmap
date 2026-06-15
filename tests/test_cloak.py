#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

cloak / decloak (extra/cloak/cloak.py) - the zlib+XOR transform used to pack the
payload stager files (.py_) that sqlmap drops and unpacks on a target during
takeover/file-write. A broken round-trip here corrupts every deployed stager.

decloak(cloak(x)) must be the identity for arbitrary bytes; pinned with known
vectors and a property sweep over random binary inputs.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

# cloak ships under extra/cloak (build-time + runtime stager packer)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "extra", "cloak"))
import cloak as C

RND = random.Random(1234)


def _rand_bytes(n):
    return bytes(bytearray(RND.randint(0, 255) for _ in range(n)))


class TestCloakRoundTrip(unittest.TestCase):
    def test_known_payload(self):
        data = b"print('stager')"
        self.assertEqual(C.decloak(data=C.cloak(data=data)), data)

    def test_empty(self):
        self.assertEqual(C.decloak(data=C.cloak(data=b"")), b"")

    def test_cloak_changes_bytes(self):
        # cloak must actually transform (compress+xor), not pass through
        data = b"A" * 64
        self.assertNotEqual(C.cloak(data=data), data)

    def test_cloak_compresses_compressible_input(self):
        # highly-repetitive input must come out SMALLER (proves zlib is actually applied,
        # not just an XOR-only obfuscation). NOTE: random/incompressible data would grow,
        # so this assertion is only valid for compressible input.
        data = b"A" * 1000
        self.assertLess(len(C.cloak(data=data)), len(data))

    def test_property_random_binary(self):
        for _ in range(500):
            data = _rand_bytes(RND.randint(0, 200))
            self.assertEqual(C.decloak(data=C.cloak(data=data)), data, msg="cloak round-trip failed for %r" % data)

    def test_property_large(self):
        for size in (1024, 8192, 65536):
            data = _rand_bytes(size)
            self.assertEqual(C.decloak(data=C.cloak(data=data)), data, msg="cloak round-trip failed at size %d" % size)


if __name__ == "__main__":
    unittest.main(verbosity=2)
