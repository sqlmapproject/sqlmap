#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Locks the RestrictedUnpickler security control (lib/core/patch.py, installed over
pickle.loads by dirtyPatches()). sqlmap deserializes pickled blobs out of its own
session DB / cache, so the unpickler is an ALLOWLIST: only safe builtin data types
and sqlmap's own (lib/plugins/thirdparty) classes may be reconstructed.

Two directions, both of which must keep holding:
  - LEGIT round-trips sqlmap actually relies on (AttribDict, BigArray, nested
    builtins, and - the easy-to-regress one - bytes under PICKLE_PROTOCOL=2, which
    emits a _codecs.encode global) must survive base64pickle -> base64unpickle.
  - MALICIOUS / exotic globals (eval, os.system, subprocess.Popen, importlib,
    operator.attrgetter, and even the non-whitelisted _codecs.lookup) must be
    REJECTED at find_class time, before the object is ever built.

A regression in either direction is a security or a data-loss bug, hence the test.
"""

import os
import pickle
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()   # installs dirtyPatches(), i.e. the RestrictedUnpickler over pickle.loads

from lib.core.bigarray import BigArray
from lib.core.convert import base64pickle, base64unpickle, encodeBase64
from lib.core.datatype import AttribDict
from lib.core.settings import PICKLE_PROTOCOL


class _EvilReduce(object):
    """On unpickling, __reduce__ asks the loader to resolve (and would call) an arbitrary global."""
    def __init__(self, func, args):
        self._func = func
        self._args = args

    def __reduce__(self):
        return (self._func, self._args)


def _payload(func, *args):
    # built with the REAL pickler (only pickle.loads is restricted, not dumps); base64 to mirror
    # exactly what base64unpickle() consumes from sqlmap's session store
    return encodeBase64(pickle.dumps(_EvilReduce(func, args), PICKLE_PROTOCOL), binary=False)


class TestUnpicklerIsInstalled(unittest.TestCase):
    def test_patch_active(self):
        # if this is False the whole allowlist is bypassed and the negative tests would pass vacuously
        self.assertTrue(getattr(pickle, "_patched", False))


class TestLegitRoundTrips(unittest.TestCase):
    def _roundtrip(self, value):
        return base64unpickle(base64pickle(value))

    def test_nested_builtins(self):
        value = {"a": [1, 2.5, True, None, complex(1, 2)], "b": (u"x", b"y"), "c": {3, 4}, "d": frozenset([5])}
        self.assertEqual(self._roundtrip(value), value)

    def test_bytes_protocol2(self):
        # protocol-2 pickling of bytes on Python 3 emits a _codecs.encode global; this is the
        # exact case the allowlist explicitly permits, and the one most likely to silently break
        for value in (b"", b"\x00\x01\x02binary\xff", bytearray(b"abc")):
            self.assertEqual(self._roundtrip(value), value)

    def test_attribdict(self):
        value = AttribDict()
        value.foo = "bar"
        value.nested = {"k": [1, 2]}
        restored = self._roundtrip(value)
        self.assertIsInstance(restored, AttribDict)
        self.assertEqual(restored.foo, "bar")
        self.assertEqual(restored.nested, {"k": [1, 2]})

    def test_bigarray(self):
        restored = self._roundtrip(BigArray([1, 2, 3]))
        self.assertIsInstance(restored, BigArray)
        self.assertEqual(list(restored), [1, 2, 3])


class TestMaliciousRejected(unittest.TestCase):
    def _assert_blocked(self, payload):
        # find_class() raises ValueError; base64unpickle only swallows TypeError, so it propagates
        self.assertRaises(ValueError, base64unpickle, payload)

    def test_dangerous_builtins(self):
        # builtins are allowed ONLY for the safe data-type subset; callables must be refused
        for func in (eval, getattr, __import__):
            self._assert_blocked(_payload(func, "1+1") if func is eval else _payload(func, "x"))

    def test_os_system(self):
        self._assert_blocked(_payload(os.system, "echo pwned"))

    def test_subprocess_popen(self):
        self._assert_blocked(_payload(subprocess.Popen, "echo pwned"))

    def test_importlib(self):
        import importlib
        self._assert_blocked(_payload(importlib.import_module, "os"))

    def test_operator_attrgetter(self):
        import operator
        self._assert_blocked(_payload(operator.attrgetter, "system"))

    def test_codecs_lookup_not_whitelisted(self):
        # only _codecs.encode is allowed (for the bytes round-trip); every other _codecs name stays blocked
        import codecs
        self._assert_blocked(_payload(codecs.lookup, "utf-8"))


if __name__ == "__main__":
    unittest.main()
