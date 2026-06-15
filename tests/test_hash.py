#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Password-hashing primitives (lib/utils/hash.py) used by the dictionary-attack
cracker (-? / --passwords). These are pure functions; correctness here is what
makes a cracked password actually match the target hash.

The generic hashes are cross-checked against the stdlib hashlib (an INDEPENDENT
oracle, not just a regression against sqlmap's own output). The DBMS-specific
algorithms (MySQL/MSSQL/Oracle/Postgres) are pinned to known vectors, and
hashRecognition's classification is exercised as a table.
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.utils import hash as H
from lib.core.enums import HASH


class TestGenericVsHashlib(unittest.TestCase):
    """Independent oracle: sqlmap's generic hashes must equal stdlib hashlib."""

    PW = "testpass"

    def test_md5(self):
        self.assertEqual(H.md5_generic_passwd(self.PW), hashlib.md5(b"testpass").hexdigest())

    def test_sha1(self):
        self.assertEqual(H.sha1_generic_passwd(self.PW), hashlib.sha1(b"testpass").hexdigest())

    def test_sha224(self):
        self.assertEqual(H.sha224_generic_passwd(self.PW), hashlib.sha224(b"testpass").hexdigest())

    def test_sha256(self):
        self.assertEqual(H.sha256_generic_passwd(self.PW), hashlib.sha256(b"testpass").hexdigest())

    def test_sha384(self):
        self.assertEqual(H.sha384_generic_passwd(self.PW), hashlib.sha384(b"testpass").hexdigest())

    def test_sha512(self):
        self.assertEqual(H.sha512_generic_passwd(self.PW), hashlib.sha512(b"testpass").hexdigest())


class TestUppercase(unittest.TestCase):
    def test_uppercase_flag(self):
        self.assertEqual(H.md5_generic_passwd("testpass", uppercase=True),
                         hashlib.md5(b"testpass").hexdigest().upper())

    def test_lowercase_default(self):
        out = H.md5_generic_passwd("testpass", uppercase=False)
        self.assertEqual(out, out.lower())


class TestDbmsSpecificVectors(unittest.TestCase):
    """Known vectors for the DBMS-native algorithms (mirrors the docstrings)."""

    def test_mysql(self):
        self.assertEqual(H.mysql_passwd("testpass", uppercase=True),
                         "*00E247AC5F9AF26AE0194B41E1E769DEE1429A29")

    def test_mysql_old(self):
        self.assertEqual(H.mysql_old_passwd("testpass", uppercase=True), "7DCDA0D57290B453")

    def test_postgres(self):
        self.assertEqual(H.postgres_passwd("testpass", "testuser", uppercase=False),
                         "md599e5ea7a6f7c3269995cba3927fd0093")

    def test_mssql(self):
        self.assertEqual(H.mssql_passwd("testpass", salt="4086ceb6", uppercase=False),
                         "0x01004086ceb60c90646a8ab9889fe3ed8e5c150b5460ece8425a")

    def test_oracle(self):
        self.assertEqual(H.oracle_passwd("SHAlala", salt="1B7B5F82B7235E9E182C", uppercase=True),
                         "S:2BFCFDF5895014EE9BB2B9BA067B01E0389BB5711B7B5F82B7235E9E182C")

    def test_oracle_old(self):
        self.assertEqual(H.oracle_old_passwd("tiger", "scott", uppercase=True), "F894844C34402B67")


class TestHashRecognition(unittest.TestCase):
    def test_md5_generic(self):
        self.assertEqual(H.hashRecognition("179ad45c6ce2cb97cf1029e212046e81"), HASH.MD5_GENERIC)

    def test_sha1_generic(self):
        self.assertEqual(H.hashRecognition("206c80413b9a96c1312cc346b7d2517b84463edd"), HASH.SHA1_GENERIC)

    def test_mysql(self):
        self.assertEqual(H.hashRecognition("*00E247AC5F9AF26AE0194B41E1E769DEE1429A29"), HASH.MYSQL)

    def test_junk_is_none(self):
        self.assertIsNone(H.hashRecognition("foobar"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
