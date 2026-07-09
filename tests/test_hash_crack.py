#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Dictionary-attack machinery in lib/utils/hash.py (the cracking loop, hash-file
parsing, result storage and table/cache post-processing) - the part NOT covered
by tests/test_hash.py, which only exercises the pure hash-format functions.

These run the single-process cracking path (conf.disableMulti=True) against a
TINY temp wordlist that contains the known plaintext, so a known hash is cracked
deterministically in milliseconds without interactive prompts, multiprocessing
pools, network, or the real default dictionary. conf.hashDB is forced to None so
hashDBRetrieve/hashDBWrite become no-ops (no session DB side effects).
"""

import glob
import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.utils import hash as H
from lib.core.data import conf, kb
from lib.core.enums import MKSTEMP_PREFIX

import atexit
import shutil
SCRATCH = tempfile.mkdtemp(prefix="sqlmap_test_hashcrack_")
atexit.register(lambda: shutil.rmtree(SCRATCH, ignore_errors=True))

# known plaintext / hashes shared across tests
PW = "testpass"
MD5_HASH = hashlib.md5(PW.encode("utf-8")).hexdigest()


class _CrackBase(unittest.TestCase):
    """Sets up a tiny wordlist and non-interactive, no-DB, single-process state."""

    @classmethod
    def setUpClass(cls):
        cls._tmpfiles = []

        # tiny wordlist containing the known plaintext (plus decoys)
        cls.wordlist = os.path.join(SCRATCH, "test_hash_crack_wl.txt")
        with open(cls.wordlist, "w") as f:
            f.write("foo\nbar\n%s\nbaz\n" % PW)
        cls._tmpfiles.append(cls.wordlist)

    @classmethod
    def tearDownClass(cls):
        for path in cls._tmpfiles:
            try:
                os.remove(path)
            except OSError:
                pass

    def setUp(self):
        # snapshot global state we mutate
        self._saved = {
            "disableMulti": conf.disableMulti,
            "hashDB": conf.hashDB,
            "hashFile": conf.hashFile,
            "wordlists": kb.wordlists,
            "cachedUsersPasswords": kb.data.cachedUsersPasswords if "cachedUsersPasswords" in kb.data else None,
            "storeHashes": kb.choices.storeHashes if "storeHashes" in kb.choices else None,
        }

        # deterministic, fast, side-effect-free cracking
        conf.disableMulti = True
        conf.hashDB = None
        kb.wordlists = [self.wordlist]

        # cracking prints "[INFO] cracked password ..." via dataToStdout(forceOutput=True), which
        # bypasses both the logger and kb.wizardMode suppression; redirect stdout so the unittest
        # report stays clean (these tests assert on return values/kb, never on console output).
        self._saved_stdout = sys.stdout
        sys.stdout = open(os.devnull, "w")

    def tearDown(self):
        if getattr(self, "_saved_stdout", None) is not None:
            try:
                sys.stdout.close()
            finally:
                sys.stdout = self._saved_stdout
        conf.disableMulti = self._saved["disableMulti"]
        conf.hashDB = self._saved["hashDB"]
        conf.hashFile = self._saved["hashFile"]
        kb.wordlists = self._saved["wordlists"]
        kb.data.cachedUsersPasswords = self._saved["cachedUsersPasswords"]
        kb.choices.storeHashes = self._saved["storeHashes"]


class TestDictionaryAttack(_CrackBase):
    def test_crack_md5_generic_variant_a(self):
        # generic (no-salt) algorithms go through _bruteProcessVariantA
        results = H.dictionaryAttack({"admin": [MD5_HASH]})
        self.assertEqual(results, [("admin", MD5_HASH, PW)])

    def test_crack_postgres_variant_b(self):
        # username-dependent algorithm goes through _bruteProcessVariantB
        h = H.postgres_passwd(PW, "testuser", uppercase=False)
        results = H.dictionaryAttack({"testuser": [h]})
        self.assertEqual(results, [("testuser", h, PW)])

    def test_crack_django_md5_salted_variant_b(self):
        # salted algorithm: salt is parsed out of the stored hash by dictionaryAttack
        h = H.django_md5_passwd(PW, "salt")
        results = H.dictionaryAttack({"u2": [h]})
        self.assertEqual(results, [("u2", h, PW)])

    def test_no_password_found_returns_empty(self):
        # plaintext not in wordlist -> nothing cracked
        h = hashlib.md5(b"not-in-wordlist-xyz").hexdigest()
        results = H.dictionaryAttack({"admin": [h]})
        self.assertEqual(results, [])

    def test_unknown_hash_format_ignored(self):
        # a value that hashRecognition rejects produces no hash_regexes and no results
        results = H.dictionaryAttack({"admin": ["not_a_hash"]})
        self.assertEqual(results, [])

    def test_empty_attack_dict(self):
        self.assertEqual(H.dictionaryAttack({}), [])


class TestCrackHashFile(_CrackBase):
    def setUp(self):
        super(TestCrackHashFile, self).setUp()
        # capture the parsed attack_dict that crackHashFile feeds to dictionaryAttack
        self._captured = {}
        self._real_attack = H.dictionaryAttack

        def _capture(attack_dict):
            self._captured.clear()
            self._captured.update(attack_dict)
            return []

        H.dictionaryAttack = _capture

    def tearDown(self):
        H.dictionaryAttack = self._real_attack
        super(TestCrackHashFile, self).tearDown()

    def test_user_colon_hash_file(self):
        path = os.path.join(SCRATCH, "test_hash_crack_hashes.txt")
        with open(path, "w") as f:
            f.write("admin:%s\n" % MD5_HASH)
        self._tmpfiles.append(path)

        conf.hashFile = path
        self.assertIsNone(H.crackHashFile(path))

        # the "user:hash" line is parsed into {username: [hash]}
        self.assertEqual(self._captured, {"admin": [MD5_HASH]})

    def test_bare_hash_file(self):
        # no "user:hash" structure -> a dummy user is synthesised per line
        path = os.path.join(SCRATCH, "test_hash_crack_bare.txt")
        with open(path, "w") as f:
            f.write("%s\n" % MD5_HASH)
        self._tmpfiles.append(path)

        conf.hashFile = path
        self.assertIsNone(H.crackHashFile(path))

        from lib.core.settings import DUMMY_USER_PREFIX
        self.assertEqual(len(self._captured), 1)
        (key, value), = self._captured.items()
        # the synthesised key uses the dummy-user prefix and maps to the bare hash
        self.assertTrue(key.startswith(DUMMY_USER_PREFIX),
                        msg="bare line was not assigned a dummy user: %r" % key)
        self.assertEqual(value, [MD5_HASH])


class TestAttackCachedUsersPasswords(_CrackBase):
    def test_annotates_cleartext(self):
        kb.data.cachedUsersPasswords = {"admin": [MD5_HASH]}
        H.attackCachedUsersPasswords()
        # the original value is augmented in place with the recovered clear-text
        self.assertIn("clear-text password: %s" % PW, kb.data.cachedUsersPasswords["admin"][0])

    def test_no_cached_data_is_noop(self):
        kb.data.cachedUsersPasswords = {}
        # must simply return without touching anything
        self.assertIsNone(H.attackCachedUsersPasswords())


class TestStoreHashesToFile(_CrackBase):
    def _hash_tempfiles(self):
        pattern = os.path.join(tempfile.gettempdir(), MKSTEMP_PREFIX.HASHES + "*")
        return set(glob.glob(pattern))

    def test_store_disabled_writes_nothing(self):
        kb.choices.storeHashes = False
        before = self._hash_tempfiles()
        H.storeHashesToFile({"admin": [MD5_HASH]})
        self.assertEqual(self._hash_tempfiles(), before)

    def test_store_enabled_writes_recognised_hash(self):
        kb.choices.storeHashes = True
        before = self._hash_tempfiles()
        try:
            H.storeHashesToFile({"admin": [MD5_HASH]})
            new = self._hash_tempfiles() - before
            self.assertEqual(len(new), 1)
            with open(next(iter(new))) as fh:
                written = fh.read()
            self.assertIn(MD5_HASH, written)
            self.assertIn("admin", written)
        finally:
            for path in self._hash_tempfiles() - before:
                try:
                    os.remove(path)
                except OSError:
                    pass

    def test_empty_attack_dict_is_noop(self):
        kb.choices.storeHashes = True
        before = self._hash_tempfiles()
        H.storeHashesToFile({})
        self.assertEqual(self._hash_tempfiles(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
