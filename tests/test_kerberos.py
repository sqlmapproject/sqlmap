#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Tests for the dependency-free Kerberos stack under extra/kerberos: the AES core (FIPS-197), the
RFC 3961/3962 etype crypto (n-fold, string-to-key, authenticated encryption) and the ASN.1 DER codec.
All assertions use published FIPS/RFC test vectors, so they validate the crypto and encoding offline
(the AS/TGS protocol and the HTTP Negotiate handler are exercised against a live KDC, not here).
"""

import binascii
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from extra.kerberos import client
from extra.kerberos import der
from extra.kerberos import discovery
from extra.kerberos.aes import AES
from extra.kerberos.crypto import ENCTYPES, nfold


def _dnsName(name):
    out = bytearray()
    for label in name.split("."):
        out.append(len(label))
        out += label.encode("ascii")
    out.append(0)
    return bytes(out)


def _h(value):
    return binascii.unhexlify(value)


class TestKerberosAES(unittest.TestCase):
    def test_fips197_known_answer(self):
        # FIPS-197 Appendix C.1 (AES-128) and C.3 (AES-256)
        for key, pt, ct in (
            ("000102030405060708090a0b0c0d0e0f",
             "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
             "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
        ):
            aes = AES(_h(key))
            self.assertEqual(aes.encryptBlock(_h(pt)), _h(ct))
            self.assertEqual(aes.decryptBlock(_h(ct)), _h(pt))

    def test_cbc_round_trip(self):
        aes = AES(_h("00" * 32))
        iv, data = _h("0f" * 16), os.urandom(64)
        self.assertEqual(aes.cbcDecrypt(iv, aes.cbcEncrypt(iv, data)), data)


class TestKerberosCrypto(unittest.TestCase):
    def test_nfold_rfc3961(self):
        # RFC 3961 Appendix A.1
        for text, size, expected in (
            ("012345", 8, "be072631276b1955"),
            ("password", 7, "78a07b6caf85fa"),
            ("Rough Consensus, and Running Code", 8, "bb6ed30870b7f0e0"),
            ("password", 21, "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"),
            ("MASSACHVSETTS INSTITVTE OF TECHNOLOGY", 24,
             "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b"),
        ):
            self.assertEqual(binascii.hexlify(nfold(text.encode(), size)).decode(), expected)

    def test_string2key_rfc3962(self):
        # RFC 3962 Appendix B (pass 'password', salt 'ATHENA.MIT.EDUraeburn')
        for iterations, keysize, expected in (
            (1, 16, "42263c6e89f4fc28b8df68ee09799f15"),
            (1, 32, "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"),
            (1200, 16, "4c01cd46d632d01e6dbe230a01ed642a"),
            (1200, 32, "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a"),
        ):
            key = ENCTYPES[17 if keysize == 16 else 18].string2key("password", "ATHENA.MIT.EDUraeburn", iterations)
            self.assertEqual(binascii.hexlify(key).decode(), expected)

    def test_encrypt_decrypt_round_trip(self):
        for etype in (17, 18):
            enc = ENCTYPES[etype]
            key = os.urandom(enc.keysize)
            for length in (0, 1, 15, 16, 17, 31, 32, 100):
                plaintext = os.urandom(length)
                self.assertEqual(enc.decrypt(key, 1024, enc.encrypt(key, 1024, plaintext)), plaintext)

    def test_integrity_check(self):
        enc = ENCTYPES[18]
        key = os.urandom(32)
        ciphertext = bytearray(enc.encrypt(key, 3, b"secret"))
        ciphertext[-1] ^= 1
        self.assertRaises(ValueError, enc.decrypt, key, 3, bytes(ciphertext))

    def test_decrypt_short_ciphertext(self):
        # a hostile/truncated enc-part (< blocksize + macsize) must raise ValueError, not IndexError
        enc = ENCTYPES[18]
        key = os.urandom(32)
        for length in (0, 1, 12, 27):
            self.assertRaises(ValueError, enc.decrypt, key, 3, os.urandom(length))

    def test_string2key_bytes_salt(self):
        # the salt is opaque octets (RFC 3961): a bytes salt must derive the same key as the str form
        enc = ENCTYPES[18]
        self.assertEqual(enc.string2key("password", b"ATHENA.MIT.EDUraeburn", 1200),
                         enc.string2key("password", "ATHENA.MIT.EDUraeburn", 1200))


class TestKerberosRC4(unittest.TestCase):
    def test_nt_hash_string2key(self):
        # rc4-hmac long-term key is the NT hash: MD4(UTF-16LE(password))
        self.assertEqual(binascii.hexlify(ENCTYPES[23].string2key("password")).decode(),
                         "8846f7eaee8fb117ad06bdd830b7586c")

    def test_encrypt_decrypt_round_trip(self):
        enc = ENCTYPES[23]
        key = enc.string2key("Secret123")
        for length in (0, 1, 16, 100):
            plaintext = os.urandom(length)
            self.assertEqual(enc.decrypt(key, 1024, enc.encrypt(key, 1024, plaintext)), plaintext)

    def test_integrity_check(self):
        enc = ENCTYPES[23]
        key = enc.string2key("x")
        ciphertext = bytearray(enc.encrypt(key, 3, b"secret"))
        ciphertext[-1] ^= 1
        self.assertRaises(ValueError, enc.decrypt, key, 3, bytes(ciphertext))


class TestKerberosDER(unittest.TestCase):
    def test_integer_canonical(self):
        for value, expected in ((0, "020100"), (127, "02017f"), (128, "02020080"),
                                (256, "02020100"), (-1, "0201ff"), (-129, "0202ff7f")):
            self.assertEqual(binascii.hexlify(der.integer(value)).decode(), expected)
            self.assertEqual(der.decodeInteger(der.peel(der.integer(value))[1]), value)

    def test_application_tags(self):
        self.assertEqual(bytearray(der.application(10, der.sequence()))[0], 0x6a)   # AS-REQ
        self.assertEqual(bytearray(der.application(14, der.sequence()))[0], 0x6e)   # AP-REQ
        self.assertEqual(bytearray(der.tagged(0, der.integer(1)))[0], 0xa0)         # [0] EXPLICIT

    def test_nested_round_trip(self):
        pname = der.sequence(
            der.tagged(0, der.integer(1)),
            der.tagged(1, der.sequenceOf([der.generalString("HTTP"), der.generalString("web.example.com")])),
        )
        _, content, _ = der.peel(pname)
        fields = dict(der.children(content))
        components = [der.decodeGeneralString(c) for _, c in der.children(der.peel(fields[0xa1])[1])]
        self.assertEqual(der.decodeInteger(der.peel(fields[0xa0])[1]), 1)
        self.assertEqual(components, ["HTTP", "web.example.com"])


class TestKerberosClient(unittest.TestCase):
    def test_malformed_reply_raises_kerberoserror(self):
        # a hostile/truncated KDC reply must surface as KerberosError, never a raw parse exception
        key, nonce = os.urandom(32), 0x11223344
        for blob in (b"", b"\x7e\x01", b"\x6b\x02\x30\x00", os.urandom(40)):
            self.assertRaises(client.KerberosError, client._parseRep, blob, key, 3, nonce, client.AS_REP)
            self.assertRaises(client.KerberosError, client._replyEtype, blob)

    def test_etype_info2_best_effort(self):
        # a malformed PA-ETYPE-INFO2 must yield no advertised info (fall back to defaults), not crash
        self.assertEqual(client._parseEtypeInfo2({12: der.octetString(b"\xff\xff\xff")}), [])
        self.assertEqual(client._parseEtypeInfo2({}), [])


class TestKerberosDiscovery(unittest.TestCase):
    def test_krb5conf(self):
        content = ("[realms]\n"
                   " EXAMPLE.COM = {\n  kdc = dc1.example.com:88\n  admin_server = dc1.example.com\n }\n"
                   " OTHER.COM = { kdc = other-dc }\n"
                   # a nested '{ }' block ahead of 'kdc =' must not truncate the realm section
                   " NESTED.COM = {\n  auth_to_local_names = {\n    joe = joe\n  }\n  kdc = dc.nested.com\n }\n")
        handle, path = tempfile.mkstemp()
        os.write(handle, content.encode("utf-8"))
        os.close(handle)
        saved = os.environ.get("KRB5_CONFIG")
        os.environ["KRB5_CONFIG"] = path
        try:
            self.assertEqual(discovery._fromKrb5Conf("EXAMPLE.COM"), "dc1.example.com:88")
            self.assertEqual(discovery._fromKrb5Conf("OTHER.COM"), "other-dc")
            self.assertEqual(discovery._fromKrb5Conf("NESTED.COM"), "dc.nested.com")
            self.assertIsNone(discovery._fromKrb5Conf("MISSING.COM"))
        finally:
            os.remove(path)
            os.environ.pop("KRB5_CONFIG", None) if saved is None else os.environ.__setitem__("KRB5_CONFIG", saved)

    def test_split_host_port(self):
        self.assertEqual(discovery._splitHostPort("dc.example.com"), ("dc.example.com", 88))
        self.assertEqual(discovery._splitHostPort("dc.example.com:1088"), ("dc.example.com", 1088))
        self.assertEqual(discovery._splitHostPort("[2001:db8::1]:1088"), ("2001:db8::1", 1088))
        self.assertEqual(discovery._splitHostPort("[2001:db8::1]"), ("2001:db8::1", 88))
        self.assertEqual(discovery._splitHostPort("2001:db8::1"), ("2001:db8::1", 88))

    def test_srv_parse(self):
        header = struct.pack(">HHHHHH", 0x2a2a, 0x8180, 1, 1, 0, 0)
        question = _dnsName("_kerberos._tcp.EXAMPLE.COM") + struct.pack(">HH", 33, 1)
        rdata = struct.pack(">HHH", 0, 100, 88) + _dnsName("dc.example.com")
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 33, 1, 300, len(rdata)) + rdata  # name = ptr to question
        self.assertEqual(discovery.parseSrv(header + question + answer), [(0, 100, 88, "dc.example.com")])

    def test_srv_parse_hostile_input(self):
        # a compression-pointer cycle (name at offset 12 points to itself) must not hang or crash
        cycle = struct.pack(">HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c"
        self.assertEqual(discovery.parseSrv(cycle), [])
        self.assertEqual(discovery.parseSrv(b""), [])
        self.assertEqual(discovery.parseSrv(b"\x00\x00\x81\x80\x00\x00\x00\x05\xff\xff"), [])

    def test_precedence_env_overrides(self):
        saved = os.environ.get("SQLMAP_KERBEROS_KDC")
        os.environ["SQLMAP_KERBEROS_KDC"] = "10.0.0.1:8888"
        try:
            self.assertEqual(discovery.discoverKdc("EXAMPLE.COM"), ("10.0.0.1", 8888))
        finally:
            os.environ.pop("SQLMAP_KERBEROS_KDC", None) if saved is None else os.environ.__setitem__("SQLMAP_KERBEROS_KDC", saved)

    def test_fallback_to_realm(self):
        savedEnv = os.environ.pop("SQLMAP_KERBEROS_KDC", None)
        savedCfg = os.environ.get("KRB5_CONFIG")
        os.environ["KRB5_CONFIG"] = "/nonexistent/sqlmap-krb5.conf"
        savedDns = discovery._fromDnsSrv
        discovery._fromDnsSrv = lambda realm: None         # avoid real DNS I/O in the test
        try:
            self.assertEqual(discovery.discoverKdc("CORP.EXAMPLE"), ("corp.example", 88))
        finally:
            discovery._fromDnsSrv = savedDns
            if savedEnv is not None:
                os.environ["SQLMAP_KERBEROS_KDC"] = savedEnv
            os.environ.pop("KRB5_CONFIG", None) if savedCfg is None else os.environ.__setitem__("KRB5_CONFIG", savedCfg)


if __name__ == "__main__":
    unittest.main()
