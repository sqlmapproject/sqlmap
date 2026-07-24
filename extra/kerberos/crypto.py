#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# Dependency-free Kerberos "simplified profile" crypto (RFC 3961) for the AES-CTS-HMAC-SHA1-96 etypes
# (RFC 3962: aes128-cts-hmac-sha1-96 = etype 17, aes256-cts-hmac-sha1-96 = etype 18), built on the
# pure-Python AES core. Provides n-fold, DK/DR key derivation, string-to-key (PBKDF2-HMAC-SHA1) and
# authenticated encrypt/decrypt. Validated against the RFC 3961 A / RFC 3962 B test vectors.
# Python 2.7 / 3.x.

import binascii
import hashlib
import hmac
import os
import struct

from extra.kerberos.aes import AES, _xor                   # _xor reused (no second copy) from the AES core
from lib.core.decorators import cachedmethod
from lib.request.ntlm import _md4                          # proven RFC 1320 MD4 (reused, not re-derived)

# RFC 3962 string-to-key default work factor when the KDC advertises no explicit count
DEFAULT_PBKDF2_ITERATIONS = 4096

def _to_bytes(value):
    return value if isinstance(value, bytes) else value.encode("utf-8")

def _b2i(data):
    data = bytearray(data)
    return int(binascii.hexlify(bytes(data)), 16) if data else 0

def _i2b(n, length):
    if length <= 0:
        return bytearray()
    return bytearray(binascii.unhexlify(("%0*x" % (length * 2, n))[-length * 2:]))

def _eq(a, b):
    return hmac.compare_digest(bytes(a), bytes(b)) if hasattr(hmac, "compare_digest") else (bytes(a) == bytes(b))

def _pbkdf2(password, salt, iterations, dklen):
    """PBKDF2-HMAC-SHA1. Uses the stdlib primitive when present, with an RFC 2898 fallback for the
    pre-2.7.8 interpreters that lack hashlib.pbkdf2_hmac."""

    if hasattr(hashlib, "pbkdf2_hmac"):
        return hashlib.pbkdf2_hmac("sha1", password, salt, iterations, dklen)

    out = bytearray()
    block = 1
    while len(out) < dklen:
        u = hmac.new(password, salt + struct.pack(">I", block), hashlib.sha1).digest()
        acc = bytearray(u)
        for _ in range(iterations - 1):
            u = hmac.new(password, u, hashlib.sha1).digest()
            acc = bytearray(x ^ y for x, y in zip(acc, bytearray(u)))
        out += acc
        block += 1
    return bytes(out[:dklen])

def _rotate_right(data, nbits):
    """Rotate a byte string right by 'nbits' bits, preserving its length."""

    data = bytearray(data)
    if not data:
        return data
    total = len(data) * 8
    nbits %= total
    value = ((_b2i(data) >> nbits) | (_b2i(data) << (total - nbits))) & ((1 << total) - 1)
    return _i2b(value, len(data))

def nfold(data, nbytes):
    """RFC 3961 n-fold: spread 'data' over 'nbytes' bytes via 13-bit rotated copies summed with an
    end-around carry (ones-complement addition)."""

    data = bytearray(data)

    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    lcm = len(data) * nbytes // gcd(len(data), nbytes)

    buf = bytearray()
    rotation = 0
    while len(buf) < lcm:
        buf += _rotate_right(data, rotation)
        rotation += 13

    bits = 8 * nbytes
    mask = (1 << bits) - 1
    acc = sum(_b2i(buf[off:off + nbytes]) for off in range(0, lcm, nbytes))
    while acc > mask:
        acc = (acc & mask) + (acc >> bits)
    return bytes(_i2b(acc, nbytes))

class AESEnctype(object):
    """AES-CTS-HMAC-SHA1-96 simplified-profile enctype (RFC 3962). keysize 16 => etype 17, 32 => 18."""

    blocksize = 16
    macsize = 12

    def __init__(self, keysize):
        self.keysize = keysize
        self.cksumtype = 16 if keysize == 32 else 15       # hmac-sha1-96-aes256 / -aes128

    def checksum(self, key, usage, data):
        """Keyed checksum (RFC 3961 get_mic): HMAC-SHA1-96 under the checksum key DK(key, usage|0x99)."""

        kc = self.dk(key, struct.pack(">IB", usage, 0x99))
        return hmac.new(kc, data, hashlib.sha1).digest()[:self.macsize]

    # --- key schedule -------------------------------------------------------------------------------
    def _dr(self, key, constant):
        """RFC 3961 DR: iterate the single-block cipher over the (n-folded) constant to seedsize."""

        aes = AES(key)
        block = nfold(constant, self.blocksize)
        out = bytearray()
        while len(out) < self.keysize:
            block = aes.encryptBlock(block)                     # single 16-byte block => CBC(iv=0) == ECB
            out += bytearray(block)
        return bytes(out[:self.keysize])

    @cachedmethod
    def dk(self, key, constant):
        """RFC 3961 DK = random-to-key(DR(...)); random-to-key is the identity for AES.

        Cached: it is a pure function of (key, constant), while a scan mints an authenticator per
        request from the same handful of long-lived keys, so the pure-Python DR would otherwise be
        recomputed for every single one."""

        return self._dr(key, constant)

    def string2key(self, password, salt, iterations=None):
        """RFC 3962 string-to-key: DK(PBKDF2-HMAC-SHA1(password, salt), "kerberos")."""

        iterations = iterations or DEFAULT_PBKDF2_ITERATIONS
        tkey = _pbkdf2(_to_bytes(password), _to_bytes(salt), iterations, self.keysize)
        return self.dk(tkey, b"kerberos")

    # --- CBC ciphertext stealing (RFC 3962, CS3: always swap the final two blocks) ------------------
    def _basicEncrypt(self, key, data):
        aes = AES(key)
        padded = data + b"\x00" * ((-len(data)) % self.blocksize)
        ct = aes.cbcEncrypt(b"\x00" * self.blocksize, padded)
        if len(data) > self.blocksize:
            lastlen = len(data) % self.blocksize or self.blocksize
            ct = ct[:-2 * self.blocksize] + ct[-self.blocksize:] + ct[-2 * self.blocksize:-self.blocksize][:lastlen]
        return ct

    def _basicDecrypt(self, key, data):
        aes = AES(key)
        if len(data) == self.blocksize:
            return aes.decryptBlock(data)

        blocks = [bytearray(data[p:p + self.blocksize]) for p in range(0, len(data), self.blocksize)]
        lastlen = len(blocks[-1])
        prev = bytearray(self.blocksize)
        out = bytearray()
        for block in blocks[:-2]:
            out += bytearray(_xor(aes.decryptBlock(bytes(block)), prev))
            prev = block

        decrypted = bytearray(aes.decryptBlock(bytes(blocks[-2])))
        lastPlain = _xor(decrypted[:lastlen], blocks[-1])
        omitted = decrypted[lastlen:]
        secondLast = _xor(aes.decryptBlock(bytes(blocks[-1] + omitted)), prev)
        return bytes(out) + secondLast + lastPlain

    # --- authenticated encryption (RFC 3961 section 5.3) --------------------------------------------
    def _keys(self, key, usage):
        ke = self.dk(key, struct.pack(">IB", usage, 0xAA))
        ki = self.dk(key, struct.pack(">IB", usage, 0x55))
        return ke, ki

    def encrypt(self, key, usage, plaintext, confounder=None):
        ke, ki = self._keys(key, usage)
        if confounder is None:
            confounder = os.urandom(self.blocksize)
        basic = confounder + plaintext
        return self._basicEncrypt(ke, basic) + hmac.new(ki, basic, hashlib.sha1).digest()[:self.macsize]

    def decrypt(self, key, usage, ciphertext):
        if len(ciphertext) < self.blocksize + self.macsize:   # confounder block + HMAC; guards a hostile short reply
            raise ValueError("Kerberos ciphertext too short")
        ke, ki = self._keys(key, usage)
        ct, mac = ciphertext[:-self.macsize], ciphertext[-self.macsize:]
        basic = self._basicDecrypt(ke, ct)
        if not _eq(mac, hmac.new(ki, basic, hashlib.sha1).digest()[:self.macsize]):
            raise ValueError("Kerberos integrity check failed (wrong key or corrupted ciphertext)")
        return basic[self.blocksize:]

def _rc4(key, data):
    """RC4 (ARCFOUR) stream cipher."""

    key, data = bytearray(key), bytearray(data)
    if not key:
        raise ValueError("RC4 requires a non-empty key")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]

    out = bytearray(len(data))
    i = j = 0
    for n in range(len(data)):
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out[n] = data[n] ^ s[(s[i] + s[j]) & 0xff]
    return bytes(out)

class RC4Enctype(object):
    """rc4-hmac (etype 23, RFC 4757). The long-term key is the NT hash MD4(UTF-16LE(password)); the
    salt and iteration count are unused. Legacy, but still enabled in many AD environments."""

    keysize = 16
    cksumtype = -138                                       # hmac-md5

    def string2key(self, password, salt=None, iterations=None):
        # the password is text; encode it UTF-16LE (in py2 a str is bytes, so decode to text first)
        if isinstance(password, bytes):
            password = password.decode("utf-8")
        return _md4(password.encode("utf-16-le"))

    @staticmethod
    def _usage(usage):
        # RFC 4757 section 3: a couple of Kerberos usages map to Microsoft-specific values (per the
        # published errata, usage 9 is NOT folded into 8 - only 3->8 and 23->13 apply)
        return struct.pack("<I", {3: 8, 23: 13}.get(usage, usage))

    def encrypt(self, key, usage, plaintext, confounder=None):
        if confounder is None:
            confounder = os.urandom(8)
        ki = hmac.new(key, self._usage(usage), hashlib.md5).digest()
        cksum = hmac.new(ki, confounder + plaintext, hashlib.md5).digest()
        ke = hmac.new(ki, cksum, hashlib.md5).digest()
        return cksum + _rc4(ke, confounder + plaintext)

    def decrypt(self, key, usage, ciphertext):
        if len(ciphertext) < 24:
            raise ValueError("rc4-hmac ciphertext too short")
        cksum, data = ciphertext[:16], ciphertext[16:]
        ki = hmac.new(key, self._usage(usage), hashlib.md5).digest()
        ke = hmac.new(ki, cksum, hashlib.md5).digest()
        plaintext = _rc4(ke, data)
        if not _eq(cksum, hmac.new(ki, plaintext, hashlib.md5).digest()):
            raise ValueError("Kerberos integrity check failed (wrong key or corrupted ciphertext)")
        return plaintext[8:]                               # strip the 8-byte confounder

    def checksum(self, key, usage, data):
        ksign = hmac.new(key, b"signaturekey\x00", hashlib.md5).digest()
        return hmac.new(ksign, hashlib.md5(self._usage(usage) + bytes(data)).digest(), hashlib.md5).digest()

# etype number -> enctype implementation
ENCTYPES = {
    17: AESEnctype(16),
    18: AESEnctype(32),
    23: RC4Enctype(),
}
