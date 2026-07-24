#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# Dependency-free AES (FIPS-197) block cipher with CBC mode, supporting 128- and 256-bit keys. It is
# the primitive underneath Kerberos' AES-CTS-HMAC-SHA1-96 (RFC 3962) etypes, kept pure-Python so
# '--auth-type=Negotiate' needs no third-party crypto library. Validated against the FIPS-197
# known-answer vectors. Python 2.7 / 3.x.
#
# The state is a flat list of 16 ints in AES column-major order: byte i holds row (i % 4), column
# (i // 4), i.e. column c occupies positions [4*c : 4*c + 4].

def _gmul(a, b):
    """Multiplication in GF(2**8) with the AES reduction polynomial 0x11b."""

    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        high = a & 0x80
        a = (a << 1) & 0xff
        if high:
            a ^= 0x1b
        b >>= 1
    return p

# GF(2**8) log/exp tables (generator 0x03) -> multiplicative inverse -> S-box (affine transform),
# computed rather than transcribed so there is no 256-entry table to get wrong
_EXP = [0] * 256
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x = _gmul(_x, 0x03)

def _inv(b):
    return 0 if b == 0 else _EXP[(255 - _LOG[b]) % 255]

def _rotl8(b, n):
    return ((b << n) | (b >> (8 - n))) & 0xff

SBOX = []
for _b in range(256):
    _v = _inv(_b)
    SBOX.append(_v ^ _rotl8(_v, 1) ^ _rotl8(_v, 2) ^ _rotl8(_v, 3) ^ _rotl8(_v, 4) ^ 0x63)

INV_SBOX = [0] * 256
for _b in range(256):
    INV_SBOX[SBOX[_b]] = _b

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d]

def _xor(a, b):
    if len(a) != len(b):                                   # equal-length by construction; fail loud (not via assert, which -O strips)
        raise ValueError("XOR operands differ in length")
    return bytes(bytearray(x ^ y for x, y in zip(bytearray(a), bytearray(b))))

class AES(object):
    """AES-128/256 block cipher (16-byte block) with a minimal CBC mode."""

    def __init__(self, key):
        key = bytearray(key)
        if len(key) not in (16, 32):
            raise ValueError("AES key must be 16 or 32 bytes")
        self.rounds = 10 if len(key) == 16 else 14
        self._roundKeys = self._expand(key)

    def _expand(self, key):
        nk = len(key) // 4
        words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (self.rounds + 1)):
            temp = list(words[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]                          # RotWord
                temp = [SBOX[b] for b in temp]                      # SubWord
                temp[0] ^= RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                temp = [SBOX[b] for b in temp]
            words.append([words[i - nk][j] ^ temp[j] for j in range(4)])

        roundKeys = []
        for r in range(self.rounds + 1):
            rk = []
            for c in range(4):
                rk.extend(words[4 * r + c])
            roundKeys.append(rk)
        return roundKeys

    @staticmethod
    def _addRoundKey(state, rk):
        for i in range(16):
            state[i] ^= rk[i]

    @staticmethod
    def _shiftRows(s):
        out = [0] * 16
        for r in range(4):
            for c in range(4):
                out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
        return out

    @staticmethod
    def _invShiftRows(s):
        out = [0] * 16
        for r in range(4):
            for c in range(4):
                out[r + 4 * c] = s[r + 4 * ((c - r) % 4)]
        return out

    @staticmethod
    def _mixColumns(s):
        out = [0] * 16
        for c in range(4):
            col = s[4 * c:4 * c + 4]
            out[4 * c + 0] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
            out[4 * c + 1] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
            out[4 * c + 2] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
            out[4 * c + 3] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)
        return out

    @staticmethod
    def _invMixColumns(s):
        out = [0] * 16
        for c in range(4):
            col = s[4 * c:4 * c + 4]
            out[4 * c + 0] = _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9)
            out[4 * c + 1] = _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13)
            out[4 * c + 2] = _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11)
            out[4 * c + 3] = _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14)
        return out

    def encryptBlock(self, block):
        state = list(bytearray(block))
        self._addRoundKey(state, self._roundKeys[0])
        for r in range(1, self.rounds):
            state = self._mixColumns(self._shiftRows([SBOX[b] for b in state]))
            self._addRoundKey(state, self._roundKeys[r])
        state = self._shiftRows([SBOX[b] for b in state])
        self._addRoundKey(state, self._roundKeys[self.rounds])
        return bytes(bytearray(state))

    def decryptBlock(self, block):
        state = list(bytearray(block))
        self._addRoundKey(state, self._roundKeys[self.rounds])
        for r in range(self.rounds - 1, 0, -1):
            state = [INV_SBOX[b] for b in self._invShiftRows(state)]
            self._addRoundKey(state, self._roundKeys[r])
            state = self._invMixColumns(state)
        state = [INV_SBOX[b] for b in self._invShiftRows(state)]
        self._addRoundKey(state, self._roundKeys[0])
        return bytes(bytearray(state))

    def cbcEncrypt(self, iv, data):
        if len(data) % 16 != 0:
            raise ValueError("CBC input is not block-aligned")
        prev, out = iv, []
        for i in range(0, len(data), 16):
            prev = self.encryptBlock(_xor(data[i:i + 16], prev))
            out.append(prev)
        return b"".join(out)

    def cbcDecrypt(self, iv, data):
        if len(data) % 16 != 0:
            raise ValueError("CBC input is not block-aligned")
        prev, out = iv, []
        for i in range(0, len(data), 16):
            block = data[i:i + 16]
            out.append(_xor(self.decryptBlock(block), prev))
            prev = block
        return b"".join(out)
