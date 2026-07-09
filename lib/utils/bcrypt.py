#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import struct

from lib.core.compat import xrange
from lib.core.convert import getBytes

# bcrypt (Provos-Mazieres EksBlowfish); the Blowfish P/S init constants are the fractional hex digits of pi
BCRYPT_ITOA64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

_bcryptState = None

def _bcryptInitState():
    global _bcryptState

    if _bcryptState is None:
        count = 18 + 4 * 256
        ndigits = count * 8
        prec = ndigits + 16
        one = 1 << (4 * prec)

        def _arctan(inv):
            total = term = one // inv
            square = inv * inv
            i = 1
            while term:
                term //= square
                total += (term // (2 * i + 1)) * (-1 if i % 2 else 1)
                i += 1
            return total

        frac = (16 * _arctan(5) - 4 * _arctan(239) - 3 * one) >> (4 * (prec - ndigits))
        hexstr = "%0*x" % (ndigits, frac)
        words = [int(hexstr[i * 8:(i + 1) * 8], 16) for i in xrange(count)]
        _bcryptState = (words[:18], [words[18 + i * 256:18 + (i + 1) * 256] for i in xrange(4)])

    return _bcryptState

def _bcryptEncipher(P, S, L, R):
    for i in xrange(16):
        L ^= P[i]
        R ^= (((S[0][(L >> 24) & 0xff] + S[1][(L >> 16) & 0xff]) & 0xffffffff) ^ S[2][(L >> 8) & 0xff]) + S[3][L & 0xff] & 0xffffffff
        L, R = R, L
    L, R = R, L
    return (L ^ P[17]) & 0xffffffff, (R ^ P[16]) & 0xffffffff

def _bcryptStream(data, offset):
    word = 0
    for _ in xrange(4):
        word = ((word << 8) | data[offset[0]]) & 0xffffffff
        offset[0] = (offset[0] + 1) % len(data)
    return word

def _bcryptExpand(P, S, data, key):
    koffset = [0]
    for i in xrange(18):
        P[i] ^= _bcryptStream(key, koffset)

    doffset = [0]
    L = R = 0
    for i in xrange(0, 18, 2):
        if data:
            L ^= _bcryptStream(data, doffset)
            R ^= _bcryptStream(data, doffset)
        L, R = _bcryptEncipher(P, S, L, R)
        P[i], P[i + 1] = L, R

    for b in xrange(4):
        for k in xrange(0, 256, 2):
            if data:
                L ^= _bcryptStream(data, doffset)
                R ^= _bcryptStream(data, doffset)
            L, R = _bcryptEncipher(P, S, L, R)
            S[b][k], S[b][k + 1] = L, R

def _bcryptBase64(data):
    retVal = ""
    i = 0
    while i < len(data):
        c = data[i]; i += 1
        retVal += BCRYPT_ITOA64[(c >> 2) & 0x3f]
        c = (c & 3) << 4
        if i >= len(data):
            retVal += BCRYPT_ITOA64[c & 0x3f]; break
        d = data[i]; i += 1
        retVal += BCRYPT_ITOA64[(c | (d >> 4) & 0x0f) & 0x3f]
        c = (d & 0x0f) << 2
        if i >= len(data):
            retVal += BCRYPT_ITOA64[c & 0x3f]; break
        e = data[i]; i += 1
        retVal += BCRYPT_ITOA64[(c | (e >> 6) & 3) & 0x3f]
        retVal += BCRYPT_ITOA64[e & 0x3f]
    return retVal

def _bcryptUnbase64(value, length):
    retVal = bytearray()
    positions = [BCRYPT_ITOA64.index(_) for _ in value]
    i = 0
    while i < len(positions) and len(retVal) < length:
        c1 = positions[i]
        c2 = positions[i + 1] if i + 1 < len(positions) else 0
        retVal.append(((c1 << 2) | (c2 >> 4)) & 0xff)
        if len(retVal) >= length:
            break
        c3 = positions[i + 2] if i + 2 < len(positions) else 0
        retVal.append((((c2 & 0x0f) << 4) | (c3 >> 2)) & 0xff)
        if len(retVal) >= length:
            break
        c4 = positions[i + 3] if i + 3 < len(positions) else 0
        retVal.append((((c3 & 3) << 6) | c4) & 0xff)
        i += 4
    return retVal[:length]

def bcryptHash(password, salt, cost):
    """
    Provos-Mazieres EksBlowfish digest, base64-encoded (the openwall bcrypt hash tail)

    >>> bcryptHash("U*U", "CCCCCCCCCCCCCCCCCCCCC.", 5)
    'E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW'
    """

    P0, S0 = _bcryptInitState()
    P, S = list(P0), [list(_) for _ in S0]

    key = bytearray(getBytes(password) + b"\0")
    saltbytes = _bcryptUnbase64(salt, 16)

    _bcryptExpand(P, S, saltbytes, key)
    for _ in xrange(1 << cost):
        _bcryptExpand(P, S, b"", key)
        _bcryptExpand(P, S, b"", saltbytes)

    ctext = list(struct.unpack(">6I", b"OrpheanBeholderScryDoubt"))
    for _ in xrange(64):
        for j in xrange(0, 6, 2):
            ctext[j], ctext[j + 1] = _bcryptEncipher(P, S, ctext[j], ctext[j + 1])

    digest = bytearray(struct.pack(">6I", *ctext))[:23]

    return _bcryptBase64(digest)

