#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# Minimal, dependency-free ASN.1 DER codec covering exactly the constructs Kerberos (RFC 4120) uses:
# INTEGER, OCTET STRING, GeneralString, GeneralizedTime, BIT STRING, SEQUENCE / SEQUENCE OF, EXPLICIT
# context tags [n] and [APPLICATION n]. All Kerberos tag numbers are <= 30, so only the low-tag-number
# form is needed. Encoders return bytes; decoders accept bytes/bytearray. Python 2.7 / 3.x.

# universal tag bytes
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
GENERAL_STRING = 0x1b
GENERALIZED_TIME = 0x18
SEQUENCE = 0x30                                             # 0x10 | constructed(0x20)

def _encodeLength(length):
    if length < 0x80:
        return bytearray([length])
    out = bytearray()
    while length:
        out.insert(0, length & 0xff)
        length >>= 8
    return bytearray([0x80 | len(out)]) + out

def _tlv(tag, value):
    value = bytearray(value)
    return bytes(bytearray([tag]) + _encodeLength(len(value)) + value)

# ---- context / application tags (EXPLICIT) --------------------------------------------------------
def contextTag(number):
    return 0x80 | 0x20 | number                            # context-specific, constructed

def applicationTag(number):
    return 0x40 | 0x20 | number                            # application, constructed

def tagged(number, innerTLV):
    """EXPLICIT [n] wrapper around an already-encoded inner TLV."""

    return _tlv(contextTag(number), innerTLV)

def application(number, innerTLV):
    """[APPLICATION n] wrapper around an already-encoded inner TLV."""

    return _tlv(applicationTag(number), innerTLV)

# ---- primitive encoders ---------------------------------------------------------------------------
def integer(value):
    content = bytearray()
    if value == 0:
        content = bytearray([0])
    elif value > 0:
        n = value
        while n:
            content.insert(0, n & 0xff)
            n >>= 8
        if content[0] & 0x80:                              # keep the sign bit clear for a positive value
            content.insert(0, 0x00)
    else:
        n = value
        while True:
            content.insert(0, n & 0xff)
            n >>= 8
            if n == -1 and (content[0] & 0x80):
                break
    return _tlv(INTEGER, content)

def octetString(value):
    return _tlv(OCTET_STRING, value)

def generalString(value):
    return _tlv(GENERAL_STRING, value if isinstance(value, bytes) else value.encode("utf-8"))

def generalizedTime(value):
    """'value' is a 'YYYYMMDDHHMMSSZ' UTC string."""

    return _tlv(GENERALIZED_TIME, value if isinstance(value, bytes) else value.encode("ascii"))

def bitString(value, unusedBits=0):
    return _tlv(BIT_STRING, bytearray([unusedBits]) + bytearray(value))

def sequence(*elements):
    return _tlv(SEQUENCE, b"".join(bytes(_) for _ in elements))

def sequenceOf(elements):
    return _tlv(SEQUENCE, b"".join(bytes(_) for _ in elements))

# ---- decoding -------------------------------------------------------------------------------------
def peel(data, offset=0):
    """Parse one TLV at 'offset'; return (tag, content_bytearray, next_offset). Raises ValueError on
    truncated or indefinite-length input (the data may come from the network, so fail predictably)."""

    data = bytearray(data)
    if offset + 2 > len(data):
        raise ValueError("truncated DER header")
    tag = data[offset]
    first = data[offset + 1]
    offset += 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise ValueError("indefinite-length DER is not permitted")
    else:
        count = first & 0x7f
        if offset + count > len(data):
            raise ValueError("truncated DER length")
        length = 0
        for _ in range(count):
            length = (length << 8) | data[offset]
            offset += 1
    if offset + length > len(data):
        raise ValueError("truncated DER content")
    return tag, data[offset:offset + length], offset + length

def children(content):
    """Iterate the TLVs contained in a constructed value; yields (tag, content_bytearray)."""

    content = bytearray(content)
    offset = 0
    out = []
    while offset < len(content):
        tag, inner, offset = peel(content, offset)
        out.append((tag, inner))
    return out

def decodeInteger(content):
    content = bytearray(content)
    if not content:
        return 0
    value = 0
    for b in content:
        value = (value << 8) | b
    if content[0] & 0x80:                                  # negative (two's complement)
        value -= 1 << (8 * len(content))
    return value

def decodeGeneralString(content):
    return bytes(bytearray(content)).decode("utf-8", "replace")
