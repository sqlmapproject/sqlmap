#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# Native, dependency-free HTTP/2 client (RFC 9113) with HPACK (RFC 7541). Runtime code uses only
# the standard library. The accompanying tests optionally use python-hyper/hpack and hyper-h2 for
# differential and local peer validation. The implementation keeps Python 2.7-compatible syntax,
# but this rewrite was executed and tested on Python 3.13 only.

import base64
import socket
import ssl
import struct
import threading
from collections import OrderedDict

try:
    from http.client import responses as _HTTP_RESPONSES
except ImportError:
    from httplib import responses as _HTTP_RESPONSES

try:
    from urllib.parse import quote, urljoin, urlsplit
except ImportError:
    from urllib import quote
    from urlparse import urljoin, urlsplit

from email.message import Message as _Message

REDIRECT_CODES = (301, 302, 303, 307, 308)


HUFFMAN_CODES = [
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7, 0xfffffe8, 0xffffea,
    0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec, 0xfffffed, 0xfffffee, 0xfffffef,
    0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8,
    0xffffff9, 0xffffffa, 0xffffffb, 0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9,
    0x7fb, 0xfa, 0x16, 0x17, 0x18, 0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc,
    0x20, 0xffb, 0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc,
    0x22, 0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7, 0x2b, 0x76,
    0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc, 0xfffe6,
    0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc,
    0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf, 0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2,
    0x7fffe3, 0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, 0x3fffda, 0x1fffdd,
    0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf,
    0x3fffdf, 0x7fffeb, 0x7fffec, 0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
    0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, 0x3ffffe0, 0x3ffffe1, 0xfffeb,
    0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf,
    0x3ffffe5, 0xfffff1, 0x1ffffed, 0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2,
    0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5, 0xfffec,
    0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3, 0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef,
    0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4, 0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8,
    0x7ffffe9, 0x7ffffea, 0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
    0x3fffffff
]


HUFFMAN_LENGTHS = [
    0xd, 0x17, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x18, 0x1e, 0x1c, 0x1c, 0x1e, 0x1c, 0x1c, 0x1c, 0x1c,
    0x1c, 0x1c, 0x1c, 0x1c, 0x1e, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x6, 0xa, 0xa, 0xc, 0xd,
    0x6, 0x8, 0xb, 0xa, 0xa, 0x8, 0xb, 0x8, 0x6, 0x6, 0x6, 0x5, 0x5, 0x5, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x7,
    0x8, 0xf, 0x6, 0xc, 0xa, 0xd, 0x6, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7,
    0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x8, 0x7, 0x8, 0xd, 0x13, 0xd, 0xe, 0x6, 0xf, 0x5, 0x6, 0x5, 0x6, 0x5, 0x6,
    0x6, 0x6, 0x5, 0x7, 0x7, 0x6, 0x6, 0x6, 0x5, 0x6, 0x7, 0x6, 0x5, 0x5, 0x6, 0x7, 0x7, 0x7, 0x7, 0x7, 0xf, 0xb,
    0xe, 0xd, 0x1c, 0x14, 0x16, 0x14, 0x14, 0x16, 0x16, 0x16, 0x17, 0x16, 0x17, 0x17, 0x17, 0x17, 0x17, 0x18,
    0x17, 0x18, 0x18, 0x16, 0x17, 0x18, 0x17, 0x17, 0x17, 0x17, 0x15, 0x16, 0x17, 0x16, 0x17, 0x17, 0x18, 0x16,
    0x15, 0x14, 0x16, 0x16, 0x17, 0x17, 0x15, 0x17, 0x16, 0x16, 0x18, 0x15, 0x16, 0x17, 0x17, 0x15, 0x15, 0x16,
    0x15, 0x17, 0x16, 0x17, 0x17, 0x14, 0x16, 0x16, 0x16, 0x17, 0x16, 0x16, 0x17, 0x1a, 0x1a, 0x14, 0x13, 0x16,
    0x17, 0x16, 0x19, 0x1a, 0x1a, 0x1a, 0x1b, 0x1b, 0x1a, 0x18, 0x19, 0x13, 0x15, 0x1a, 0x1b, 0x1b, 0x1a, 0x1b,
    0x18, 0x15, 0x15, 0x1a, 0x1a, 0x1c, 0x1b, 0x1b, 0x1b, 0x14, 0x18, 0x14, 0x15, 0x16, 0x15, 0x15, 0x17, 0x16,
    0x16, 0x19, 0x19, 0x18, 0x18, 0x1a, 0x17, 0x1a, 0x1b, 0x1a, 0x1a, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1c, 0x1b,
    0x1b, 0x1b, 0x1b, 0x1b, 0x1a, 0x1e
]


STATIC_TABLE = (
    (b':authority', b''),
    (b':method', b'GET'),
    (b':method', b'POST'),
    (b':path', b'/'),
    (b':path', b'/index.html'),
    (b':scheme', b'http'),
    (b':scheme', b'https'),
    (b':status', b'200'),
    (b':status', b'204'),
    (b':status', b'206'),
    (b':status', b'304'),
    (b':status', b'400'),
    (b':status', b'404'),
    (b':status', b'500'),
    (b'accept-charset', b''),
    (b'accept-encoding', b'gzip, deflate'),
    (b'accept-language', b''),
    (b'accept-ranges', b''),
    (b'accept', b''),
    (b'access-control-allow-origin', b''),
    (b'age', b''),
    (b'allow', b''),
    (b'authorization', b''),
    (b'cache-control', b''),
    (b'content-disposition', b''),
    (b'content-encoding', b''),
    (b'content-language', b''),
    (b'content-length', b''),
    (b'content-location', b''),
    (b'content-range', b''),
    (b'content-type', b''),
    (b'cookie', b''),
    (b'date', b''),
    (b'etag', b''),
    (b'expect', b''),
    (b'expires', b''),
    (b'from', b''),
    (b'host', b''),
    (b'if-match', b''),
    (b'if-modified-since', b''),
    (b'if-none-match', b''),
    (b'if-range', b''),
    (b'if-unmodified-since', b''),
    (b'last-modified', b''),
    (b'link', b''),
    (b'location', b''),
    (b'max-forwards', b''),
    (b'proxy-authenticate', b''),
    (b'proxy-authorization', b''),
    (b'range', b''),
    (b'referer', b''),
    (b'refresh', b''),
    (b'retry-after', b''),
    (b'server', b''),
    (b'set-cookie', b''),
    (b'strict-transport-security', b''),
    (b'transfer-encoding', b''),
    (b'user-agent', b''),
    (b'vary', b''),
    (b'via', b''),
    (b'www-authenticate', b''),
)
STATIC_LEN = len(STATIC_TABLE)

# HTTP/2 frame codec and client implementation (RFC 9113; HPACK remains RFC 7541).
# The public API is compatible with the original module. Optional `verify` and
# `ssl_context` arguments were added so TLS verification is opt-in. By default
# verification is disabled (the tool is used against test/self-signed targets).

try:
    text_type = unicode
except NameError:
    text_type = str

try:
    integer_types = (int, long)
except NameError:
    integer_types = (int,)

# Frame types
DATA = 0x0
HEADERS = 0x1
PRIORITY = 0x2
RST_STREAM = 0x3
SETTINGS = 0x4
PUSH_PROMISE = 0x5
PING = 0x6
GOAWAY = 0x7
WINDOW_UPDATE = 0x8
CONTINUATION = 0x9

# Flags
FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

# Settings
SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_ENABLE_PUSH = 0x2
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5
SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

# Error codes
NO_ERROR = 0x0
PROTOCOL_ERROR = 0x1
INTERNAL_ERROR = 0x2
FLOW_CONTROL_ERROR = 0x3
SETTINGS_TIMEOUT = 0x4
STREAM_CLOSED = 0x5
FRAME_SIZE_ERROR = 0x6
REFUSED_STREAM = 0x7
CANCEL = 0x8
COMPRESSION_ERROR = 0x9
CONNECT_ERROR = 0xa
ENHANCE_YOUR_CALM = 0xb
INADEQUATE_SECURITY = 0xc
HTTP_1_1_REQUIRED = 0xd

CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DEFAULT_MAX_FRAME_SIZE = 16384
MAX_FRAME_SIZE = 0xffffff
MAX_WINDOW = (1 << 31) - 1
DEFAULT_WINDOW = 65535
LOCAL_INITIAL_WINDOW = 16 * 1024 * 1024
MAX_RESPONSE_SIZE = 100 * 1024 * 1024
MAX_HEADER_BLOCK_SIZE = 1024 * 1024
MAX_HEADER_LIST_SIZE = 1024 * 1024
MAX_HPACK_INTEGER = MAX_WINDOW
MAX_STREAM_ID = (1 << 31) - 1
H2_POOL_LIMIT = 32
MAX_INFORMATIONAL_RESPONSES = 32
MAX_INFORMATIONAL_HEADER_BYTES = 1024 * 1024
MAX_RESPONSE_FRAMES = 100000

_TOKEN_BYTES = frozenset(bytearray(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz"))
_METHOD_TOKEN_BYTES = frozenset(bytearray(
    b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
))
_CONNECTION_FIELDS = frozenset((
    b"connection", b"proxy-connection", b"keep-alive", b"transfer-encoding", b"upgrade"
))
_SENSITIVE_REDIRECT_FIELDS = frozenset((b"authorization", b"cookie", b"proxy-authorization"))
_CONTENT_REDIRECT_FIELDS = frozenset((b"content-length", b"content-type", b"content-encoding"))


class H2Error(IOError):
    pass


class H2ProtocolError(H2Error):
    pass


class H2CompressionError(H2ProtocolError):
    pass


class H2TransportError(H2Error):
    pass


class _UnprocessedStream(H2Error):
    """The peer explicitly guaranteed that the request stream was not processed."""


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, text_type):
        return value.encode("latin-1")
    raise TypeError("expected bytes/text value, got %s" % type(value).__name__)


def encode_frame(ftype, flags, stream_id, payload=b""):
    """Serialize an HTTP/2 frame.

    >>> decode_frame_header(encode_frame(HEADERS, FLAG_END_HEADERS, 1, b'abc')[:9])
    (3, 1, 4, 1)
    """
    payload = _as_bytes(payload)
    if not (0 <= ftype <= 0xff and 0 <= flags <= 0xff):
        raise ValueError("frame type and flags must fit in one octet")
    if not (0 <= stream_id <= MAX_STREAM_ID):
        raise ValueError("stream id must be between 0 and 2^31-1")
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError("frame payload exceeds 24-bit length")
    header = struct.pack("!I", len(payload))[1:]
    header += struct.pack("!BBI", ftype, flags, stream_id)
    return header + payload


def decode_frame_header(nine):
    """Parse a 9-byte frame header into (length, type, flags, stream_id).

    >>> decode_frame_header(encode_frame(DATA, 0, 1, b'')[:9])
    (0, 0, 0, 1)
    """
    if len(nine) != 9:
        raise ValueError("frame header must be exactly 9 bytes")
    length = struct.unpack("!I", b"\x00" + nine[:3])[0]
    ftype, flags, stream_id = struct.unpack("!BBI", nine[3:9])
    return length, ftype, flags, stream_id & MAX_STREAM_ID


# ---------- Huffman ----------
def huffman_encode(data):
    """Huffman-encode a byte string using the RFC 7541 static code.

    >>> huffman_decode(huffman_encode(b'www.example.com')) == b'www.example.com'
    True
    """
    data = _as_bytes(data)
    if not data:
        return b""
    acc = 0
    nbits = 0
    for item in bytearray(data):
        acc = (acc << HUFFMAN_LENGTHS[item]) | HUFFMAN_CODES[item]
        nbits += HUFFMAN_LENGTHS[item]
    pad = (8 - nbits % 8) % 8
    acc = (acc << pad) | ((1 << pad) - 1)
    total = (nbits + pad) // 8
    out = bytearray()
    for index in range(total - 1, -1, -1):
        out.append((acc >> (8 * index)) & 0xff)
    return bytes(out)


_HUFF_ROOT = {}


def _build_huffman_trie():
    for sym in range(256):
        code = HUFFMAN_CODES[sym]
        length = HUFFMAN_LENGTHS[sym]
        node = _HUFF_ROOT
        for index in range(length - 1, -1, -1):
            bit = (code >> index) & 1
            if index == 0:
                node[bit] = sym
            else:
                child = node.get(bit)
                if child is None:
                    child = {}
                    node[bit] = child
                elif not isinstance(child, dict):
                    raise AssertionError("invalid prefix Huffman table")
                node = child


_build_huffman_trie()


def huffman_decode(data):
    data = _as_bytes(data)
    out = bytearray()
    node = _HUFF_ROOT
    consumed = 0
    tail = 0
    for item in bytearray(data):
        for index in range(7, -1, -1):
            bit = (item >> index) & 1
            nxt = node.get(bit)
            if nxt is None:
                raise H2CompressionError("invalid Huffman sequence")
            consumed += 1
            tail = (tail << 1) | bit
            if isinstance(nxt, dict):
                node = nxt
            else:
                out.append(nxt)
                node = _HUFF_ROOT
                consumed = 0
                tail = 0
    if node is not _HUFF_ROOT:
        if consumed > 7 or tail != (1 << consumed) - 1:
            raise H2CompressionError("invalid Huffman EOS padding")
    return bytes(out)


# ---------- HPACK integer/string ----------
def encode_integer(value, prefix_bits, first_byte=0):
    if not isinstance(value, integer_types) or value < 0:
        raise ValueError("HPACK integer must be non-negative")
    if not 1 <= prefix_bits <= 8:
        raise ValueError("invalid HPACK prefix width")
    mask = (1 << prefix_bits) - 1
    if value < mask:
        return bytearray([first_byte | value])
    out = bytearray([first_byte | mask])
    value -= mask
    while value >= 0x80:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return out


def decode_integer(data, pos, prefix_bits, max_value=MAX_HPACK_INTEGER):
    if not 1 <= prefix_bits <= 8:
        raise H2CompressionError("invalid HPACK prefix width")
    if pos < 0 or pos >= len(data):
        raise H2CompressionError("truncated HPACK integer")
    mask = (1 << prefix_bits) - 1
    value = data[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    shift = 0
    while True:
        if pos >= len(data):
            raise H2CompressionError("truncated HPACK integer")
        item = data[pos]
        pos += 1
        addend = (item & 0x7f) << shift
        if addend > max_value - value:
            raise H2CompressionError("HPACK integer exceeds implementation limit")
        value += addend
        if not (item & 0x80):
            return value, pos
        shift += 7
        if shift > 28:
            raise H2CompressionError("HPACK integer encoding is too long")


def encode_string(value, huffman=True):
    value = _as_bytes(value)
    if huffman:
        encoded = huffman_encode(value)
        if len(encoded) < len(value):
            return encode_integer(len(encoded), 7, 0x80) + bytearray(encoded)
    return encode_integer(len(value), 7, 0x00) + bytearray(value)


def decode_string(data, pos):
    if pos < 0 or pos >= len(data):
        raise H2CompressionError("truncated HPACK string")
    use_huffman = bool(data[pos] & 0x80)
    length, pos = decode_integer(data, pos, 7, max_value=MAX_HEADER_BLOCK_SIZE)
    end = pos + length
    if end > len(data):
        raise H2CompressionError("truncated HPACK string payload")
    raw = bytes(data[pos:end])
    return (huffman_decode(raw) if use_huffman else raw), end


class Decoder(object):
    def __init__(self, max_size=4096, max_header_list_size=MAX_HEADER_LIST_SIZE):
        self.max_allowed_size = max_size
        self.max_size = max_size
        self.max_header_list_size = max_header_list_size
        self.dynamic = []
        self._size = 0

    @staticmethod
    def _entry_size(name, value):
        return 32 + len(name) + len(value)

    def _add(self, name, value):
        entry_size = self._entry_size(name, value)
        if entry_size > self.max_size:
            self.dynamic = []
            self._size = 0
            return
        self.dynamic.insert(0, (name, value))
        self._size += entry_size
        self._evict()

    def _evict(self):
        while self._size > self.max_size and self.dynamic:
            name, value = self.dynamic.pop()
            self._size -= self._entry_size(name, value)

    def _get(self, index):
        if index <= 0:
            raise H2CompressionError("invalid HPACK header index 0")
        if index <= STATIC_LEN:
            return STATIC_TABLE[index - 1]
        dynamic_index = index - STATIC_LEN - 1
        if dynamic_index < 0 or dynamic_index >= len(self.dynamic):
            raise H2CompressionError("HPACK dynamic index out of range")
        return self.dynamic[dynamic_index]

    def decode(self, data):
        data = bytearray(_as_bytes(data))
        pos = 0
        headers = []
        list_size = 0
        saw_header = False
        while pos < len(data):
            first = data[pos]
            if first & 0x80:
                saw_header = True
                index, pos = decode_integer(data, pos, 7)
                name, value = self._get(index)
                headers.append((name, value))
            elif first & 0x40:
                saw_header = True
                index, pos = decode_integer(data, pos, 6)
                if index:
                    name = self._get(index)[0]
                else:
                    name, pos = decode_string(data, pos)
                value, pos = decode_string(data, pos)
                self._add(name, value)
                headers.append((name, value))
            elif first & 0x20:
                if saw_header:
                    raise H2CompressionError("dynamic table size update is not at block start")
                new_size, pos = decode_integer(data, pos, 5)
                if new_size > self.max_allowed_size:
                    raise H2CompressionError("dynamic table size exceeds advertised maximum")
                self.max_size = new_size
                self._evict()
                continue
            else:
                saw_header = True
                index, pos = decode_integer(data, pos, 4)
                if index:
                    name = self._get(index)[0]
                else:
                    name, pos = decode_string(data, pos)
                value, pos = decode_string(data, pos)
                headers.append((name, value))

            name, value = headers[-1]
            list_size += self._entry_size(name, value)
            if list_size > self.max_header_list_size:
                raise H2CompressionError("decoded header list exceeds configured limit")
        return headers


class Encoder(object):
    """A stateless, literal-without-indexing HPACK encoder."""

    def encode(self, headers):
        out = bytearray()
        for name, value in headers:
            name = _as_bytes(name)
            value = _as_bytes(value)
            out += encode_integer(0, 4, 0x00)
            out += encode_string(name)
            out += encode_string(value)
        return bytes(out)


def _recv_exact(sock, count):
    if count < 0:
        raise ValueError("negative receive size")
    chunks = []
    received = 0
    while received < count:
        chunk = sock.recv(count - received)
        if not chunk:
            raise H2TransportError("connection closed by peer")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def _read_frame(sock, max_frame_size=DEFAULT_MAX_FRAME_SIZE):
    length, ftype, flags, sid = decode_frame_header(_recv_exact(sock, 9))
    if length > max_frame_size:
        raise H2ProtocolError("received frame exceeds local maximum frame size")
    payload = _recv_exact(sock, length) if length else b""
    return ftype, flags, sid, payload


def _idna_host(host):
    if isinstance(host, bytes):
        try:
            host = host.decode("ascii")
        except UnicodeDecodeError:
            try:
                host = host.decode("utf-8")
            except UnicodeDecodeError:
                raise H2Error("hostname bytes are neither ASCII nor UTF-8")
    if not isinstance(host, text_type):
        host = text_type(host)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise H2Error("hostname is required")
    if ":" in host:  # IPv6 literal, optionally with a zone identifier
        return host
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, AttributeError):
        raise H2Error("invalid internationalized hostname %r" % host)


def _format_authority_host(host):
    host = _idna_host(host)
    if ":" in host:
        return "[%s]" % host
    return host


def _authority_for_host(host, port):
    authority = _format_authority_host(host)
    if port != 443:
        authority += ":%d" % port
    return authority


def _connect_socket(host, port, proxy, timeout):
    if not proxy:
        return socket.create_connection((host, port), timeout=timeout)

    proxy_host, proxy_port, proxy_cred = proxy
    raw = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        tunnel_host = _format_authority_host(host)
        authority = "%s:%d" % (tunnel_host, port)
        request = "CONNECT %s HTTP/1.1\r\nHost: %s\r\n" % (authority, authority)
        if proxy_cred:
            token = base64.b64encode(_as_bytes(proxy_cred)).decode("ascii")
            request += "Proxy-Authorization: Basic %s\r\n" % token
        request += "\r\n"
        raw.sendall(request.encode("latin-1"))

        # Read only through the CONNECT header terminator. A large recv() can consume
        # bytes from the tunneled TLS handshake that immediately follows the proxy
        # response, and those bytes cannot be pushed back before wrap_socket().
        response = bytearray()
        while not bytes(response).endswith(b"\r\n\r\n"):
            chunk = raw.recv(1)
            if not chunk:
                raise H2Error("proxy closed connection during CONNECT")
            response.extend(chunk)
            if len(response) > 65536:
                raise H2Error("oversized proxy CONNECT response")
        status_line = bytes(response).split(b"\r\n", 1)[0].decode("latin-1", "replace")
        fields = status_line.split(None, 2)
        code = int(fields[1]) if len(fields) >= 2 and fields[1].isdigit() else 0
        if not 200 <= code < 300:
            raise H2Error("proxy CONNECT failed: %s" % status_line)
        return raw
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
        raise


def _make_ssl_context(verify, ssl_context):
    context = ssl_context
    if context is None:
        if verify:
            creator = getattr(ssl, "create_default_context", None)
            if creator is None:
                raise H2Error("certificate verification requires ssl.create_default_context")
            context = creator()
        else:
            creator = getattr(ssl, "_create_unverified_context", None)
            if creator is not None:
                context = creator()
            else:
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                context.verify_mode = ssl.CERT_NONE
    tls_version = getattr(ssl, "TLSVersion", None)
    if tls_version is not None and hasattr(context, "minimum_version"):
        if context.minimum_version < tls_version.TLSv1_2:
            context.minimum_version = tls_version.TLSv1_2
    else:
        for option_name in ("OP_NO_SSLv2", "OP_NO_SSLv3", "OP_NO_TLSv1", "OP_NO_TLSv1_1"):
            option = getattr(ssl, option_name, 0)
            if option:
                context.options |= option
    no_compression = getattr(ssl, "OP_NO_COMPRESSION", 0)
    if no_compression:
        context.options |= no_compression
    setter = getattr(context, "set_alpn_protocols", None)
    if setter is None:
        raise H2Error("this Python/OpenSSL build does not support ALPN")
    setter(["h2"])
    return context


def _iter_header_items(headers):
    if headers is None:
        return []
    if hasattr(headers, "items"):
        return list(headers.items())
    return list(headers)


def _validate_regular_name(name):
    if not name or name.startswith(b":"):
        raise H2ProtocolError("invalid regular field name")
    for item in bytearray(name):
        if item not in _TOKEN_BYTES:
            raise H2ProtocolError("invalid HTTP field name %r" % name)


def _validate_field_value(value):
    if b"\x00" in value or b"\r" in value or b"\n" in value:
        raise H2ProtocolError("invalid control character in HTTP field value")
    if value[:1] in (b" ", b"\t") or value[-1:] in (b" ", b"\t"):
        raise H2ProtocolError("HTTP/2 field values may not have leading/trailing whitespace")


def _validate_pseudo_value(name, value):
    _validate_field_value(value)
    for item in bytearray(value):
        if item < 0x21 or item > 0x7e:
            raise H2ProtocolError("invalid octet in %s pseudo-field" % name)


def _validate_method(method):
    if not method:
        raise H2ProtocolError("method is required")
    for item in bytearray(method):
        if item not in _METHOD_TOKEN_BYTES:
            raise H2ProtocolError("invalid HTTP method token")


def _normalize_request_headers(headers, body):
    raw_items = []
    connection_tokens = set()
    for key, value in _iter_header_items(headers):
        name = _as_bytes(key).lower()
        val = _as_bytes(value)
        if name.startswith(b":"):
            raise H2ProtocolError("callers may not inject HTTP/2 pseudo-fields")
        _validate_regular_name(name)
        _validate_field_value(val)
        raw_items.append((name, val))
        if name == b"connection":
            for token in val.split(b","):
                token = token.strip().lower()
                if token:
                    _validate_regular_name(token)
                    connection_tokens.add(token)

    normalized = []
    content_lengths = []
    content_length_added = False
    for name, value in raw_items:
        if name == b"host" or name == b"proxy-authorization":
            continue
        if name in _CONNECTION_FIELDS or name in connection_tokens:
            continue
        if name == b"te" and value.strip().lower() != b"trailers":
            raise H2ProtocolError("HTTP/2 permits TE only with value 'trailers'")
        if name == b"content-length":
            content_lengths.append(value.strip())
            if content_length_added:
                continue
            content_length_added = True
        normalized.append((name, value))

    if content_lengths:
        if len(set(content_lengths)) != 1 or not content_lengths[0].isdigit():
            raise H2ProtocolError("invalid or conflicting content-length fields")
        expected = len(body)
        if int(content_lengths[0]) != expected:
            raise H2ProtocolError("content-length does not match request body")
    return normalized


def _request_header_list(method, path, authority, headers, body):
    method = _as_bytes(method)
    authority = _as_bytes(authority)
    path = _as_bytes(path)
    _validate_method(method)
    if not authority:
        raise H2ProtocolError("authority is required")
    _validate_pseudo_value(":authority", authority)
    if method == b"CONNECT":
        request = [(b":method", method), (b":authority", authority)]
    else:
        if not path:
            raise H2ProtocolError("non-CONNECT requests require a non-empty :path")
        _validate_pseudo_value(":path", path)
        request = [(b":method", method), (b":scheme", b"https"), (b":path", path), (b":authority", authority)]
    request.extend(_normalize_request_headers(headers, body))
    return request


def _field_section_size(headers):
    return sum(32 + len(name) + len(value) for name, value in headers)


def _header_frames(stream_id, block, max_frame_size, end_stream):
    if max_frame_size < DEFAULT_MAX_FRAME_SIZE:
        raise H2ProtocolError("peer advertised an invalid maximum frame size")
    if not block:
        return [encode_frame(HEADERS, FLAG_END_HEADERS | (FLAG_END_STREAM if end_stream else 0), stream_id, b"")]
    frames = []
    pos = 0
    first = True
    while pos < len(block):
        chunk = block[pos:pos + max_frame_size]
        pos += len(chunk)
        final = pos == len(block)
        if first:
            flags = (FLAG_END_STREAM if end_stream else 0) | (FLAG_END_HEADERS if final else 0)
            frames.append(encode_frame(HEADERS, flags, stream_id, chunk))
            first = False
        else:
            flags = FLAG_END_HEADERS if final else 0
            frames.append(encode_frame(CONTINUATION, flags, stream_id, chunk))
    return frames


def _data_frames(stream_id, body, max_frame_size):
    frames = []
    pos = 0
    while pos < len(body):
        chunk = body[pos:pos + max_frame_size]
        pos += len(chunk)
        flags = FLAG_END_STREAM if pos == len(body) else 0
        frames.append(encode_frame(DATA, flags, stream_id, chunk))
    return frames


def _extract_header_fragment(ftype, flags, payload):
    if ftype == CONTINUATION:
        return payload
    pos = 0
    pad_length = 0
    if flags & FLAG_PADDED:
        if not payload:
            raise H2ProtocolError("padded HEADERS frame has no pad length")
        pad_length = bytearray(payload)[0]
        pos = 1
    if flags & FLAG_PRIORITY:
        if len(payload) - pos < 5:
            raise H2ProtocolError("truncated HEADERS priority fields")
        pos += 5
    if pad_length > len(payload) - pos:
        raise H2ProtocolError("HEADERS padding exceeds frame payload")
    end = len(payload) - pad_length
    return payload[pos:end]


def _extract_data(flags, payload):
    if not (flags & FLAG_PADDED):
        return payload
    if not payload:
        raise H2ProtocolError("padded DATA frame has no pad length")
    pad_length = bytearray(payload)[0]
    if pad_length > len(payload) - 1:
        raise H2ProtocolError("DATA padding exceeds frame payload")
    return payload[1:len(payload) - pad_length]


def _parse_content_length(headers, trailers=False):
    values = []
    for name, value in headers:
        if _as_bytes(name).lower() != b"content-length":
            continue
        if trailers:
            raise H2ProtocolError("content-length is not permitted in trailers")
        for part in _as_bytes(value).split(b","):
            part = part.strip()
            if not part or not part.isdigit():
                raise H2ProtocolError("invalid content-length field")
            values.append(int(part))
    if not values:
        return None
    expected = values[0]
    if any(value != expected for value in values[1:]):
        raise H2ProtocolError("conflicting content-length fields")
    return expected


def _validate_response_field_section(headers, trailers=False):
    regular_seen = False
    status = None
    for name, value in headers:
        name = _as_bytes(name)
        value = _as_bytes(value)
        _validate_field_value(value)
        if name.startswith(b":"):
            if trailers or regular_seen or name != b":status" or status is not None:
                raise H2ProtocolError("invalid response pseudo-field ordering or duplication")
            if len(value) != 3 or not value.isdigit():
                raise H2ProtocolError("invalid :status pseudo-field")
            status = int(value)
            if not 100 <= status <= 599:
                raise H2ProtocolError("response status is outside the valid range")
            if status == 101:
                raise H2ProtocolError("101 Switching Protocols is not valid in HTTP/2")
        else:
            regular_seen = True
            if name.lower() != name:
                raise H2ProtocolError("uppercase HTTP/2 field name")
            _validate_regular_name(name)
            if name in _CONNECTION_FIELDS:
                raise H2ProtocolError("connection-specific field in HTTP/2 response")
    content_length = _parse_content_length(headers, trailers=trailers)
    if trailers:
        return None, None
    if status is None:
        raise H2ProtocolError("response field section lacks :status")
    return status, content_length


class _ResponseState(object):
    def __init__(self, stream_id, request_method):
        self.stream_id = stream_id
        self.request_method = _as_bytes(request_method)
        self.block = None
        self.block_end_stream = False
        self.headers = None
        self.trailers = []
        self.informational_count = 0
        self.informational_bytes = 0
        self.status = None
        self.expected_content_length = None
        self.body_forbidden = False
        self.body = bytearray()
        self.recv_window = LOCAL_INITIAL_WINDOW
        self.complete = False


class _H2Connection(object):
    """A sequential HTTP/2 connection with an explicit two-stream timing primitive."""

    def __init__(self, host, port, proxy, timeout, verify=False, ssl_context=None):
        self.host = _idna_host(host)
        self.port = port
        self.proxy = proxy
        self.dec = Decoder()
        self.next_sid = 1
        self.usable = True
        self.sock = None
        self.peer_max_frame_size = DEFAULT_MAX_FRAME_SIZE
        self.peer_initial_window = DEFAULT_WINDOW
        self.peer_max_concurrent_streams = None
        self.peer_max_header_list_size = None
        self.conn_send_window = DEFAULT_WINDOW
        self.conn_recv_window = LOCAL_INITIAL_WINDOW
        self.stream_send_windows = {}
        self.local_max_frame_size = DEFAULT_MAX_FRAME_SIZE
        self._our_settings_acked = False
        context = _make_ssl_context(verify, ssl_context)
        raw = _connect_socket(self.host, port, proxy, timeout)
        try:
            try:
                raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except (OSError, socket.error):
                pass
            self.sock = context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            try:
                raw.close()
            except Exception:
                pass
            raise
        try:
            selected = getattr(self.sock, "selected_alpn_protocol", lambda: None)()
            if selected != "h2":
                raise H2Error("server did not negotiate h2 (ALPN=%r)" % selected)
            tls_version = getattr(self.sock, "version", lambda: None)()
            if tls_version not in ("TLSv1.2", "TLSv1.3"):
                raise H2Error("HTTP/2 requires TLS 1.2 or newer (negotiated %r)" % tls_version)
            compression = getattr(self.sock, "compression", lambda: None)()
            if compression is not None:
                raise H2Error("TLS compression is not permitted for HTTP/2")
            self.sock.settimeout(timeout)
            settings_payload = struct.pack(
                "!HIHIHI",
                SETTINGS_ENABLE_PUSH, 0,
                SETTINGS_INITIAL_WINDOW_SIZE, LOCAL_INITIAL_WINDOW,
                SETTINGS_MAX_HEADER_LIST_SIZE, MAX_HEADER_LIST_SIZE,
            )
            self.sock.sendall(CONNECTION_PREFACE + encode_frame(SETTINGS, 0, 0, settings_payload))
            self.sock.sendall(encode_frame(
                WINDOW_UPDATE, 0, 0, struct.pack("!I", LOCAL_INITIAL_WINDOW - DEFAULT_WINDOW)
            ))
            self._receive_initial_settings()
        except Exception:
            self.close()
            raise

    def close(self):
        self.usable = False
        sock = getattr(self, "sock", None)
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
            self.sock = None

    def __del__(self):
        self.close()

    def _connection_error(self, message):
        self.usable = False
        raise H2ProtocolError(message)

    def _receive_initial_settings(self):
        ftype, flags, sid, payload = _read_frame(self.sock, self.local_max_frame_size)
        if ftype != SETTINGS or sid != 0 or (flags & FLAG_ACK):
            self._connection_error("the server connection preface did not start with SETTINGS")
        self._handle_settings(flags, sid, payload)

    def _handle_settings(self, flags, sid, payload):
        if sid != 0:
            self._connection_error("SETTINGS frame used a non-zero stream id")
        if flags & FLAG_ACK:
            if payload:
                self._connection_error("SETTINGS acknowledgement carried a payload")
            self._our_settings_acked = True
            return
        if len(payload) % 6:
            self._connection_error("SETTINGS payload length is not a multiple of 6")
        data = bytearray(payload)
        for pos in range(0, len(data), 6):
            setting_id, value = struct.unpack("!HI", bytes(data[pos:pos + 6]))
            if setting_id == SETTINGS_ENABLE_PUSH:
                if value != 0:
                    self._connection_error("a server may set SETTINGS_ENABLE_PUSH only to 0")
            elif setting_id == SETTINGS_MAX_CONCURRENT_STREAMS:
                self.peer_max_concurrent_streams = value
            elif setting_id == SETTINGS_INITIAL_WINDOW_SIZE:
                if value > MAX_WINDOW:
                    self._connection_error("invalid SETTINGS_INITIAL_WINDOW_SIZE")
                delta = value - self.peer_initial_window
                for stream_id in list(self.stream_send_windows):
                    updated = self.stream_send_windows[stream_id] + delta
                    if updated > MAX_WINDOW:
                        self._connection_error("stream send window overflow after SETTINGS")
                    self.stream_send_windows[stream_id] = updated
                self.peer_initial_window = value
            elif setting_id == SETTINGS_MAX_FRAME_SIZE:
                if not DEFAULT_MAX_FRAME_SIZE <= value <= MAX_FRAME_SIZE:
                    self._connection_error("invalid SETTINGS_MAX_FRAME_SIZE")
                self.peer_max_frame_size = value
            elif setting_id == SETTINGS_MAX_HEADER_LIST_SIZE:
                self.peer_max_header_list_size = value
            elif setting_id == SETTINGS_HEADER_TABLE_SIZE:
                # Our encoder never uses the dynamic table, so every value is safe.
                pass
        self.sock.sendall(encode_frame(SETTINGS, FLAG_ACK, 0, b""))

    def _handle_ping(self, flags, sid, payload):
        if sid != 0 or len(payload) != 8:
            self._connection_error("invalid PING frame")
        if not (flags & FLAG_ACK):
            self.sock.sendall(encode_frame(PING, FLAG_ACK, 0, payload))

    def _handle_window_update(self, sid, payload):
        if len(payload) != 4:
            self._connection_error("invalid WINDOW_UPDATE length")
        increment = struct.unpack("!I", payload)[0] & MAX_WINDOW
        if increment == 0:
            self._connection_error("WINDOW_UPDATE increment is zero")
        if sid == 0:
            if self.conn_send_window > MAX_WINDOW - increment:
                self._connection_error("connection flow-control window overflow")
            self.conn_send_window += increment
        elif sid in self.stream_send_windows:
            current = self.stream_send_windows[sid]
            if current > MAX_WINDOW - increment:
                self._connection_error("stream flow-control window overflow")
            self.stream_send_windows[sid] = current + increment
        elif sid % 2 == 0 or sid >= self.next_sid:
            self._connection_error("WINDOW_UPDATE referenced an idle stream")

    def _allocate_stream_ids(self, count):
        if count <= 0:
            raise ValueError("stream count must be positive")
        last = self.next_sid + 2 * (count - 1)
        if last > MAX_STREAM_ID:
            self.usable = False
            raise H2Error("HTTP/2 stream-id space exhausted")
        sids = [self.next_sid + 2 * index for index in range(count)]
        self.next_sid += 2 * count
        if self.next_sid > MAX_STREAM_ID:
            self.usable = False
        return sids

    def _send_headers(self, sid, request_headers, end_stream):
        if self.peer_max_header_list_size is not None:
            if _field_section_size(request_headers) > self.peer_max_header_list_size:
                raise H2Error("request header list exceeds peer-advertised limit")
        block = Encoder().encode(request_headers)
        return b"".join(_header_frames(sid, block, self.peer_max_frame_size, end_stream))

    def _finish_response(self, state):
        actual = len(state.body)
        if state.body_forbidden and actual:
            self._connection_error("response semantics forbid a message body")
        if (not state.body_forbidden and state.expected_content_length is not None and
                actual != state.expected_content_length):
            self._connection_error(
                "response content-length mismatch (expected %d, received %d)" %
                (state.expected_content_length, actual)
            )
        state.complete = True

    def _complete_header_block(self, state):
        try:
            headers = self.dec.decode(bytes(state.block))
        except H2CompressionError:
            self.usable = False
            raise
        end_stream = state.block_end_stream
        state.block = None
        state.block_end_stream = False

        if state.headers is None:
            status, content_length = _validate_response_field_section(headers, trailers=False)
            if 100 <= status < 200:
                if end_stream:
                    self._connection_error("informational response ended the stream")
                if content_length is not None:
                    self._connection_error("informational response carried content-length")
                state.informational_count += 1
                state.informational_bytes += _field_section_size(headers)
                if state.informational_count > MAX_INFORMATIONAL_RESPONSES:
                    self.usable = False
                    raise H2Error("too many informational responses")
                if state.informational_bytes > MAX_INFORMATIONAL_HEADER_BYTES:
                    self.usable = False
                    raise H2Error("informational response headers exceed configured limit")
                return
            state.headers = headers
            state.status = status
            state.expected_content_length = content_length
            state.body_forbidden = state.request_method == b"HEAD" or status in (204, 205, 304)
            if status == 204 and content_length is not None:
                self._connection_error("204 response must not carry content-length")
            if status == 205 and content_length not in (None, 0):
                self._connection_error("205 response content-length must be zero")
            if state.request_method == b"CONNECT" and 200 <= status < 300 and content_length is not None:
                self._connection_error("successful CONNECT response must not carry content-length")
            if (not state.body_forbidden and content_length is not None and
                    content_length > MAX_RESPONSE_SIZE):
                self.usable = False
                raise H2Error("declared response body exceeds configured limit")
            if end_stream:
                self._finish_response(state)
        else:
            _validate_response_field_section(headers, trailers=True)
            if not end_stream:
                self._connection_error("trailing field section did not end the stream")
            if _field_section_size(state.headers) + _field_section_size(headers) > MAX_HEADER_LIST_SIZE:
                self.usable = False
                raise H2Error("aggregate response headers exceed configured limit")
            state.trailers.extend(headers)
            state.headers.extend(headers)
            self._finish_response(state)

    def _process_header_frame(self, ftype, flags, sid, payload, states, continuation_sid):
        if continuation_sid is not None:
            if ftype != CONTINUATION or sid != continuation_sid:
                self._connection_error("frame interleaved inside a CONTINUATION sequence")
        elif ftype == CONTINUATION:
            self._connection_error("unexpected CONTINUATION frame")

        state = states.get(sid)
        if state is None:
            self._connection_error("header frame for an unknown stream")
        if state.complete:
            self._connection_error("header frame received after END_STREAM")

        if ftype == HEADERS:
            if state.block is not None:
                self._connection_error("new HEADERS before the prior field section completed")
            state.block = bytearray()
            state.block_end_stream = bool(flags & FLAG_END_STREAM)
        state.block.extend(_extract_header_fragment(ftype, flags, payload))
        if len(state.block) > MAX_HEADER_BLOCK_SIZE:
            self.usable = False
            raise H2Error("compressed response header block exceeds configured limit")

        if flags & FLAG_END_HEADERS:
            self._complete_header_block(state)
            return None
        return sid

    def _process_data_frame(self, flags, sid, payload, states):
        state = states.get(sid)
        if state is None:
            self._connection_error("DATA frame for an unknown stream")
        if state.headers is None:
            self._connection_error("DATA received before final response headers")
        if state.complete:
            self._connection_error("DATA received after END_STREAM")
        flow_len = len(payload)
        if flow_len > self.conn_recv_window:
            self._connection_error("peer exceeded the connection receive window")
        if flow_len > state.recv_window:
            self._connection_error("peer exceeded the stream receive window")
        self.conn_recv_window -= flow_len
        state.recv_window -= flow_len
        data = _extract_data(flags, payload)
        if state.body_forbidden and data:
            self._connection_error("response semantics forbid a message body")
        if (state.expected_content_length is not None and not state.body_forbidden and
                len(state.body) + len(data) > state.expected_content_length):
            self._connection_error("response body exceeds declared content-length")
        if len(state.body) + len(data) > MAX_RESPONSE_SIZE:
            self.usable = False
            raise H2Error("response body exceeds configured limit")
        state.body.extend(data)

        end_stream = bool(flags & FLAG_END_STREAM)
        if flow_len:
            if end_stream:
                try:
                    self.sock.sendall(encode_frame(WINDOW_UPDATE, 0, 0, struct.pack("!I", flow_len)))
                    self.conn_recv_window += flow_len
                except (socket.error, ssl.SSLError, IOError):
                    self.usable = False
            else:
                self.sock.sendall(encode_frame(WINDOW_UPDATE, 0, 0, struct.pack("!I", flow_len)))
                self.sock.sendall(encode_frame(WINDOW_UPDATE, 0, sid, struct.pack("!I", flow_len)))
                self.conn_recv_window += flow_len
                state.recv_window += flow_len
        if end_stream:
            self._finish_response(state)

    def _process_frame(self, frame, states, continuation_sid):
        ftype, flags, sid, payload = frame
        if continuation_sid is not None and not (ftype == CONTINUATION and sid == continuation_sid):
            self._connection_error("non-CONTINUATION frame interleaved in a field section")

        if ftype == SETTINGS:
            self._handle_settings(flags, sid, payload)
        elif ftype == PING:
            self._handle_ping(flags, sid, payload)
        elif ftype == WINDOW_UPDATE:
            self._handle_window_update(sid, payload)
        elif ftype == GOAWAY:
            if sid != 0 or len(payload) < 8:
                self._connection_error("invalid GOAWAY frame")
            self.usable = False
            last_sid = struct.unpack("!I", payload[:4])[0] & MAX_STREAM_ID
            active = sorted(states)
            unprocessed = [stream_id for stream_id in active if stream_id > last_sid]
            if len(unprocessed) == len(active):
                raise _UnprocessedStream("GOAWAY confirms active stream(s) were not processed")
            if unprocessed:
                raise H2Error("GOAWAY partially processed a multi-stream exchange")
        elif ftype == RST_STREAM:
            if sid == 0 or len(payload) != 4:
                self._connection_error("invalid RST_STREAM frame")
            if sid in states:
                error_code = struct.unpack("!I", payload)[0]
                if len(states) == 1 and error_code == REFUSED_STREAM:
                    raise _UnprocessedStream("peer refused the stream before processing")
                raise H2Error("stream %d reset by peer (error %d)" % (sid, error_code))
            if sid % 2 == 0 or sid >= self.next_sid:
                self._connection_error("RST_STREAM referenced an idle stream")
        elif ftype == PUSH_PROMISE:
            self._connection_error("server push received despite SETTINGS_ENABLE_PUSH=0")
        elif ftype in (HEADERS, CONTINUATION):
            continuation_sid = self._process_header_frame(
                ftype, flags, sid, payload, states, continuation_sid
            )
        elif ftype == DATA:
            if sid == 0:
                self._connection_error("DATA frame used stream 0")
            self._process_data_frame(flags, sid, payload, states)
        elif ftype == PRIORITY:
            if sid == 0 or len(payload) != 5:
                self._connection_error("invalid PRIORITY frame")
        # Unknown extension frames are ignored, as required by HTTP/2.
        return continuation_sid

    def exchange(self, method, path, authority, headers, body, timeout):
        if not self.usable:
            raise H2Error("HTTP/2 connection is not usable")
        if self.peer_max_concurrent_streams == 0:
            raise H2Error("peer currently permits no new streams")
        self.sock.settimeout(timeout)
        body = b"" if body is None else _as_bytes(body)
        method = _as_bytes(method)
        sid = self._allocate_stream_ids(1)[0]
        self.stream_send_windows[sid] = self.peer_initial_window
        try:
            state = _ResponseState(sid, method)
            states = {sid: state}
            request_headers = _request_header_list(method, path, authority, headers, body)
            self.sock.sendall(self._send_headers(sid, request_headers, not body))

            body_pos = 0
            continuation_sid = None
            frames_seen = 0
            while not state.complete:
                while body_pos < len(body):
                    available = min(
                        self.peer_max_frame_size,
                        self.conn_send_window,
                        self.stream_send_windows[sid],
                        len(body) - body_pos,
                    )
                    if available <= 0:
                        break
                    chunk = body[body_pos:body_pos + available]
                    body_pos += len(chunk)
                    flags = FLAG_END_STREAM if body_pos == len(body) else 0
                    self.sock.sendall(encode_frame(DATA, flags, sid, chunk))
                    self.conn_send_window -= len(chunk)
                    self.stream_send_windows[sid] -= len(chunk)

                if state.complete:
                    break
                frame = _read_frame(self.sock, self.local_max_frame_size)
                frames_seen += 1
                if frames_seen > MAX_RESPONSE_FRAMES:
                    self.usable = False
                    raise H2Error("response exceeded the frame-count limit")
                continuation_sid = self._process_frame(frame, states, continuation_sid)

            if continuation_sid is not None:
                self._connection_error("stream ended with an incomplete field section")
            if body_pos < len(body):
                self.usable = False
                try:
                    self.sock.sendall(encode_frame(RST_STREAM, 0, sid, struct.pack("!I", CANCEL)))
                except Exception:
                    pass
            if state.status is None:
                self._connection_error("stream ended without final response headers")
            return state.status, state.headers, bytes(state.body)
        finally:
            self.stream_send_windows.pop(sid, None)

    def exchange_pair(self, requests, timeout):
        """Send exactly two small requests in one application-level write.

        A single sendall() reduces userspace scheduling skew, but TCP/TLS may still split
        the bytes into multiple records or packets; packet-level coalescing is not guaranteed.
        """
        if not self.usable:
            raise H2Error("HTTP/2 connection is not usable")
        requests = list(requests)
        if len(requests) != 2:
            raise ValueError("exchange_pair requires exactly two requests")
        if self.peer_max_concurrent_streams is not None and self.peer_max_concurrent_streams < 2:
            raise H2Error("peer does not permit two concurrent streams")
        self.sock.settimeout(timeout)
        sids = self._allocate_stream_ids(2)
        for sid in sids:
            self.stream_send_windows[sid] = self.peer_initial_window
        try:
            states = {}
            outbound = []
            total_body = 0
            for sid, request in zip(sids, requests):
                body = b"" if request.get("body") is None else _as_bytes(request.get("body"))
                method = _as_bytes(request.get("method", "GET"))
                states[sid] = _ResponseState(sid, method)
                if len(body) > self.peer_initial_window:
                    raise H2Error("timeless-pair body exceeds the peer stream window")
                total_body += len(body)
                request_headers = _request_header_list(
                    method,
                    request["path"],
                    request.get("authority") or _authority_for_host(self.host, self.port),
                    request.get("headers"),
                    body,
                )
                outbound.append(self._send_headers(sid, request_headers, not body))
                if body:
                    outbound.extend(_data_frames(sid, body, self.peer_max_frame_size))
                    self.stream_send_windows[sid] -= len(body)
            if total_body > self.conn_send_window:
                raise H2Error("timeless-pair bodies exceed the connection flow-control window")
            self.conn_send_window -= total_body
            self.sock.sendall(b"".join(outbound))

            finish_order = []
            continuation_sid = None
            frames_seen = 0
            while len(finish_order) < 2:
                before = dict((sid, states[sid].complete) for sid in sids)
                frame = _read_frame(self.sock, self.local_max_frame_size)
                frames_seen += 1
                if frames_seen > MAX_RESPONSE_FRAMES:
                    self.usable = False
                    raise H2Error("timeless pair exceeded the frame-count limit")
                continuation_sid = self._process_frame(frame, states, continuation_sid)
                for sid in sids:
                    if states[sid].complete and not before[sid] and sid not in finish_order:
                        finish_order.append(sid)
            if continuation_sid is not None:
                self._connection_error("pair ended with an incomplete field section")
            results = {}
            for sid in sids:
                state = states[sid]
                if state.status is None:
                    self._connection_error("pair stream ended without final response headers")
                results[sid] = (state.status, state.headers, bytes(state.body))
            return finish_order, results
        finally:
            for sid in sids:
                self.stream_send_windows.pop(sid, None)


_h2_pool = threading.local()


def _pool_key(host, port, proxy, verify, ssl_context):
    proxy_key = tuple(proxy) if isinstance(proxy, list) else proxy
    context_key = ssl_context if ssl_context is not None else bool(verify)
    return _idna_host(host), port, proxy_key, context_key


def _get_pool():
    pool = getattr(_h2_pool, "connections", None)
    if pool is None or not isinstance(pool, OrderedDict):
        pool = OrderedDict()
        _h2_pool.connections = pool
    return pool


def _pool_put(pool, key, conn):
    old = pool.pop(key, None)
    if old is not None and old is not conn:
        old.close()
    pool[key] = conn
    while len(pool) > H2_POOL_LIMIT:
        _, stale = pool.popitem(last=False)
        stale.close()


def close_pooled_connections():
    pool = _get_pool()
    for conn in list(pool.values()):
        conn.close()
    pool.clear()


def _retryable_after_stale_connection(method):
    return _as_bytes(method) in (b"GET", b"HEAD")


def _pooledExchange(host, port, proxy, method, path, authority, headers, body, timeout,
                    verify=False, ssl_context=None):
    pool = _get_pool()
    key = _pool_key(host, port, proxy, verify, ssl_context)
    conn = pool.pop(key, None)
    reused = conn is not None and conn.usable
    if conn is None or not conn.usable:
        if conn is not None:
            conn.close()
        conn = _H2Connection(host, port, proxy, timeout, verify=verify, ssl_context=ssl_context)
    _pool_put(pool, key, conn)
    try:
        result = conn.exchange(method, path, authority, headers, body, timeout)
    except _UnprocessedStream:
        conn.close()
        pool.pop(key, None)
        replacement = _H2Connection(host, port, proxy, timeout, verify=verify, ssl_context=ssl_context)
        _pool_put(pool, key, replacement)
        try:
            result = replacement.exchange(method, path, authority, headers, body, timeout)
        except Exception:
            replacement.close()
            pool.pop(key, None)
            raise
        conn = replacement
    except (socket.error, ssl.SSLError, H2TransportError):
        conn.close()
        pool.pop(key, None)
        if not (reused and _retryable_after_stale_connection(method)):
            raise
        replacement = _H2Connection(host, port, proxy, timeout, verify=verify, ssl_context=ssl_context)
        _pool_put(pool, key, replacement)
        try:
            result = replacement.exchange(method, path, authority, headers, body, timeout)
        except Exception:
            replacement.close()
            pool.pop(key, None)
            raise
        conn = replacement
    except (H2Error, IOError):
        conn.close()
        pool.pop(key, None)
        raise
    if not conn.usable:
        conn.close()
        pool.pop(key, None)
    return result


def h2_request(host, port=443, method="GET", path="/", authority=None, headers=None, body=None,
               timeout=30, proxy=None, verify=False, ssl_context=None):
    conn = _H2Connection(host, port, proxy, timeout, verify=verify, ssl_context=ssl_context)
    try:
        return conn.exchange(method, path, authority or _authority_for_host(host, port), headers, body, timeout)
    finally:
        conn.close()


class H2Response(object):
    """A small urllib-response-compatible wrapper for a buffered HTTP/2 response."""

    def __init__(self, url, status, headers, body):
        self.url = url
        self.code = self.status = status
        self.msg = _HTTP_RESPONSES.get(status, "")
        self.http_version = "HTTP/2.0"
        self._body = body
        self._offset = 0
        self._info = _Message()
        for name, value in headers or []:
            name = name.decode("latin-1") if isinstance(name, bytes) else name
            value = value.decode("latin-1") if isinstance(value, bytes) else value
            if not name.startswith(":"):
                self._info[name] = value
        self._info.headers = ["%s: %s\r\n" % item for item in self._info.items()]

    def info(self):
        return self._info

    def geturl(self):
        return self.url

    def getcode(self):
        return self.code

    def read(self, amt=None):
        if amt is None or amt < 0:
            data = self._body[self._offset:]
            self._offset = len(self._body)
        else:
            data = self._body[self._offset:self._offset + amt]
            self._offset += len(data)
        return data

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False


def _headers_without(headers, names):
    names = set(names)
    result = []
    for key, value in _iter_header_items(headers):
        name = _as_bytes(key).lower()
        if name not in names:
            result.append((key, value))
    return result


def _url_port(parts):
    try:
        return parts.port or 443
    except ValueError as ex:
        raise H2Error("invalid URL port: %s" % ex)


def _origin_tuple(parts):
    host = _idna_host(parts.hostname or "").lower()
    return parts.scheme.lower(), host, _url_port(parts)


def _quote_target_component(value, safe):
    if isinstance(value, text_type):
        try:
            value.encode("ascii")
        except UnicodeEncodeError:
            value = value.encode("utf-8")
    return quote(value, safe=safe)


def proxy_tuple(proxy, cred=None):
    """Convert a sqlmap '--proxy' value into the (host, port, cred) tuple the `proxy` parameter of this
    client expects. Returns None when unset. SOCKS is not supported by the native client, so it raises
    ValueError and leaves it to the caller to decide how to surface that (hard error / skip the feature).

    >>> proxy_tuple("http://127.0.0.1:8080")
    ('127.0.0.1', 8080, None)
    >>> proxy_tuple("127.0.0.1")
    ('127.0.0.1', 8080, None)
    """
    if not proxy:
        return None
    parts = urlsplit(proxy if "://" in proxy else "http://%s" % proxy)
    if (parts.scheme or "").lower().startswith("socks"):
        raise ValueError("native HTTP/2 client does not support SOCKS proxies")
    return (parts.hostname, parts.port or 8080, cred or None)


def open_url(url, method="GET", headers=None, body=None, timeout=30, follow_redirects=True,
             max_redirects=10, proxy=None, verify=False, ssl_context=None):
    req_headers = headers or {}
    current_method = method
    current_body = body

    for redirect_count in range(max_redirects + 1):
        parts = urlsplit(url)
        if parts.scheme.lower() != "https":
            raise H2Error("native HTTP/2 client supports only https URLs")
        if not parts.hostname:
            raise H2Error("URL has no hostname")
        host = _idna_host(parts.hostname)
        port = _url_port(parts)
        path = _quote_target_component(parts.path or "/", "/%:@!$&'()*+,;=-._~")
        if parts.query:
            path += "?" + _quote_target_component(parts.query, "/?%:@!$&'()*+,;=-._~")
        authority = _authority_for_host(host, port)
        status, response_headers, response_body = _pooledExchange(
            host, port, proxy, current_method, path, authority,
            req_headers, current_body, timeout, verify=verify, ssl_context=ssl_context
        )
        if not (follow_redirects and status in REDIRECT_CODES):
            return H2Response(url, status, response_headers, response_body)

        location = None
        for name, value in response_headers or []:
            if _as_bytes(name).lower() == b"location":
                location = value.decode("latin-1") if isinstance(value, bytes) else value
                break
        if not location:
            return H2Response(url, status, response_headers, response_body)
        if redirect_count == max_redirects:
            break

        new_url = urljoin(url, location)
        old_parts = parts
        new_parts = urlsplit(new_url)
        if _origin_tuple(old_parts) != _origin_tuple(new_parts):
            req_headers = _headers_without(req_headers, _SENSITIVE_REDIRECT_FIELDS)

        method_bytes = _as_bytes(current_method)
        change_to_get = status == 303 and method_bytes != b"HEAD"
        change_to_get = change_to_get or (status in (301, 302) and method_bytes == b"POST")
        if change_to_get:
            current_method = "GET"
            current_body = None
            req_headers = _headers_without(req_headers, _CONTENT_REDIRECT_FIELDS)
        url = new_url

    raise H2Error("too many HTTP/2 redirects")
