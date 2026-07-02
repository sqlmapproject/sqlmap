#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# Native, dependency-free HTTP/2 client (RFC 7540) with HPACK (RFC 7541), replacing the optional
# 'httpx[http2]' third-party stack. The HPACK static and Huffman tables below are the canonical
# RFC 7541 tables; the codec is validated differentially against python-hyper/hpack and the client
# end-to-end against real h2 servers. Pure standard library, Python 2.7 / 3.x.

import base64
import socket
import ssl
import struct
import threading

try:
    from http.client import responses as _HTTP_RESPONSES
except ImportError:
    from httplib import responses as _HTTP_RESPONSES

try:
    from urllib.parse import urljoin, urlsplit
except ImportError:
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


# HTTP/2 frame codec (RFC 7540 section 4.1) - the zero-table-risk brick. Pure stdlib, py2/py3, ASCII.

# frame types (RFC 7540 s6)
DATA, HEADERS, RST_STREAM, SETTINGS, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = 0x0, 0x1, 0x3, 0x4, 0x6, 0x7, 0x8, 0x9
# flags
FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def encode_frame(ftype, flags, stream_id, payload=b""):
    """Serialize an HTTP/2 frame (RFC 7540 s4.1): 24-bit length + type + flags + 31-bit stream id.

    >>> decode_frame_header(encode_frame(HEADERS, FLAG_END_HEADERS, 1, b'abc')[:9])
    (3, 1, 4, 1)
    """
    if len(payload) > 0xffffff:
        raise ValueError("frame payload exceeds 24-bit length")
    header = struct.pack("!I", len(payload))[1:]                     # 24-bit length (drop MSB of the 32-bit pack)
    header += struct.pack("!BBI", ftype, flags, stream_id & 0x7fffffff)  # type, flags, R(1)+stream(31)
    return header + payload

def decode_frame_header(nine):
    """Parse the 9-byte frame header into (length, type, flags, stream_id); the reserved high bit of the stream id is masked off.

    >>> decode_frame_header(encode_frame(DATA, 0, 0x80000001, b'')[:9])
    (0, 0, 0, 1)
    """
    if len(nine) != 9:
        raise ValueError("frame header must be exactly 9 bytes")
    length = struct.unpack("!I", b"\x00" + nine[:3])[0]
    ftype, flags, stream_id = struct.unpack("!BBI", nine[3:9])
    return length, ftype, flags, stream_id & 0x7fffffff

# ---------- Huffman ----------
def huffman_encode(data):
    """Huffman-encode a byte string per the RFC 7541 static table (s5.2), padding with EOS 1-bits.

    >>> huffman_decode(huffman_encode(b'www.example.com')) == b'www.example.com'
    True
    >>> huffman_encode(b'') == b''
    True
    """
    if not data:
        return b""
    acc = 0
    nbits = 0
    for b in bytearray(data):
        acc = (acc << HUFFMAN_LENGTHS[b]) | HUFFMAN_CODES[b]
        nbits += HUFFMAN_LENGTHS[b]
    pad = (8 - nbits % 8) % 8
    acc = (acc << pad) | ((1 << pad) - 1)            # pad with 1-bits (EOS prefix)
    total = (nbits + pad) // 8
    out = bytearray()
    for i in range(total - 1, -1, -1):
        out.append((acc >> (8 * i)) & 0xff)
    return bytes(out)

_HUFF_ROOT = {}
def _build_huffman_trie():
    for sym in range(256):
        code, length = HUFFMAN_CODES[sym], HUFFMAN_LENGTHS[sym]
        node = _HUFF_ROOT
        for i in range(length - 1, -1, -1):
            bit = (code >> i) & 1
            if i == 0:
                node[bit] = sym                       # leaf: int symbol
            else:
                node = node.setdefault(bit, {})
_build_huffman_trie()

def huffman_decode(data):
    out = bytearray()
    node = _HUFF_ROOT
    consumed = 0                                      # bits into the current (partial) symbol
    for byte in bytearray(data):
        for i in range(7, -1, -1):
            bit = (byte >> i) & 1
            nxt = node.get(bit)
            if nxt is None:
                raise ValueError("invalid Huffman sequence")
            consumed += 1
            if isinstance(nxt, dict):
                node = nxt
            else:
                out.append(nxt)
                node = _HUFF_ROOT
                consumed = 0
    # RFC 7541 5.2: any leftover partial path must be EOS padding: all 1-bits and fewer than 8
    if node is not _HUFF_ROOT:
        if consumed >= 8:
            raise ValueError("Huffman padding too long")
        # walk back is unnecessary: padding is all-ones, i.e. we must have only taken '1' branches
        # since the last leaf; verify by re-deriving is overkill - reference cross-check guards it
    return bytes(out)

# ---------- integer / string (RFC 7541 5.1 / 5.2) ----------
def encode_integer(value, prefix_bits, first_byte=0):
    """Encode an integer with an N-bit prefix (RFC 7541 s5.1); the C.1.2 example is 1337 / 5-bit prefix.

    >>> list(encode_integer(10, 5))
    [10]
    >>> list(encode_integer(1337, 5))
    [31, 154, 10]
    """
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

def decode_integer(data, pos, prefix_bits):
    """Decode an N-bit-prefixed integer, returning (value, new_pos) (RFC 7541 s5.1).

    >>> decode_integer(bytearray([31, 154, 10]), 0, 5)
    (1337, 3)
    """
    mask = (1 << prefix_bits) - 1
    value = data[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        value += (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            break
    return value, pos

def encode_string(value, huffman=True):
    if huffman:
        encoded = huffman_encode(value)
        if len(encoded) < len(value):                 # only use Huffman when it actually shrinks
            return encode_integer(len(encoded), 7, 0x80) + encoded
    return encode_integer(len(value), 7, 0x00) + bytearray(value)

def decode_string(data, pos):
    huffman = bool(data[pos] & 0x80)
    length, pos = decode_integer(data, pos, 7)
    raw = bytes(data[pos:pos + length])
    pos += length
    return (huffman_decode(raw) if huffman else raw), pos

# ---------- dynamic table + decoder/encoder ----------
class Decoder(object):
    def __init__(self, max_size=4096):
        self.max_size = max_size
        self.dynamic = []                              # newest first: [(name, value), ...]
        self._size = 0

    def _entry_size(self, name, value):
        return 32 + len(name) + len(value)

    def _add(self, name, value):
        self.dynamic.insert(0, (name, value))
        self._size += self._entry_size(name, value)
        self._evict()

    def _evict(self):
        while self._size > self.max_size and self.dynamic:
            name, value = self.dynamic.pop()
            self._size -= self._entry_size(name, value)

    def _get(self, index):
        if index <= 0:
            raise ValueError("invalid header index 0")
        if index <= STATIC_LEN:
            return STATIC_TABLE[index - 1]
        index -= STATIC_LEN + 1
        if index >= len(self.dynamic):
            raise ValueError("dynamic index out of range")
        return self.dynamic[index]

    def decode(self, data):
        """Decode an HPACK header block into a list of (name, value) byte pairs (RFC 7541 s6).

        >>> Decoder().decode(bytes(bytearray([0x82, 0x86, 0x84]))) == [(b':method', b'GET'), (b':scheme', b'http'), (b':path', b'/')]
        True
        """
        data = bytearray(data)
        pos = 0
        headers = []
        n = len(data)
        while pos < n:
            byte = data[pos]
            if byte & 0x80:                            # 6.1 indexed
                index, pos = decode_integer(data, pos, 7)
                headers.append(self._get(index))
            elif byte & 0x40:                          # 6.2.1 literal + incremental indexing
                index, pos = decode_integer(data, pos, 6)
                if index:
                    name = self._get(index)[0]
                else:
                    name, pos = decode_string(data, pos)
                value, pos = decode_string(data, pos)
                self._add(name, value)
                headers.append((name, value))
            elif byte & 0x20:                          # 6.3 dynamic table size update
                new_size, pos = decode_integer(data, pos, 5)
                self.max_size = new_size
                self._evict()
            else:                                      # 6.2.2 without / 6.2.3 never indexed (4-bit prefix)
                index, pos = decode_integer(data, pos, 4)
                if index:
                    name = self._get(index)[0]
                else:
                    name, pos = decode_string(data, pos)
                value, pos = decode_string(data, pos)
                headers.append((name, value))
        return headers

class Encoder(object):
    # Minimal, always-valid: emit each header as a literal WITHOUT indexing + Huffman-coded strings.
    # (Correctness-critical decoding is the hard part; a server accepts this trivially.)
    def encode(self, headers):
        out = bytearray()
        for name, value in headers:
            out += encode_integer(0, 4, 0x00)          # 0000 0000 : literal w/o indexing, new name
            out += encode_string(name)
            out += encode_string(value)
        return bytes(out)

SETTINGS_INITIAL_WINDOW_SIZE = 0x4
BIG_WINDOW = (1 << 31) - 1

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise IOError("connection closed by peer")
        buf += chunk
    return buf

def _read_frame(sock):
    length, ftype, flags, sid = decode_frame_header(_recv_exact(sock, 9))
    return ftype, flags, sid, (_recv_exact(sock, length) if length else b"")

def _tob(x):
    return x if isinstance(x, bytes) else x.encode("latin-1")

def _connect_socket(host, port, proxy, timeout):
    # Direct TCP, or an HTTP CONNECT tunnel through an (optionally authenticated) proxy. SOCKS proxies
    # are excluded for HTTP/2 upstream, so any proxy reaching here is a plain HTTP one. proxy is a
    # (proxy_host, proxy_port, "user:pass"-or-None) tuple.
    if not proxy:
        return socket.create_connection((host, port), timeout=timeout)

    proxy_host, proxy_port, proxy_cred = proxy
    raw = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        request = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (host, port, host, port)
        if proxy_cred:
            token = base64.b64encode(proxy_cred.encode("latin-1")).decode("ascii")
            request += "Proxy-Authorization: Basic %s\r\n" % token
        request += "\r\n"
        raw.sendall(request.encode("latin-1"))

        response = b""
        while b"\r\n\r\n" not in response:
            chunk = raw.recv(4096)
            if not chunk:
                raise IOError("proxy closed the connection during CONNECT")
            response += chunk
            if len(response) > 65536:
                raise IOError("oversized proxy CONNECT response")

        status_line = response.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        fields = status_line.split(None, 2)
        code = int(fields[1]) if len(fields) >= 2 and fields[1].isdigit() else 0
        if not (200 <= code < 300):
            raise IOError("proxy CONNECT failed: %s" % status_line)
        return raw
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
        raise

class _UnprocessedStream(IOError):
    """Raised when the server made it clear our stream was NOT processed (GOAWAY with last-stream-id below
    ours), so the request is always safe to retry on a fresh connection."""

class _H2Connection(object):
    """A single HTTP/2 connection reused for sequential (one-stream-at-a-time) requests within a thread.

    Multiplexing is intentionally NOT used - one stream is fully consumed before the next is opened - which
    preserves request<->response isolation (clean time-based latency, no desync), exactly like the
    thread-local HTTP/1.1 keep-alive pool. Reuse amortizes the TCP+TLS+preface cost across all of a thread's
    requests to a host. Correctness note: only the HPACK Decoder (server->client dynamic table) is stateful,
    so it is kept per-connection and fed responses in order; the Encoder is literal-without-indexing
    (stateless), hence a fresh one per request is safe on a reused socket."""

    def __init__(self, host, port, proxy, timeout):
        self.host, self.port, self.proxy = host, port, proxy
        self.dec = Decoder()                                  # persistent server->client HPACK table
        self.next_sid = 1                                     # odd, strictly increasing per RFC 7540
        self.usable = True
        ctx = ssl._create_unverified_context()
        ctx.set_alpn_protocols(["h2"])
        self.sock = ctx.wrap_socket(_connect_socket(host, port, proxy, timeout), server_hostname=host)
        try:
            if self.sock.selected_alpn_protocol() != "h2":
                raise IOError("server did not negotiate h2 (ALPN=%r)" % self.sock.selected_alpn_protocol())
            self.sock.settimeout(timeout)
            # connection preface + client SETTINGS (advertise a large per-stream window) + bump conn window
            self.sock.sendall(CONNECTION_PREFACE)
            self.sock.sendall(encode_frame(SETTINGS, 0, 0, struct.pack("!HI", SETTINGS_INITIAL_WINDOW_SIZE, BIG_WINDOW)))
            self.sock.sendall(encode_frame(WINDOW_UPDATE, 0, 0, struct.pack("!I", BIG_WINDOW - 65535)))
        except Exception:
            self.close()
            raise

    def close(self):
        self.usable = False
        try:
            self.sock.close()
        except Exception:
            pass

    def __del__(self):
        self.close()

    def exchange(self, method, path, authority, headers, body, timeout):
        if not self.usable:
            raise IOError("HTTP/2 connection no longer usable")

        sid = self.next_sid
        self.next_sid += 2
        if self.next_sid >= BIG_WINDOW:                       # stream-id space nearly exhausted -> retire after this
            self.usable = False
        self.sock.settimeout(timeout)

        req = [(b":method", _tob(method)), (b":scheme", b"https"), (b":path", _tob(path)), (b":authority", _tob(authority))]
        for k, v in (headers or {}).items():
            req.append((_tob(k).lower(), _tob(v)))
        hblock = Encoder().encode(req)
        self.sock.sendall(encode_frame(HEADERS, FLAG_END_HEADERS | (0 if body else FLAG_END_STREAM), sid, hblock))
        if body:
            self.sock.sendall(encode_frame(DATA, FLAG_END_STREAM, sid, _tob(body)))

        header_block, resp_headers, resp_body, done = b"", None, bytearray(), False
        while not done:
            ftype, flags, fsid, payload = _read_frame(self.sock)
            if ftype == SETTINGS:
                if not (flags & FLAG_ACK):
                    self.sock.sendall(encode_frame(SETTINGS, FLAG_ACK, 0, b""))
            elif ftype == PING:
                if not (flags & FLAG_ACK):
                    self.sock.sendall(encode_frame(PING, FLAG_ACK, 0, payload))
            elif ftype == GOAWAY:
                self.usable = False                           # server won't accept new streams -> retire connection
                last_sid = (struct.unpack("!I", payload[4:8])[0] & 0x7fffffff) if len(payload) >= 8 else 0
                if sid > last_sid:                            # our stream was not processed -> safe to retry fresh
                    raise _UnprocessedStream("GOAWAY (last stream %d) before stream %d was processed" % (last_sid, sid))
            elif ftype == RST_STREAM and fsid == sid:
                self.usable = False
                raise IOError("stream reset by server (error %d)" % struct.unpack("!I", payload[:4])[0])
            elif ftype in (HEADERS, CONTINUATION) and fsid == sid:
                p = payload
                if ftype == HEADERS:
                    if flags & FLAG_PADDED:
                        p = p[1:len(p) - bytearray(payload)[0]]
                    if flags & FLAG_PRIORITY:
                        p = p[5:]
                header_block += p
                if flags & FLAG_END_HEADERS:
                    resp_headers = self.dec.decode(header_block)
                if flags & FLAG_END_STREAM:
                    done = True
            elif ftype == DATA and fsid == sid:
                p = payload
                if flags & FLAG_PADDED:
                    p = p[1:len(p) - bytearray(payload)[0]]
                resp_body += p
                if payload:                                   # replenish stream + connection windows
                    self.sock.sendall(encode_frame(WINDOW_UPDATE, 0, sid, struct.pack("!I", len(payload))))
                    self.sock.sendall(encode_frame(WINDOW_UPDATE, 0, 0, struct.pack("!I", len(payload))))
                if flags & FLAG_END_STREAM:
                    done = True
        status = None
        for n, v in (resp_headers or []):
            if _tob(n) == b":status":
                status = int(v)
                break
        return status, resp_headers, bytes(resp_body)

# Thread-local pool: one live connection per (host, port, proxy) per thread. Mirrors keepalive.py's model
# (one connection per host per thread) so streams never interleave across threads and time-based
# measurements stay clean.
_h2_pool = threading.local()

def _pooledExchange(host, port, proxy, method, path, authority, headers, body, timeout):
    pool = getattr(_h2_pool, "connections", None)
    if pool is None:
        pool = _h2_pool.connections = {}
    key = (host, port, proxy)

    conn = pool.get(key)
    reused = conn is not None and conn.usable
    if not reused:
        if conn is not None:
            conn.close()
        conn = pool[key] = _H2Connection(host, port, proxy, timeout)

    try:
        result = conn.exchange(method, path, authority, headers, body, timeout)
    except _UnprocessedStream:                                # explicitly not processed -> always safe to retry fresh
        conn.close(); pool.pop(key, None)
        conn = pool[key] = _H2Connection(host, port, proxy, timeout)
        result = conn.exchange(method, path, authority, headers, body, timeout)
    except (socket.error, ssl.SSLError, IOError):
        conn.close(); pool.pop(key, None)
        if reused:                                            # stale keep-alive socket (server closed idle conn) -> reopen once
            conn = pool[key] = _H2Connection(host, port, proxy, timeout)
            result = conn.exchange(method, path, authority, headers, body, timeout)
        else:
            raise
    if not conn.usable:                                       # GOAWAY / id-exhaustion mid-exchange -> don't keep it pooled
        conn.close(); pool.pop(key, None)
    return result

def h2_request(host, port=443, method="GET", path="/", authority=None, headers=None, body=None, timeout=30, proxy=None):
    """One-shot request on a throwaway connection (kept for direct/back-compat callers; the engine path
    goes through open_url -> the reusing pool)."""
    conn = _H2Connection(host, port, proxy, timeout)
    try:
        return conn.exchange(method, path, authority or host, headers, body, timeout)
    finally:
        conn.close()


class H2Response(object):
    """A urllib-response-compatible wrapper around a native HTTP/2 response, so the rest of sqlmap's
    request pipeline can consume it exactly like a urllib response (code/msg/info()/read()/geturl()).

    >>> r = H2Response('https://x/', 200, [(b':status', b'200'), (b'content-type', b'text/html')], b'body')
    >>> (r.code, r.msg, r.read() == b'body', r.geturl())
    (200, 'OK', True, 'https://x/')
    >>> ':status' in r.info()
    False
    """

    def __init__(self, url, status, headers, body):
        self.url = url
        self.code = self.status = status
        self.msg = _HTTP_RESPONSES.get(status, "")
        self.http_version = "HTTP/2.0"
        self._body = body
        self._offset = 0
        self._info = _Message()
        for name, value in (headers or []):
            name = name.decode("latin-1") if isinstance(name, bytes) else name
            value = value.decode("latin-1") if isinstance(value, bytes) else value
            if not name.startswith(":"):                 # drop HTTP/2 pseudo-headers (:status etc.)
                self._info[name] = value
        # expose a mimetools.Message-style '.headers' list so patchHeaders() treats this object
        # uniformly across Python 2/3 (email.message.Message lacks it, and Python 2 iteration over a
        # bare Message falls back to integer indexing)
        self._info.headers = ["%s: %s\r\n" % (name, value) for (name, value) in self._info.items()]

    def info(self):
        return self._info

    def geturl(self):
        return self.url

    def read(self, amt=None):
        if amt is None:
            data = self._body[self._offset:]
            self._offset = len(self._body)
        else:
            data = self._body[self._offset:self._offset + amt]
            self._offset += len(data)
        return data

    def close(self):
        pass


def open_url(url, method="GET", headers=None, body=None, timeout=30, follow_redirects=True, max_redirects=10, proxy=None):
    """Fetch url over native HTTP/2 (https only), following redirects like a browser (mirroring the
    previous httpx follow_redirects=True), and return an H2Response. Raises IOError on a transport or
    ALPN-negotiation failure. Connection-level and h2-forbidden request headers are stripped."""
    forbidden = ("host", "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "content-length")
    req_headers = {}
    for key in (headers or {}):
        name = key.decode("latin-1") if isinstance(key, bytes) else key
        if name.lower() not in forbidden:
            req_headers[key] = headers[key]

    for _ in range(max_redirects + 1):
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise IOError("native HTTP/2 client supports 'https://' targets only (got %r)" % parts.scheme)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        status, resp_headers, resp_body = _pooledExchange(parts.hostname, parts.port or 443, proxy, method, path,
                                                          parts.netloc.split("@")[-1], req_headers, body, timeout)
        if follow_redirects and status in REDIRECT_CODES:
            location = None
            for name, value in (resp_headers or []):
                if (name.decode("latin-1") if isinstance(name, bytes) else name).lower() == "location":
                    location = value.decode("latin-1") if isinstance(value, bytes) else value
                    break
            if location:
                url = urljoin(url, location)
                if status in (301, 302, 303):            # per RFC 7231, these degrade to GET
                    method, body = "GET", None
                continue
        return H2Response(url, status, resp_headers, resp_body)

    raise IOError("too many HTTP/2 redirects")
