#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Coverage for the native HTTP/2 client in lib/request/http2.py: frame and HPACK
codecs, request/response validation, connection state, flow control, retries,
URL handling, TLS policy, and the urllib-compatible H2Response wrapper.

Most tests are deterministic and network-free. When python-hyper/h2 is installed,
two optional socketpair tests exercise an end-to-end local HTTP/2 peer; they never
use the external network. Known vectors are the canonical RFC 7541 examples.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import binascii
import os
import socket
import ssl
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.request import http2 as _http2
from lib.request.http2 import (
    Decoder,
    Encoder,
    H2CompressionError,
    H2Error,
    H2ProtocolError,
    H2TransportError,
    H2Response,
    MAX_INFORMATIONAL_RESPONSES,
    DEFAULT_MAX_FRAME_SIZE,
    DEFAULT_WINDOW,
    LOCAL_INITIAL_WINDOW,
    SETTINGS_ENABLE_PUSH,
    GOAWAY,
    CONTINUATION,
    REDIRECT_CODES,
    STATIC_LEN,
    STATIC_TABLE,
    DATA,
    HEADERS,
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    decode_frame_header,
    decode_integer,
    decode_string,
    encode_frame,
    encode_integer,
    encode_string,
    huffman_decode,
    huffman_encode,
    _H2Connection,
    _authority_for_host,
    _make_ssl_context,
    _parse_content_length,
    _request_header_list,
    _validate_response_field_section,
)

try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection as ReferenceH2Connection
    from h2.events import DataReceived, RequestReceived, StreamEnded
    HAVE_H2 = True
except ImportError:
    HAVE_H2 = False


def _b(*ints):
    # build a bytes object from ints (identical on Python 2 and 3)
    return bytes(bytearray(ints))


class _FakeSocket(object):
    def __init__(self, incoming=b""):
        self.incoming = bytearray(incoming)
        self.sent = []
        self.timeout = None
        self.closed = False

    def recv(self, size):
        if not self.incoming:
            return b""
        chunk = bytes(self.incoming[:size])
        del self.incoming[:size]
        return chunk

    def sendall(self, data):
        self.sent.append(bytes(data))

    def settimeout(self, timeout):
        self.timeout = timeout

    def close(self):
        self.closed = True


def _bare_connection(incoming=b""):
    conn = object.__new__(_H2Connection)
    conn.host = "example.test"
    conn.port = 443
    conn.proxy = None
    conn.dec = Decoder()
    conn.next_sid = 1
    conn.usable = True
    conn.sock = _FakeSocket(incoming)
    conn.peer_max_frame_size = DEFAULT_MAX_FRAME_SIZE
    conn.peer_initial_window = DEFAULT_WINDOW
    conn.peer_max_concurrent_streams = None
    conn.peer_max_header_list_size = None
    conn.conn_send_window = DEFAULT_WINDOW
    conn.conn_recv_window = LOCAL_INITIAL_WINDOW
    conn.stream_send_windows = {}
    conn.local_max_frame_size = DEFAULT_MAX_FRAME_SIZE
    conn._our_settings_acked = False
    return conn


def _response_block(status=b"200", extra=()):
    return Encoder().encode([(b":status", status)] + list(extra))


def _frames_from_bytes(data):
    result = []
    pos = 0
    while pos < len(data):
        length, ftype, flags, sid = decode_frame_header(data[pos:pos + 9])
        pos += 9
        payload = data[pos:pos + length]
        pos += length
        result.append((ftype, flags, sid, payload))
    if pos != len(data):
        raise AssertionError("trailing frame bytes")
    return result


class TestFrameCodec(unittest.TestCase):
    def test_roundtrip(self):
        header = encode_frame(HEADERS, FLAG_END_HEADERS, 1, b"abc")[:9]
        self.assertEqual(decode_frame_header(header), (3, HEADERS, FLAG_END_HEADERS, 1))

    def test_payload_is_appended_verbatim(self):
        frame = encode_frame(DATA, 0, 1, b"hello")
        self.assertEqual(frame[9:], b"hello")

    def test_reserved_stream_bit_is_masked(self):
        # the high (reserved) bit of the 31-bit stream id is rejected
        with self.assertRaises(ValueError):
            encode_frame(DATA, 0, 0x80000001, b"")

    def test_zero_length_payload(self):
        header = encode_frame(DATA, FLAG_END_STREAM, 1, b"")[:9]
        length, _, flags, _ = decode_frame_header(header)
        self.assertEqual(length, 0)
        self.assertEqual(flags, FLAG_END_STREAM)

    def test_oversized_payload_rejected(self):
        with self.assertRaises(ValueError):
            encode_frame(DATA, 0, 1, b"x" * (0xFFFFFF + 1))

    def test_bad_header_length_rejected(self):
        with self.assertRaises(ValueError):
            decode_frame_header(b"123")


class TestIntegerCoding(unittest.TestCase):
    def test_rfc_c11_small(self):
        # RFC 7541 C.1.1: 10 with a 5-bit prefix fits in the prefix
        self.assertEqual(list(encode_integer(10, 5)), [10])

    def test_rfc_c12_multibyte(self):
        # RFC 7541 C.1.2: 1337 with a 5-bit prefix
        self.assertEqual(list(encode_integer(1337, 5)), [31, 154, 10])
        self.assertEqual(decode_integer(bytearray([31, 154, 10]), 0, 5), (1337, 3))

    def test_rfc_c13_full_byte_prefix(self):
        # RFC 7541 C.1.3: 42 starting from a full (8-bit prefix at an octet boundary)
        self.assertEqual(list(encode_integer(42, 8)), [42])

    def test_roundtrip_across_prefixes(self):
        for prefix in (4, 5, 6, 7, 8):
            for value in (0, 1, 2, 30, 31, 32, 127, 128, 255, 256, 16384, 1000000):
                encoded = bytearray(encode_integer(value, prefix))
                decoded, pos = decode_integer(encoded, 0, prefix)
                self.assertEqual(decoded, value)
                self.assertEqual(pos, len(encoded))

    def test_first_byte_bits_preserved(self):
        # a caller-supplied opcode in the high bits must survive a small value
        self.assertEqual(bytearray(encode_integer(5, 7, 0x80))[0], 0x80 | 5)

    def test_negative_value_rejected(self):
        with self.assertRaises(ValueError):
            encode_integer(-1, 5)

    def test_truncated_multibyte_integer_rejected(self):
        with self.assertRaises(H2CompressionError):
            decode_integer(bytearray([31, 0x80]), 0, 5)

    def test_overlong_integer_rejected(self):
        with self.assertRaises(H2CompressionError):
            decode_integer(bytearray([31, 0x80, 0x80, 0x80, 0x80, 0x80, 0]), 0, 5)


class TestHuffman(unittest.TestCase):
    def test_known_vector_www_example_com(self):
        # RFC 7541 C.4.1
        self.assertEqual(binascii.hexlify(huffman_encode(b"www.example.com")), b"f1e3c2e5f23a6ba0ab90f4ff")

    def test_empty(self):
        self.assertEqual(huffman_encode(b""), b"")
        self.assertEqual(huffman_decode(b""), b"")

    def test_roundtrip(self):
        for sample in (b"a", b"hello world", b"/index.html?a=1&b=2",
                       b"GET", b"application/json", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                       bytes(bytearray(range(256)))):
            self.assertEqual(huffman_decode(huffman_encode(sample)), sample)

    def test_shrinks_typical_text(self):
        sample = b"www.example.com"
        self.assertLess(len(huffman_encode(sample)), len(sample))

    def test_padding_too_long_rejected(self):
        # 0xfe walks eight 1-bits into a long (unterminated) code -> more than a byte of padding
        with self.assertRaises(H2CompressionError):
            huffman_decode(_b(0xFE))

    def test_non_eos_padding_rejected(self):
        with self.assertRaises(H2CompressionError):
            huffman_decode(b"\x00")


class TestStringCoding(unittest.TestCase):
    def test_huffman_branch_roundtrip(self):
        encoded = encode_string(b"custom-value")
        self.assertTrue(bytearray(encoded)[0] & 0x80)          # huffman flag set for compressible text
        self.assertEqual(decode_string(bytearray(encoded), 0), (b"custom-value", len(encoded)))

    def test_literal_branch_when_huffman_would_not_shrink(self):
        encoded = encode_string(_b(0xFF))
        self.assertFalse(bytearray(encoded)[0] & 0x80)         # falls back to a literal string
        self.assertEqual(decode_string(bytearray(encoded), 0), (_b(0xFF), len(encoded)))

    def test_disable_huffman(self):
        encoded = encode_string(b"abc", huffman=False)
        self.assertFalse(bytearray(encoded)[0] & 0x80)
        self.assertEqual(decode_string(bytearray(encoded), 0), (b"abc", len(encoded)))

    def test_truncated_string_rejected(self):
        with self.assertRaises(H2CompressionError):
            decode_string(bytearray(b"\x03ab"), 0)


class TestHpackDecoder(unittest.TestCase):
    def test_indexed_static_entries(self):
        # 0x82/0x86/0x84 -> static indices 2, 6, 4
        self.assertEqual(
            Decoder().decode(_b(0x82, 0x86, 0x84)),
            [(b":method", b"GET"), (b":scheme", b"http"), (b":path", b"/")],
        )

    def test_static_lookup_bounds(self):
        d = Decoder()
        self.assertEqual(d._get(1), (b":authority", b""))
        self.assertEqual(d._get(2), (b":method", b"GET"))
        self.assertEqual(d._get(STATIC_LEN), STATIC_TABLE[-1])

    def test_index_zero_rejected(self):
        with self.assertRaises(H2CompressionError):
            Decoder()._get(0)

    def test_index_out_of_range_rejected(self):
        with self.assertRaises(H2CompressionError):
            Decoder()._get(STATIC_LEN + 1)     # no dynamic entries yet

    def test_literal_incremental_indexing_populates_dynamic_table(self):
        # 0x40 = literal with incremental indexing, new name
        block = bytearray([0x40]) + encode_string(b"custom-key") + encode_string(b"custom-value")
        d = Decoder()
        self.assertEqual(d.decode(bytes(block)), [(b"custom-key", b"custom-value")])
        # entry is now addressable at the first dynamic index (STATIC_LEN + 1)
        self.assertEqual(d._get(STATIC_LEN + 1), (b"custom-key", b"custom-value"))
        self.assertEqual(d._size, 32 + len(b"custom-key") + len(b"custom-value"))

    def test_literal_without_indexing_does_not_touch_dynamic_table(self):
        block = bytearray([0x00]) + encode_string(b"k") + encode_string(b"v")
        d = Decoder()
        self.assertEqual(d.decode(bytes(block)), [(b"k", b"v")])
        self.assertEqual(d.dynamic, [])

    def test_dynamic_table_eviction(self):
        d = Decoder(max_size=40)               # each 2+2 byte entry costs 32+2+2 = 36
        d._add(b"aa", b"bb")
        self.assertEqual(len(d.dynamic), 1)
        d._add(b"cc", b"dd")                   # 72 > 40 -> oldest evicted
        self.assertEqual(d.dynamic, [(b"cc", b"dd")])
        self.assertEqual(d._size, 36)

    def test_dynamic_size_update_clears(self):
        d = Decoder()
        d._add(b"x", b"y")
        d.decode(_b(0x20))                     # 0x20 = dynamic table size update to 0
        self.assertEqual(d.max_size, 0)
        self.assertEqual(d.dynamic, [])

    def test_oversized_dynamic_size_update_rejected(self):
        update = bytes(encode_integer(4097, 5, 0x20))
        with self.assertRaises(H2CompressionError):
            Decoder().decode(update)

    def test_late_dynamic_size_update_rejected(self):
        block = _b(0x82) + bytes(encode_integer(0, 5, 0x20))
        with self.assertRaises(H2CompressionError):
            Decoder().decode(block)

    def test_decoded_header_list_limit(self):
        block = bytearray([0x00]) + encode_string(b"name") + encode_string(b"value")
        with self.assertRaises(H2CompressionError):
            Decoder(max_header_list_size=1).decode(bytes(block))


class TestHpackEncoderRoundTrip(unittest.TestCase):
    def test_roundtrip_through_decoder(self):
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":path", b"/a/b?c=d"),
            (b":authority", b"example.com"),
            (b"user-agent", b"sqlmap"),
            (b"accept", b""),                  # empty value
            (b"x-custom", b"\x00\x01\xff"),    # non-ASCII value
        ]
        self.assertEqual(Decoder().decode(Encoder().encode(headers)), headers)

    def test_encoder_output_is_bytes(self):
        self.assertIsInstance(Encoder().encode([(b"a", b"b")]), bytes)


class TestH2Response(unittest.TestCase):
    def _make(self, status=200, headers=None, body=b"body"):
        headers = headers if headers is not None else [(b":status", b"200"), (b"content-type", b"text/html")]
        return H2Response("https://target/x", status, headers, body)

    def test_basic_fields(self):
        r = self._make()
        self.assertEqual(r.code, 200)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.msg, "OK")
        self.assertEqual(r.http_version, "HTTP/2.0")
        self.assertEqual(r.geturl(), "https://target/x")

    def test_unknown_status_message(self):
        self.assertEqual(self._make(status=799).msg, "")

    def test_pseudo_headers_stripped(self):
        r = self._make()
        self.assertNotIn(":status", r.info())
        self.assertEqual(r.info().get("content-type"), "text/html")

    def test_read_full_then_empty(self):
        r = self._make(body=b"hello")
        self.assertEqual(r.read(), b"hello")
        self.assertEqual(r.read(), b"")            # offset exhausted

    def test_read_in_chunks(self):
        r = self._make(body=b"abcdef")
        self.assertEqual(r.read(2), b"ab")
        self.assertEqual(r.read(3), b"cde")
        self.assertEqual(r.read(10), b"f")         # asking past the end returns the remainder
        self.assertEqual(r.read(10), b"")

    def test_str_header_names_accepted(self):
        # headers may arrive already decoded to str (not only bytes)
        r = H2Response("https://t/", 200, [("content-type", "application/json")], b"{}")
        self.assertEqual(r.info().get("content-type"), "application/json")

    def test_mimetools_style_headers_list(self):
        # patchHeaders() relies on a '.headers' list of "Name: value\r\n" lines being present
        r = self._make()
        self.assertTrue(hasattr(r.info(), "headers"))
        self.assertIn("content-type: text/html\r\n", r.info().headers)

    def test_close_is_noop(self):
        self.assertIsNone(self._make().close())

    def test_negative_read_reads_all_remaining(self):
        r = self._make(body=b"abcdef")
        self.assertEqual(r.read(2), b"ab")
        self.assertEqual(r.read(-1), b"cdef")
        self.assertEqual(r.read(), b"")


class TestRequestValidation(unittest.TestCase):
    def test_method_case_is_preserved(self):
        headers = _request_header_list("foo", "/", "example.test", None, b"")
        self.assertEqual(headers[0], (b":method", b"foo"))

    def test_lowercase_connect_is_not_rewritten(self):
        headers = _request_header_list("connect", "/x", "example.test", None, b"")
        self.assertIn((b":scheme", b"https"), headers)
        self.assertIn((b":path", b"/x"), headers)

    def test_exact_connect_uses_connect_pseudo_fields(self):
        headers = _request_header_list("CONNECT", "ignored", "example.test:443", None, b"")
        self.assertEqual(headers[:2], [(b":method", b"CONNECT"), (b":authority", b"example.test:443")])
        self.assertNotIn((b":scheme", b"https"), headers)

    def test_invalid_method_rejected(self):
        with self.assertRaises(H2ProtocolError):
            _request_header_list("GE\rT", "/", "example.test", None, b"")

    def test_invalid_path_rejected(self):
        with self.assertRaises(H2ProtocolError):
            _request_header_list("GET", "/bad\x00path", "example.test", None, b"")

    def test_invalid_authority_rejected(self):
        with self.assertRaises(H2ProtocolError):
            _request_header_list("GET", "/", "x\r\ny", None, b"")

    def test_connection_fields_and_nominees_are_removed(self):
        headers = _request_header_list(
            "GET", "/", "example.test",
            [("Connection", "x-remove"), ("X-Remove", "yes"), ("X-Keep", "yes")], b""
        )
        self.assertNotIn((b"connection", b"x-remove"), headers)
        self.assertNotIn((b"x-remove", b"yes"), headers)
        self.assertIn((b"x-keep", b"yes"), headers)

    def test_invalid_te_rejected(self):
        with self.assertRaises(H2ProtocolError):
            _request_header_list("GET", "/", "example.test", {"TE": "gzip"}, b"")

    def test_content_length_mismatch_rejected(self):
        with self.assertRaises(H2ProtocolError):
            _request_header_list("POST", "/", "example.test", {"Content-Length": "4"}, b"abc")

    def test_duplicate_content_length_is_collapsed(self):
        headers = _request_header_list(
            "POST", "/", "example.test",
            [("Content-Length", "3"), ("content-length", "3")], b"abc"
        )
        self.assertEqual([item for item in headers if item[0] == b"content-length"], [(b"content-length", b"3")])


class TestAuthorityHandling(unittest.TestCase):
    def test_default_port_is_omitted(self):
        self.assertEqual(_authority_for_host("example.test", 443), "example.test")

    def test_nondefault_port_is_included(self):
        self.assertEqual(_authority_for_host("example.test", 8443), "example.test:8443")

    def test_ipv6_is_bracketed(self):
        self.assertEqual(_authority_for_host("2001:db8::1", 8443), "[2001:db8::1]:8443")

    def test_idna_host_is_ascii(self):
        self.assertEqual(_authority_for_host(u"t\u00e4st.example", 443), "xn--tst-qla.example")


class TestResponseValidation(unittest.TestCase):
    def test_identical_content_lengths_are_accepted(self):
        headers = [(b":status", b"200"), (b"content-length", b"3"), (b"content-length", b"3")]
        self.assertEqual(_parse_content_length(headers), 3)

    def test_comma_joined_identical_content_lengths_are_accepted(self):
        self.assertEqual(_parse_content_length([(b"content-length", b"3, 3")]), 3)

    def test_conflicting_content_lengths_are_rejected(self):
        with self.assertRaises(H2ProtocolError):
            _parse_content_length([(b"content-length", b"1"), (b"content-length", b"2")])

    def test_invalid_status_range_is_rejected(self):
        with self.assertRaises(H2ProtocolError):
            _validate_response_field_section([(b":status", b"799")])

    def test_content_length_in_trailers_is_rejected(self):
        with self.assertRaises(H2ProtocolError):
            _validate_response_field_section([(b"content-length", b"0")], trailers=True)


class TestConnectionState(unittest.TestCase):
    def _exchange(self, incoming, method="GET", body=None):
        conn = _bare_connection(incoming)
        return conn, conn.exchange(method, "/", "example.test", {}, body, 1)

    def test_end_stream_headers_wait_for_continuation(self):
        block = _response_block(b"200", [(b"x-test", b"ok")])
        cut = max(1, len(block) // 2)
        incoming = (
            encode_frame(HEADERS, FLAG_END_STREAM, 1, block[:cut]) +
            encode_frame(CONTINUATION, FLAG_END_HEADERS, 1, block[cut:])
        )
        conn, result = self._exchange(incoming)
        self.assertEqual(result[0], 200)
        self.assertIn((b"x-test", b"ok"), result[1])
        self.assertEqual(conn.sock.incoming, bytearray())

    def test_content_length_short_body_is_rejected(self):
        incoming = (
            encode_frame(HEADERS, FLAG_END_HEADERS, 1, _response_block(b"200", [(b"content-length", b"4")])) +
            encode_frame(DATA, FLAG_END_STREAM, 1, b"abc")
        )
        with self.assertRaises(H2ProtocolError):
            self._exchange(incoming)

    def test_content_length_long_body_is_rejected(self):
        incoming = (
            encode_frame(HEADERS, FLAG_END_HEADERS, 1, _response_block(b"200", [(b"content-length", b"2")])) +
            encode_frame(DATA, FLAG_END_STREAM, 1, b"abc")
        )
        with self.assertRaises(H2ProtocolError):
            self._exchange(incoming)

    def test_204_body_is_rejected(self):
        incoming = (
            encode_frame(HEADERS, FLAG_END_HEADERS, 1, _response_block(b"204")) +
            encode_frame(DATA, FLAG_END_STREAM, 1, b"not allowed")
        )
        with self.assertRaises(H2ProtocolError):
            self._exchange(incoming)

    def test_204_content_length_is_rejected(self):
        incoming = encode_frame(
            HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1,
            _response_block(b"204", [(b"content-length", b"0")])
        )
        with self.assertRaises(H2ProtocolError):
            self._exchange(incoming)

    def test_head_body_is_rejected(self):
        incoming = (
            encode_frame(HEADERS, FLAG_END_HEADERS, 1, _response_block(b"200")) +
            encode_frame(DATA, FLAG_END_STREAM, 1, b"body")
        )
        with self.assertRaises(H2ProtocolError):
            self._exchange(incoming, method="HEAD")

    def test_informational_responses_are_bounded(self):
        early = encode_frame(HEADERS, FLAG_END_HEADERS, 1, _response_block(b"103"))
        incoming = early * (MAX_INFORMATIONAL_RESPONSES + 1)
        with self.assertRaises(H2Error):
            self._exchange(incoming)

    def test_receive_flow_control_is_enforced(self):
        incoming = (
            encode_frame(HEADERS, FLAG_END_HEADERS, 1, _response_block(b"200")) +
            encode_frame(DATA, FLAG_END_STREAM, 1, b"ab")
        )
        conn = _bare_connection(incoming)
        conn.conn_recv_window = 1
        with self.assertRaises(H2ProtocolError):
            conn.exchange("GET", "/", "example.test", {}, None, 1)

    def test_large_request_is_fragmented(self):
        incoming = encode_frame(
            HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, _response_block(b"200")
        )
        conn, result = self._exchange(incoming, method="POST", body=b"x" * 20000)
        self.assertEqual(result[0], 200)
        frames = _frames_from_bytes(b"".join(conn.sock.sent))
        lengths = [len(payload) for ftype, _, _, payload in frames if ftype == DATA]
        self.assertEqual(lengths, [16384, 3616])

    def test_goaway_uses_first_payload_word_as_last_stream_id(self):
        incoming = (
            encode_frame(GOAWAY, 0, 0, struct.pack("!II", 1, 0)) +
            encode_frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, _response_block(b"200"))
        )
        conn, result = self._exchange(incoming)
        self.assertEqual(result[0], 200)
        self.assertFalse(conn.usable)

    def test_trailers_are_decoded_as_separate_field_section(self):
        incoming = (
            encode_frame(HEADERS, FLAG_END_HEADERS, 1, _response_block(b"200", [(b"content-length", b"4")])) +
            encode_frame(DATA, 0, 1, b"body") +
            encode_frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, Encoder().encode([(b"x-trailer", b"done")]))
        )
        _, result = self._exchange(incoming)
        self.assertEqual(result[2], b"body")
        self.assertIn((b"x-trailer", b"done"), result[1])

    def test_server_settings_enable_push_zero_is_accepted(self):
        conn = _bare_connection()
        payload = struct.pack("!HI", SETTINGS_ENABLE_PUSH, 0)
        conn._handle_settings(0, 0, payload)
        self.assertTrue(conn.sock.sent)

    def test_server_settings_enable_push_one_is_rejected(self):
        conn = _bare_connection()
        payload = struct.pack("!HI", SETTINGS_ENABLE_PUSH, 1)
        with self.assertRaises(H2ProtocolError):
            conn._handle_settings(0, 0, payload)


class TestTlsPolicy(unittest.TestCase):
    def setUp(self):
        if not hasattr(ssl.SSLContext, "set_alpn_protocols"):
            self.skipTest("ALPN is unavailable")

    def test_verification_is_disabled_by_default_context(self):
        context = _make_ssl_context(False, None)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(getattr(context, "check_hostname", False))

    def test_verification_can_be_enabled(self):
        if not hasattr(ssl, "create_default_context"):
            self.skipTest("verified contexts are unavailable")
        context = _make_ssl_context(True, None)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_tls_minimum_is_12_when_supported(self):
        context = _make_ssl_context(False, None)
        tls_version = getattr(ssl, "TLSVersion", None)
        if tls_version is None or not hasattr(context, "minimum_version"):
            self.skipTest("minimum_version is unavailable")
        self.assertGreaterEqual(context.minimum_version, tls_version.TLSv1_2)


class TestRedirectHandling(unittest.TestCase):
    def _run_with_fake_exchange(self, responses, **kwargs):
        calls = []
        original = _http2._pooledExchange

        def fake(host, port, proxy, method, path, authority, headers, body, timeout,
                 verify=False, ssl_context=None):
            calls.append((host, port, method, path, authority, list(_http2._iter_header_items(headers)), body))
            return responses[len(calls) - 1]

        _http2._pooledExchange = fake
        try:
            response = _http2.open_url(**kwargs)
        finally:
            _http2._pooledExchange = original
        return response, calls

    def test_custom_method_is_not_case_normalized_on_redirect(self):
        responses = [
            (302, [(b":status", b"302"), (b"location", b"/next")], b""),
            (200, [(b":status", b"200")], b"ok"),
        ]
        response, calls = self._run_with_fake_exchange(
            responses, url="https://example.test/start", method="post", headers={}, body=b"x"
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(calls[1][2], "post")
        self.assertEqual(calls[1][6], b"x")

    def test_post_302_becomes_get_and_drops_entity_headers(self):
        responses = [
            (302, [(b":status", b"302"), (b"location", b"/next")], b""),
            (200, [(b":status", b"200")], b"ok"),
        ]
        _, calls = self._run_with_fake_exchange(
            responses,
            url="https://example.test/start",
            method="POST",
            headers=[("Content-Type", "text/plain"), ("X-Keep", "yes")],
            body=b"x",
        )
        self.assertEqual(calls[1][2], "GET")
        self.assertIsNone(calls[1][6])
        names = [key.lower() for key, _ in calls[1][5]]
        self.assertNotIn("content-type", names)
        self.assertIn("x-keep", names)

    def test_cross_origin_redirect_strips_all_credentials(self):
        responses = [
            (307, [(b":status", b"307"), (b"location", b"https://other.test/final")], b""),
            (200, [(b":status", b"200")], b"ok"),
        ]
        _, calls = self._run_with_fake_exchange(
            responses,
            url="https://example.test/start",
            method="GET",
            headers=[("Authorization", "a"), ("Cookie", "b"), ("Authorization", "c"), ("X-Keep", "yes")],
        )
        names = [key.lower() for key, _ in calls[1][5]]
        self.assertNotIn("authorization", names)
        self.assertNotIn("cookie", names)
        self.assertIn("x-keep", names)

    def test_idna_and_nondefault_port_authority(self):
        responses = [(200, [(b":status", b"200")], b"ok")]
        _, calls = self._run_with_fake_exchange(
            responses, url=u"https://t\u00e4st.example:8443/path", method="GET"
        )
        self.assertEqual(calls[0][0], "xn--tst-qla.example")
        self.assertEqual(calls[0][1], 8443)
        self.assertEqual(calls[0][4], "xn--tst-qla.example:8443")


class TestPoolRetries(unittest.TestCase):
    class _Connection(object):
        def __init__(self, outcomes):
            self.outcomes = outcomes
            self.usable = True
            self.closed = False

        def exchange(self, *args):
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        def close(self):
            self.closed = True
            self.usable = False

    def setUp(self):
        _http2.close_pooled_connections()

    def tearDown(self):
        _http2.close_pooled_connections()

    def _install_factory(self, connections):
        original = _http2._H2Connection

        def factory(*args, **kwargs):
            return connections.pop(0)

        _http2._H2Connection = factory
        return original

    def test_reused_get_is_retried_after_transport_eof(self):
        first = self._Connection([
            (200, [(b":status", b"200")], b"first"),
            H2TransportError("stale"),
        ])
        second = self._Connection([(200, [(b":status", b"200")], b"second")])
        original = self._install_factory([first, second])
        try:
            _http2._pooledExchange("x", 443, None, "GET", "/", "x", {}, None, 1)
            result = _http2._pooledExchange("x", 443, None, "GET", "/", "x", {}, None, 1)
        finally:
            _http2._H2Connection = original
        self.assertEqual(result[2], b"second")
        self.assertTrue(first.closed)

    def test_reused_post_is_not_retried_after_transport_eof(self):
        first = self._Connection([
            (200, [(b":status", b"200")], b"first"),
            H2TransportError("stale"),
        ])
        original = self._install_factory([first])
        try:
            _http2._pooledExchange("x", 443, None, "POST", "/", "x", {}, b"a", 1)
            with self.assertRaises(H2TransportError):
                _http2._pooledExchange("x", 443, None, "POST", "/", "x", {}, b"a", 1)
        finally:
            _http2._H2Connection = original


@unittest.skipUnless(HAVE_H2, "python-hyper/h2 is not installed")
class TestLocalH2Peer(unittest.TestCase):
    class _WrappedSocket(object):
        def __init__(self, raw):
            self.raw = raw

        def selected_alpn_protocol(self):
            return "h2"

        def version(self):
            return "TLSv1.2"

        def compression(self):
            return None

        def __getattr__(self, name):
            return getattr(self.raw, name)

    class _FakeContext(object):
        def wrap_socket(self, raw, server_hostname=None):
            return TestLocalH2Peer._WrappedSocket(raw)

    def _with_peer(self, server_target, client_target):
        client_raw, server_raw = socket.socketpair()
        errors = []

        def run_server():
            try:
                server_target(server_raw)
            except Exception as ex:
                errors.append(ex)
            finally:
                server_raw.close()

        original_connect = _http2._connect_socket
        original_context = _http2._make_ssl_context
        _http2._connect_socket = lambda *args, **kwargs: client_raw
        _http2._make_ssl_context = lambda *args, **kwargs: self._FakeContext()
        thread = threading.Thread(target=run_server)
        thread.start()
        try:
            result = client_target()
        finally:
            _http2._connect_socket = original_connect
            _http2._make_ssl_context = original_context
            client_raw.close()
            thread.join(5)
        if thread.is_alive():
            self.fail("local HTTP/2 peer did not terminate")
        if errors:
            raise errors[0]
        return result

    def test_large_post_flow_control_and_method_preservation(self):
        observed = {"headers": None, "body": bytearray()}

        def server(raw):
            h2 = ReferenceH2Connection(config=H2Configuration(client_side=False, header_encoding=None))
            h2.initiate_connection()
            raw.sendall(h2.data_to_send())
            done = False
            while not done:
                data = raw.recv(65536)
                if not data:
                    break
                for event in h2.receive_data(data):
                    if isinstance(event, RequestReceived):
                        observed["headers"] = event.headers
                    elif isinstance(event, DataReceived):
                        observed["body"].extend(event.data)
                        h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded):
                        h2.send_headers(event.stream_id, [(b":status", b"200"), (b"content-length", b"2")])
                        h2.send_data(event.stream_id, b"ok", end_stream=True)
                        done = True
                outbound = h2.data_to_send()
                if outbound:
                    raw.sendall(outbound)

        def client():
            conn = _H2Connection("example.test", 443, None, 5)
            try:
                return conn.exchange("foo", "/upload", "example.test", {}, b"x" * 100000, 5)
            finally:
                conn.close()

        result = self._with_peer(server, client)
        self.assertEqual(result[0], 200)
        self.assertEqual(result[2], b"ok")
        self.assertEqual(len(observed["body"]), 100000)
        self.assertIn((b":method", b"foo"), observed["headers"])

    def test_exchange_pair_reports_completion_order(self):
        def server(raw):
            h2 = ReferenceH2Connection(config=H2Configuration(client_side=False, header_encoding=None))
            h2.initiate_connection()
            raw.sendall(h2.data_to_send())
            ended = []
            while len(ended) < 2:
                data = raw.recv(65536)
                if not data:
                    break
                for event in h2.receive_data(data):
                    if isinstance(event, StreamEnded):
                        ended.append(event.stream_id)
                outbound = h2.data_to_send()
                if outbound:
                    raw.sendall(outbound)
            for sid in reversed(ended):
                h2.send_headers(sid, [(b":status", b"200")], end_stream=True)
            raw.sendall(h2.data_to_send())

        def client():
            conn = _H2Connection("example.test", 443, None, 5)
            try:
                return conn.exchange_pair([
                    {"method": "GET", "path": "/first"},
                    {"method": "GET", "path": "/second"},
                ], 5)
            finally:
                conn.close()

        order, results = self._with_peer(server, client)
        self.assertEqual(order, [3, 1])
        self.assertEqual(results[1][0], 200)
        self.assertEqual(results[3][0], 200)


class TestConstants(unittest.TestCase):
    def test_redirect_codes(self):
        for code in (301, 302, 303, 307, 308):
            self.assertIn(code, REDIRECT_CODES)
        self.assertNotIn(200, REDIRECT_CODES)

    def test_static_table_length(self):
        self.assertEqual(STATIC_LEN, len(STATIC_TABLE))
        self.assertEqual(STATIC_LEN, 61)           # RFC 7541 Appendix A


if __name__ == "__main__":
    unittest.main(verbosity=2)
