#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit coverage for the PURE (network-free) parts of the native HTTP/2 client in
lib/request/http2.py: the RFC 7540 frame codec, the RFC 7541 HPACK integer /
Huffman / string primitives, the HPACK Decoder/Encoder (static + dynamic table),
and the urllib-compatible H2Response wrapper.

Nothing here opens a socket or negotiates TLS - only the deterministic codecs and
the response adapter are exercised. Known vectors are the canonical RFC 7541
examples; everything else is a round-trip / invariant check.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import binascii
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.request.http2 import (
    Decoder,
    Encoder,
    H2Response,
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
)


def _b(*ints):
    # build a bytes object from ints (identical on Python 2 and 3)
    return bytes(bytearray(ints))


class TestFrameCodec(unittest.TestCase):
    def test_roundtrip(self):
        header = encode_frame(HEADERS, FLAG_END_HEADERS, 1, b"abc")[:9]
        self.assertEqual(decode_frame_header(header), (3, HEADERS, FLAG_END_HEADERS, 1))

    def test_payload_is_appended_verbatim(self):
        frame = encode_frame(DATA, 0, 1, b"hello")
        self.assertEqual(frame[9:], b"hello")

    def test_reserved_stream_bit_is_masked(self):
        # the high (reserved) bit of the 31-bit stream id must be dropped on both ends
        header = encode_frame(DATA, 0, 0x80000001, b"")[:9]
        self.assertEqual(decode_frame_header(header), (0, DATA, 0, 1))

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
        with self.assertRaises(ValueError):
            huffman_decode(_b(0xFE))


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
        with self.assertRaises(ValueError):
            Decoder()._get(0)

    def test_index_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
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
