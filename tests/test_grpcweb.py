#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

gRPC-Web body support (lib/utils/grpcweb.py, grpc-web-text/unary). Covers the peer-review merge gate:
exact round-trip, injection with length recomputation, strict framing validation (truncation / length
mismatch / trailing bytes / compression / bad varint / field 0), repeated-field distinct injection
points, response decoding incl. trailers-only-via-headers and response-Content-Type gating, and the
side-effect-free probe that lets a declined prompt send the original body.
"""

import base64
import json
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.data import conf
from lib.core.data import kb
from lib.utils import grpcweb

TEXT_CT = [("Content-Type", "application/grpc-web-text")]


def _grpcBody(fields):
    return base64.b64encode(grpcweb._frame(grpcweb._encode(fields))).decode("ascii")


class TestCodec(unittest.TestCase):
    def test_wire_roundtrip_exact(self):
        inner = grpcweb._encode([[1, 2, b"deep"], [2, 0, 7]])
        msg = grpcweb._encode([[1, 2, b"alice"], [2, 0, 10], [3, 2, inner], [4, 5, b"\x01\x02\x03\x04"]])
        self.assertEqual(grpcweb._encode(grpcweb._decode(msg)), msg)

    def test_varint_boundaries(self):
        for n in (0, 1, 127, 128, 300, 16384, 2 ** 31, 2 ** 63):
            self.assertEqual(grpcweb._readVarint(grpcweb._writeVarint(n), 0)[0], n)

    def test_overlong_varint_rejected(self):
        self.assertRaises(ValueError, grpcweb._readVarint, b"\x80" * 11, 0)

    def test_field_zero_rejected(self):
        self.assertRaises(ValueError, grpcweb._decode, b"\x02\x01a")  # tag 0x02 -> field 0, wire 2

    def test_truncated_field_rejected(self):
        self.assertRaises(ValueError, grpcweb._decode, b"\x0a\x05abc")  # declares 5, has 3

    def test_unframe_strict(self):
        good = grpcweb._frame(b"\x08\x01")
        self.assertEqual(grpcweb._unframe(good), b"\x08\x01")
        self.assertRaises(ValueError, grpcweb._unframe, good[:4])            # truncated header
        self.assertRaises(ValueError, grpcweb._unframe, good + b"\x00")      # trailing bytes
        self.assertRaises(ValueError, grpcweb._unframe, good[:-1])           # declared > available
        self.assertRaises(ValueError, grpcweb._unframe, b"\x01" + good[1:])  # compressed flag


class TestTranscode(unittest.TestCase):
    def setUp(self):
        self._h, self._g = conf.httpHeaders, kb.get("grpcWeb")
        conf.httpHeaders = list(TEXT_CT)
        kb.grpcWeb = None

    def tearDown(self):
        conf.httpHeaders, kb.grpcWeb = self._h, self._g

    def test_decode_is_side_effect_free(self):
        # probe must NOT touch kb.grpcWeb (that is what lets a declined prompt restore the original)
        view, skeleton = grpcweb.decodeBody(_grpcBody([[1, 2, b"alice"], [2, 0, 10]]))
        self.assertEqual(json.loads(view), {"f1": "alice"})
        self.assertIsNotNone(skeleton)
        self.assertIsNone(kb.grpcWeb)

    def test_exact_roundtrip_no_injection(self):
        body = _grpcBody([[1, 2, b"alice"], [2, 0, 10]])
        view, skeleton = grpcweb.decodeBody(body)
        kb.grpcWeb = skeleton
        self.assertEqual(grpcweb.encodeBody(view), body)   # merge-gate #11: encodeBody(decodeBody(x)) == x

    def test_injection_reencodes_with_correct_length(self):
        view, skeleton = grpcweb.decodeBody(_grpcBody([[1, 2, b"alice"], [2, 0, 10]]))
        kb.grpcWeb = skeleton
        wire = grpcweb.encodeBody(json.dumps({"f1": "alice' OR '1'='1"}))
        fields = grpcweb._decode(grpcweb._unframe(base64.b64decode(wire)))
        self.assertEqual(bytes(fields[0][2]).decode(), "alice' OR '1'='1")
        self.assertEqual(fields[1][2], 10)  # non-string field preserved

    def test_repeated_fields_distinct_points(self):
        view, _ = grpcweb.decodeBody(_grpcBody([[3, 2, b"first"], [3, 2, b"second"]]))
        self.assertEqual(json.loads(view), {"f3_0": "first", "f3_1": "second"})

    def test_parseable_strings_are_offered(self):
        # ordinary strings that ALSO happen to parse as protobuf wire data must NOT be silently dropped
        # ("A12345678" -> fixed64 tag, "M1234" -> fixed32 tag); descriptorless can't tell, so offer them
        view, _ = grpcweb.decodeBody(_grpcBody([[1, 2, b"A12345678"], [2, 2, b"M1234"]]))
        self.assertEqual(json.loads(view), {"f1": "A12345678", "f2": "M1234"})

    def test_non_grpc_and_binary_not_detected(self):
        conf.httpHeaders = [("Content-Type", "application/json")]
        self.assertEqual(grpcweb.decodeBody('{"a":"b"}'), (None, None))
        conf.httpHeaders = [("Content-Type", "application/grpc-web+proto")]   # binary: deliberately out of scope
        self.assertEqual(grpcweb.decodeBody(_grpcBody([[1, 2, b"x"]])), (None, None))

    def test_encode_guards_bad_surrogate(self):
        _, skeleton = grpcweb.decodeBody(_grpcBody([[1, 2, b"alice"]]))
        kb.grpcWeb = skeleton
        self.assertEqual(grpcweb.encodeBody("[1,2,3]"), "[1,2,3]")   # JSON scalar/array -> unchanged
        self.assertEqual(grpcweb.encodeBody("not json"), "not json")


class TestResponse(unittest.TestCase):
    def setUp(self):
        self._g = kb.get("grpcWeb")
        kb.grpcWeb = {"fields": [], "map": {}}   # any truthy skeleton enables response decoding

    def tearDown(self):
        kb.grpcWeb = self._g

    def _resp(self, frames, ct="application/grpc-web-text", extra=None):
        page = base64.b64encode(b"".join(frames)).decode("ascii") if frames else ""
        headers = {"Content-Type": ct}
        if extra:
            headers.update(extra)
        return grpcweb.decodeResponse(page, headers)

    def test_message_and_trailer_rendered(self):
        msg = grpcweb._frame(grpcweb._encode([[1, 0, 3], [2, 2, b"luther"]]))
        trailer = b"\x80" + struct.pack(">I", len(b"grpc-status:0")) + b"grpc-status:0"
        decoded = self._resp([msg, trailer])
        self.assertIn("3", decoded)
        self.assertIn("luther", decoded)
        self.assertIn("grpc-status:0", decoded)

    def test_backend_error_in_trailer(self):
        tmsg = b"grpc-status:13\r\ngrpc-message:SQLite%20error%3A%20near%20syntax"
        decoded = self._resp([b"\x80" + struct.pack(">I", len(tmsg)) + tmsg])
        self.assertIn("SQLite error: near syntax", decoded)   # unquoted -> matchable by errors.xml

    def test_trailers_only_via_headers(self):
        # empty body, status/message carried in response HEADERS (protocol-allowed trailers-only)
        decoded = grpcweb.decodeResponse("", {"Content-Type": "application/grpc-web-text",
                                              "grpc-status": "13", "grpc-message": "boom%20here"})
        self.assertIn("grpc-status:13", decoded)
        self.assertIn("boom here", decoded)

    def test_response_content_type_gating(self):
        # a non-grpc-web response (e.g. an HTML error page) must be left untouched
        page = base64.b64encode(grpcweb._frame(b"\x08\x01")).decode("ascii")
        self.assertEqual(grpcweb.decodeResponse(page, {"Content-Type": "text/html"}), page)

    def test_compressed_response_frame_falls_back(self):
        page = base64.b64encode(b"\x01" + struct.pack(">I", 2) + b"\x08\x01").decode("ascii")
        self.assertEqual(grpcweb.decodeResponse(page, {"Content-Type": "application/grpc-web-text"}), page)


class TestReviewRound2(unittest.TestCase):
    """The three second-round blockers + smaller hardening."""

    def setUp(self):
        self._h, self._g = conf.httpHeaders, kb.get("grpcWeb")
        conf.httpHeaders = list(TEXT_CT)
        kb.grpcWeb = None

    def tearDown(self):
        conf.httpHeaders, kb.grpcWeb = self._h, self._g

    def test_unrelated_json_body_not_converted(self):
        # blocker #1: an unrelated JSON body on the shared request path must pass through untouched
        _, skeleton = grpcweb.decodeBody(_grpcBody([[1, 2, b"alice"]]))
        kb.grpcWeb = skeleton
        self.assertEqual(grpcweb.encodeBody('{"foo":"bar"}'), '{"foo":"bar"}')      # different keys
        self.assertEqual(grpcweb.encodeBody('{"f1":"x","extra":"y"}'), '{"f1":"x","extra":"y"}')  # superset
        # but the genuine surrogate (exact keys) IS transformed
        self.assertNotEqual(grpcweb.encodeBody('{"f1":"x"}'), '{"f1":"x"}')

    def test_streaming_response_rejected(self):
        kb.grpcWeb = {"fields": [], "map": {}}
        two = grpcweb._frame(grpcweb._encode([[1, 2, b"a"]])) + grpcweb._frame(grpcweb._encode([[1, 2, b"b"]]))
        page = base64.b64encode(two).decode("ascii")
        self.assertEqual(grpcweb.decodeResponse(page, {"Content-Type": TEXT_CT[0][1]}), page)  # falls back, no corruption

    def test_reserved_frame_flags_rejected(self):
        # request: reserved flag byte -> not a valid gRPC-Web frame -> not detected
        bad = b"\x02" + struct.pack(">I", 3) + grpcweb._encode([[1, 2, b"x"]])
        self.assertRaises(ValueError, grpcweb._unframe, bad)
        # response: 0x82 (trailer + reserved bit) rejected -> fall back
        kb.grpcWeb = {"fields": [], "map": {}}
        page = base64.b64encode(b"\x82" + struct.pack(">I", 3) + b"a=0").decode("ascii")
        self.assertEqual(grpcweb.decodeResponse(page, {"Content-Type": TEXT_CT[0][1]}), page)

    def test_strict_base64(self):
        self.assertRaises(ValueError, grpcweb._b64decode, "!!!!")               # invalid chars
        self.assertRaises(ValueError, grpcweb._b64decode, "AAA")                # bad length
        self.assertRaises(ValueError, grpcweb._b64decode, "AAAA=BCD")           # stray mid-quantum pad
        # independently-padded chunks ARE accepted (reconstruct the concatenation) - a unary text
        # response may legitimately be flushed as separate padded base64 segments
        a, b = b"hello", b"world!!"
        chunks = base64.b64encode(a).decode("ascii") + base64.b64encode(b).decode("ascii")
        self.assertEqual(grpcweb._b64decode(chunks), a + b)

    def test_strict_media_type(self):
        conf.httpHeaders = [("Content-Type", "application/grpc-web-textual")]   # not the real type
        self.assertEqual(grpcweb.decodeBody(_grpcBody([[1, 2, b"x"]])), (None, None))
        conf.httpHeaders = [("Content-Type", "application/grpc-web-text; charset=utf-8")]  # params OK
        view, _ = grpcweb.decodeBody(_grpcBody([[1, 2, b"x"]]))
        self.assertIsNotNone(view)

    def test_header_status_preserved_on_body_failure(self):
        kb.grpcWeb = {"fields": [], "map": {}}
        raw = b"\x00" + struct.pack(">I", 5) + b"ab"   # declares 5, has 2 -> body parse fails
        page = base64.b64encode(raw).decode("ascii")
        decoded = grpcweb.decodeResponse(page, {"Content-Type": TEXT_CT[0][1], "grpc-status": "13"})
        self.assertIn("grpc-status:13", decoded)   # header status not lost
        self.assertIn(page, decoded)               # raw page still available to the oracle

    def test_varint_and_field_number_bounds(self):
        self.assertRaises(ValueError, grpcweb._readVarint, b"\xff" * 9 + b"\x02", 0)   # > 64 bits
        # field number above the protobuf max (2**29 - 1)
        big = grpcweb._writeVarint(((0x1fffffff + 1) << 3) | 2) + b"\x01a"
        self.assertRaises(ValueError, grpcweb._decode, big)


class TestReviewRound3(unittest.TestCase):
    """Media-type +proto acceptance, Accept negotiation helper, unsupported-CT body preservation."""

    def setUp(self):
        self._h, self._g = conf.httpHeaders, kb.get("grpcWeb")
        kb.grpcWeb = None

    def tearDown(self):
        conf.httpHeaders, kb.grpcWeb = self._h, self._g

    def test_proto_media_type_accepted(self):
        for ct in ("application/grpc-web-text+proto", "application/grpc-web-text+proto; charset=utf-8"):
            conf.httpHeaders = [("Content-Type", ct)]
            view, _ = grpcweb.decodeBody(_grpcBody([[1, 2, b"alice"]]))
            self.assertEqual(json.loads(view), {"f1": "alice"}, "CT %r not accepted" % ct)

    def test_accepts_text_content_type_helper(self):
        self.assertFalse(grpcweb.acceptsTextContentType("*/*"))
        self.assertFalse(grpcweb.acceptsTextContentType("application/json"))
        self.assertTrue(grpcweb.acceptsTextContentType("application/grpc-web-text"))
        self.assertTrue(grpcweb.acceptsTextContentType("application/json, application/grpc-web-text+proto"))

    def test_unsupported_response_ct_preserves_body_and_status(self):
        kb.grpcWeb = {"fields": [], "map": {}}
        page = base64.b64encode(grpcweb._frame(b"\x08\x01")).decode("ascii")
        decoded = grpcweb.decodeResponse(page, {"Content-Type": "text/html", "grpc-status": "2"})
        self.assertIn("grpc-status:2", decoded)   # header status kept
        self.assertIn(page, decoded)              # body not dropped
        # and with no status, an unsupported-CT body is returned unchanged
        self.assertEqual(grpcweb.decodeResponse(page, {"Content-Type": "text/html"}), page)

    def test_proto_response_ct_decoded(self):
        kb.grpcWeb = {"fields": [], "map": {}}
        msg = grpcweb._frame(grpcweb._encode([[2, 2, b"luther"]]))
        page = base64.b64encode(msg).decode("ascii")
        self.assertIn("luther", grpcweb.decodeResponse(page, {"Content-Type": "application/grpc-web-text+proto"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
