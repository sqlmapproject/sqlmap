#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import base64
import json
import re
import struct

from lib.core.data import conf
from lib.core.data import kb
from lib.core.enums import HTTP_HEADER
from thirdparty.six.moves.urllib.parse import unquote

# gRPC-Web body support (grpc-web-text / base64, unary only). A gRPC-Web message is a length-prefixed
# protobuf frame; grpc-web-text is that frame base64-encoded. Because protobuf is length-prefixed and
# sqlmap injects by appending, the body is decoded to a JSON view of its (heuristically-detected) string
# fields so the existing JSON injection engine handles marking/placement, then re-encoded with corrected
# length prefixes at send time (see connect.py). NOT supported (deliberately not detected, never
# corrupted): binary application/grpc-web+proto, compression (grpc-encoding), and streaming.

CONTENT_TYPE = "application/grpc-web-text"
CONTENT_TYPE_PROTO = "application/grpc-web-text+proto"  # equivalent spelling (message format hint)
_MAX_VARINT_BYTES = 10          # a 64-bit varint is at most 10 bytes
_MAX_FIELD_NUMBER = 0x1fffffff  # protobuf maximum field number (2**29 - 1)
_BASE64_QUANTUM_REGEX = re.compile(r"\A(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)\Z")

def _b64decode(text):
    # strict, py2/py3-safe (no 'validate=' kwarg): reject whitespace/invalid chars, but decode per 4-char
    # quantum so INDEPENDENTLY-padded base64 chunks (allowed even for a unary text response) reconstruct
    # correctly - a mid-stream padded quantum is fine, arbitrary mid-stream padding chars are not
    if isinstance(text, bytes):
        text = text.decode("ascii")
    if len(text) % 4 != 0:
        raise ValueError("invalid base64 length")
    out = bytearray()
    for offset in range(0, len(text), 4):
        quantum = text[offset:offset + 4]
        if not _BASE64_QUANTUM_REGEX.match(quantum):
            raise ValueError("invalid base64")
        out += base64.b64decode(quantum)
    return bytes(out)

def _readVarint(buf, pos):
    shift = result = 0
    start = pos
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        b = buf[pos] if isinstance(buf[pos], int) else ord(buf[pos])
        pos += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            if result >= (1 << 64):
                raise ValueError("varint exceeds 64 bits")
            return result, pos
        shift += 7
        if pos - start >= _MAX_VARINT_BYTES:
            raise ValueError("overlong varint")

def _writeVarint(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)

def _readExact(buf, pos, length):
    end = pos + length
    if length < 0 or end > len(buf):
        raise ValueError("truncated protobuf field")
    return buf[pos:end], end

def _decode(buf):
    buf = bytes(buf)
    pos = 0
    out = []
    while pos < len(buf):
        tag, pos = _readVarint(buf, pos)
        fn, wt = tag >> 3, tag & 7
        if fn == 0 or fn > _MAX_FIELD_NUMBER:
            raise ValueError("invalid field number %d" % fn)
        if wt == 0:
            val, pos = _readVarint(buf, pos)
        elif wt == 1:
            val, pos = _readExact(buf, pos, 8)
        elif wt == 2:
            ln, pos = _readVarint(buf, pos)
            val, pos = _readExact(buf, pos, ln)
        elif wt == 5:
            val, pos = _readExact(buf, pos, 4)
        else:
            raise ValueError("unsupported wire type %d" % wt)
        out.append([fn, wt, val])
    return out

def _encode(fields):
    out = bytearray()
    for fn, wt, val in fields:
        out += _writeVarint((fn << 3) | wt)
        if wt == 0:
            out += _writeVarint(val)
        elif wt == 2:
            val = val if isinstance(val, bytes) else bytes(val)
            out += _writeVarint(len(val)) + val
        else:
            out += val if isinstance(val, bytes) else bytes(val)
    return bytes(out)

def _frame(msg):
    return b"\x00" + struct.pack(">I", len(msg)) + msg

def _unframe(data):
    # strict: exactly one uncompressed data frame (flag 0x00), nothing trailing (unary; no
    # compression/streaming/reserved flag bits)
    if len(data) < 5:
        raise ValueError("truncated gRPC-Web frame")
    flag = data[0] if isinstance(data[0], int) else ord(data[0])
    if flag != 0x00:
        raise ValueError("unsupported request frame flags 0x%02x" % flag)
    length = struct.unpack(">I", data[1:5])[0]
    if len(data) != 5 + length:
        raise ValueError("incomplete/oversized gRPC-Web frame")
    return data[5:5 + length]

def _isTextContentType(value):
    return (value or "").split(";", 1)[0].strip().lower() in (CONTENT_TYPE, CONTENT_TYPE_PROTO)

def acceptsTextContentType(value):
    # True if a (possibly comma-separated) Accept header already negotiates a grpc-web-text response
    return any(_isTextContentType(_) for _ in (value or "").split(","))

def _stringFields(fields):
    # Descriptorless: wire type 2 is string / bytes / embedded-message / packed - indistinguishable
    # without the .proto. Offer every printable-UTF-8 length-delimited field as a candidate; do NOT try
    # to exclude values that merely also parse as protobuf (ordinary strings like "A12345678"/"M1234" do,
    # so excluding them silently drops real injection points). Non-selected fields stay in the skeleton
    # untouched, so a mis-picked embedded message just fails to inject and is skipped - the safe failure.
    retVal = []
    for index, (fn, wt, val) in enumerate(fields):
        if wt != 2:
            continue
        try:
            value = bytes(val).decode("utf-8")
        except Exception:
            continue
        if all(char in "\t\n" or ord(char) > 31 for char in value):
            retVal.append((index, fn, value))
    return retVal

def _requestContentType():
    for header, value in (conf.httpHeaders or []):
        if header.lower() == HTTP_HEADER.CONTENT_TYPE.lower():
            return value
    return ""

def _headerValue(headers, key):
    if not headers:
        return None
    key = key.lower()
    try:
        items = headers.items()
    except AttributeError:
        items = headers
    for header, value in items:
        if header.lower() == key:
            return value
    return None

def decodeBody(data):
    """
    Probe 'data' for a gRPC-Web (grpc-web-text) body WITHOUT any side effects. Returns a
    (jsonView, skeleton) tuple - the JSON string of injectable string fields plus the message skeleton
    to re-encode with - or (None, None). The caller commits the skeleton to kb.grpcWeb only on acceptance.
    """

    if not _isTextContentType(_requestContentType()):
        return None, None

    try:
        fields = _decode(_unframe(_b64decode(data)))
    except Exception:
        return None, None

    strings = _stringFields(fields)
    if not strings:
        return None, None

    counts = {}
    for _, fn, _value in strings:
        counts[fn] = counts.get(fn, 0) + 1

    occurrence = {}
    mapping = {}
    view = {}
    for index, fn, value in strings:
        if counts[fn] == 1:
            key = "f%d" % fn
        else:
            key = "f%d_%d" % (fn, occurrence.get(fn, 0))
            occurrence[fn] = occurrence.get(fn, 0) + 1
        mapping[key] = index
        view[key] = value

    skeleton = {"fields": [list(_) for _ in fields], "map": mapping}

    return json.dumps(view), skeleton

def encodeBody(jsonBody):
    """
    Inverse of decodeBody(): overlay the (possibly injected) JSON string values onto the skeleton and
    re-encode a grpc-web-text (base64) body, recomputing the length prefixes. Called at send time.

    Only a body whose keys are EXACTLY the gRPC surrogate keys is transformed - so unrelated JSON bodies
    on the shared request path (CSRF/second-order/redirect/safe requests) pass through untouched.
    """

    if not kb.grpcWeb:
        return jsonBody

    try:
        parsed = json.loads(jsonBody)
    except Exception:
        return jsonBody

    if not isinstance(parsed, dict) or set(parsed) != set(kb.grpcWeb["map"]):
        return jsonBody

    fields = [list(_) for _ in kb.grpcWeb["fields"]]

    for key, index in kb.grpcWeb["map"].items():
        value = parsed[key]
        fields[index][2] = (value if hasattr(value, "encode") else str(value)).encode("utf-8")

    return base64.b64encode(_frame(_encode(fields))).decode("ascii")

def decodeResponse(page, responseHeaders=None):
    """
    Render a gRPC-Web response as readable text (message-frame fields + the trailer frame's
    grpc-status/grpc-message = the back-end error) so the oracle/error-regex/in-band paths see content,
    not an opaque blob. Handles trailers-only errors (status/message in response headers, empty body).
    Unary only: at most one data frame, an optional final trailer, exact frame flags. Only a
    grpc-web-text response body is decoded; anything else is left unchanged.
    """

    if not kb.grpcWeb:
        return page

    out = []

    status = _headerValue(responseHeaders, "grpc-status")
    if status is not None:
        out.append("grpc-status:%s" % status)
    message = _headerValue(responseHeaders, "grpc-message")
    if message:
        out.append("grpc-message:%s" % unquote(message))

    if page and _isTextContentType(_headerValue(responseHeaders, HTTP_HEADER.CONTENT_TYPE)):
        try:
            raw = _b64decode(page)
            bodyOut = []       # separate so a mid-parse failure never leaks partial frame renders
            pos = 0
            dataFrames = 0
            seenTrailer = False
            while pos + 5 <= len(raw):
                flag = raw[pos] if isinstance(raw[pos], int) else ord(raw[pos])
                length = struct.unpack(">I", raw[pos + 1:pos + 5])[0]
                payload, pos = _readExact(raw, pos + 5, length)
                if seenTrailer:
                    raise ValueError("frame after trailer")
                if flag == 0x00:      # data frame
                    dataFrames += 1
                    if dataFrames > 1:
                        raise ValueError("streaming response not supported")
                    for _fn, wt, val in _decode(payload):
                        bodyOut.append(bytes(val).decode("utf-8", "replace") if wt == 2 else str(val))
                elif flag == 0x80:    # trailer frame (grpc-status / grpc-message), must be last
                    seenTrailer = True
                    bodyOut.append(unquote(payload.decode("latin-1")))
                else:
                    raise ValueError("unsupported response frame flags 0x%02x" % flag)
            if pos != len(raw):
                raise ValueError("trailing bytes after final frame")
            out.extend(bodyOut)   # commit body renders only on a fully-valid parse
        except Exception:
            # keep status/message recovered from HEADERS (discard any partial body); append the raw page
            out.append(page)
            return "\n".join(out)
    elif page:
        out.append(page)   # unsupported/absent response Content-Type: leave the body for the oracle

    return "\n".join(out) if out else page
