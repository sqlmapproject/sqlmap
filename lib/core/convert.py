#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import base64
import binascii
import codecs
import datetime
import decimal
import json
import re
import sys
import time

from lib.core.bigarray import BigArray
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.settings import INVALID_UNICODE_PRIVATE_AREA
from lib.core.settings import IS_TTY
from lib.core.settings import IS_WIN
from lib.core.settings import NULL
from lib.core.settings import SAFE_HEX_MARKER
from lib.core.settings import UNICODE_ENCODING
from thirdparty import six
from thirdparty.six import unichr as _unichr
from thirdparty.six.moves import html_parser
from thirdparty.six.moves import collections_abc as _collections

try:
    from html import escape as _escape
except ImportError:
    from cgi import escape as _escape

htmlEscape = _escape

# Safe (no arbitrary code execution) serialization used for the session store (HashDB)
# and BigArray disk chunks. The former serializer could execute code while loading, so
# deserializing sqlmap's own (locally writable) session/cache files was a recurring
# report magnet. This codec serializes to plain JSON with explicit type tags, so nothing
# is ever executed on load.
#
# JSON natively covers only str/int/float/bool/None/list, and silently loses the rest
# (int/tuple dict keys become strings, set/tuple/bytes are rejected). The tagged wrappers
# below preserve every type sqlmap actually stores: bytes, tuple, set/frozenset, dict with
# arbitrary (non-string) keys, DB-driver scalars (Decimal/datetime/...), and the handful of
# sqlmap's own classes below. Reconstruction of classes is limited to that explicit
# allowlist (no module/namespace wildcard), so no dangerous callable is ever reachable.

# reserved wrapper key; data mappings are encoded as tagged pair-lists (never as bare JSON
# objects), so any decoded JSON object is one of our wrappers and this key can never collide
_SERIALIZE_TAG = "$T"

# fully-qualified names of the ONLY classes that may be reconstructed on deserialization
_SERIALIZE_CLASSES = frozenset((
    "lib.core.datatype.AttribDict",
    "lib.core.datatype.InjectionDict",
    "lib.utils.har.RawPair",
))

def _serializeEncode(value):
    """
    Turns a Python value into a JSON-serializable (tagged) structure
    """

    if value is None or isinstance(value, bool) or isinstance(value, float) or isinstance(value, six.integer_types):
        return value

    if isinstance(value, six.text_type):
        return value

    # Note: on Python 2 'str' is binary; base64-tagging it (rather than emitting a native JSON
    # string that would round-trip as 'unicode') keeps the exact byte type across versions
    if isinstance(value, (six.binary_type, bytearray)):
        raw = bytes(value) if isinstance(value, bytearray) else value
        retVal = {_SERIALIZE_TAG: "b", "v": encodeBase64(raw, binary=False), "a": 1 if isinstance(value, bytearray) else 0}
        if six.PY3:             # mark genuine Python 3 bytes so restore keeps them bytes; a
            retVal["pv"] = 3    # Python 2 'str' (text) is unmarked and recovered as text (see decode)
        return retVal

    if isinstance(value, memoryview):
        retVal = {_SERIALIZE_TAG: "b", "v": encodeBase64(value.tobytes(), binary=False), "a": 0}
        if six.PY3:
            retVal["pv"] = 3
        return retVal

    try:
        if isinstance(value, buffer):  # noqa: F821  # Python 2 only
            return {_SERIALIZE_TAG: "b", "v": encodeBase64(bytes(value), binary=False), "a": 0}
    except NameError:
        pass

    # Note: BigArray is a 'list' subclass, so it must be matched before the plain-list branch
    # (otherwise it would round-trip as a plain list, losing its type)
    if isinstance(value, BigArray):
        return {_SERIALIZE_TAG: "ba", "v": [_serializeEncode(_) for _ in value]}

    if isinstance(value, list):
        return [_serializeEncode(_) for _ in value]

    if isinstance(value, tuple):
        return {_SERIALIZE_TAG: "t", "v": [_serializeEncode(_) for _ in value]}

    if isinstance(value, frozenset):
        return {_SERIALIZE_TAG: "f", "v": [_serializeEncode(_) for _ in value]}

    if isinstance(value, (set, _collections.Set)):
        return {_SERIALIZE_TAG: "s", "v": [_serializeEncode(_) for _ in value]}

    if isinstance(value, dict):
        name = "%s.%s" % (value.__class__.__module__, value.__class__.__name__)
        if name in _SERIALIZE_CLASSES:
            return {_SERIALIZE_TAG: "o", "c": name, "d": [[_serializeEncode(k), _serializeEncode(v)] for (k, v) in value.items()], "s": _serializeEncode(dict(value.__dict__))}
        elif value.__class__ is dict or (name or "").split(".")[0] not in ("lib", "plugins", "thirdparty"):
            # a plain dict, or a foreign mapping subclass (e.g. collections.OrderedDict/defaultdict): store the
            # items as a plain mapping so the data round-trips, instead of silently degrading to its text repr.
            # A non-allowlisted lib/plugins/thirdparty subclass still falls through to _serializeUnknown (fail loudly)
            return {_SERIALIZE_TAG: "m", "v": [[_serializeEncode(k), _serializeEncode(v)] for (k, v) in value.items()]}
        else:
            return _serializeUnknown(value, name)

    if isinstance(value, decimal.Decimal):
        return {_SERIALIZE_TAG: "dec", "v": getUnicode(value)}

    if isinstance(value, datetime.datetime):
        return {_SERIALIZE_TAG: "dt", "v": [value.year, value.month, value.day, value.hour, value.minute, value.second, value.microsecond]}

    if isinstance(value, datetime.date):
        return {_SERIALIZE_TAG: "date", "v": [value.year, value.month, value.day]}

    if isinstance(value, datetime.time):
        return {_SERIALIZE_TAG: "time", "v": [value.hour, value.minute, value.second, value.microsecond]}

    if isinstance(value, datetime.timedelta):
        return {_SERIALIZE_TAG: "td", "v": [value.days, value.seconds, value.microseconds]}

    name = "%s.%s" % (value.__class__.__module__, value.__class__.__name__)
    if name in _SERIALIZE_CLASSES:
        return {_SERIALIZE_TAG: "o", "c": name, "s": _serializeEncode(dict(value.__dict__))}

    return _serializeUnknown(value, name)

def _serializeUnknown(value, name):
    """
    Fallback for a type not explicitly handled by the serializer
    """

    # sqlmap's own (or bundled) classes MUST be added to the allowlist explicitly - fail loudly
    # (caught by the regression tests) rather than silently store something that cannot be restored
    if (name or "").split(".")[0] in ("lib", "plugins", "thirdparty"):
        raise TypeError("serialization of type '%s' is not supported" % name)

    # a foreign/exotic scalar (e.g. an unusual DB-driver value): degrade to its textual form rather
    # than crash a user's session - session values are only ever rendered (getUnicode) downstream
    singleTimeWarnMessage("serializing value of unsupported type '%s' as text" % name)
    return getUnicode(value)

def _serializeDecode(struct):
    """
    Restores a Python value from a JSON-deserialized (tagged) structure
    """

    if struct is None or isinstance(struct, bool) or isinstance(struct, float) or isinstance(struct, six.integer_types):
        return struct

    if isinstance(struct, six.text_type):
        return struct

    if isinstance(struct, six.binary_type):  # defensive - json.loads() yields text, not bytes
        return getUnicode(struct)

    if isinstance(struct, list):
        return [_serializeDecode(_) for _ in struct]

    if isinstance(struct, dict):
        tag = struct.get(_SERIALIZE_TAG)

        if tag == "b":
            raw = decodeBase64(struct["v"], binary=True)
            if struct.get("a"):
                return bytearray(raw)
            # Genuine Python 3 bytes (pv==3) are kept as-is. A value WITHOUT the marker was
            # written by Python 2, whose text-'str' goes through this bytes branch; on Python 3
            # that would surface as 'bytes' and break str consumers - most visibly kb.chars,
            # whose str-key lookups then return None and crash cleanupPayload(). Recover such
            # cross-version TEXT by decoding valid UTF-8 to 'str'; real binary stays bytes.
            if struct.get("pv") == 3 or not six.PY3:
                return raw
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return raw
        elif tag == "t":
            return tuple(_serializeDecode(_) for _ in struct["v"])
        elif tag == "f":
            return frozenset(_serializeDecode(_) for _ in struct["v"])
        elif tag == "ba":
            return BigArray([_serializeDecode(_) for _ in struct["v"]])
        elif tag == "s":
            return set(_serializeDecode(_) for _ in struct["v"])
        elif tag == "m":
            return dict((_serializeDecode(k), _serializeDecode(v)) for (k, v) in struct["v"])
        elif tag == "dec":
            return decimal.Decimal(struct["v"])
        elif tag == "dt":
            return datetime.datetime(*struct["v"])
        elif tag == "date":
            return datetime.date(*struct["v"])
        elif tag == "time":
            return datetime.time(*struct["v"])
        elif tag == "td":
            return datetime.timedelta(struct["v"][0], struct["v"][1], struct["v"][2])
        elif tag == "o":
            return _serializeDecodeObject(struct)
        elif tag is None:  # defensive - a bare mapping should never occur
            return dict((_serializeDecode(k), _serializeDecode(v)) for (k, v) in struct.items())
        else:
            raise ValueError("unsupported serialized tag '%s'" % tag)

    raise ValueError("unsupported serialized structure of type '%s'" % type(struct))

def _serializeResolveClass(name):
    """
    Resolves an allowlisted class name to its class (nothing else may be reconstructed)
    """

    if name not in _SERIALIZE_CLASSES:
        raise ValueError("deserialization of class '%s' is forbidden" % name)

    if name == "lib.utils.har.RawPair":
        from lib.utils.har import RawPair
        return RawPair
    else:
        from lib.core.datatype import AttribDict, InjectionDict
        return InjectionDict if name.endswith("InjectionDict") else AttribDict

def _serializeDecodeObject(struct):
    """
    Reconstructs an allowlisted class instance from its serialized form
    """

    _class = _serializeResolveClass(struct.get("c"))
    retVal = _class.__new__(_class)

    if isinstance(retVal, dict):
        for pair in (struct.get("d") or []):
            dict.__setitem__(retVal, _serializeDecode(pair[0]), _serializeDecode(pair[1]))

    state = _serializeDecode(struct.get("s") or {})
    if isinstance(state, dict):
        retVal.__dict__.update(state)

    return retVal

def serializeValue(value):
    """
    Safely serializes a Python value to its canonical serialized form (JSON text), without any
    code-execution risk

    Note: the output is pure ASCII text, so it is stored verbatim in the (TEXT) session store - no
    Base64 (or any base-N) wrapping is needed (that was only required by the former binary
    serialization), which also keeps the stored form as small as possible. Callers that need raw
    bytes (e.g. a compressed BigArray disk chunk) simply encode the returned text.

    >>> deserializeValue(serializeValue({1: 'a', 'b': (2, 3), 'c': {4, 5}})) == {1: 'a', 'b': (2, 3), 'c': {4, 5}}
    True
    >>> deserializeValue(serializeValue([1, 2, (3, {4: b'5'})])) == [1, 2, (3, {4: b'5'})]
    True
    """

    return json.dumps(_serializeEncode(value), ensure_ascii=True, separators=(',', ':'))

def deserializeValue(value):
    """
    Restores a Python value from its serialized form (accepts the serialized data as either text or
    bytes)
    """

    return _serializeDecode(json.loads(getText(value)))

def htmlUnescape(value):
    """
    Returns HTML unescaped value

    >>> htmlUnescape('a&lt;b') == 'a<b'
    True
    >>> htmlUnescape('a&lt;b') == 'a<b'
    True
    >>> htmlUnescape('&#x66;&#x6f;&#x6f;&#x62;&#x61;&#x72;') == 'foobar'
    True
    >>> htmlUnescape('&#102;&#111;&#111;&#98;&#97;&#114;') == 'foobar'
    True
    >>> htmlUnescape('&copy;&euro;') == htmlUnescape('&#xA9;&#x20AC;')
    True
    """

    if value and isinstance(value, six.string_types):
        if six.PY3:
            import html
            return html.unescape(value)
        else:
            return html_parser.HTMLParser().unescape(value)
    return value

def singleTimeWarnMessage(message):  # Cross-referenced function
    sys.stdout.write(message)
    sys.stdout.write("\n")
    sys.stdout.flush()

def filterNone(values):  # Cross-referenced function
    return [_ for _ in values if _] if isinstance(values, _collections.Iterable) else values

def isListLike(value):  # Cross-referenced function
    return isinstance(value, (list, tuple, set, BigArray))

def shellExec(cmd):  # Cross-referenced function
    raise NotImplementedError

def jsonize(data):
    """
    Returns JSON serialized data

    >>> jsonize({'foo':'bar'})
    '{\\n    "foo": "bar"\\n}'
    """

    return json.dumps(data, sort_keys=False, indent=4)

def dejsonize(data):
    """
    Returns JSON deserialized data

    >>> dejsonize('{\\n    "foo": "bar"\\n}') == {u'foo': u'bar'}
    True
    """

    return json.loads(data)

def decodeHex(value, binary=True):
    """
    Returns a decoded representation of the provided hexadecimal value

    >>> decodeHex("313233") == b"123"
    True
    >>> decodeHex("313233", binary=False) == u"123"
    True
    """

    retVal = value

    if isinstance(value, six.binary_type):
        value = getText(value)

    if value.lower().startswith("0x"):
        value = value[2:]

    try:
        retVal = codecs.decode(value, "hex")
    except LookupError:
        retVal = binascii.unhexlify(value)

    if not binary:
        retVal = getText(retVal)

    return retVal

def encodeHex(value, binary=True):
    """
    Returns an encoded representation of the provided value

    >>> encodeHex(b"123") == b"313233"
    True
    >>> encodeHex("123", binary=False)
    '313233'
    >>> encodeHex(b"123"[0]) == b"31"
    True
    >>> encodeHex(123, binary=False)
    '7b'
    """

    if isinstance(value, int):
        value = six.int2byte(value)

    if isinstance(value, six.text_type):
        value = value.encode(UNICODE_ENCODING)

    try:
        retVal = codecs.encode(value, "hex")
    except LookupError:
        retVal = binascii.hexlify(value)

    if not binary:
        retVal = getText(retVal)

    return retVal

def decodeBase64(value, binary=True, encoding=None):
    """
    Returns a decoded representation of provided Base64 value

    >>> decodeBase64("MTIz") == b"123"
    True
    >>> decodeBase64("MTIz", binary=False)
    '123'
    >>> decodeBase64("A-B_CDE") == decodeBase64("A+B/CDE")
    True
    >>> decodeBase64(b"MTIzNA") == b"1234"
    True
    >>> decodeBase64("MTIzNA") == b"1234"
    True
    >>> decodeBase64("MTIzNA==") == b"1234"
    True
    """

    if value is None:
        return None

    padding = b'=' if isinstance(value, bytes) else '='

    # Reference: https://stackoverflow.com/a/49459036
    if not value.endswith(padding):
        value += 3 * padding

    # Reference: https://en.wikipedia.org/wiki/Base64#URL_applications
    # Reference: https://perldoc.perl.org/MIME/Base64.html
    if isinstance(value, bytes):
        value = value.replace(b'-', b'+').replace(b'_', b'/')
    else:
        value = value.replace('-', '+').replace('_', '/')

    retVal = base64.b64decode(value)

    if not binary:
        retVal = getText(retVal, encoding)

    return retVal

def encodeBase64(value, binary=True, encoding=None, padding=True, safe=False):
    """
    Returns a Base64 encoded representation of the provided value

    >>> encodeBase64(b"123") == b"MTIz"
    True
    >>> encodeBase64(u"1234", binary=False)
    'MTIzNA=='
    >>> encodeBase64(u"1234", binary=False, padding=False)
    'MTIzNA'
    >>> encodeBase64(decodeBase64("A-B_CDE"), binary=False, safe=True)
    'A-B_CDE'
    """

    if value is None:
        return None

    if isinstance(value, six.text_type):
        value = value.encode(encoding or UNICODE_ENCODING)

    retVal = base64.b64encode(value)

    if not binary:
        retVal = getText(retVal, encoding)

    if safe:
        padding = False

        # Reference: https://en.wikipedia.org/wiki/Base64#URL_applications
        # Reference: https://perldoc.perl.org/MIME/Base64.html
        if isinstance(retVal, bytes):
            retVal = retVal.replace(b'+', b'-').replace(b'/', b'_')
        else:
            retVal = retVal.replace('+', '-').replace('/', '_')

    if not padding:
        retVal = retVal.rstrip(b'=' if isinstance(retVal, bytes) else '=')

    return retVal

def getBytes(value, encoding=None, errors="strict", unsafe=True):
    """
    Returns byte representation of provided Unicode value

    >>> getBytes(u"foo\\\\x01\\\\x83\\\\xffbar") == b"foo\\x01\\x83\\xffbar"
    True
    >>> getBytes(u"C:\\\\\\\\x64\\\\secrets.txt") == b"C:\\\\x64\\\\secrets.txt"
    True
    """

    retVal = value

    if encoding is None:
        encoding = conf.get("encoding") or UNICODE_ENCODING

    try:
        codecs.lookup(encoding)
    except (LookupError, TypeError):
        encoding = UNICODE_ENCODING

    if isinstance(value, bytearray):
        return bytes(value)
    elif isinstance(value, memoryview):
        return value.tobytes()
    elif isinstance(value, six.text_type):
        if INVALID_UNICODE_PRIVATE_AREA:
            if unsafe:
                for char in xrange(0xF0000, 0xF00FF + 1):
                    value = value.replace(_unichr(char), "%s%02x" % (SAFE_HEX_MARKER, char - 0xF0000))

            retVal = value.encode(encoding, errors)

            if unsafe:
                retVal = re.sub((r"%s([0-9a-f]{2})" % SAFE_HEX_MARKER).encode(), lambda _: decodeHex(_.group(1)), retVal)
        else:
            try:
                retVal = value.encode(encoding, errors)
            except UnicodeError:
                retVal = value.encode(UNICODE_ENCODING, errors="replace")

            if unsafe:
                retVal = re.sub(b"(?<!\\\\)\\\\x([0-9a-fA-F]{2})", lambda _: decodeHex(_.group(1)), retVal)
                retVal = retVal.replace(b"\\\\x", b"\\x")

    return retVal

def getOrds(value):
    """
    Returns ORD(...) representation of provided string value

    >>> getOrds(u'fo\\xf6bar')
    [102, 111, 246, 98, 97, 114]
    >>> getOrds(b"fo\\xc3\\xb6bar")
    [102, 111, 195, 182, 98, 97, 114]
    """

    return [_ if isinstance(_, int) else ord(_) for _ in value]

def getUnicode(value, encoding=None, noneToNull=False):
    """
    Returns the unicode representation of the supplied value

    >>> getUnicode('test') == u'test'
    True
    >>> getUnicode(1) == u'1'
    True
    >>> getUnicode(None) == 'None'
    True
    >>> getUnicode(b'/etc/passwd') == '/etc/passwd'
    True
    """

    # Best position for --time-limit mechanism
    if conf.get("timeLimit") and kb.get("startTime") and (time.time() - kb.startTime > conf.timeLimit):
        raise SystemExit

    if noneToNull and value is None:
        return NULL

    if isinstance(value, six.text_type):
        return value
    elif isinstance(value, six.binary_type):
        # Heuristics (if encoding not explicitly specified)
        candidates = filterNone((encoding, kb.get("pageEncoding") if kb.get("originalPage") else None, conf.get("encoding"), UNICODE_ENCODING, sys.getfilesystemencoding()))
        if all(_ in value for _ in (b'<', b'>')):
            pass
        elif b'\n' not in value and re.search(r"(?i)\w+\.\w{2,3}\Z|\A(\w:\\|/\w+)", six.text_type(value, UNICODE_ENCODING, errors="ignore")):
            candidates = filterNone((encoding, sys.getfilesystemencoding(), kb.get("pageEncoding") if kb.get("originalPage") else None, UNICODE_ENCODING, conf.get("encoding")))
        elif conf.get("encoding") and b'\n' not in value:
            candidates = filterNone((encoding, conf.get("encoding"), kb.get("pageEncoding") if kb.get("originalPage") else None, sys.getfilesystemencoding(), UNICODE_ENCODING))

        for candidate in candidates:
            try:
                return six.text_type(value, candidate)
            except (UnicodeDecodeError, LookupError):
                pass

        try:
            return six.text_type(value, encoding or (kb.get("pageEncoding") if kb.get("originalPage") else None) or UNICODE_ENCODING)
        except UnicodeDecodeError:
            return six.text_type(value, UNICODE_ENCODING, errors="reversible")
    elif isListLike(value):
        value = list(getUnicode(_, encoding, noneToNull) for _ in value)
        return value
    else:
        try:
            return six.text_type(value)
        except UnicodeDecodeError:
            return six.text_type(str(value), errors="ignore")  # encoding ignored for non-basestring instances

def getText(value, encoding=None):
    """
    Returns textual value of a given value (Note: not necessary Unicode on Python2)

    >>> getText(b"foobar")
    'foobar'
    >>> isinstance(getText(u"fo\\u2299bar"), six.text_type)
    True
    """

    retVal = value

    if isinstance(value, six.binary_type):
        retVal = getUnicode(value, encoding)

    if six.PY2:
        try:
            retVal = str(retVal)
        except:
            pass

    return retVal

def stdoutEncode(value):
    """
    Returns textual representation of a given value safe for writing to stdout
    >>> stdoutEncode(b"foobar")
    'foobar'
    >>> stdoutEncode({"url": "http://example.com/foo", "data": "id=1"}) == {"url": "http://example.com/foo", "data": "id=1"}
    True
    """

    if value is None:
        value = ""

    if IS_WIN and IS_TTY and kb.get("codePage", -1) is None:
        output = shellExec("chcp")
        match = re.search(r": (\d{3,})", output or "")

        if match:
            try:
                candidate = "cp%s" % match.group(1)
                codecs.lookup(candidate)
                kb.codePage = candidate
            except (LookupError, TypeError):
                pass

        kb.codePage = kb.codePage or ""

    encoding = kb.get("codePage") or getattr(sys.stdout, "encoding", None) or UNICODE_ENCODING

    if six.PY3:
        if isinstance(value, (bytes, bytearray)):
            value = getUnicode(value, encoding)
        elif not isinstance(value, str):
            # Reference: https://github.com/sqlmapproject/sqlmap/issues/6054
            return value

        try:
            retVal = value.encode(encoding, errors="replace").decode(encoding, errors="replace")
        except (LookupError, TypeError):
            retVal = value.encode("ascii", errors="replace").decode("ascii", errors="replace")
    else:
        if isinstance(value, six.text_type):
            try:
                retVal = value.encode(encoding, errors="replace")
            except (LookupError, TypeError):
                retVal = value.encode("ascii", errors="replace")
        else:
            retVal = value

    return retVal

# str.isascii() is available on Python 3.7+ only (sqlmap still supports 2.7)
_HAS_ISASCII = hasattr(str, "isascii")

def getConsoleLength(value):
    """
    Returns console width of unicode values

    >>> getConsoleLength("abc")
    3
    >>> getConsoleLength(u"\\u957f\\u6c5f")
    4
    """

    if isinstance(value, six.text_type):
        # Fast path: ASCII values have no wide (>= U+3000) characters, so their
        # console width is simply their length. str.isascii() (Python 3.7+) is a
        # C-level scan, far cheaper than the per-character generator below (which
        # stays for the rare wide-character case and for Python 2). This runs
        # once per dumped cell, so it dominates large table dumps.
        if _HAS_ISASCII and value.isascii():
            retVal = len(value)
        else:
            retVal = len(value) + sum(ord(_) >= 0x3000 for _ in value)
    else:
        retVal = len(value)

    return retVal
