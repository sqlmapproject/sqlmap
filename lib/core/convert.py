#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

try:
    import cPickle as pickle
except:
    import pickle

import base64
import binascii
import codecs
import json
import re
import sys

from lib.core.bigarray import BigArray
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.settings import INVALID_UNICODE_PRIVATE_AREA
from lib.core.settings import IS_TTY
from lib.core.settings import IS_WIN
from lib.core.settings import NULL
from lib.core.settings import PICKLE_PROTOCOL
from lib.core.settings import SAFE_HEX_MARKER
from lib.core.settings import UNICODE_ENCODING
from thirdparty import six
from thirdparty.six import unichr as _unichr
from thirdparty.six.moves import collections_abc as _collections

try:
    from html import escape as htmlEscape
except ImportError:
    from cgi import escape as htmlEscape

def base64pickle(value):
    """
    Serializes (with pickle) and encodes to Base64 format supplied (binary) value

    >>> base64unpickle(base64pickle([1, 2, 3])) == [1, 2, 3]
    True
    """

    retVal = None

    try:
        retVal = encodeBase64(pickle.dumps(value, PICKLE_PROTOCOL), binary=False)
    except:
        warnMsg = "problem occurred while serializing "
        warnMsg += "instance of a type '%s'" % type(value)
        singleTimeWarnMessage(warnMsg)

        try:
            retVal = encodeBase64(pickle.dumps(value), binary=False)
        except:
            retVal = encodeBase64(pickle.dumps(str(value), PICKLE_PROTOCOL), binary=False)

    return retVal

def base64unpickle(value):
    """
    Decodes value from Base64 to plain format and deserializes (with pickle) its content

    >>> type(base64unpickle('gAJjX19idWlsdGluX18Kb2JqZWN0CnEBKYFxAi4=')) == object
    True
    """

    retVal = None

    try:
        retVal = pickle.loads(decodeBase64(value))
    except TypeError:
        retVal = pickle.loads(decodeBase64(bytes(value)))

    return retVal

def htmlUnescape(value):
    """
    Returns (basic conversion) HTML unescaped value

    >>> htmlUnescape('a&lt;b') == 'a<b'
    True
    """

    retVal = value

    if value and isinstance(value, six.string_types):
        replacements = (("&lt;", '<'), ("&gt;", '>'), ("&quot;", '"'), ("&nbsp;", ' '), ("&amp;", '&'), ("&apos;", "'"))
        for code, value in replacements:
            retVal = retVal.replace(code, value)

        try:
            retVal = re.sub(r"&#x([^ ;]+);", lambda match: _unichr(int(match.group(1), 16)), retVal)
        except (ValueError, OverflowError):
            pass

    return retVal

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
    Returns a decoded representation of provided hexadecimal value

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
    Returns a encoded representation of provided string value

    >>> encodeHex(b"123") == b"313233"
    True
    >>> encodeHex("123", binary=False)
    '313233'
    >>> encodeHex(b"123"[0]) == b"31"
    True
    """

    if isinstance(value, int):
        value = six.unichr(value)

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
    Returns a decoded representation of provided Base64 value

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
    """

    retVal = value

    if encoding is None:
        encoding = conf.get("encoding") or UNICODE_ENCODING

    try:
        codecs.lookup(encoding)
    except (LookupError, TypeError):
        encoding = UNICODE_ENCODING

    if isinstance(value, six.text_type):
        if INVALID_UNICODE_PRIVATE_AREA:
            if unsafe:
                for char in xrange(0xF0000, 0xF00FF + 1):
                    value = value.replace(_unichr(char), "%s%02x" % (SAFE_HEX_MARKER, char - 0xF0000))

            retVal = value.encode(encoding, errors)

            if unsafe:
                retVal = re.sub(r"%s([0-9a-f]{2})" % SAFE_HEX_MARKER, lambda _: decodeHex(_.group(1)), retVal)
        else:
            try:
                retVal = value.encode(encoding, errors)
            except UnicodeError:
                retVal = value.encode(UNICODE_ENCODING, errors="replace")

            if unsafe:
                retVal = re.sub(b"\\\\x([0-9a-f]{2})", lambda _: decodeHex(_.group(1)), retVal)

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
    """

    if noneToNull and value is None:
        return NULL

    if isinstance(value, six.text_type):
        return value
    elif isinstance(value, six.binary_type):
        # Heuristics (if encoding not explicitly specified)
        candidates = filterNone((encoding, kb.get("pageEncoding") if kb.get("originalPage") else None, conf.get("encoding"), UNICODE_ENCODING, sys.getfilesystemencoding()))
        if all(_ in value for _ in (b'<', b'>')):
            pass
        elif any(_ in value for _ in (b":\\", b'/', b'.')) and b'\n' not in value:
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
    Returns binary representation of a given Unicode value safe for writing to stdout
    """

    value = value or ""

    if IS_WIN and IS_TTY and kb.get("codePage", -1) is None:
        output = shellExec("chcp")
        match = re.search(r": (\d{3,})", output or "")

        if match:
            try:
                candidate = "cp%s" % match.group(1)
                codecs.lookup(candidate)
            except LookupError:
                pass
            else:
                kb.codePage = candidate

        kb.codePage = kb.codePage or ""

    if isinstance(value, six.text_type):
        encoding = kb.get("codePage") or getattr(sys.stdout, "encoding", None) or UNICODE_ENCODING

        while True:
            try:
                retVal = value.encode(encoding)
                break
            except UnicodeEncodeError as ex:
                value = value[:ex.start] + "?" * (ex.end - ex.start) + value[ex.end:]

                warnMsg = "cannot properly display (some) Unicode characters "
                warnMsg += "inside your terminal ('%s') environment. All " % encoding
                warnMsg += "unhandled occurrences will result in "
                warnMsg += "replacement with '?' character. Please, find "
                warnMsg += "proper character representation inside "
                warnMsg += "corresponding output files"
                singleTimeWarnMessage(warnMsg)

        if six.PY3:
            retVal = getUnicode(retVal, encoding)

    else:
        retVal = value

    return retVal

def getConsoleLength(value):
    """
    Returns console width of unicode values

    >>> getConsoleLength("abc")
    3
    >>> getConsoleLength(u"\\u957f\\u6c5f")
    4
    """

    if isinstance(value, six.text_type):
        retVal = sum((2 if ord(_) >= 0x3000 else 1) for _ in value)
    else:
        retVal = len(value)

    return retVal
