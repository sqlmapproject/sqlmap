#!/usr/bin/env python2

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

try:
    import cPickle as pickle
except:
    import pickle

import base64
import binascii
import json
import re
import sys

from lib.core.settings import IS_WIN
from lib.core.settings import PICKLE_PROTOCOL
from lib.core.settings import UNICODE_ENCODING
from thirdparty import six

def base64decode(value):
    """
    Decodes string value from Base64 to plain format

    >>> base64decode('Zm9vYmFy') == b'foobar'
    True
    """

    return base64.b64decode(unicodeencode(value))

def base64encode(value):
    """
    Encodes string value from plain to Base64 format

    >>> base64encode('foobar') == b'Zm9vYmFy'
    True
    """

    return base64.b64encode(unicodeencode(value))

def base64pickle(value):
    """
    Serializes (with pickle) and encodes to Base64 format supplied (binary) value

    >>> base64unpickle(base64pickle([1, 2, 3])) == [1, 2, 3]
    True
    """

    retVal = None

    try:
        retVal = base64encode(pickle.dumps(value, PICKLE_PROTOCOL))
    except:
        warnMsg = "problem occurred while serializing "
        warnMsg += "instance of a type '%s'" % type(value)
        singleTimeWarnMessage(warnMsg)

        try:
            retVal = base64encode(pickle.dumps(value))
        except:
            retVal = base64encode(pickle.dumps(str(value), PICKLE_PROTOCOL))

    return retVal

def base64unpickle(value):
    """
    Decodes value from Base64 to plain format and deserializes (with pickle) its content

    >>> type(base64unpickle('gAJjX19idWlsdGluX18Kb2JqZWN0CnEBKYFxAi4=')) == object
    True
    """

    retVal = None

    try:
        retVal = pickle.loads(base64decode(value))
    except TypeError:
        retVal = pickle.loads(base64decode(bytes(value)))

    return retVal

def hexdecode(value):
    """
    Decodes string value from hex to plain format

    >>> hexdecode('666f6f626172') == b'foobar'
    True
    """

    value = value.lower()
    value = value[2:] if value.startswith("0x") else value

    if six.PY2:
        retVal = value.decode("hex")
    else:
        retVal = bytes.fromhex(value)

    return retVal

def hexencode(value, encoding=None):
    """
    Encodes string value from plain to hex format

    >>> hexencode('foobar') == b'666f6f626172'
    True
    """

    retVal = unicodeencode(value, encoding)
    retVal = binascii.hexlify(retVal)

    return retVal

def unicodeencode(value, encoding=None):
    """
    Returns 8-bit string representation of the supplied unicode value

    >>> unicodeencode(u'foobar') == b'foobar'
    True
    """

    retVal = value

    if isinstance(value, six.text_type):
        try:
            retVal = value.encode(encoding or UNICODE_ENCODING)
        except UnicodeEncodeError:
            retVal = value.encode(encoding or UNICODE_ENCODING, "replace")

    return retVal

def utf8encode(value):
    """
    Returns 8-bit string representation of the supplied UTF-8 value

    >>> utf8encode(u'foobar') == b'foobar'
    True
    """

    return unicodeencode(value, "utf-8")

def utf8decode(value):
    """
    Returns UTF-8 representation of the supplied 8-bit string representation

    >>> utf8decode(b'foobar') == u'foobar'
    True
    """

    retVal = value

    if isinstance(value, six.binary_type):
        retVal = value.decode("utf-8")

    return retVal

def htmlunescape(value):
    """
    Returns (basic conversion) HTML unescaped value

    >>> htmlunescape('a&lt;b')
    'a<b'
    """

    retVal = value
    if value and isinstance(value, six.string_types):
        replacements = (("&lt;", '<'), ("&gt;", '>'), ("&quot;", '"'), ("&nbsp;", ' '), ("&amp;", '&'), ("&apos;", "'"))
        for code, value in replacements:
            retVal = retVal.replace(code, value)

        try:
            retVal = re.sub(r"&#x([^ ;]+);", lambda match: unichr(int(match.group(1), 16)), retVal)
        except ValueError:
            pass
    return retVal

def singleTimeWarnMessage(message):  # Cross-referenced function
    sys.stdout.write(message)
    sys.stdout.write("\n")
    sys.stdout.flush()

def stdoutencode(data):
    retVal = data

    if six.PY2:
        try:
            retVal = unicodeencode(data or "", sys.stdout.encoding)

            # Reference: http://bugs.python.org/issue1602
            if IS_WIN:
                if '?' in retVal and '?' not in retVal:
                    warnMsg = "cannot properly display Unicode characters "
                    warnMsg += "inside Windows OS command prompt "
                    warnMsg += "(http://bugs.python.org/issue1602). All "
                    warnMsg += "unhandled occurrences will result in "
                    warnMsg += "replacement with '?' character. Please, find "
                    warnMsg += "proper character representation inside "
                    warnMsg += "corresponding output files. "
                    singleTimeWarnMessage(warnMsg)

        except:
            retVal = unicodeencode(data or "")

    return retVal

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
