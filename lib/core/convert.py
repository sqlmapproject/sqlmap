#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import base64
import json
import pickle
import re
import StringIO
import sys

from lib.core.settings import IS_WIN
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import PICKLE_REDUCE_WHITELIST

def base64decode(value):
    """
    Decodes string value from Base64 to plain format

    >>> base64decode('Zm9vYmFy')
    'foobar'
    """

    return base64.b64decode(value)

def base64encode(value):
    """
    Encodes string value from plain to Base64 format

    >>> base64encode('foobar')
    'Zm9vYmFy'
    """

    return base64.b64encode(value)

def base64pickle(value):
    """
    Serializes (with pickle) and encodes to Base64 format supplied (binary) value

    >>> base64pickle('foobar')
    'gAJVBmZvb2JhcnEALg=='
    """

    retVal = None

    try:
        retVal = base64encode(pickle.dumps(value, pickle.HIGHEST_PROTOCOL))
    except:
        warnMsg = "problem occurred while serializing "
        warnMsg += "instance of a type '%s'" % type(value)
        singleTimeWarnMessage(warnMsg)

        try:
            retVal = base64encode(pickle.dumps(value))
        except:
            retVal = base64encode(pickle.dumps(str(value), pickle.HIGHEST_PROTOCOL))

    return retVal

def base64unpickle(value):
    """
    Decodes value from Base64 to plain format and deserializes (with pickle) its content

    >>> base64unpickle('gAJVBmZvb2JhcnEALg==')
    'foobar'
    """

    retVal = None

    def _(self):
        if len(self.stack) > 1:
            func = self.stack[-2]
            if func not in PICKLE_REDUCE_WHITELIST:
                raise Exception, "abusing reduce() is bad, Mkay!"
        self.load_reduce()

    def loads(str):
        file = StringIO.StringIO(str)
        unpickler = pickle.Unpickler(file)
        unpickler.dispatch[pickle.REDUCE] = _
        return unpickler.load()

    try:
        retVal = loads(base64decode(value))
    except TypeError: 
        retVal = loads(base64decode(bytes(value)))

    return retVal

def hexdecode(value):
    """
    Decodes string value from hex to plain format

    >>> hexdecode('666f6f626172')
    'foobar'
    """

    value = value.lower()
    return (value[2:] if value.startswith("0x") else value).decode("hex")

def hexencode(value):
    """
    Encodes string value from plain to hex format

    >>> hexencode('foobar')
    '666f6f626172'
    """

    return utf8encode(value).encode("hex")

def unicodeencode(value, encoding=None):
    """
    Returns 8-bit string representation of the supplied unicode value

    >>> unicodeencode(u'foobar')
    'foobar'
    """

    retVal = value
    if isinstance(value, unicode):
        try:
            retVal = value.encode(encoding or UNICODE_ENCODING)
        except UnicodeEncodeError:
            retVal = value.encode(UNICODE_ENCODING, "replace")
    return retVal

def utf8encode(value):
    """
    Returns 8-bit string representation of the supplied UTF-8 value

    >>> utf8encode(u'foobar')
    'foobar'
    """

    return unicodeencode(value, "utf-8")

def utf8decode(value):
    """
    Returns UTF-8 representation of the supplied 8-bit string representation

    >>> utf8decode('foobar')
    u'foobar'
    """

    return value.decode("utf-8")

def htmlunescape(value):
    """
    Returns (basic conversion) HTML unescaped value

    >>> htmlunescape('a&lt;b')
    'a<b'
    """

    retVal = value
    if value and isinstance(value, basestring):
        codes = (('&lt;', '<'), ('&gt;', '>'), ('&quot;', '"'), ('&nbsp;', ' '), ('&amp;', '&'))
        retVal = reduce(lambda x, y: x.replace(y[0], y[1]), codes, retVal)
        try:
            retVal = re.sub(r"&#x([^ ;]+);", lambda match: unichr(int(match.group(1), 16)), retVal)
        except ValueError:
            pass
    return retVal

def singleTimeWarnMessage(message):  # Cross-linked function
    sys.stdout.write(message)
    sys.stdout.write("\n")
    sys.stdout.flush()

def stdoutencode(data):
    retVal = None

    try:
        data = data or ""

        # Reference: http://bugs.python.org/issue1602
        if IS_WIN:
            output = data.encode(sys.stdout.encoding, "replace")

            if '?' in output and '?' not in data:
                warnMsg = "cannot properly display Unicode characters "
                warnMsg += "inside Windows OS command prompt "
                warnMsg += "(http://bugs.python.org/issue1602). All "
                warnMsg += "unhandled occurances will result in "
                warnMsg += "replacement with '?' character. Please, find "
                warnMsg += "proper character representation inside "
                warnMsg += "corresponding output files. "
                singleTimeWarnMessage(warnMsg)

            retVal = output
        else:
            retVal = data.encode(sys.stdout.encoding)
    except:
        retVal = data.encode(UNICODE_ENCODING) if isinstance(data, unicode) else data

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

    >>> dejsonize('{\\n    "foo": "bar"\\n}')
    {u'foo': u'bar'}
    """

    return json.loads(data)
