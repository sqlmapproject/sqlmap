#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import binascii
import re
import string
import sys

PY3 = sys.version_info >= (3, 0)

if PY3:
    xrange = range
    text_type = str
    string_types = (str,)
    unichr = chr
else:
    text_type = unicode
    string_types = (basestring,)

# Regex used for recognition of hex encoded characters
HEX_ENCODED_CHAR_REGEX = r"(?P<result>\\x[0-9A-Fa-f]{2})"

# Raw chars that will be safe encoded to their slash (\) representations (e.g. newline to \n)
SAFE_ENCODE_SLASH_REPLACEMENTS = "\t\n\r\x0b\x0c"

# Characters that don't need to be safe encoded
SAFE_CHARS = "".join([_ for _ in string.printable.replace('\\', '') if _ not in SAFE_ENCODE_SLASH_REPLACEMENTS])

# Prefix used for hex encoded values
HEX_ENCODED_PREFIX = r"\x"

# Strings used for temporary marking of hex encoded prefixes (to prevent double encoding)
HEX_ENCODED_PREFIX_MARKER = "__HEX_ENCODED_PREFIX__"

# String used for temporary marking of slash characters
SLASH_MARKER = "__SLASH__"

def safecharencode(value):
    """
    Returns safe representation of a given basestring value

    >>> safecharencode(u'test123') == u'test123'
    True
    >>> safecharencode(u'test\x01\x02\xaf') == u'test\\\\x01\\\\x02\\xaf'
    True
    """

    retVal = value

    if isinstance(value, string_types):
        if any(_ not in SAFE_CHARS for _ in value):
            retVal = retVal.replace(HEX_ENCODED_PREFIX, HEX_ENCODED_PREFIX_MARKER)
            retVal = retVal.replace('\\', SLASH_MARKER)

            for char in SAFE_ENCODE_SLASH_REPLACEMENTS:
                retVal = retVal.replace(char, repr(char).strip('\''))

            for char in set(retVal):
                if not (char in string.printable or isinstance(value, text_type) and ord(char) >= 160):
                    retVal = retVal.replace(char, '\\x%02x' % ord(char))

            retVal = retVal.replace(SLASH_MARKER, "\\\\")
            retVal = retVal.replace(HEX_ENCODED_PREFIX_MARKER, HEX_ENCODED_PREFIX)
    elif isinstance(value, list):
        for i in xrange(len(value)):
            retVal[i] = safecharencode(value[i])

    return retVal

def safechardecode(value, binary=False):
    """
    Reverse function to safecharencode
    """

    retVal = value
    if isinstance(value, string_types):
        retVal = retVal.replace('\\\\', SLASH_MARKER)

        while True:
            match = re.search(HEX_ENCODED_CHAR_REGEX, retVal)
            if match:
                retVal = retVal.replace(match.group("result"), unichr(ord(binascii.unhexlify(match.group("result").lstrip("\\x")))))
            else:
                break

        for char in SAFE_ENCODE_SLASH_REPLACEMENTS[::-1]:
            retVal = retVal.replace(repr(char).strip('\''), char)

        retVal = retVal.replace(SLASH_MARKER, '\\')

        if binary:
            if isinstance(retVal, text_type):
                retVal = retVal.encode("utf8", errors="surrogatepass" if PY3 else "strict")

    elif isinstance(value, (list, tuple)):
        for i in xrange(len(value)):
            retVal[i] = safechardecode(value[i])

    return retVal
