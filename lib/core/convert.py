#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

try:
    import hashlib
except:
    import md5
    import sha

import pickle
import re
import sys
import struct
import urllib

from lib.core.data import conf
from lib.core.data import kb
from lib.core.enums import PLACE
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import URLENCODE_CHAR_LIMIT
from lib.core.settings import URLENCODE_FAILSAFE_CHARS

def base64decode(value):
    return value.decode("base64")

def base64encode(value):
    return value.encode("base64")[:-1].replace("\n", "")

def base64pickle(value):
    return base64encode(pickle.dumps(value, pickle.HIGHEST_PROTOCOL))

def base64unpickle(value):
    return pickle.loads(base64decode(value))

def hexdecode(value):
    value = value.lower()
    return (value[2:] if value.startswith("0x") else value).decode("hex")

def hexencode(value):
    return value.encode("hex")

def md5hash(value):
    if sys.modules.has_key('hashlib'):
        return hashlib.md5(value).hexdigest()
    else:
        return md5.new(value).hexdigest()

def orddecode(value):
    packedString = struct.pack("!"+"I" * len(value), *value)
    return "".join(chr(char) for char in struct.unpack("!"+"I"*(len(packedString)/4), packedString))

def ordencode(value):
    return tuple(ord(char) for char in value)

def sha1hash(value):
    if sys.modules.has_key('hashlib'):
        return hashlib.sha1(value).hexdigest()
    else:
        return sha.new(value).hexdigest()

def urldecode(value, encoding=None):
    result = None

    if value:
        try:
            # for cases like T%C3%BCrk%C3%A7e
            value = str(value)
        except ValueError:
            pass
        finally:
            result = urllib.unquote_plus(value)

    if isinstance(result, str):
        result = unicode(result, encoding or UNICODE_ENCODING, "replace")

    return result

def urlencode(value, safe="%&=", convall=False, limit=False):
    if conf.direct or PLACE.SOAP in conf.paramDict:
        return value

    count = 0
    result = None if value is None else ""

    if value:
        if convall or safe is None:
            safe = ""

        # corner case when character % really needs to be
        # encoded (when not representing url encoded char)
        # except in cases when tampering scripts are used
        if all(map(lambda x: '%' in x, [safe, value])) and not kb.tamperFunctions:
            value = re.sub("%(?![0-9a-fA-F]{2})", "%25", value)

        while True:
            result = urllib.quote(utf8encode(value), safe)

            if limit and len(result) > URLENCODE_CHAR_LIMIT:
                if count >= len(URLENCODE_FAILSAFE_CHARS):
                    break

                while count < len(URLENCODE_FAILSAFE_CHARS):
                    safe += URLENCODE_FAILSAFE_CHARS[count]
                    count += 1
                    if safe[-1] in value:
                        break
            else:
                break

    return result

def unicodeencode(value, encoding=None):
    """
    Return 8-bit string representation of the supplied unicode value:

    >>> unicodeencode(u'test')
    'test'
    """

    retVal = value
    if isinstance(value, unicode):
        try:
            retVal = value.encode(encoding or UNICODE_ENCODING)
        except UnicodeEncodeError:
            retVal = value.encode(UNICODE_ENCODING, "replace")
    return retVal

def utf8encode(value):
    return unicodeencode(value, "utf-8")

def utf8decode(value):
    return value.decode("utf-8")

def htmlescape(value):
    _ = (('&', '&amp;'), ('<', '&lt;'), ('>', '&gt;'), ('"', '&quot;'), ("'", '&#39;'), (' ', '&nbsp;'))
    return reduce(lambda x, y: x.replace(y[0], y[1]), _, value)

def htmlunescape(value):
    retVal = value
    if value and isinstance(value, basestring):
        _ = (('&amp;', '&'), ('&lt;', '<'), ('&gt;', '>'), ('&quot;', '"'), ('&nbsp;', ' '))
        retVal = reduce(lambda x, y: x.replace(y[0], y[1]), _, retVal)
        retVal = re.sub('&#(\d+);', lambda x: unichr(int(x.group(1))), retVal)
    return retVal
