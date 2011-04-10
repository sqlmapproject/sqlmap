#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

try:
    import hashlib
except:
    import md5
    import sha

import pickle
import sys
import string
import struct
import urllib

from lib.core.data import conf
from lib.core.data import logger
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import URLENCODE_CHAR_LIMIT
from lib.core.settings import URLENCODE_FAILSAFE_CHARS

def base64decode(value):
    return value.decode("base64")

def base64encode(value):
    return value.encode("base64")[:-1].replace("\n", "")

def base64pickle(value):
    return base64encode(pickle.dumps(value))

def base64unpickle(value):
    return pickle.loads(base64decode(value))

def hexdecode(value):
    value = value.lower()

    if value.startswith("0x"):
        value = value[2:]

    return value.decode("hex")

def hexencode(value):
    return value.encode("hex")

def md5hash(value):
    if sys.modules.has_key('hashlib'):
        return hashlib.md5(value).hexdigest()
    else:
        return md5.new(value).hexdigest()

def orddecode(value):
    packedString = struct.pack("!"+"I" * len(value), *value)
    return "".join([chr(char) for char in struct.unpack("!"+"I"*(len(packedString)/4), packedString)])

def ordencode(value):
    return tuple([ord(char) for char in value])

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
        result = unicode(result, encoding or UNICODE_ENCODING, errors="replace")

    return result

def urlencode(value, safe="%&=", convall=False, limit=False):
    if conf.direct or "POSTxml" in conf.paramDict:
        return value

    count = 0
    result = None

    if value is None:
        return result

    if convall or safe is None:
        safe = ""

    while True:
        result = urllib.quote(utf8encode(value), safe)

        if limit and len(result) > URLENCODE_CHAR_LIMIT:
            if count >= len(URLENCODE_FAILSAFE_CHARS):
                dbgMsg  = "failed to fully shorten urlencoding value"
                logger.debug(dbgMsg)
                break

            while count < len(URLENCODE_FAILSAFE_CHARS):
                safe += URLENCODE_FAILSAFE_CHARS[count]
                count += 1
                if safe[-1] in value:
                    break
        else:
            break

    return result

def utf8encode(value):
    return value.encode("utf-8")

def utf8decode(value):
    return value.decode("utf-8")

def htmlescape(value):
    return value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;').replace(' ', '&nbsp;')

def htmlunescape(value):
    return value.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#39;', "'").replace('&nbsp;', ' ')

def safehexencode(value):
    """
    Returns safe hex representation of a given basestring value

    >>> safehexencode(u'test123')
    u'test123'
    >>> safehexencode(u'test\x01\x02\xff')
    u'test\\01\\02\\03\\ff'
    """

    retVal = value
    if isinstance(value, basestring):
        retVal = reduce(lambda x, y: x + (y if (y in string.printable or ord(y) > 255) else '\%02x' % ord(y)), value, unicode())
    elif isinstance(value, list):
        for i in xrange(len(value)):
            retVal[i] = safehexencode(value[i])
    return retVal
