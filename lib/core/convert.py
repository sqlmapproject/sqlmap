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
import struct
import urllib

from lib.core.data import conf
from lib.core.settings import UNICODE_ENCODING

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

def urlencode(value, safe="%&=|()", convall=False):
    if conf.direct or "POSTxml" in conf.paramDict:
        return value

    result = None

    if value is None:
        return result

    if convall:
        result = urllib.quote(utf8encode(value)) # Reference: http://old.nabble.com/Re:-Problem:-neither-urllib2.quote-nor-urllib.quote-encode-the--unicode-strings-arguments-p19823144.html
    else:
        result = urllib.quote(utf8encode(value), safe)

    return result

def utf8encode(value):
    return value.encode("utf-8")

def utf8decode(value):
    return value.decode("utf-8")

def htmlescape(value):
    return value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;').replace(' ', '&nbsp;')

def htmlunescape(value):
    return value.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#39;', "'").replace('&nbsp;', ' ')
