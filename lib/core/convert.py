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

def base64decode(string):
    return string.decode("base64")

def base64encode(string):
    return string.encode("base64")[:-1].replace("\n", "")

def base64pickle(string):
    return base64encode(pickle.dumps(string))

def base64unpickle(string):
    return pickle.loads(base64decode(string))

def hexdecode(string):
    string = string.lower()

    if string.startswith("0x"):
        string = string[2:]

    return string.decode("hex")

def hexencode(string):
    return string.encode("hex")

def md5hash(string):
    if sys.modules.has_key('hashlib'):
        return hashlib.md5(string).hexdigest()
    else:
        return md5.new(string).hexdigest()

def orddecode(string):
    packedString = struct.pack("!"+"I" * len(string), *string)
    return "".join([chr(char) for char in struct.unpack("!"+"I"*(len(packedString)/4), packedString)])

def ordencode(string):
    return tuple([ord(char) for char in string])

def sha1hash(string):
    if sys.modules.has_key('hashlib'):
        return hashlib.sha1(string).hexdigest()
    else:
        return sha.new(string).hexdigest()

def urldecode(string):
    result = None

    if string:
        result = urllib.unquote_plus(string)

    return result

def urlencode(string, safe=":/?%&=", convall=False):
    if conf.direct or "POSTxml" in conf.paramDict:
        return string

    result = None

    if string is None:
        return result

    if convall:
        result = urllib.quote(utf8encode(string)) # Reference: http://old.nabble.com/Re:-Problem:-neither-urllib2.quote-nor-urllib.quote-encode-the--unicode-strings-arguments-p19823144.html
    else:
        result = urllib.quote(utf8encode(string), safe)

    return result

def utf8encode(string):
    return string.encode("utf-8")

def utf8decode(string):
    return string.decode("utf-8")

def htmlescape(string):
    return string.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')

def htmlunescape(string):
    return string.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#39;', "'")
