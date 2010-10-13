import re
import string

from lib.core.convert import urlencode
from lib.core.exception import sqlmapUnsupportedFeatureException

"""
value -> urlencode of nonencoded chars in value
"""
def tamper(place, value):
    retVal = value
    if value:
        if place != "URI":
            retVal = ""
            i = 0
            while i < len(value):
                if value[i] == '%' and (i < len(value) - 2) and value[i+1] in string.hexdigits and value[i+2] in string.hexdigits:
                    retVal += value[i:i+3]
                    i += 3
                else:
                    retVal += '%%%X' % ord(value[i])
                    i += 1
        else:
            raise sqlmapUnsupportedFeatureException, "can't use tampering module 'charencode.py' with 'URI' type injections"
    return retVal
