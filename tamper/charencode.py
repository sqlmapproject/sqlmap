import re
import string

from lib.core.exception import sqlmapUnsupportedFeatureException

"""
value -> urlencode of nonencoded chars in value (e.g., SELECT%20FIELD%20FROM%20TABLE -> %53%45%4c%45%43%54%20%46%49%45%4c%44%20%46%52%4f%4d%20%54%41%42%4c%45)
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
            raise sqlmapUnsupportedFeatureException, "can't use tampering module '%s' with 'URI' type injections" % __name__
    return retVal
