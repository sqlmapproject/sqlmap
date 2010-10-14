import re

from lib.core.convert import urldecode
from lib.core.convert import urlencode

"""
' ' -> /**/ (e.g., SELECT id FROM users->SELECT/**/id/**/FROM users)
"""
def tamper(place, value):
    retVal = value
    if value:
        if place != "URI":
            value = urldecode(value)

        retVal = ""
        qoute, doublequote, firstspace = False, False, False

        for i in xrange(len(value)):
            if not firstspace:
                if value[i].isspace():
                    firstspace = True
                    retVal += "/**/"
                    continue
            elif value[i] == '\'':
                qoute = not qoute
            elif value[i] == '"':
                doublequote = not doublequote
            elif value[i]==" " and not doublequote and not qoute:
                retVal += "/**/"
                continue
            retVal += value[i]

        if place != "URI":
            retVal = urlencode(retVal)
    return retVal

