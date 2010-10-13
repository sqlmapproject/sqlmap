import re

from lib.core.convert import urldecode
from lib.core.convert import urlencode

"""
' ' -> /**/
"""
def tamper(place, value):
    if value:
        if place != "URI":
            value = urldecode(value)
        value = value.replace(" ", "/**/")
        if place != "URI":
            value = urlencode(value)
    return value
