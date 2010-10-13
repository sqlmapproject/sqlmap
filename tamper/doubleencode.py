import re

from lib.core.convert import urlencode

"""
Tampering value -> urlencode(value)
"""
def tamper(place, value):
    if value:
        value = urlencode(value)
    return value
