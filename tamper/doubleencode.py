import re

from lib.core.convert import urlencode
from lib.core.exception import sqlmapUnsupportedFeatureException

"""
Tampering value -> urlencode(value)
"""
def tamper(place, value):
    if value:
        if place != "URI":
            value = urlencode(value)
        else:
            raise sqlmapUnsupportedFeatureException, "can't use tampering module '%s' with 'URI' type injections" % __name__
    return value
