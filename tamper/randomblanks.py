import re
import string

from lib.core.common import randomRange
from lib.core.exception import sqlmapUnsupportedFeatureException

"""
value -> value with inserted random blanks (e.g., INSERT->IN/**/S/**/ERT)
"""
#TODO: all
#TODO: only do it for deepness = 0 regarding '"
def tamper(place, value):
    return value
