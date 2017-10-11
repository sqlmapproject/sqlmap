#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)
