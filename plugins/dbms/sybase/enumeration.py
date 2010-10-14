#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file doc/COPYING for copying permission.
"""

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapUnsupportedFeatureException

from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self, "Sybase")

    def getPasswordHashes(self):
        warnMsg = "on Sybase it is not possible to enumerate the user password hashes"
        logger.warn(warnMsg)

        return {}
