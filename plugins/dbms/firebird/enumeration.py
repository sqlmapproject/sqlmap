#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.data import logger
from lib.core.settings import DBMS

from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self, DBMS.FIREBIRD)

    def getDbs(self):
        warnMsg = "on Firebird it is not possible to enumerate databases"
        logger.warn(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "on Firebird it is not possible to enumerate the user password hashes"
        logger.warn(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = "on Firebird it is not possible to search databases"
        logger.warn(warnMsg)

        return []
