#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.data import kb
from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)

        kb.data.processChar = lambda x: x.replace('_', ' ') if x else x

    def getDbs(self):
        warnMsg = "on SAP MaxDB it is not possible to enumerate databases"
        logger.warn(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "on SAP MaxDB it is not possible to enumerate the user password hashes"
        logger.warn(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = "on SAP MaxDB it is not possible to search databases"
        logger.warn(warnMsg)

        return []
