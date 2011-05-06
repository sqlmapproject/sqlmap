#!/usr/bin/env python

"""
$Id: enumeration.py 3678 2011-04-15 12:33:18Z stamparm $

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""


from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)        
    
    def getPasswordHashes(self):
        warnMsg = "on DB2 it is not possible to list password hashes"
        logger.warn(warnMsg)

        return {}