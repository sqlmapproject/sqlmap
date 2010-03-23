#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapUnsupportedFeatureException

from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self, "SQLite")

    def getCurrentUser(self):
        warnMsg = "on SQLite it is not possible to enumerate the current user"
        logger.warn(warnMsg)

    def getCurrentDb(self):
        warnMsg = "on SQLite it is not possible to enumerate the current database"
        logger.warn(warnMsg)

    def isDba(self):
        warnMsg = "on SQLite the current user has all privileges"
        logger.warn(warnMsg)

    def getUsers(self):
        warnMsg = "on SQLite it is not possible to enumerate the users"
        logger.warn(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "on SQLite it is not possible to enumerate the user password hashes"
        logger.warn(warnMsg)

        return {}

    def getPrivileges(self):
        warnMsg = "on SQLite it is not possible to enumerate the user privileges"
        logger.warn(warnMsg)

        return {}

    def getDbs(self):
        warnMsg = "on SQLite it is not possible to enumerate databases"
        logger.warn(warnMsg)

        return []

    def getColumns(self, onlyColNames=False):
        errMsg  = "on SQLite it is not possible to enumerate database "
        errMsg += "table columns"

        if conf.dumpTable or conf.dumpAll:
            errMsg += ", provide them with -C option"
            raise sqlmapUnsupportedFeatureException, errMsg

        logger.warn(errMsg)

    def dumpColumn(self):
        errMsg = "on SQLite you must specify the table and columns to dump"
        raise sqlmapUnsupportedFeatureException, errMsg

    def dumpAll(self):
        errMsg = "on SQLite you must specify the table and columns to dump"
        raise sqlmapUnsupportedFeatureException, errMsg
