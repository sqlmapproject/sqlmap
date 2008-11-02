#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2008 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

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



import time

from lib.core.agent import agent
from lib.core.common import dataToStdout
from lib.core.common import formatFingerprint
from lib.core.common import getHtmlErrorFp
from lib.core.common import randomInt
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapSyntaxException
from lib.core.session import setDbms
from lib.core.settings import MSSQL_ALIASES
from lib.core.settings import MSSQL_SYSTEM_DBS
from lib.core.unescaper import unescaper
from lib.parse.banner import bannerParser
from lib.request import inject
from lib.request.connect import Connect as Request
#from lib.utils.fuzzer import passiveFuzzing

from plugins.generic.enumeration import Enumeration
from plugins.generic.filesystem import Filesystem
from plugins.generic.fingerprint import Fingerprint
from plugins.generic.takeover import Takeover


class MSSQLServerMap(Fingerprint, Enumeration, Filesystem, Takeover):
    """
    This class defines Microsoft SQL Server methods
    """

    def __init__(self):
        self.excludeDbsList = MSSQL_SYSTEM_DBS
        Enumeration.__init__(self, "Microsoft SQL Server")

        unescaper.setUnescape(MSSQLServerMap.unescape)


    @staticmethod
    def unescape(expression, quote=True):
        if quote:
            while True:
                index = expression.find("'")
                if index == -1:
                    break

                firstIndex = index + 1
                index = expression[firstIndex:].find("'")

                if index == -1:
                    raise sqlmapSyntaxException, "Unenclosed ' in '%s'" % expression

                lastIndex = firstIndex + index
                old = "'%s'" % expression[firstIndex:lastIndex]
                #unescaped = "("
                unescaped = ""

                for i in range(firstIndex, lastIndex):
                    unescaped += "CHAR(%d)" % (ord(expression[i]))
                    if i < lastIndex - 1:
                        unescaped += "+"

                #unescaped += ")"
                expression = expression.replace(old, unescaped)
        else:
            expression = "+".join("CHAR(%d)" % ord(c) for c in expression)

        return expression


    @staticmethod
    def escape(expression):
        while True:
            index = expression.find("CHAR(")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex:].find("))")

            if index == -1:
                raise sqlmapSyntaxException, "Unenclosed ) in '%s'" % expression

            lastIndex = firstIndex + index + 1
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.replace("CHAR(", "").replace(")", "")
            oldUpper = oldUpper.split("+")

            escaped = "'%s'" % "".join([chr(int(char)) for char in oldUpper])
            expression = expression.replace(old, escaped)

        return expression


    def getFingerprint(self):
        actVer = formatFingerprint()

        if not conf.extensiveFp:
            return actVer

        blank = " " * 16
        value = "active fingerprint: %s" % actVer

        if self.banner:
            release, version, servicepack = bannerParser(self.banner, paths.MSSQL_XML)

            if release and version and servicepack:
                banVer  = "Microsoft SQL Server %s " % release
                banVer += "Service Pack %s " % servicepack
                banVer += "version %s" % version

                value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        #passiveFuzzing()
        htmlParsed = getHtmlErrorFp()

        if htmlParsed:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlParsed)

        return value


    def checkDbms(self):
        if conf.dbms in MSSQL_ALIASES and kb.dbmsVersion and kb.dbmsVersion[0].isdigit():
            setDbms("Microsoft SQL Server %s" % kb.dbmsVersion[0])

            if not conf.extensiveFp:
                return True

        logMsg = "testing Microsoft SQL Server"
        logger.info(logMsg)

        randInt = str(randomInt(1))
        query = "LTRIM(STR(LEN(%s)))" % randInt

        if inject.getValue(query) == "1":
            query = "SELECT SUBSTRING((@@VERSION), 25, 1)"
            version = inject.getValue(query)

            if version == "8":
                kb.dbmsVersion = ["2008"]
            elif version == "5":
                kb.dbmsVersion = ["2005"]
            elif version == "0":
                kb.dbmsVersion = ["2000"]

            if kb.dbmsVersion:
                setDbms("Microsoft SQL Server %s" % kb.dbmsVersion[0])
            else:
                setDbms("Microsoft SQL Server")

            if not conf.extensiveFp:
                return True

            if conf.getBanner:
                self.banner = inject.getValue("@@VERSION")

            return True
        else:
            warnMsg = "the back-end DMBS is not Microsoft SQL Server"
            logger.warn(warnMsg)

            return False


    def getPrivileges(self):
        warnMsg = "this plugin can not fetch database users privileges"
        logger.warn(warnMsg)

        return {}


    def getTables(self):
        logMsg = "fetching tables"
        if conf.db:
            logMsg += " for database '%s'" % conf.db
        logger.info(logMsg)

        rootQuery = queries[kb.dbms].tables

        if not conf.db:
            if not len(self.cachedDbs):
                dbs = self.getDbs()
            else:
                dbs = self.cachedDbs
        else:
            if "," in conf.db:
                dbs = conf.db.split(",")
            else:
                dbs = [conf.db]

        if conf.unionUse:
            for db in dbs:
                if conf.excludeSysDbs and db in self.excludeDbsList:
                    logMsg = "skipping system database '%s'" % db
                    logger.info(logMsg)

                    continue

                query = rootQuery["inband"]["query"] % db
                value = inject.getValue(query, blind=False)

                if value:
                    self.cachedTables[db] = value

        if not self.cachedTables:
            for db in dbs:
                if conf.excludeSysDbs and db in self.excludeDbsList:
                    logMsg = "skipping system database '%s'" % db
                    logger.info(logMsg)

                    continue

                logMsg  = "fetching number of tables for "
                logMsg += "database '%s'" % db
                logger.info(logMsg)

                query = rootQuery["blind"]["count"] % db
                count = inject.getValue(query, inband=False)

                if not len(count) or count == "0":
                    warnMsg  = "unable to retrieve the number of "
                    warnMsg += "tables for database '%s'" % db
                    logger.warn(warnMsg)
                    continue

                tables = []

                for index in range(int(count)):
                    query = rootQuery["blind"]["query"] % (db, index, db)
                    table = inject.getValue(query, inband=False)
                    tables.append(table)

                if tables:
                    self.cachedTables[db] = tables
                else:
                    warnMsg  = "unable to retrieve the tables "
                    warnMsg += "for database '%s'" % db
                    logger.warn(warnMsg)

        if not self.cachedTables:
            errMsg = "unable to retrieve the tables for any database"
            raise sqlmapNoneDataException, errMsg

        return self.cachedTables
