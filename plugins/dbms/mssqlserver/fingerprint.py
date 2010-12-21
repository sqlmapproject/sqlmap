#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import formatDBMSfp
from lib.core.common import formatFingerprint
from lib.core.common import getHtmlErrorFp
from lib.core.common import getUnicode
from lib.core.common import randomInt
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import MSSQL_ALIASES
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self)

    def getFingerprint(self):
        value = ""
        wsOsFp = formatFingerprint("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = formatFingerprint("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "back-end DBMS: "
        actVer = formatDBMSfp()

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
                banVer = "Microsoft SQL Server %s " % release
                banVer += "Service Pack %s " % servicepack
                banVer += "version %s" % version

                value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = getHtmlErrorFp()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if ((kb.dbms is not None and kb.dbms.lower() in MSSQL_ALIASES) \
           or conf.dbms in MSSQL_ALIASES) and kb.dbmsVersion and \
           kb.dbmsVersion[0].isdigit():
            setDbms("%s %s" % (DBMS.MSSQL, kb.dbmsVersion[0]))

            self.getBanner()

            if not conf.extensiveFp:
                kb.os = "Windows"

                return True

        infoMsg = "testing Microsoft SQL Server"
        logger.info(infoMsg)

        # NOTE: SELECT LEN(@@VERSION)=LEN(@@VERSION) FROM DUAL does not
        # work connecting directly to the Microsoft SQL Server database
        if conf.direct:
            result = True
        else:
            randInt = randomInt()
            result = inject.checkBooleanExpression("BINARY_CHECKSUM(%d)=BINARY_CHECKSUM(%d)" % (randInt, randInt))

        if result:
            infoMsg = "confirming Microsoft SQL Server"
            logger.info(infoMsg)

            for version, check in [\
                    ("2000", "HOST_NAME()=HOST_NAME()"),\
                    ("2005", "XACT_STATE()=XACT_STATE()"),\
                    ("2008", "SYSDATETIME()>0") ]:
                result = inject.checkBooleanExpression(check)

                if result:
                    kb.dbmsVersion = [version]

            if kb.dbmsVersion:
                setDbms("%s %s" % (DBMS.MSSQL, kb.dbmsVersion[0]))
            else:
                setDbms(DBMS.MSSQL)

            self.getBanner()

            kb.os = "Windows"

            return True
        else:
            warnMsg = "the back-end DBMS is not Microsoft SQL Server"
            logger.warn(warnMsg)

            return False

    def checkDbmsOs(self, detailed=False):
        if kb.os and kb.osVersion and kb.osSP:
            return

        if not kb.os:
            kb.os = "Windows"

        if not detailed:
            return

        infoMsg  = "fingerprinting the back-end DBMS operating system "
        infoMsg += "version and service pack"
        logger.info(infoMsg)

        infoMsg = "the back-end DBMS operating system is %s" % kb.os

        self.createSupportTbl(self.fileTblName, self.tblField, "varchar(1000)")
        inject.goStacked("INSERT INTO %s(%s) VALUES (%s)" % (self.fileTblName, self.tblField, "@@VERSION"))

        versions = { "2003": ("5.2", (2, 1)),
                     #"2003": ("6.0", (2, 1)),
                     "2008": ("7.0", (1,)),
                     "2000": ("5.0", (4, 3, 2, 1)),
                     "XP": ("5.1", (2, 1)),
                     "NT": ("4.0", (6, 5, 4, 3, 2, 1)) }

        # Get back-end DBMS underlying operating system version
        for version, data in versions.items():
            query =  "(SELECT LEN(%s) FROM %s WHERE %s " % (self.tblField, self.fileTblName, self.tblField)
            query += "LIKE '%Windows NT " + data[0] + "%')>0"

            if inject.checkBooleanExpression(query):
                infoMsg += " %s" % kb.osVersion
                kb.osVersion = version
                break

        if not kb.osVersion:
            kb.osVersion = "2003"
            kb.osSP = 2

            warnMsg = "unable to fingerprint the underlying operating "
            warnMsg += "system version, assuming it is Windows "
            warnMsg += "%s Service Pack %d" % (kb.osVersion, kb.osSP)
            logger.warn(warnMsg)

            self.cleanup(onlyFileTbl=True)

            return

        # Get back-end DBMS underlying operating system service pack
        sps = versions[kb.osVersion][1]

        for sp in sps:
            query =  "(SELECT LEN(%s) FROM %s WHERE %s " % (self.tblField, self.fileTblName, self.tblField)
            query += "LIKE '%Service Pack " + getUnicode(sp) + "%')>0"

            if inject.checkBooleanExpression(query):
                kb.osSP = sp
                break

        if not kb.osSP:
            debugMsg = "assuming the operating system has no service pack"
            logger.debug(debugMsg)

            kb.osSP = 0

        if kb.osVersion:
            infoMsg += " Service Pack %d" % kb.osSP

        logger.info(infoMsg)

        self.cleanup(onlyFileTbl=True)
