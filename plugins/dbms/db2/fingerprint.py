#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""


from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import randomInt
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import DB2_ALIASES
from lib.request import inject

from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.DB2)		

    def __versionCheck(self):
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
        value  = ""
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

        actVer      = Format.getDbms()
        blank       = " " * 15
        value      += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"] if 'dbmsVersion' in kb.bannerFp else None
            banVer = Format.getDbms([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and (Backend.isDbmsWithin(DB2_ALIASES) or conf.dbms in DB2_ALIASES):
            setDbms(DBMS.DB2)

            return True

        logMsg = "testing %s" % DBMS.DB2
        logger.info(logMsg)

        randInt = randomInt()
        result = inject.checkBooleanExpression("%d=(SELECT %d FROM SYSIBM.SYSDUMMY1)" % (randInt, randInt))

        if result:
            logMsg = "confirming %s" % DBMS.DB2
            logger.info(logMsg)

            version = self.__versionCheck()

            if version:
                Backend.setVersion(version)
                setDbms("%s %s" % (DBMS.DB2, Backend.getVersion()))

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.DB2
            logger.warn(warnMsg)

            return False
