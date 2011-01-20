#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import backend
from lib.core.common import format
from lib.core.common import randomInt
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import SYBASE_ALIASES
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.SYBASE)

    def getFingerprint(self):
        value  = ""
        wsOsFp = format.getOs("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "back-end DBMS: "

        if not conf.extensiveFp:
            value += DBMS.SYBASE
            return value

        actVer = format.getDbms()
        blank  = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"]
            banVer = format.getDbms([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and (backend.isDbmsWithin(SYBASE_ALIASES) \
           or conf.dbms in SYBASE_ALIASES) and backend.getVersion() and \
           backend.getVersion().isdigit():
            setDbms("%s %s" % (DBMS.SYBASE, backend.getVersion()))

            self.getBanner()

            kb.os = "Windows"

            return True

        infoMsg = "testing %s" % DBMS.SYBASE
        logger.info(infoMsg)

        if conf.direct:
            result = True
        else:
            result = inject.checkBooleanExpression("tempdb_id()=tempdb_id()")

        if result:
            logMsg = "confirming %s" % DBMS.SYBASE
            logger.info(logMsg)

            result = inject.checkBooleanExpression("suser_id()=suser_id()")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.SYBASE
                logger.warn(warnMsg)

                return False

            setDbms(DBMS.SYBASE)

            self.getBanner()

            if not conf.extensiveFp:
                return True

            infoMsg = "actively fingerprinting %s" % DBMS.SYBASE
            logger.info(infoMsg)

            for version in range(12, 16):
                result = inject.checkBooleanExpression("@@VERSION_NUMBER/1000=%d" % version)

                if result:
                    backend.setVersion(str(version))
                    break

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.SYBASE
            logger.warn(warnMsg)

            return False
