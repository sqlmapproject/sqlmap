#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import formatDBMSfp
from lib.core.common import formatFingerprint
from lib.core.common import getErrorParsedDBMSesFormatted
from lib.core.common import getIdentifiedDBMS
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
        wsOsFp = formatFingerprint("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = formatFingerprint("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "back-end DBMS: "

        if not conf.extensiveFp:
            value += DBMS.SYBASE
            return value

        actVer = formatDBMSfp()
        blank  = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"]
            banVer = formatDBMSfp([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = getErrorParsedDBMSesFormatted()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if ((getIdentifiedDBMS() is not None and getIdentifiedDBMS().lower() in SYBASE_ALIASES) \
           or conf.dbms in SYBASE_ALIASES) and kb.dbmsVersion and \
           kb.dbmsVersion[0].isdigit():
            setDbms("%s %s" % (DBMS.SYBASE, kb.dbmsVersion[0]))

            self.getBanner()

            if not conf.extensiveFp:
                kb.os = "Windows"

                return True

        infoMsg = "testing Sybase"
        logger.info(infoMsg)

        if conf.direct:
            result = True
        else:
            result = inject.checkBooleanExpression("tempdb_id()=tempdb_id()")

        if result:
            logMsg = "confirming Sybase"
            logger.info(logMsg)

            result = inject.checkBooleanExpression("suser_id()=suser_id()")

            if not result:
                warnMsg = "the back-end DBMS is not Sybase"
                logger.warn(warnMsg)

                return False

            setDbms(DBMS.SYBASE)

            self.getBanner()

            if not conf.extensiveFp:
                return True

            for version in range(12, 16):
                result = inject.checkBooleanExpression("@@VERSION_NUMBER/1000=%d" % version)
                if result:
                    kb.dbmsVersion = ["%d" % version]
                    break

            return True
        else:
            warnMsg = "the back-end DBMS is not Sybase"
            logger.warn(warnMsg)

            return False
