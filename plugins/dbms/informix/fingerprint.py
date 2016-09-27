#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import INFORMIX_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.INFORMIX)

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
            value += DBMS.INFORMIX
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
        if not conf.extensiveFp and (Backend.isDbmsWithin(INFORMIX_ALIASES) or (conf.dbms or "").lower() in INFORMIX_ALIASES):
            setDbms(DBMS.INFORMIX)

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.INFORMIX
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM SYSMASTER:SYSDUAL)")

        if result:
            infoMsg = "confirming %s" % DBMS.INFORMIX
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("(SELECT DBINFO('DBNAME') FROM SYSMASTER:SYSDUAL) IS NOT NULL")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.INFORMIX
                logger.warn(warnMsg)

                return False

            setDbms(DBMS.INFORMIX)

            self.getBanner()

            if not conf.extensiveFp:
                return True

            infoMsg = "actively fingerprinting %s" % DBMS.INFORMIX
            logger.info(infoMsg)

            for version in ("12.1", "11.7", "11.5"):
                output = inject.checkBooleanExpression("EXISTS(SELECT 1 FROM SYSMASTER:SYSDUAL WHERE DBINFO('VERSION,'FULL') LIKE '%%%s%%')" % version)

                if output:
                    Backend.setVersion(version)
                    break

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.INFORMIX
            logger.warn(warnMsg)

            return False
