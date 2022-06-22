#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import VERTICA_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.VERTICA)

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
            value += DBMS.VERTICA
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
        if not conf.extensiveFp and Backend.isDbmsWithin(VERTICA_ALIASES):
            setDbms(DBMS.VERTICA)

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.VERTICA
        logger.info(infoMsg)

        # NOTE: Vertica works too without the CONVERT_TO()
        result = inject.checkBooleanExpression("BITSTRING_TO_BINARY(NULL) IS NULL")

        if result:
            infoMsg = "confirming %s" % DBMS.VERTICA
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("HEX_TO_INTEGER(NULL) IS NULL")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.VERTICA
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.VERTICA)

            self.getBanner()

            if not conf.extensiveFp:
                return True

            infoMsg = "actively fingerprinting %s" % DBMS.VERTICA
            logger.info(infoMsg)

            if inject.checkBooleanExpression("CALENDAR_HIERARCHY_DAY(NULL) IS NULL"):
                Backend.setVersion(">= 9.0")
            else:
                Backend.setVersion("< 9.0")

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.VERTICA
            logger.warning(warnMsg)

            return False
