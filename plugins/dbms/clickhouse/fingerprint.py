#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import CLICKHOUSE_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.CLICKHOUSE)

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
            value += DBMS.CLICKHOUSE
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
        if not conf.extensiveFp and Backend.isDbmsWithin(CLICKHOUSE_ALIASES):
            setDbms(DBMS.CLICKHOUSE)

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.CLICKHOUSE
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("halfMD5('abcd')='16356072519128051347'")

        if result:
            infoMsg = "confirming %s" % DBMS.CLICKHOUSE
            logger.info(infoMsg)
            result = inject.checkBooleanExpression("generateUUIDv4(1)!=generateUUIDv4(2)")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.CLICKHOUSE
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.CLICKHOUSE)
            self.getBanner()
            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.CLICKHOUSE
            logger.warning(warnMsg)

            return False
