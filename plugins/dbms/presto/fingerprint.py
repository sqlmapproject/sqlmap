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
from lib.core.settings import PRESTO_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.PRESTO)

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
            value += DBMS.PRESTO
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
        if not conf.extensiveFp and Backend.isDbmsWithin(PRESTO_ALIASES):
            setDbms(DBMS.PRESTO)

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.PRESTO
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("TO_BASE64URL(NULL) IS NULL")

        if result:
            infoMsg = "confirming %s" % DBMS.PRESTO
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("TO_HEX(FROM_HEX(NULL)) IS NULL")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.PRESTO
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.PRESTO)

            if not conf.extensiveFp:
                return True

            infoMsg = "actively fingerprinting %s" % DBMS.PRESTO
            logger.info(infoMsg)

            # Reference: https://prestodb.io/docs/current/release/release-0.200.html
            if inject.checkBooleanExpression("FROM_IEEE754_32(NULL) IS NULL"):
                Backend.setVersion(">= 0.200")
            # Reference: https://prestodb.io/docs/current/release/release-0.193.html
            elif inject.checkBooleanExpression("NORMAL_CDF(NULL,NULL,NULL) IS NULL"):
                Backend.setVersion(">= 0.193")
            # Reference: https://prestodb.io/docs/current/release/release-0.183.html
            elif inject.checkBooleanExpression("MAP_ENTRIES(NULL) IS NULL"):
                Backend.setVersion(">= 0.183")
            # Reference: https://prestodb.io/docs/current/release/release-0.171.html
            elif inject.checkBooleanExpression("CODEPOINT(NULL) IS NULL"):
                Backend.setVersion(">= 0.171")
            # Reference: https://prestodb.io/docs/current/release/release-0.162.html
            elif inject.checkBooleanExpression("XXHASH64(NULL) IS NULL"):
                Backend.setVersion(">= 0.162")
            # Reference: https://prestodb.io/docs/current/release/release-0.151.html
            elif inject.checkBooleanExpression("COSINE_SIMILARITY(NULL,NULL) IS NULL"):
                Backend.setVersion(">= 0.151")
            # Reference: https://prestodb.io/docs/current/release/release-0.143.html
            elif inject.checkBooleanExpression("TRUNCATE(NULL) IS NULL"):
                Backend.setVersion(">= 0.143")
            # Reference: https://prestodb.io/docs/current/release/release-0.137.html
            elif inject.checkBooleanExpression("BIT_COUNT(NULL,NULL) IS NULL"):
                Backend.setVersion(">= 0.137")
            # Reference: https://prestodb.io/docs/current/release/release-0.130.html
            elif inject.checkBooleanExpression("MAP_CONCAT(NULL,NULL) IS NULL"):
                Backend.setVersion(">= 0.130")
            # Reference: https://prestodb.io/docs/current/release/release-0.115.html
            elif inject.checkBooleanExpression("SHA1(NULL) IS NULL"):
                Backend.setVersion(">= 0.115")
            # Reference: https://prestodb.io/docs/current/release/release-0.100.html
            elif inject.checkBooleanExpression("SPLIT(NULL,NULL) IS NULL"):
                Backend.setVersion(">= 0.100")
            # Reference: https://prestodb.io/docs/current/release/release-0.70.html
            elif inject.checkBooleanExpression("GREATEST(NULL,NULL) IS NULL"):
                Backend.setVersion(">= 0.70")
            else:
                Backend.setVersion("< 0.100")

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.PRESTO
            logger.warning(warnMsg)

            return False
