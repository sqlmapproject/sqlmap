#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import SNOWFLAKE_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.SNOWFLAKE)

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
            value += DBMS.SNOWFLAKE
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
        """
        References for fingerprint:

        * https://docs.snowflake.com/en/sql-reference/functions/current_warehouse
        * https://docs.snowflake.com/en/sql-reference/functions/md5_number_upper64
        """

        if not conf.extensiveFp and Backend.isDbmsWithin(SNOWFLAKE_ALIASES):
            setDbms("%s %s" % (DBMS.SNOWFLAKE, Backend.getVersion()))
            self.getBanner()
            return True

        infoMsg = "testing %s" % DBMS.SNOWFLAKE
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("CURRENT_WAREHOUSE()=CURRENT_WAREHOUSE()")
        if result:
            infoMsg = "confirming %s" % DBMS.SNOWFLAKE
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("MD5_NUMBER_UPPER64('[RANDSTR]')=MD5_NUMBER_UPPER64('[RANDSTR]')")
            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.SNOWFLAKE
                logger.warning(warnMsg)
                return False

            setDbms(DBMS.SNOWFLAKE)
            self.getBanner()
            return True

        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.SNOWFLAKE
            logger.warning(warnMsg)

            return False
