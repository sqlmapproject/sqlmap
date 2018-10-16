#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import unArrayizeValue
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import H2_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.H2)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("web server", kb.headersFp)

        if wsOsFp and not conf.api:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp and not conf.api:
                value += "%s\n" % dbmsOsFp

        value += "back-end DBMS: "
        actVer = Format.getDbms()

        if not conf.extensiveFp:
            value += actVer
            return value

        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if re.search(r"-log$", kb.data.banner):
                banVer += ", logging enabled"

            banVer = Format.getDbms([banVer] if banVer else None)
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(H2_ALIASES):
            setDbms("%s %s" % (DBMS.H2, Backend.getVersion()))

            if Backend.isVersionGreaterOrEqualThan("1.7.2"):
                kb.data.has_information_schema = True

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.H2
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("ZERO() IS 0")

        if result:
            infoMsg = "confirming %s" % DBMS.H2
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("ROUNDMAGIC(PI())>=3")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.H2
                logger.warn(warnMsg)

                return False
            else:
                kb.data.has_information_schema = True
                Backend.setVersion(">= 1.7.2")
                setDbms("%s 1.7.2" % DBMS.H2)

                banner = self.getBanner()
                if banner:
                    Backend.setVersion("= %s" % banner)
                else:
                    if inject.checkBooleanExpression("(SELECT [RANDNUM] FROM (VALUES(0)))=[RANDNUM]"):
                        Backend.setVersionList([">= 2.0.0", "< 2.3.0"])
                    else:
                        banner = unArrayizeValue(inject.getValue("\"org.hsqldbdb.Library.getDatabaseFullProductVersion\"()", safeCharEncode=True))
                        if banner:
                            Backend.setVersion("= %s" % banner)
                        else:
                            Backend.setVersionList([">= 1.7.2", "< 1.8.0"])

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.H2
            logger.warn(warnMsg)

            dbgMsg = "...or version is < 1.7.2"
            logger.debug(dbgMsg)

            return False

    def getHostname(self):
        warnMsg = "on H2 it is not possible to enumerate the hostname"
        logger.warn(warnMsg)
