#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
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
from lib.core.settings import HSQLDB_ALIASES
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.HSQLDB)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("web server", kb.headersFp)

        if wsOsFp and not hasattr(conf, "api"):
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp and not hasattr(conf, "api"):
                value += "%s\n" % dbmsOsFp

        value += "back-end DBMS: "
        actVer = Format.getDbms()

        if not conf.extensiveFp:
            value += actVer
            return value

        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"] if 'dbmsVersion' in kb.bannerFp else None

            if re.search("-log$", kb.data.banner):
                banVer += ", logging enabled"

            banVer = Format.getDbms([banVer] if banVer else None)
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        """
        References for fingerprint:
        DATABASE_VERSION()
        version 2.2.6 added two-arg REPLACE functio REPLACE('a','a') compared to REPLACE('a','a','d')
        version 2.2.5 added SYSTIMESTAMP function
        version 2.2.3 added REGEXPR_SUBSTRING and REGEXPR_SUBSTRING_ARRAY functions
        version 2.2.0 added support for ROWNUM() function
        version 2.1.0 added MEDIAN aggregate function
        version < 2.0.1 added support for datetime ROUND and TRUNC functions
        version 2.0.0 added VALUES support
        version 1.8.0.4 Added org.hsqldbdb.Library function, getDatabaseFullProductVersion to return the
                        full version string, including the 4th digit (e.g 1.8.0.4).
        version 1.7.2 CASE statements added and INFORMATION_SCHEMA

        """

        if not conf.extensiveFp and (Backend.isDbmsWithin(HSQLDB_ALIASES) \
           or (conf.dbms or "").lower() in HSQLDB_ALIASES) and Backend.getVersion() and \
           Backend.getVersion() != UNKNOWN_DBMS_VERSION:
            setDbms("%s %s" % (DBMS.HSQLDB, Backend.getVersion()))

            if Backend.isVersionGreaterOrEqualThan("1.7.2"):
                kb.data.has_information_schema = True

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.HSQLDB
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("CASEWHEN(1=1,1,0)=1")

        if result:
            infoMsg = "confirming %s" % DBMS.HSQLDB
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("ROUNDMAGIC(PI())>=3")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.HSQLDB
                logger.warn(warnMsg)

                return False
            else:
                kb.data.has_information_schema = True
                Backend.setVersion(">= 1.7.2")
                setDbms("%s 1.7.2" % DBMS.HSQLDB)

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
            warnMsg = "the back-end DBMS is not %s or version is < 1.7.2" % DBMS.HSQLDB
            logger.warn(warnMsg)

            return False

    def getHostname(self):
        warnMsg = "on HSQLDB it is not possible to enumerate the hostname"
        logger.warn(warnMsg)
