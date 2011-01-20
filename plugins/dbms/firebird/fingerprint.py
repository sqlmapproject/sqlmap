#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.agent import agent
from lib.core.common import backend
from lib.core.common import format
from lib.core.common import getUnicode
from lib.core.common import randomInt
from lib.core.common import randomRange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import FIREBIRD_ALIASES
from lib.core.settings import METADB_SUFFIX
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.FIREBIRD)

    def getFingerprint(self):
        value  = ""
        wsOsFp = format.getOs("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value  += "back-end DBMS: "

        if not conf.extensiveFp:
            value += DBMS.FIREBIRD
            return value

        actVer  = format.getDbms() + " (%s)" % (self.__dialectCheck())
        blank       = " " * 15
        value      += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"]

            if re.search("-log$", kb.data.banner):
                banVer += ", logging enabled"

            banVer = format.getDbms([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def __sysTablesCheck(self):
        retVal = None
        table = (
                    ("1.0", ["EXISTS(SELECT CURRENT_USER FROM RDB$DATABASE)"]),
                    ("1.5", ["NULLIF(%d,%d) IS NULL", "EXISTS(SELECT CURRENT_TRANSACTION FROM RDB$DATABASE)"]),
                    ("2.0", ["EXISTS(SELECT CURRENT_TIME(0) FROM RDB$DATABASE)", "BIT_LENGTH(%d)>0", "CHAR_LENGTH(%d)>0"]),
                    ("2.1", ["BIN_XOR(%d,%d)=0", "PI()>0.%d", "RAND()<1.%d", "FLOOR(1.%d)>=0"])
                 )

        for i in xrange(len(table)):
            version, checks = table[i]
            failed = False
            check = checks[randomRange(0, len(checks)-1)].replace("%d", getUnicode(randomRange(1,100)))
            result = inject.checkBooleanExpression(check)

            if result:
                retVal = version
            else:
                failed = True
                break

            if failed:
                break

        return retVal

    def __dialectCheck(self):
        retVal = None

        if backend.getIdentifiedDbms():
            result = inject.checkBooleanExpression("EXISTS(SELECT CURRENT_DATE FROM RDB$DATABASE)")
            retVal = "dialect 3" if result else "dialect 1"

        return retVal

    def checkDbms(self):
        if not conf.extensiveFp and (backend.isDbmsWithin(FIREBIRD_ALIASES) or conf.dbms in FIREBIRD_ALIASES):
            setDbms(DBMS.FIREBIRD)

            self.getBanner()

            if not conf.extensiveFp:
                return True

        logMsg = "testing %s" % DBMS.FIREBIRD
        logger.info(logMsg)

        randInt = randomInt()
        result = inject.checkBooleanExpression("EXISTS(SELECT * FROM RDB$DATABASE WHERE %d=%d)" % (randInt, randInt))

        if result:
            logMsg = "confirming %s" % DBMS.FIREBIRD
            logger.info(logMsg)

            result = inject.checkBooleanExpression("EXISTS(SELECT CURRENT_USER FROM RDB$DATABASE)")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.FIREBIRD
                logger.warn(warnMsg)

                return False

            setDbms(DBMS.FIREBIRD)

            infoMsg = "actively fingerprinting %s" % DBMS.FIREBIRD
            logger.info(infoMsg)

            version = self.__sysTablesCheck()

            if version is not None:
                backend.setVersion(version)

            self.getBanner()

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.FIREBIRD
            logger.warn(warnMsg)

            return False

    def forceDbmsEnum(self):
        conf.db = "%s%s" % (DBMS.FIREBIRD, METADB_SUFFIX)

        if conf.tbl:
            conf.tbl = conf.tbl.upper()
