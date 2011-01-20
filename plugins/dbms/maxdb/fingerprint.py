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
from lib.core.common import randomInt
from lib.core.common import randomRange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import MAXDB_ALIASES
from lib.core.settings import METADB_SUFFIX
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.MAXDB)

    def __versionCheck(self):
        infoMsg = "executing %s SYSINFO version check" % DBMS.MAXDB
        logger.info(infoMsg)

        query   = agent.prefixQuery("/* NoValue */")
        query   = agent.suffixQuery(query)
        payload = agent.payload(newValue=query)
        result  = Request.queryPage(payload)

        if not result:
            warnMsg = "unable to perform %s version check" % DBMS.MAXDB
            logger.warn(warnMsg)

            return None

        minor, major = None, None

        for version in [6, 7]:
            result = inject.checkBooleanExpression("%d=(SELECT MAJORVERSION FROM SYSINFO.VERSION)" % version)

            if result:
                major = version

        for version in xrange(0, 10):
            result = inject.checkBooleanExpression("%d=(SELECT MINORVERSION FROM SYSINFO.VERSION)" % version)

            if result:
                minor = version

        if major and minor:
            return "%s.%s" % (major, minor)
        else:
            return None

    def getFingerprint(self):
        value  = ""
        wsOsFp = format.getOs("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        blank   = " " * 15
        value  += "back-end DBMS: "

        if not conf.extensiveFp:
            value += DBMS.MAXDB
            return value

        actVer = format.getDbms() + " (%s)" % self.__versionCheck()
        blank  = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            value += "\n%sbanner parsing fingerprint: -" % blank

        htmlErrorFp = format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and (backend.isDbmsWithin(MAXDB_ALIASES) or conf.dbms in MAXDB_ALIASES):
            setDbms(DBMS.MAXDB)

            self.getBanner()

            return True

        logMsg = "testing %s" % DBMS.MAXDB
        logger.info(logMsg)

        randInt = randomInt()
        result = inject.checkBooleanExpression("%d=NOROUND(%d)" % (randInt, randInt))

        if result:
            logMsg = "confirming %s" % DBMS.MAXDB
            logger.info(logMsg)

            result = inject.checkBooleanExpression("MAPCHAR(NULL,1,DEFAULTMAP) IS NULL")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.MAXDB
                logger.warn(warnMsg)

                return False

            setDbms(DBMS.MAXDB)

            self.getBanner()

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.MAXDB
            logger.warn(warnMsg)

            return False

    def forceDbmsEnum(self):
        conf.db = "%s%s" % (DBMS.MAXDB, METADB_SUFFIX)
