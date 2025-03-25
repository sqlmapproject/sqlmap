#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import Format
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import MAXDB_ALIASES
from lib.request import inject
from lib.request.connect import Connect as Request
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.MAXDB)

    def _versionCheck(self):
        infoMsg = "executing %s SYSINFO version check" % DBMS.MAXDB
        logger.info(infoMsg)

        query = agent.prefixQuery("/* NoValue */")
        query = agent.suffixQuery(query)
        payload = agent.payload(newValue=query)
        result = Request.queryPage(payload)

        if not result:
            warnMsg = "unable to perform %s version check" % DBMS.MAXDB
            logger.warning(warnMsg)

            return None

        minor, major = None, None

        for version in (6, 7):
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
        value = ""
        wsOsFp = Format.getOs("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        blank = " " * 15
        value += "back-end DBMS: "

        if not conf.extensiveFp:
            value += DBMS.MAXDB
            return value

        actVer = Format.getDbms() + " (%s)" % self._versionCheck()
        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            value += "\n%sbanner parsing fingerprint: -" % blank

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(MAXDB_ALIASES):
            setDbms(DBMS.MAXDB)

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.MAXDB
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("ALPHA(NULL) IS NULL")

        if result:
            infoMsg = "confirming %s" % DBMS.MAXDB
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("MAPCHAR(NULL,1,DEFAULTMAP) IS NULL")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.MAXDB
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.MAXDB)

            self.getBanner()

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.MAXDB
            logger.warning(warnMsg)

            return False

    def forceDbmsEnum(self):
        if conf.db:
            conf.db = conf.db.upper()
        else:
            conf.db = "USER"

        if conf.tbl:
            conf.tbl = conf.tbl.upper()
