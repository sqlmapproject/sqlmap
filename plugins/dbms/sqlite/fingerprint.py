#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import METADB_SUFFIX
from lib.core.settings import SQLITE_ALIASES
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.SQLITE)

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
            value += DBMS.SQLITE
            return value

        actVer = Format.getDbms()
        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"]
            banVer = Format.getDbms([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        """
        References for fingerprint:

        * http://www.sqlite.org/lang_corefunc.html
        * http://www.sqlite.org/cvstrac/wiki?p=LoadableExtensions
        """

        if not conf.extensiveFp and (Backend.isDbmsWithin(SQLITE_ALIASES) or conf.dbms in SQLITE_ALIASES):
            setDbms(DBMS.SQLITE)

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.SQLITE
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("LAST_INSERT_ROWID()=LAST_INSERT_ROWID()")

        if result:
            infoMsg = "confirming %s" % DBMS.SQLITE
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("SQLITE_VERSION()=SQLITE_VERSION()")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.SQLITE
                logger.warn(warnMsg)

                return False
            else:
                infoMsg = "actively fingerprinting %s" % DBMS.SQLITE
                logger.info(infoMsg)

                result = inject.checkBooleanExpression("RANDOMBLOB(-1)>0")
                version = '3' if result else '2'
                Backend.setVersion(version)

            setDbms(DBMS.SQLITE)

            self.getBanner()

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.SQLITE
            logger.warn(warnMsg)

            return False

    def forceDbmsEnum(self):
        conf.db = "%s%s" % (DBMS.SQLITE, METADB_SUFFIX)
