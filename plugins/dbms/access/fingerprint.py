#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import getCurrentThreadData
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import wasLastRequestDBMSError
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import ACCESS_ALIASES
from lib.core.settings import METADB_SUFFIX
from lib.core.threads import getCurrentThreadData
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.ACCESS)

    def __sandBoxCheck(self):
        # Reference: http://milw0rm.com/papers/198
        retVal = None
        table = None

        if Backend.isVersionWithin(("97", "2000")):
            table = "MSysAccessObjects"
        elif Backend.isVersionWithin(("2002-2003", "2007")):
            table = "MSysAccessStorage"

        if table is not None:
            result = inject.checkBooleanExpression("EXISTS(SELECT CURDIR() FROM %s)" % table)
            retVal = "not sandboxed" if result else "sandboxed"

        return retVal

    def __sysTablesCheck(self):
        infoMsg = "executing system table(s) existence fingerprint"
        logger.info(infoMsg)

        # Microsoft Access table reference updated on 01/2010
        sysTables = { 
                      "97":           ("MSysModules2", "MSysAccessObjects"),
                      "2000" :        ("!MSysModules2", "MSysAccessObjects"),
                      "2002-2003" :   ("MSysAccessStorage", "!MSysNavPaneObjectIDs"),
                      "2007" :        ("MSysAccessStorage", "MSysNavPaneObjectIDs")
                    }
        # MSysAccessXML is not a reliable system table because it doesn't always exist
        # ("Access through Access", p6, should be "normally doesn't exist" instead of "is normally empty")

        for version, tables in sysTables.items():
            exist = True

            for table in tables:
                negate = False

                if table[0] == '!':
                    negate = True
                    table = table[1:]

                randInt = randomInt()
                result = inject.checkBooleanExpression("EXISTS(SELECT * FROM %s WHERE %d=%d)" % (table, randInt, randInt))
                if result is None:
                    result = False

                if negate:
                    result = not result

                exist &= result

                if not exist:
                    break

            if exist:
                return version

        return None

    def __getDatabaseDir(self):
        retVal = None

        infoMsg = "searching for database directory"
        logger.info(infoMsg)

        randInt = randomInt()
        randStr = randomStr()
        _ = inject.checkBooleanExpression("EXISTS(SELECT * FROM %s.%s WHERE %d=%d)" % (randStr, randStr, randInt, randInt))

        if wasLastRequestDBMSError():
            threadData = getCurrentThreadData()
            match = re.search("Could not find file\s+'([^']+?)'", threadData.lastErrorPage[1])

            if match:
                retVal = match.group(1).rstrip("%s.mdb" % randStr)

                if retVal.endswith('\\'):
                    retVal = retVal[:-1]

        return retVal

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
            value += DBMS.ACCESS
            return value

        actVer = Format.getDbms() + " (%s)" % (self.__sandBoxCheck())
        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"]

            if re.search("-log$", kb.data.banner):
                banVer += ", logging enabled"

            banVer = Format.getDbms([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        value += "\ndatabase directory: '%s'" % self.__getDatabaseDir()

        return value

    def checkDbms(self):
        if not conf.extensiveFp and (Backend.isDbmsWithin(ACCESS_ALIASES) or conf.dbms in ACCESS_ALIASES):
            setDbms(DBMS.ACCESS)

            return True

        infoMsg = "testing %s" % DBMS.ACCESS
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("VAL(CVAR(1))=1")

        if result:
            infoMsg = "confirming %s" % DBMS.ACCESS
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.ACCESS
                logger.warn(warnMsg)
                return False

            setDbms(DBMS.ACCESS)

            if not conf.extensiveFp:
                return True

            infoMsg = "actively fingerprinting %s" % DBMS.ACCESS
            logger.info(infoMsg)

            version = self.__sysTablesCheck()

            if version is not None:
                Backend.setVersion(version)

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.ACCESS
            logger.warn(warnMsg)

            return False

    def forceDbmsEnum(self):
        conf.db = ("%s%s" % (DBMS.ACCESS, METADB_SUFFIX)).replace(' ', '_')
