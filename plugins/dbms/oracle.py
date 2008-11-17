#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2008 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

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

from lib.core.common import formatDBMSfp
from lib.core.common import formatOSfp
from lib.core.common import getHtmlErrorFp
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapSyntaxException
from lib.core.session import setDbms
from lib.core.settings import ORACLE_ALIASES
from lib.core.settings import ORACLE_SYSTEM_DBS
from lib.core.unescaper import unescaper
from lib.parse.banner import bannerParser
from lib.request import inject
#from lib.utils.fuzzer import passiveFuzzing

from plugins.generic.enumeration import Enumeration
from plugins.generic.filesystem import Filesystem
from plugins.generic.fingerprint import Fingerprint
from plugins.generic.takeover import Takeover


class OracleMap(Fingerprint, Enumeration, Filesystem, Takeover):
    """
    This class defines Oracle methods
    """


    def __init__(self):
        self.excludeDbsList = ORACLE_SYSTEM_DBS
        Enumeration.__init__(self, "Oracle")

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
        value  = "back-end DBMS: "

        if not conf.extensiveFp:
            value += "Oracle"
            return value

        actVer      = formatDBMSfp()
        blank       = " " * 15
        formatInfo  = None
        value      += "active fingerprint: %s" % actVer

        if self.banner:
            info       = bannerParser(self.banner)
            formatInfo = formatOSfp(info)

            banVer = info['version']
            banVer = formatDBMSfp([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        #passiveFuzzing()
        htmlErrorFp = getHtmlErrorFp()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        if formatInfo:
            value += "\n%s" % formatInfo

        return value


    def checkDbms(self):
        if conf.dbms in ORACLE_ALIASES:
            setDbms("Oracle")

            if not conf.extensiveFp:
                return True

        logMsg = "testing Oracle"
        logger.info(logMsg)

        query = "LENGTH(SYSDATE)"
        sysdate = inject.getValue(query)

        if sysdate and int(sysdate) > 0:
            logMsg = "confirming Oracle"
            logger.info(logMsg)

            query = "SELECT SUBSTR((VERSION), 1, 2) FROM SYS.PRODUCT_COMPONENT_VERSION WHERE ROWNUM=1"
            version = inject.getValue(query)

            if not version:
                warnMsg = "the back-end DMBS is not Oracle"
                logger.warn(warnMsg)

                return False

            setDbms("Oracle")

            if not conf.extensiveFp:
                return True

            if re.search("^11", version):
                kb.dbmsVersion = ["11i"]
            elif re.search("^10", version):
                kb.dbmsVersion = ["10g"]
            elif re.search("^9", version):
                kb.dbmsVersion = ["9i"]
            elif re.search("^8", version):
                kb.dbmsVersion = ["8i"]

            if conf.getBanner:
                self.banner = inject.getValue("SELECT banner FROM v$version WHERE ROWNUM=1")

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
