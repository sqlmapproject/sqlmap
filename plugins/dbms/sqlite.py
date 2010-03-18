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
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapSyntaxException
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.session import setDbms
from lib.core.settings import SQLITE_ALIASES
from lib.core.settings import SQLITE_SYSTEM_DBS
from lib.core.unescaper import unescaper
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.enumeration import Enumeration
from plugins.generic.filesystem import Filesystem
from plugins.generic.fingerprint import Fingerprint
from plugins.generic.misc import Miscellaneous
from plugins.generic.takeover import Takeover


class SQLiteMap(Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines SQLite methods
    """

    def __init__(self):
        self.excludeDbsList = SQLITE_SYSTEM_DBS

        Enumeration.__init__(self, "SQLite")
        Filesystem.__init__(self)
        Takeover.__init__(self)
        
        unescaper.setUnescape(SQLiteMap.unescape)

    @staticmethod
    def unescape(expression, quote=True):
        # The following is not supported on SQLite 2
        return expression

        if quote:
            expression = expression.replace("'", "''")
            while True:
                index = expression.find("''")
                if index == -1:
                    break

                firstIndex = index + 2
                index = expression[firstIndex:].find("''")

                if index == -1:
                    raise sqlmapSyntaxException, "Unenclosed ' in '%s'" % expression.replace("''", "'")

                lastIndex = firstIndex + index
                old = "''%s''" % expression[firstIndex:lastIndex]
                unescaped = ""

                for i in range(firstIndex, lastIndex):
                    unescaped += "X'%x'" % ord(expression[i])
                    if i < lastIndex - 1:
                        unescaped += "||"

                #unescaped += ")"
                expression = expression.replace(old, unescaped)
            expression = expression.replace("''", "'")
        else:
            expression = "||".join("X'%x" % ord(c) for c in expression)

        return expression

    @staticmethod
    def escape(expression):
        # Example on SQLite 3, not supported on SQLite 2:
        # select X'48'||X'656c6c6f20576f726c6400'; -- Hello World
        while True:
            index = expression.find("X'")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex+2:].find("'")

            if index == -1:
                raise sqlmapSyntaxException, "Unenclosed ' in '%s'" % expression

            lastIndex = firstIndex + index + 3
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.replace("X'", "").replace("'", "")

            for i in xrange(len(oldUpper)/2):
                char = oldUpper[i*2:i*2+2]
                escaped = "'%s'" % chr(int(char, 16))
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
            value += "SQLite"
            return value

        actVer = formatDBMSfp()
        blank  = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"]
            banVer = formatDBMSfp([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = getHtmlErrorFp()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        """
        References for fingerprint:

        * http://www.sqlite.org/lang_corefunc.html
        * http://www.sqlite.org/cvstrac/wiki?p=LoadableExtensions
        """

        if conf.dbms in SQLITE_ALIASES:
            setDbms("SQLite")

            self.getBanner()

            if not conf.extensiveFp:
                return True

        logMsg = "testing SQLite"
        logger.info(logMsg)

        payload = agent.fullPayload(" AND LAST_INSERT_ROWID()=LAST_INSERT_ROWID()")
        result  = Request.queryPage(payload)

        if result:
            logMsg = "confirming SQLite"
            logger.info(logMsg)

            payload = agent.fullPayload(" AND SQLITE_VERSION()=SQLITE_VERSION()")
            result  = Request.queryPage(payload)

            if not result:
                warnMsg = "the back-end DMBS is not SQLite"
                logger.warn(warnMsg)

                return False

            setDbms("SQLite")

            self.getBanner()

            if not conf.extensiveFp:
                return True

            version = inject.getValue("SUBSTR((SQLITE_VERSION()), 1, 1)", unpack=False, charsetType=2)
            kb.dbmsVersion = [ version ]

            return True
        else:
            warnMsg = "the back-end DMBS is not SQLite"
            logger.warn(warnMsg)

            return False

    def forceDbmsEnum(self):
        conf.db = "SQLite"

    def getCurrentUser(self):
        warnMsg = "on SQLite it is not possible to enumerate the current user"
        logger.warn(warnMsg)

    def getCurrentDb(self):
        warnMsg = "on SQLite it is not possible to enumerate the current database"
        logger.warn(warnMsg)

    def isDba(self):
        warnMsg = "on SQLite the current user has all privileges"
        logger.warn(warnMsg)

    def getUsers(self):
        warnMsg = "on SQLite it is not possible to enumerate the users"
        logger.warn(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "on SQLite it is not possible to enumerate the user password hashes"
        logger.warn(warnMsg)

        return {}

    def getPrivileges(self):
        warnMsg = "on SQLite it is not possible to enumerate the user privileges"
        logger.warn(warnMsg)

        return {}

    def getDbs(self):
        warnMsg = "on SQLite it is not possible to enumerate databases"
        logger.warn(warnMsg)

        return []

    def getColumns(self, onlyColNames=False):
        errMsg  = "on SQLite it is not possible to enumerate database "
        errMsg += "table columns"

        if conf.dumpTable or conf.dumpAll:
            errMsg += ", provide them with -C option"
            raise sqlmapUnsupportedFeatureException, errMsg

        logger.warn(errMsg)

    def dumpColumn(self):
        errMsg = "on SQLite you must specify the table and columns to dump"
        raise sqlmapUnsupportedFeatureException, errMsg

    def dumpAll(self):
        errMsg = "on SQLite you must specify the table and columns to dump"
        raise sqlmapUnsupportedFeatureException, errMsg

    def readFile(self, rFile):
        errMsg = "on SQLite it is not possible to read files"
        raise sqlmapUnsupportedFeatureException, errMsg

    def writeFile(self, wFile, dFile, fileType=None, confirm=True):
        errMsg = "on SQLite it is not possible to write files"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osCmd(self):
        errMsg = "on SQLite it is not possible to execute commands"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osShell(self):
        errMsg = "on SQLite it is not possible to execute commands"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osPwn(self):
        errMsg  = "on SQLite it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osSmb(self):
        errMsg  = "on SQLite it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise sqlmapUnsupportedFeatureException, errMsg
