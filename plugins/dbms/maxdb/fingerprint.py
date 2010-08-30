#!/usr/bin/env python

"""
$Id$

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

import re

from lib.core.agent import agent
from lib.core.common import formatDBMSfp
from lib.core.common import formatFingerprint
from lib.core.common import getHtmlErrorFp
from lib.core.common import getUnicode
from lib.core.common import randomInt
from lib.core.common import randomRange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.session import setDbms
from lib.core.settings import MAXDB_ALIASES
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

        blank   = " " * 15
        value  += "back-end DBMS: "

        if not conf.extensiveFp:
            value += "SAP MaxDB"
            return value

        actVer = formatDBMSfp() + " (%s)" % None
        blank  = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            value += "\n%sbanner parsing fingerprint: -" % blank

        htmlErrorFp = getHtmlErrorFp()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if conf.dbms in MAXDB_ALIASES:
            setDbms("SAP MaxDB")

            self.getBanner()

            if not conf.extensiveFp:
                return True

        logMsg = "testing SAP MaxDB"
        logger.info(logMsg)

        randInt = randomInt()

        payload = agent.fullPayload(" AND NOROUND(%d)=%d" % (randInt, randInt))
        result  = Request.queryPage(payload)

        if result:
            logMsg = "confirming SAP MaxDB"
            logger.info(logMsg)

            payload = agent.fullPayload(" AND MAPCHAR(NULL,1,DEFAULTMAP) IS NULL")
            result  = Request.queryPage(payload)

            if not result:
                warnMsg = "the back-end DMBS is not SAP MaxDB"
                logger.warn(warnMsg)

                return False

            setDbms("SAP MaxDB")

            self.getBanner()

            if not conf.extensiveFp:
                return True

            kb.dbmsVersion = None

            return True
        else:
            warnMsg = "the back-end DMBS is not SAP MaxDB"
            logger.warn(warnMsg)

            return False

    def forceDbmsEnum(self):
        conf.db = "SAP MaxDB"
