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
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.session import setDbms
from lib.core.settings import DBMS
from lib.core.settings import ORACLE_ALIASES
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
            value += "Oracle"
            return value

        actVer      = formatDBMSfp()
        blank       = " " * 15
        value      += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"] if 'dbmsVersion' in kb.bannerFp else None
            banVer = formatDBMSfp([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = getHtmlErrorFp()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if conf.dbms in ORACLE_ALIASES:
            setDbms(DBMS.ORACLE)

            self.getBanner()

            if not conf.extensiveFp:
                return True

        logMsg = "testing Oracle"
        logger.info(logMsg)

        # NOTE: SELECT ROWNUM=ROWNUM FROM DUAL does not work connecting
        # directly to the Oracle database
        if conf.direct:
            result = True
        else:
            payload = agent.fullPayload(" AND ROWNUM=ROWNUM")
            result  = Request.queryPage(payload)

        if result:
            logMsg = "confirming Oracle"
            logger.info(logMsg)

            # NOTE: SELECT LENGTH(SYSDATE)=LENGTH(SYSDATE) FROM DUAL does
            # not work connecting directly to the Oracle database
            if conf.direct:
                result = True
            else:
                payload = agent.fullPayload(" AND LENGTH(SYSDATE)=LENGTH(SYSDATE)")
                result  = Request.queryPage(payload)

            if not result:
                warnMsg = "the back-end DMBS is not Oracle"
                logger.warn(warnMsg)

                return False

            setDbms(DBMS.ORACLE)

            self.getBanner()

            if not conf.extensiveFp:
                return True

            query = "SELECT SUBSTR((VERSION), 1, 2) FROM SYS.PRODUCT_COMPONENT_VERSION WHERE ROWNUM=1"
            version = inject.getValue(query, unpack=False, suppressOutput=True)

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
