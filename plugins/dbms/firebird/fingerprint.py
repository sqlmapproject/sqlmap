#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import randomRange
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import FIREBIRD_ALIASES
from lib.core.settings import METADB_SUFFIX
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.FIREBIRD)

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
        actVer = Format.getDbms()

        if not conf.extensiveFp:
            value += actVer
            return value

        actVer = Format.getDbms() + " (%s)" % (self._dialectCheck())
        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if re.search(r"-log$", kb.data.banner):
                banVer += ", logging enabled"

            banVer = Format.getDbms([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def _sysTablesCheck(self):
        retVal = None
        table = (
            ("1.0", ("EXISTS(SELECT CURRENT_USER FROM RDB$DATABASE)",)),
            ("1.5", ("NULLIF(%d,%d) IS NULL", "EXISTS(SELECT CURRENT_TRANSACTION FROM RDB$DATABASE)")),
            ("2.0", ("EXISTS(SELECT CURRENT_TIME(0) FROM RDB$DATABASE)", "BIT_LENGTH(%d)>0", "CHAR_LENGTH(%d)>0")),
            ("2.1", ("BIN_XOR(%d,%d)=0", "PI()>0.%d", "RAND()<1.%d", "FLOOR(1.%d)>=0")),
            # TODO: add test for Firebird 2.5
        )

        for i in xrange(len(table)):
            version, checks = table[i]
            failed = False
            check = checks[randomRange(0, len(checks) - 1)].replace("%d", getUnicode(randomRange(1, 100)))
            result = inject.checkBooleanExpression(check)

            if result:
                retVal = version
            else:
                failed = True
                break

            if failed:
                break

        return retVal

    def _dialectCheck(self):
        retVal = None

        if Backend.getIdentifiedDbms():
            result = inject.checkBooleanExpression("EXISTS(SELECT CURRENT_DATE FROM RDB$DATABASE)")
            retVal = "dialect 3" if result else "dialect 1"

        return retVal

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(FIREBIRD_ALIASES):
            setDbms("%s %s" % (DBMS.FIREBIRD, Backend.getVersion()))

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.FIREBIRD
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("(SELECT COUNT(*) FROM RDB$DATABASE WHERE [RANDNUM]=[RANDNUM])>0")

        if result:
            infoMsg = "confirming %s" % DBMS.FIREBIRD
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("EXISTS(SELECT CURRENT_USER FROM RDB$DATABASE)")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.FIREBIRD
                logger.warn(warnMsg)

                return False

            setDbms(DBMS.FIREBIRD)

            infoMsg = "actively fingerprinting %s" % DBMS.FIREBIRD
            logger.info(infoMsg)

            version = self._sysTablesCheck()

            if version is not None:
                Backend.setVersion(version)
                setDbms("%s %s" % (DBMS.FIREBIRD, version))

            self.getBanner()

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.FIREBIRD
            logger.warn(warnMsg)

            return False

    def forceDbmsEnum(self):
        conf.db = "%s%s" % (DBMS.FIREBIRD, METADB_SUFFIX)

        if conf.tbl:
            conf.tbl = conf.tbl.upper()
