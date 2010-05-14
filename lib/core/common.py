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

import os
import random
import re
import socket
import string
import sys
import time
import urlparse
import ntpath
import posixpath
import subprocess

from StringIO import StringIO
from tempfile import NamedTemporaryFile
from tempfile import mkstemp
from xml.sax import parse

from extra.cloak.cloak import decloak
from lib.contrib import magic
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.data import temp
from lib.core.convert import urlencode
from lib.core.exception import sqlmapFilePathException
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapMissingDependence
from lib.core.exception import sqlmapSyntaxException
from lib.core.settings import DESCRIPTION
from lib.core.settings import IS_WIN
from lib.core.settings import SITE
from lib.core.settings import SQL_STATEMENTS
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import VERSION_STRING
from lib.core.settings import MSSQL_ALIASES
from lib.core.settings import MYSQL_ALIASES
from lib.core.settings import PGSQL_ALIASES
from lib.core.settings import ORACLE_ALIASES
from lib.core.settings import SQLITE_ALIASES
from lib.core.settings import ACCESS_ALIASES
from lib.core.settings import FIREBIRD_ALIASES

def paramToDict(place, parameters=None):
    """
    Split the parameters into names and values, check if these parameters
    are within the testable parameters and return in a dictionary.

    @param place: where sqlmap has to work, can be GET, POST or Cookie.
    @type place: C{str}

    @param parameters: parameters string in the format for instance
    'p1=v1&p2=v2' (GET and POST) or 'p1=v1;p2=v2' (Cookie).
    @type parameters: C{str}

    @return: the parameters in a dictionary.
    @rtype: C{str}
    """

    testableParameters = {}

    if conf.parameters.has_key(place) and not parameters:
        parameters = conf.parameters[place]

    parameters = parameters.replace(", ", ",")

    if place == "Cookie":
        splitParams = parameters.split(";")
    else:
        splitParams = parameters.split("&")

    for element in splitParams:
        elem = element.split("=")

        if len(elem) == 2:
            parameter = elem[0].replace(" ", "")

            condition  = not conf.testParameter
            condition |= parameter in conf.testParameter

            if condition:
                value = elem[1]
                testableParameters[parameter] = value

    if conf.testParameter and not testableParameters:
        paramStr = ", ".join(test for test in conf.testParameter)

        if len(conf.testParameter) > 1:
            warnMsg  = "the testable parameters '%s' " % paramStr
            warnMsg += "you provided are not into the %s" % place
        else:
            parameter = conf.testParameter[0]

            warnMsg  = "the testable parameter '%s' " % paramStr
            warnMsg += "you provided is not into the %s" % place

        logger.warn(warnMsg)

    elif len(conf.testParameter) != len(testableParameters.keys()):
        for parameter in conf.testParameter:
            if not testableParameters.has_key(parameter):
                warnMsg  =  "the testable parameter '%s' " % parameter
                warnMsg += "you provided is not into the %s" % place
                logger.warn(warnMsg)

    return testableParameters

def formatDBMSfp(versions=None):
    """
    This function format the back-end DBMS fingerprint value and return its
    values formatted as a human readable string.

    @return: detected back-end DBMS based upon fingerprint techniques.
    @rtype: C{str}
    """

    if ( not versions or versions == [None] ) and kb.dbmsVersion and kb.dbmsVersion[0] != "Unknown":
        versions = kb.dbmsVersion

    if isinstance(versions, str):
        return "%s %s" % (kb.dbms, versions)
    elif isinstance(versions, (list, set, tuple)):
        return "%s %s" % (kb.dbms, " and ".join([version for version in versions]))
    elif not versions:
        warnMsg  = "unable to extensively fingerprint the back-end "
        warnMsg += "DBMS version"
        logger.warn(warnMsg)

        return kb.dbms

def formatFingerprintString(values, chain=" or "):
    strJoin = "|".join([v for v in values])

    return strJoin.replace("|", chain)

def formatFingerprint(target, info):
    """
    This function format the back-end operating system fingerprint value
    and return its values formatted as a human readable string.

    Example of info (kb.headersFp) dictionary:

    {
      'distrib': set(['Ubuntu']),
      'type': set(['Linux']),
      'technology': set(['PHP 5.2.6', 'Apache 2.2.9']),
      'release': set(['8.10'])
    }

    Example of info (kb.bannerFp) dictionary:

    {
      'sp': set(['Service Pack 4']),
      'dbmsVersion': '8.00.194',
      'dbmsServicePack': '0',
      'distrib': set(['2000']),
      'dbmsRelease': '2000',
      'type': set(['Windows'])
    }

    @return: detected back-end operating system based upon fingerprint
    techniques.
    @rtype: C{str}
    """

    infoStr = ""

    if info and "type" in info:
        infoStr += "%s operating system: %s" % (target, formatFingerprintString(info["type"]))

        if "distrib" in info:
            infoStr += " %s" % formatFingerprintString(info["distrib"])

        if "release" in info:
            infoStr += " %s" % formatFingerprintString(info["release"])

        if "sp" in info:
            infoStr += " %s" % formatFingerprintString(info["sp"])

        if "codename" in info:
            infoStr += " (%s)" % formatFingerprintString(info["codename"])

    if "technology" in info:
        infoStr += "\nweb application technology: %s" % formatFingerprintString(info["technology"], ", ")

    return infoStr

def getHtmlErrorFp():
    """
    This function parses the knowledge base htmlFp list and return its
    values formatted as a human readable string.

    @return: list of possible back-end DBMS based upon error messages
    parsing.
    @rtype: C{str}
    """

    htmlParsed = ""

    if not kb.htmlFp:
        return None

    if len(kb.htmlFp) == 1:
        htmlVer = kb.htmlFp[0]
        htmlParsed = htmlVer
    elif len(kb.htmlFp) > 1:
        htmlParsed = " or ".join([htmlFp for htmlFp in kb.htmlFp])

    return htmlParsed

def getDocRoot(webApi=None):
    docRoot = None
    pagePath = directoryPath(conf.path)

    if kb.os == "Windows":
        if webApi == "php":
            defaultDocRoot = "C:/xampp/htdocs/"
        else:
            defaultDocRoot = "C:/Inetpub/wwwroot/"
    else:
        defaultDocRoot = "/var/www/"

    if kb.absFilePaths:
        for absFilePath in kb.absFilePaths:
            if directoryPath(absFilePath) == '/':
                continue

            absFilePath = normalizePath(absFilePath)
            absFilePathWin = None

            if isWindowsPath(absFilePath):
                absFilePathWin = posixToNtSlashes(absFilePath)
                absFilePath    = ntToPosixSlashes(absFilePath[2:])
            elif isWindowsDriveLetterPath(absFilePath): # E.g. C:/xampp/htdocs
                absFilePath    = absFilePath[2:]

            if pagePath in absFilePath:
                index   = absFilePath.index(pagePath)
                docRoot = absFilePath[:index]

                if len(docRoot) == 0:
                    docRoot = None
                    continue

                if absFilePathWin:
                    docRoot = "C:/%s" % ntToPosixSlashes(docRoot)

                docRoot = normalizePath(docRoot)
                break

    if docRoot:
        infoMsg = "retrieved the web server document root: '%s'" % docRoot
        logger.info(infoMsg)
    else:
        warnMsg = "unable to retrieve the web server document root"
        logger.warn(warnMsg)

        message  = "please provide the web server document root "
        message += "[%s]: " % defaultDocRoot
        inputDocRoot = readInput(message, default=defaultDocRoot)

        if inputDocRoot:
            docRoot = inputDocRoot
        else:
            docRoot = defaultDocRoot

    return docRoot

def getDirs(webApi=None):
    directories = set()

    if kb.os == "Windows":
        if webApi == "php":
            defaultDirs = ["C:/xampp/htdocs/"]
        else:
            defaultDirs = ["C:/Inetpub/wwwroot/"]
    else:
        defaultDirs = ["/var/www/"]

    if kb.absFilePaths:
        infoMsg  = "retrieved web server full paths: "
        infoMsg += "'%s'" % ", ".join(path for path in kb.absFilePaths)
        logger.info(infoMsg)
        
        for absFilePath in kb.absFilePaths:
            if absFilePath:
                directory = directoryPath(absFilePath)

                if isWindowsPath(directory):
                    directory = ntToPosixSlashes(directory)

                if directory == '/':
                    continue

                directories.add(directory)
    else:
        warnMsg = "unable to retrieve any web server path"
        logger.warn(warnMsg)

    message   = "please provide any additional web server full path to try "
    message  += "to upload the agent [%s]: " % ",".join(directory for directory in defaultDirs)
    inputDirs = readInput(message, default=",".join(directory for directory in defaultDirs))

    if inputDirs:
        inputDirs = inputDirs.replace(", ", ",")
        inputDirs = inputDirs.split(",")

        for inputDir in inputDirs:
            if inputDir:
                directories.add(inputDir)
    else:
        [directories.add(directory) for directory in defaultDirs]

    return directories

def filePathToString(filePath):
    strRepl = filePath.replace("/", "_").replace("\\", "_")
    strRepl = strRepl.replace(" ", "_").replace(":", "_")

    return strRepl

def dataToStdout(data):
    sys.stdout.write(data)
    sys.stdout.flush()

def dataToSessionFile(data):
    if not conf.sessionFile:
        return

    conf.sessionFP.write(data)
    conf.sessionFP.flush()

def dataToDumpFile(dumpFile, data):
    dumpFile.write(data)
    dumpFile.flush()

def dataToOutFile(data):
    if not data:
        return "No data retrieved"

    rFile     = filePathToString(conf.rFile)
    rFilePath = "%s%s%s" % (conf.filePath, os.sep, rFile)
    rFileFP   = open(rFilePath, "wb")

    rFileFP.write(data)
    rFileFP.flush()
    rFileFP.close()

    return rFilePath

def strToHex(inpStr):
    """
    @param inpStr: inpStr to be converted into its hexadecimal value.
    @type inpStr: C{str}

    @return: the hexadecimal converted inpStr.
    @rtype: C{str}
    """

    hexStr = ""

    for character in inpStr:
        if character == "\n":
            character = " "

        hexChar = "%2x" % ord(character)
        hexChar = hexChar.replace(" ", "0")
        hexChar = hexChar.upper()

        hexStr += hexChar

    return hexStr
        
def fileToStr(fileName):
    """
    @param fileName: file path to read the content and return as a no
    NEWLINE string.
    @type fileName: C{file.open}

    @return: the file content as a string without TAB and NEWLINE.
    @rtype: C{str}
    """

    filePointer = open(fileName, "r")
    fileText = filePointer.read()

    return fileText.replace("    ", "").replace("\t", "").replace("\r", "").replace("\n", " ")

def fileToHex(fileName):
    """
    @param fileName: file path to read the content and return as an
    hexadecimal string.
    @type fileName: C{file.open}

    @return: the file content as an hexadecimal string.
    @rtype: C{str}
    """

    fileText = fileToStr(fileName)
    hexFile = strToHex(fileText)

    return hexFile

def readInput(message, default=None):
    """
    @param message: message to display on terminal.
    @type message: C{str}

    @return: a string read from keyboard as input.
    @rtype: C{str}
    """

    if "\n" in message:
        message += "\n> "

    if conf.batch and default:
        infoMsg = "%s%s" % (message, str(default))
        logger.info(infoMsg)

        debugMsg = "used the default behaviour, running in batch mode"
        logger.debug(debugMsg)

        data = default
    else:
        data = raw_input(message)

        if not data:
            data = default

    return data
        
def randomRange(start=0, stop=1000):
    """
    @param start: starting number.
    @type start: C{int}

    @param stop: last number.
    @type stop: C{int}

    @return: a random number within the range.
    @rtype: C{int}
    """

    return int(random.randint(start, stop))

def randomInt(length=4):
    """
    @param length: length of the random string.
    @type length: C{int}

    @return: a random string of digits.
    @rtype: C{str}
    """

    return int("".join([random.choice(string.digits) for _ in xrange(0, length)]))

def randomStr(length=4, lowercase=False):
    """
    @param length: length of the random string.
    @type length: C{int}

    @return: a random string of characters.
    @rtype: C{str}
    """

    if lowercase:
        rndStr = "".join([random.choice(string.lowercase) for _ in xrange(0, length)])
    else:
        rndStr = "".join([random.choice(string.letters) for _ in xrange(0, length)])

    return rndStr
    
def sanitizeStr(inpStr):
    """
    @param inpStr: inpStr to sanitize: cast to str datatype and replace
    newlines with one space and strip carriage returns.
    @type inpStr: C{str}

    @return: sanitized inpStr
    @rtype: C{str}
    """

    cleanString = str(inpStr)
    cleanString = cleanString.replace("\n", " ").replace("\r", "")

    return cleanString

def checkFile(filename):
    """
    @param filename: filename to check if it exists.
    @type filename: C{str}
    """

    if not os.path.exists(filename):
        raise sqlmapFilePathException, "unable to read file '%s'" % filename

def replaceNewlineTabs(inpStr, stdout=False):
    if stdout:
        replacedString = inpStr.replace("\n", " ").replace("\t", " ")
    else:
        replacedString = inpStr.replace("\n", "__NEWLINE__").replace("\t", "__TAB__")

    replacedString = replacedString.replace(temp.delimiter, "__DEL__")

    return replacedString

def banner():
    """
    This function prints sqlmap banner with its version
    """

    print """
    %s - %s
    %s
    """ % (VERSION_STRING, DESCRIPTION, SITE)
    
def parsePasswordHash(password):
    blank = " " * 8

    if not password or password == " ":
        password = "NULL"

    if kb.dbms == "Microsoft SQL Server" and password != "NULL":
        hexPassword = password
        password  = "%s\n" % hexPassword
        password += "%sheader: %s\n" % (blank, hexPassword[:6])
        password += "%ssalt: %s\n" % (blank, hexPassword[6:14])
        password += "%smixedcase: %s\n" % (blank, hexPassword[14:54])

        if kb.dbmsVersion[0] not in ( "2005", "2008" ):
            password += "%suppercase: %s" % (blank, hexPassword[54:])

    return password

def cleanQuery(query):
    upperQuery = query

    for sqlStatements in SQL_STATEMENTS.values():
        for sqlStatement in sqlStatements:
            sqlStatementEsc = sqlStatement.replace("(", "\\(")
            queryMatch = re.search("(%s)" % sqlStatementEsc, query, re.I)

            if queryMatch:
                upperQuery = upperQuery.replace(queryMatch.group(1), sqlStatement.upper())

    return upperQuery
            
def setPaths():
    # sqlmap paths
    paths.SQLMAP_CONTRIB_PATH    = os.path.join(paths.SQLMAP_ROOT_PATH, "lib", "contrib")
    paths.SQLMAP_SHELL_PATH      = os.path.join(paths.SQLMAP_ROOT_PATH, "shell")
    paths.SQLMAP_TXT_PATH        = os.path.join(paths.SQLMAP_ROOT_PATH, "txt")
    paths.SQLMAP_UDF_PATH        = os.path.join(paths.SQLMAP_ROOT_PATH, "udf")
    paths.SQLMAP_XML_PATH        = os.path.join(paths.SQLMAP_ROOT_PATH, "xml")
    paths.SQLMAP_XML_BANNER_PATH = os.path.join(paths.SQLMAP_XML_PATH, "banner")
    paths.SQLMAP_OUTPUT_PATH     = os.path.join(paths.SQLMAP_ROOT_PATH, "output")
    paths.SQLMAP_DUMP_PATH       = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "dump")
    paths.SQLMAP_FILES_PATH      = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "files")

    # sqlmap files
    paths.SQLMAP_HISTORY         = os.path.join(paths.SQLMAP_ROOT_PATH, ".sqlmap_history")
    paths.SQLMAP_CONFIG          = os.path.join(paths.SQLMAP_ROOT_PATH, "sqlmap-%s.conf" % randomStr())
    paths.FUZZ_VECTORS           = os.path.join(paths.SQLMAP_TXT_PATH, "fuzz_vectors.txt")
    paths.DETECTION_RULES_XML    = os.path.join(paths.SQLMAP_XML_PATH, "detection.xml")
    paths.ERRORS_XML             = os.path.join(paths.SQLMAP_XML_PATH, "errors.xml")
    paths.QUERIES_XML            = os.path.join(paths.SQLMAP_XML_PATH, "queries.xml")
    paths.GENERIC_XML            = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "generic.xml")
    paths.MSSQL_XML              = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "mssql.xml")
    paths.MYSQL_XML              = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "mysql.xml")
    paths.ORACLE_XML             = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "oracle.xml")
    paths.PGSQL_XML              = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "postgresql.xml")
    
def weAreFrozen():
    """
    Returns whether we are frozen via py2exe.
    This will affect how we find out where we are located.
    Reference: http://www.py2exe.org/index.cgi/WhereAmI
    """

    return hasattr(sys, "frozen")

def parseTargetDirect():
    """
    Parse target dbms and set some attributes into the configuration singleton.
    """

    if not conf.direct:
        return

    details = None
    remote = False

    for dbms in SUPPORTED_DBMS:
        details = re.search("^(?P<dbms>%s)://(?P<credentials>(?P<user>.+?)\:(?P<pass>.*?)\@)?(?P<remote>(?P<hostname>.+?)\:(?P<port>[\d]+)\/)?(?P<db>[\w\d\.\_\-\/]+?)$" % dbms, conf.direct, re.I)

        if details:
            conf.dbms = details.group('dbms')

            if details.group('credentials'):
                conf.dbmsUser = details.group('user')
                conf.dbmsPass = details.group('pass')
            else:
                conf.dbmsUser = str()
                conf.dbmsPass = str()

            if not conf.dbmsPass:
                conf.dbmsPass = None

            if details.group('remote'):
                remote = True
                conf.hostname = details.group('hostname')
                conf.port     = int(details.group('port'))   
            else:
                conf.hostname = "localhost"
                conf.port     = 0

            conf.dbmsDb = details.group('db')

            conf.parameters[None] = "direct connection"

            break

    if not details:
        errMsg = "invalid target details, valid syntax is for instance "
        errMsg += "'mysql://USER:PASSWORD@DBMS_IP:DBMS_PORT/DATABASE_NAME' "
        errMsg += "or 'access://DATABASE_FILEPATH'"
        raise sqlmapSyntaxException, errMsg

    dbmsDict = { "Microsoft SQL Server": [MSSQL_ALIASES, "python-pymssql", "http://pymssql.sourceforge.net/"],
                 "MySQL": [MYSQL_ALIASES, "python-mysqldb", "http://mysql-python.sourceforge.net/"],
                 "PostgreSQL": [PGSQL_ALIASES, "python-psycopg2", "http://initd.org/psycopg/"],
                 "Oracle": [ORACLE_ALIASES, "python cx_Oracle", "http://cx-oracle.sourceforge.net/"],
                 "SQLite": [SQLITE_ALIASES, "python-pysqlite2 and python-sqlite", "http://pysqlite.googlecode.com/"],
                 "Access": [ACCESS_ALIASES, "python-pyodbc", "http://pyodbc.googlecode.com/"],
                 "Firebird": [FIREBIRD_ALIASES, "python-kinterbasdb", "http://kinterbasdb.sourceforge.net/"] }

    for dbmsName, data in dbmsDict.items():
        if conf.dbms in data[0]:
            try:
                if dbmsName in ('Access', 'SQLite'):
                    if remote:
                        warnMsg = "direct connection over the network for "
                        warnMsg += "%s DBMS is not supported" % dbmsName
                        logger.warn(warnMsg)

                        conf.hostname = "localhost"
                        conf.port     = 0
                elif not remote:
                        errMsg = "missing remote connection details"
                        raise sqlmapSyntaxException, errMsg

                if dbmsName == "Microsoft SQL Server":
                    import _mssql
                    import pymssql

                    if not hasattr(pymssql, "__version__") or pymssql.__version__ < "1.0.2":
                        errMsg = "pymssql library on your system must be "
                        errMsg += "version 1.0.2 to work, get it from "
                        errMsg += "http://sourceforge.net/projects/pymssql/files/pymssql/1.0.2/"
                        raise sqlmapMissingDependence, errMsg

                elif dbmsName == "MySQL":
                    import MySQLdb
                elif dbmsName == "PostgreSQL":
                    import psycopg2
                elif dbmsName == "Oracle":
                    import cx_Oracle
                elif dbmsName == "SQLite":
                    import sqlite
                    import sqlite3
                elif dbmsName == "Access":
                    import pyodbc
                elif dbmsName == "Firebird":
                    import kinterbasdb
            except ImportError, _:
                errMsg  = "sqlmap requires %s third-party library " % data[1]
                errMsg += "in order to directly connect to the database "
                errMsg += "%s. Download from %s" % (dbmsName, data[2])
                raise sqlmapMissingDependence, errMsg

def parseTargetUrl():
    """
    Parse target url and set some attributes into the configuration singleton.
    """

    if not conf.url:
        return

    if not re.search("^http[s]*://", conf.url):
        if ":443/" in conf.url:
            conf.url = "https://" + conf.url
        else:
            conf.url = "http://" + conf.url

    __urlSplit     = urlparse.urlsplit(conf.url)
    __hostnamePort = __urlSplit[1].split(":")

    conf.scheme    = __urlSplit[0]
    conf.path      = __urlSplit[2]
    conf.hostname  = __hostnamePort[0]

    if len(__hostnamePort) == 2:
        try:
            conf.port = int(__hostnamePort[1])
        except:
            errMsg = "invalid target url"
            raise sqlmapSyntaxException, errMsg
    elif conf.scheme == "https":
        conf.port = 443
    else:
        conf.port = 80

    if __urlSplit[3]:
        conf.parameters["GET"] = __urlSplit[3]

    conf.url = "%s://%s:%d%s" % (conf.scheme, conf.hostname, conf.port, conf.path)
    
def expandAsteriskForColumns(expression):
    # If the user provided an asterisk rather than the column(s)
    # name, sqlmap will retrieve the columns itself and reprocess
    # the SQL query string (expression)
    asterisk = re.search("^SELECT\s+\*\s+FROM\s+([\w\.\_]+)\s*", expression, re.I)

    if asterisk:
        infoMsg  = "you did not provide the fields in your query. "
        infoMsg += "sqlmap will retrieve the column names itself"
        logger.info(infoMsg)

        dbTbl = asterisk.group(1)

        if dbTbl and "." in dbTbl:
            conf.db, conf.tbl = dbTbl.split(".")
        else:
            conf.tbl = dbTbl

        columnsDict = conf.dbmsHandler.getColumns(onlyColNames=True)

        if columnsDict and conf.db in columnsDict and conf.tbl in columnsDict[conf.db]:
            columns = columnsDict[conf.db][conf.tbl].keys()
            columns.sort()
            columnsStr = ", ".join([column for column in columns])
            expression = expression.replace("*", columnsStr, 1)

            infoMsg  = "the query with column names is: "
            infoMsg += "%s" % expression
            logger.info(infoMsg)

    return expression

def getRange(count, dump=False, plusOne=False):
    count      = int(count)
    indexRange = None
    limitStart = 1
    limitStop  = count

    if dump:
        if isinstance(conf.limitStop, int) and conf.limitStop > 0 and conf.limitStop < limitStop:
            limitStop = conf.limitStop

        if isinstance(conf.limitStart, int) and conf.limitStart > 0 and conf.limitStart <= limitStop:
            limitStart = conf.limitStart

    if plusOne:
        indexRange = range(limitStart, limitStop + 1)
    else:
        indexRange = range(limitStart - 1, limitStop)

    return indexRange
    
def parseUnionPage(output, expression, partial=False, condition=None, sort=True):
    data = []

    outCond1 = ( output.startswith(temp.start) and output.endswith(temp.stop) )
    outCond2 = ( output.startswith("__START__") and output.endswith("__STOP__") )

    if outCond1 or outCond2:
        if outCond1:
            regExpr = '%s(.*?)%s' % (temp.start, temp.stop)
        elif outCond2:
            regExpr = '__START__(.*?)__STOP__'

        output = re.findall(regExpr, output, re.S)

        if condition is None:
            condition = (
                          kb.resumedQueries and conf.url in kb.resumedQueries.keys()
                          and expression in kb.resumedQueries[conf.url].keys()
                        )

        if partial or not condition:
            logOutput = "".join(["__START__%s__STOP__" % replaceNewlineTabs(value) for value in output])
            dataToSessionFile("[%s][%s][%s][%s][%s]\n" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], expression, logOutput))

        if sort:
            output = set(output)

        for entry in output:
            info = []

            if "__DEL__" in entry:
                entry = entry.split("__DEL__")
            else:
                entry = entry.split(temp.delimiter)

            if len(entry) == 1:
                data.append(entry[0])
            else:
                for value in entry:
                    info.append(value)

                data.append(info)
    else:
        data = output

    if len(data) == 1 and isinstance(data[0], str):
        data = data[0]

    return data

def getDelayQuery(andCond=False):
    query = None

    if kb.dbms in ("MySQL", "PostgreSQL"):
        if not kb.data.banner:
            conf.dbmsHandler.getVersionFromBanner()

        banVer = kb.bannerFp["dbmsVersion"]

        if (kb.dbms == "MySQL" and banVer >= "5.0.12") or (kb.dbms == "PostgreSQL" and banVer >= "8.2"):
            query = queries[kb.dbms].timedelay % conf.timeSec

        else:
            query = queries[kb.dbms].timedelay2 % conf.timeSec
    elif kb.dbms == "Firebird":
        query = queries[kb.dbms].timedelay
    else:
        query = queries[kb.dbms].timedelay % conf.timeSec

    if andCond:
        if kb.dbms in ( "MySQL", "SQLite" ):
            query = query.replace("SELECT ", "")
        elif kb.dbms == "Firebird":
            query = "(%s)>0" % query

    return query
    
def getLocalIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((conf.hostname, conf.port))
    ip, _ = s.getsockname()
    s.close()

    return ip

def getRemoteIP():
    return socket.gethostbyname(conf.hostname)

def getFileType(filePath):
    try:
        magicFileType = magic.from_file(filePath)
    except:
        return "unknown"

    if "ASCII" in magicFileType or "text" in magicFileType:
        return "text"
    else:
        return "binary"
    
def pollProcess(process):
    while True:
        dataToStdout(".")
        time.sleep(1)

        returncode = process.poll()

        if returncode is not None:
            if returncode == 0:
                dataToStdout(" done\n")
            elif returncode < 0:
                dataToStdout(" process terminated by signal %d\n" % returncode)
            elif returncode > 0:
                dataToStdout(" quit unexpectedly with return code %d\n" % returncode)

            break
            
def getCharset(charsetType=None):
    asciiTbl = []

    if charsetType is None:
        asciiTbl = range(0, 128)

    # 0 or 1
    elif charsetType == 1:
        asciiTbl.extend([ 0, 1 ])
        asciiTbl.extend(range(47, 50))

    # Digits
    elif charsetType == 2:
        asciiTbl.extend([ 0, 1 ])
        asciiTbl.extend(range(47, 58))

    # Hexadecimal
    elif charsetType == 3:
        asciiTbl.extend([ 0, 1 ])
        asciiTbl.extend(range(47, 58))
        asciiTbl.extend(range(64, 71))
        asciiTbl.extend(range(96, 103))

    # Characters
    elif charsetType == 4:
        asciiTbl.extend([ 0, 1 ])
        asciiTbl.extend(range(64, 91))
        asciiTbl.extend(range(96, 123))

    # Characters and digits
    elif charsetType == 5:
        asciiTbl.extend([ 0, 1 ])
        asciiTbl.extend(range(47, 58))
        asciiTbl.extend(range(64, 91))
        asciiTbl.extend(range(96, 123))

    return asciiTbl
    
def searchEnvPath(fileName):
    envPaths = os.environ["PATH"]
    result = None

    if IS_WIN:
        envPaths = envPaths.split(";")
    else:
        envPaths = envPaths.split(":")

    for envPath in envPaths:
        envPath = envPath.replace(";", "")
        result = os.path.exists(os.path.normpath(os.path.join(envPath, fileName)))

        if result:
            break

    return result

def urlEncodeCookieValues(cookieStr):
    if cookieStr:
        result = ""
        for part in cookieStr.split(';'):
            index = part.find('=') + 1
            if index > 0:
                name = part[:index - 1].strip()
                value = urlencode(part[index:], convall=True)
                result += "; %s=%s" % (name, value)
            elif part.strip().lower() != "secure":
                result += "%s%s" % ("%3B", urlencode(part, convall=True))
            else:
                result += "; secure"
        if result.startswith('; '):
            result = result[2:]
        elif result.startswith('%3B'):
            result = result[3:]
        return result
    else:
        return None

def directoryPath(path):
    retVal = None

    if isWindowsDriveLetterPath(path):
        retVal = ntpath.dirname(path)
    else:
        retVal = posixpath.dirname(path)

    return retVal

def normalizePath(path):
    retVal = None

    if isWindowsDriveLetterPath(path):
        retVal = ntpath.normpath(path)
    else:
        retVal = posixpath.normpath(path)

    return retVal

def safeStringFormat(formatStr, params):
    retVal = formatStr.replace("%d", "%s")

    if isinstance(params, str):
        retVal = retVal.replace("%s", params)
    else:
        count = 0
        index = 0

        while index != -1:
            index = retVal.find("%s")

            if index != -1:
                if count < len(params):
                    retVal = retVal[:index] + str(params[count]) + retVal[index+2:]
                else:
                    raise sqlmapNoneDataException, "wrong number of parameters during string formatting"
                count += 1

    return retVal

def sanitizeAsciiString(subject):
    if subject:
        index = None
        for i in xrange(len(subject)):
            if ord(subject[i]) >= 128:
                index = i
                break
        if not index:
            return subject
        else:
            return subject[:index] + "".join(subject[i] if ord(subject[i]) < 128 else '?' for i in xrange(index, len(subject)))
    else:
        return None

def decloakToNamedTemporaryFile(filepath, name=None):
    retVal = NamedTemporaryFile()

    def __del__():
        try:
            if hasattr(retVal, 'old_name'):
                retVal.name = old_name
            retVal.close()
        except OSError:
            pass

    retVal.__del__ = __del__
    retVal.write(decloak(filepath))
    retVal.seek(0)

    if name:
        retVal.old_name = retVal.name
        retVal.name = name

    return retVal

def decloakToMkstemp(filepath, **kwargs):
    name = mkstemp(**kwargs)[1]
    retVal = open(name, 'w+b')
    retVal.write(decloak(filepath))
    retVal.seek(0)
    return retVal

def isWindowsPath(filepath):
    return re.search("\A[\w]\:\\\\", filepath) is not None

def isWindowsDriveLetterPath(filepath):
    return re.search("\A[\w]\:", filepath) is not None

def posixToNtSlashes(filepath):
    return filepath.replace('/', '\\')

def ntToPosixSlashes(filepath):
    return filepath.replace('\\', '/')

def isBase64EncodedString(subject):
    return re.match(r"\A(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z", subject) is not None
    
def isHexEncodedString(subject):
    return re.match(r"\A[0-9a-fA-F]+\Z", subject) is not None

def getConsoleWidth(default=80):
    width = None

    if 'COLUMNS' in os.environ and os.environ['COLUMNS'].isdigit():
        width = int(os.environ['COLUMNS'])
    else:
        output=subprocess.Popen('stty size', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.read()
        items = output.split()
        if len(items) == 2 and items[1].isdigit():
            width = int(items[1])

    if width is None:
        try:
            import curses
            stdscr = curses.initscr()
            _, width = stdscr.getmaxyx()
            curses.endwin()
        except:
            pass

    return width if width else default

def parseXmlFile(xmlFile, handler):
    xfile = open(xmlFile)
    content = xfile.read()
    stream = StringIO(content)
    parse(stream, handler)
    stream.close()
    xfile.close()

def calculateDeltaSeconds(start, epsilon=0.05):
    return int(time.time() - start + epsilon)
