#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import ctypes
import inspect
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
import httplib

from ConfigParser import DEFAULTSECT
from ConfigParser import RawConfigParser
from StringIO import StringIO
from difflib import SequenceMatcher
from inspect import getmembers
from math import sqrt
from subprocess import PIPE
from subprocess import Popen as execute
from tempfile import NamedTemporaryFile
from tempfile import mkstemp
from xml.etree import ElementTree as ET
from xml.dom import minidom
from xml.sax import parse

from extra.cloak.cloak import decloak
from lib.contrib import magic
from lib.core.data import conf
from lib.core.data import dbmsDict
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.convert import htmlunescape
from lib.core.convert import urlencode
from lib.core.enums import DBMS
from lib.core.enums import PLACE
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapFilePathException
from lib.core.exception import sqlmapGenericException
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapMissingDependence
from lib.core.exception import sqlmapSyntaxException
from lib.core.optiondict import optDict
from lib.core.settings import DESCRIPTION
from lib.core.settings import IS_WIN
from lib.core.settings import PLATFORM
from lib.core.settings import SITE
from lib.core.settings import ERROR_PARSING_REGEXES
from lib.core.settings import NON_CONTROL_CHAR_REGEX
from lib.core.settings import SQL_STATEMENTS
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.core.settings import VERSION_STRING
from lib.core.settings import DUMP_NEWLINE_MARKER
from lib.core.settings import DUMP_CR_MARKER
from lib.core.settings import DUMP_DEL_MARKER
from lib.core.settings import DUMP_TAB_MARKER
from lib.core.settings import DUMP_START_MARKER
from lib.core.settings import DUMP_STOP_MARKER
from lib.core.settings import MIN_TIME_RESPONSES
from lib.core.settings import TIME_STDEV_COEFF
from lib.core.settings import DYNAMICITY_MARK_LENGTH
from lib.core.threads import getCurrentThreadData

class UnicodeRawConfigParser(RawConfigParser):
    """
    RawConfigParser with unicode writing support
    """
    def write(self, fp):
        """
        Write an .ini-format representation of the configuration state.
        """

        if self._defaults:
            fp.write("[%s]\n" % DEFAULTSECT)

            for (key, value) in self._defaults.items():
                fp.write("%s = %s\n" % (key, getUnicode(value, conf.dataEncoding).replace('\n', '\n\t')))

            fp.write("\n")

        for section in self._sections:
            fp.write("[%s]\n" % section)

            for (key, value) in self._sections[section].items():
                if key != "__name__":
                    if value is None:
                        fp.write("%s\n" % (key))
                    else:
                        fp.write("%s = %s\n" % (key, getUnicode(value, conf.dataEncoding).replace('\n', '\n\t')))

            fp.write("\n")


class DynamicContentItem:
    """
    Represents line in content page with dynamic properties (candidate for removal prior detection phase)
    """

    def __init__(self, lineNumber, pageTotal, lineContentBefore, lineContentAfter):
        self.lineNumber = lineNumber
        self.pageTotal = pageTotal
        self.lineContentBefore = lineContentBefore
        self.lineContentAfter = lineContentAfter


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

    if place is not "POSTxml":
        parameters = parameters.replace(", ", ",")

        if place == PLACE.COOKIE:
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
                    testableParameters[parameter] = elem[1]
    else:
        root = ET.XML(parameters)
        iterator = root.getiterator()

        for child in iterator:
            parameter = child.tag

            if "}" in parameter:
                testParam = parameter.split("}")[1]
            else:
                testParam = parameter

            condition = not conf.testParameter
            condition |= testParam in conf.testParameter

            if condition:
                testableParameters[parameter] = child.text

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

    while versions and None in versions:
        versions.remove(None)

    if not versions and kb.dbmsVersion and kb.dbmsVersion[0] != UNKNOWN_DBMS_VERSION and kb.dbmsVersion[0] != None:
        versions = kb.dbmsVersion

    if isinstance(versions, basestring):
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

def getErrorParsedDBMSesFormatted():
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
        if webApi in ("php", "jsp"):
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
        if webApi in ("php", "jsp"):
            defaultDirs = ["C:/xampp/htdocs/"]
        else:
            defaultDirs = ["C:/Inetpub/wwwroot/"]
    else:
        defaultDirs = ["/var/www/"]

    if kb.docRoot and kb.docRoot not in defaultDirs:
        defaultDirs.append(kb.docRoot)

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

def dataToStdout(data, forceOutput=False):
    if not ('threadException' in kb and kb.threadException):
        if forceOutput or (conf.verbose > 0) and not ('disableStdOut' in kb and kb.disableStdOut):
            try:
                sys.stdout.write(data)
                sys.stdout.flush()
            except UnicodeEncodeError:
                print data.encode(conf.dataEncoding)

def dataToSessionFile(data):
    if not conf.sessionFile:
        return

    conf.sessionFP.write(data)
    conf.sessionFP.flush()

def dataToTrafficFile(data):
    if not conf.trafficFile:
        return

    conf.trafficFP.write(data)
    conf.trafficFP.flush()

def dataToDumpFile(dumpFile, data):
    dumpFile.write(data)
    dumpFile.flush()

def dataToOutFile(data):
    if not data:
        return "No data retrieved"

    rFile = filePathToString(conf.rFile)
    rFilePath = "%s%s%s" % (conf.filePath, os.sep, rFile)
    rFileFP = codecs.open(rFilePath, "wb")

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

def readInput(message, default=None):
    """
    @param message: message to display on terminal.
    @type message: C{str}

    @return: a string read from keyboard as input.
    @rtype: C{str}
    """

    if "\n" in message:
        message += "\n> "
    elif message[-1] == ']':
        message += " "

    if conf.batch and default:
        infoMsg = "%s%s" % (message, getUnicode(default, conf.dataEncoding))
        logger.info(infoMsg)

        debugMsg = "used the default behaviour, running in batch mode"
        logger.debug(debugMsg)

        data = default
    else:
        data = raw_input(message.encode(sys.stdout.encoding or conf.dataEncoding))

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

def randomStr(length=4, lowercase=False, alphabet=None):
    """
    @param length: length of the random string.
    @type length: C{int}

    @return: a random string of characters.
    @rtype: C{str}
    """

    if alphabet:
        rndStr = "".join([random.choice(alphabet) for _ in xrange(0, length)])    
    elif lowercase:
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

    cleanString = getUnicode(inpStr)
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
    if inpStr is None:
        return

    if stdout:
        replacedString = inpStr.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    else:
        replacedString = inpStr.replace("\n", DUMP_NEWLINE_MARKER).replace("\r", DUMP_CR_MARKER).replace("\t", DUMP_TAB_MARKER)

    replacedString = replacedString.replace(kb.misc.delimiter, DUMP_DEL_MARKER)

    return replacedString

def restoreDumpMarkedChars(inpStr, onlyNewlineTab=False):
    replacedString = inpStr

    if isinstance(replacedString, basestring):
        replacedString = replacedString.replace(DUMP_NEWLINE_MARKER, "\n").replace(DUMP_CR_MARKER, "\r").replace(DUMP_TAB_MARKER, "\t")

        if not onlyNewlineTab:
            replacedString = replacedString.replace(DUMP_START_MARKER, "").replace(DUMP_STOP_MARKER, "")
            replacedString = replacedString.replace(DUMP_DEL_MARKER, ", ")

    return replacedString

def banner():
    """
    This function prints sqlmap banner with its version
    """

    ban = """
    %s - %s
    %s\n
""" % (VERSION_STRING, DESCRIPTION, SITE)

    dataToStdout(ban, forceOutput=True)

def parsePasswordHash(password):
    blank = " " * 8

    if not password or password == " ":
        password = "NULL"

    if kb.dbms == DBMS.MSSQL and password != "NULL" and isHexEncodedString(password):
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
    paths.SQLMAP_EXTRAS_PATH     = os.path.join(paths.SQLMAP_ROOT_PATH, "extra")
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
    paths.COMMON_COLUMNS         = os.path.join(paths.SQLMAP_TXT_PATH, "common-columns.txt")
    paths.COMMON_TABLES          = os.path.join(paths.SQLMAP_TXT_PATH, "common-tables.txt")
    paths.COMMON_OUTPUTS         = os.path.join(paths.SQLMAP_TXT_PATH, 'common-outputs.txt')
    paths.SQL_KEYWORDS           = os.path.join(paths.SQLMAP_TXT_PATH, "keywords.txt")
    paths.ORACLE_DEFAULT_PASSWD  = os.path.join(paths.SQLMAP_TXT_PATH, "oracle-default-passwords.txt")
    paths.USER_AGENTS            = os.path.join(paths.SQLMAP_TXT_PATH, "user-agents.txt")
    paths.WORDLIST               = os.path.join(paths.SQLMAP_TXT_PATH, "wordlist.txt")
    paths.PHPIDS_RULES_XML       = os.path.join(paths.SQLMAP_XML_PATH, "phpids_rules.xml")
    paths.ERRORS_XML             = os.path.join(paths.SQLMAP_XML_PATH, "errors.xml")
    paths.PAYLOADS_XML           = os.path.join(paths.SQLMAP_XML_PATH, "payloads.xml")
    paths.INJECTIONS_XML         = os.path.join(paths.SQLMAP_XML_PATH, "injections.xml")
    paths.LIVE_TESTS_XML         = os.path.join(paths.SQLMAP_XML_PATH, "livetests.xml")
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
        details = re.search("^(?P<dbms>%s)://(?P<credentials>(?P<user>.+?)\:(?P<pass>.*?)\@)?(?P<remote>(?P<hostname>.+?)\:(?P<port>[\d]+)\/)?(?P<db>[\w\d\ \:\.\_\-\/\\\\]+?)$" % dbms, conf.direct, re.I)

        if details:
            conf.dbms = details.group('dbms')

            if details.group('credentials'):
                conf.dbmsUser = details.group('user')
                conf.dbmsPass = details.group('pass')
            else:
                conf.dbmsUser = unicode()
                conf.dbmsPass = unicode()

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

    for dbmsName, data in dbmsDict.items():
        if conf.dbms in data[0]:
            try:
                if dbmsName in (DBMS.ACCESS, DBMS.SQLITE, DBMS.FIREBIRD):
                    if remote:
                        warnMsg = "direct connection over the network for "
                        warnMsg += "%s DBMS is not supported" % dbmsName
                        logger.warn(warnMsg)

                        conf.hostname = "localhost"
                        conf.port     = 0
                elif not remote:
                        errMsg = "missing remote connection details"
                        raise sqlmapSyntaxException, errMsg

                if dbmsName == DBMS.MSSQL:
                    import _mssql
                    import pymssql

                    if not hasattr(pymssql, "__version__") or pymssql.__version__ < "1.0.2":
                        errMsg = "pymssql library on your system must be "
                        errMsg += "version 1.0.2 to work, get it from "
                        errMsg += "http://sourceforge.net/projects/pymssql/files/pymssql/1.0.2/"
                        raise sqlmapMissingDependence, errMsg

                elif dbmsName == DBMS.MYSQL:
                    import MySQLdb
                elif dbmsName == DBMS.PGSQL:
                    import psycopg2
                elif dbmsName == DBMS.ORACLE:
                    import cx_Oracle
                elif dbmsName == DBMS.SQLITE:
                    import sqlite3
                elif dbmsName == DBMS.ACCESS:
                    import pyodbc
                elif dbmsName == DBMS.FIREBIRD:
                    import kinterbasdb
            except ImportError, _:
                errMsg  = "sqlmap requires '%s' third-party library " % data[1]
                errMsg += "in order to directly connect to the database "
                errMsg += "'%s'. Download from '%s'" % (dbmsName, data[2])
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
        conf.parameters[PLACE.GET] = __urlSplit[3]

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
            conf.db, conf.tbl = dbTbl.split(".", 1)
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

    outCond1 = ( output.startswith(kb.misc.start) and output.endswith(kb.misc.stop) )
    outCond2 = ( output.startswith(DUMP_START_MARKER) and output.endswith(DUMP_STOP_MARKER) )

    if outCond1 or outCond2:
        if outCond1:
            regExpr = '%s(.*?)%s' % (kb.misc.start, kb.misc.stop)
        elif outCond2:
            regExpr = '%s(.*?)%s' % (DUMP_START_MARKER, DUMP_STOP_MARKER)

        output = re.findall(regExpr, output, re.S)

        if condition is None:
            condition = (
                          kb.resumedQueries and conf.url in kb.resumedQueries.keys()
                          and expression in kb.resumedQueries[conf.url].keys()
                        )

        if partial or not condition:
            logOutput = "".join(["%s%s%s" % (DUMP_START_MARKER, replaceNewlineTabs(value), DUMP_STOP_MARKER) for value in output])
            dataToSessionFile("[%s][%s][%s][%s][%s]\n" % (conf.url, kb.injection.place, conf.parameters[kb.injection.place], expression, logOutput))

        if sort:
            output = set(output)

        for entry in output:
            info = []

            if DUMP_DEL_MARKER in entry:
                entry = entry.split(DUMP_DEL_MARKER)
            else:
                entry = entry.split(kb.misc.delimiter)

            if len(entry) == 1:
                data.append(entry[0])
            else:
                for value in entry:
                    info.append(value)

                data.append(info)
    else:
        data = output

    if len(data) == 1 and isinstance(data[0], basestring):
        data = data[0]

    return data

def getDelayQuery(andCond=False):
    query = None

    if kb.dbms in (DBMS.MYSQL, DBMS.PGSQL):
        if not kb.data.banner:
            conf.dbmsHandler.getVersionFromBanner()

        banVer = kb.bannerFp["dbmsVersion"] if 'dbmsVersion' in kb.bannerFp else None

        if banVer is None or (kb.dbms == DBMS.MYSQL and banVer >= "5.0.12") or (kb.dbms == DBMS.PGSQL and banVer >= "8.2"):
            query = queries[kb.dbms].timedelay.query % conf.timeSec
        else:
            query = queries[kb.dbms].timedelay.query2 % conf.timeSec
    elif kb.dbms == DBMS.FIREBIRD:
        query = queries[kb.dbms].timedelay.query
    else:
        query = queries[kb.dbms].timedelay.query % conf.timeSec

    if andCond:
        if kb.dbms in ( DBMS.MYSQL, DBMS.SQLITE ):
            query = query.replace("SELECT ", "")
        elif kb.dbms == DBMS.FIREBIRD:
            query = "(%s)>0" % query

    return query

def getLocalIP():
    retVal = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((conf.hostname, conf.port))
        retVal, _ = s.getsockname()
        s.close()
    except:
        debugMsg = "there was an error in opening socket "
        debugMsg += "connection toward '%s'" % conf.hostname
        logger.debug(debugMsg)

    return retVal

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

    if isinstance(params, basestring):
        retVal = retVal.replace("%s", params)
    else:
        count = 0
        index = 0

        while index != -1:
            index = retVal.find("%s")

            if index != -1:
                if count < len(params):
                    retVal = retVal[:index] + getUnicode(params[count]) + retVal[index+2:]
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
        if index is None:
            return subject
        else:
            return subject[:index] + "".join(subject[i] if ord(subject[i]) < 128 else '?' for i in xrange(index, len(subject)))
    else:
        return None

def getFilteredPageContent(page, onlyText=True):
    retVal = page

    if isinstance(page, basestring):
        retVal = re.sub(r"(?s)<script.+?</script>|<style.+?</style>%s" % (r"|<[^>]+>|\t|\n|\r" if onlyText else ""), " ", page)

        while retVal.find("  ") != -1:
            retVal = retVal.replace("  ", " ")

        retVal = htmlunescape(retVal)

    return retVal

def getPageTextWordsSet(page):
    retVal = None

    if isinstance(page, basestring):
        page = getFilteredPageContent(page)
        retVal = set(re.findall(r"\w+", page))

    return retVal

def showStaticWords(firstPage, secondPage):
    infoMsg = "finding static words in longest matching part of dynamic page content"
    logger.info(infoMsg)

    firstPage = getFilteredPageContent(firstPage)
    secondPage = getFilteredPageContent(secondPage)
    match = SequenceMatcher(None, firstPage, secondPage).find_longest_match(0, len(firstPage), 0, len(secondPage))
    commonText = firstPage[match[0]:match[0]+match[2]]
    commonWords = getPageTextWordsSet(commonText)

    infoMsg = "static words: "

    if commonWords:
        commonWords = list(commonWords)
        commonWords.sort(lambda a, b: cmp(a.lower(), b.lower()))

    for word in commonWords:
        if len(word) > 2:
            infoMsg += "'%s', " % word

    infoMsg = infoMsg.rstrip(", ")
    logger.info(infoMsg)

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
    """
    Replaces all occurances of Posix slashes (/) in provided
    filepath with NT ones (/)
    >>> posixToNtSlashes('C:/Windows')
    'C:\\\\Windows'
    """

    return filepath.replace('/', '\\')

def ntToPosixSlashes(filepath):
    """
    Replaces all occurances of NT slashes (\) in provided
    filepath with Posix ones (/)
    >>> ntToPosixSlashes('C:\\Windows')
    'C:/Windows'
    """

    return filepath.replace('\\', '/')

def isBase64EncodedString(subject):
    """
    Checks if the provided string is Base64 encoded
    >>> isBase64EncodedString('dGVzdA==')
    True
    >>> isBase64EncodedString('123456')
    False
    """

    return re.match(r"\A(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z", subject) is not None

def isHexEncodedString(subject):
    """
    Checks if the provided string is hex encoded
    >>> isHexEncodedString('DEADBEEF')
    True
    >>> isHexEncodedString('test')
    False
    """

    return re.match(r"\A[0-9a-fA-Fx]+\Z", subject) is not None

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

def clearConsoleLine(forceOutput=False):
    dataToStdout("\r%s\r" % (" " * (getConsoleWidth() - 1)), forceOutput)

def parseXmlFile(xmlFile, handler):
    stream = StringIO(readCachedFileContent(xmlFile))
    parse(stream, handler)
    stream.close()

def readCachedFileContent(filename, mode='rb'):
    if filename not in kb.cache.content:
        kb.locks.cacheLock.acquire()

        if filename not in kb.cache.content:
            checkFile(filename)
            xfile = codecs.open(filename, mode, conf.dataEncoding)
            content = xfile.read()
            kb.cache.content[filename] = content
            xfile.close()

        kb.locks.cacheLock.release()

    return kb.cache.content[filename]

def readXmlFile(xmlFile):
    checkFile(xmlFile)  

    xfile = codecs.open(xmlFile, 'r', conf.dataEncoding)
    retVal = minidom.parse(xfile).documentElement

    xfile.close()

    return retVal

def stdev(values):
    """
    Computes standard deviation of a list of numbers.
    Reference: http://www.goldb.org/corestats.html
    """

    if not values or len(values) < 2:
        return None

    key = (values[0], values[-1], len(values))

    if key in kb.cache.stdev:
        return kb.cache.stdev[key]
    else:
        summa = 0.0
        avg = average(values)

        for value in values:
            summa += pow(value - avg, 2)

        retVal = sqrt(summa/(len(values) - 1))
        kb.cache.stdev[key] = retVal
        return retVal

def average(values):
    """
    Computes the arithmetic mean of a list of numbers.
    """
    retVal = None

    if values:
        retVal = sum(values) / len(values)

    return retVal

def calculateDeltaSeconds(start):
    """
    Returns elapsed time from start till now
    """
    return time.time() - start

def initCommonOutputs():
    kb.commonOutputs = {}
    key = None

    cfile = codecs.open(paths.COMMON_OUTPUTS, 'r', conf.dataEncoding)

    for line in cfile.readlines(): # xreadlines doesn't return unicode strings when codec.open() is used
        if line.find('#') != -1:
            line = line[:line.find('#')]

        line = line.strip()

        if len(line) > 1:
            if line.startswith('[') and line.endswith(']'):
                key = line[1:-1]
            elif key:
                if key not in kb.commonOutputs:
                    kb.commonOutputs[key] = set()

                if line not in kb.commonOutputs[key]:
                    kb.commonOutputs[key].add(line)

    cfile.close()

def getFileItems(filename, commentPrefix='#', unicode_=True, lowercase=False, unique=False):
    retVal = []

    checkFile(filename)

    if unicode_:
        ifile = codecs.open(filename, 'r', conf.dataEncoding)
    else:
        ifile = open(filename, 'r')

    for line in ifile.readlines(): # xreadlines doesn't return unicode strings when codec.open() is used
        if commentPrefix:
            if line.find(commentPrefix) != -1:
                line = line[:line.find(commentPrefix)]
        line = line.strip()
        if not unicode_:
            try:
                line = str.encode(line)
            except UnicodeDecodeError:
                continue
        if line:
            if lowercase:
                line = line.lower()
            if unique and line in retVal:
                continue
            retVal.append(line)

    return retVal

def goGoodSamaritan(prevValue, originalCharset):
    """
    Function for retrieving parameters needed for common prediction (good
    samaritan) feature.

    prevValue: retrieved query output so far (e.g. 'i').

    Returns commonValue if there is a complete single match (in kb.partRun
    of txt/common-outputs.txt under kb.partRun) regarding parameter
    prevValue. If there is no single value match, but multiple, commonCharset is
    returned containing more probable characters (retrieved from matched
    values in txt/common-outputs.txt) together with the rest of charset as
    otherCharset.
    """

    if kb.commonOutputs is None:
        initCommonOutputs()

    predictionSet = set()
    commonValue = None
    commonPattern = None
    countCommonValue = 0

    # If the header (e.g. Databases) we are looking for has common
    # outputs defined
    if kb.partRun in kb.commonOutputs:
        commonPartOutputs = kb.commonOutputs[kb.partRun]
        commonPattern = commonFinderOnly(prevValue, commonPartOutputs)

        # If the longest common prefix is the same as previous value then
        # do not consider it
        if commonPattern and commonPattern == prevValue:
            commonPattern = None

        # For each common output
        for item in commonPartOutputs:
            # Check if the common output (item) starts with prevValue
            # where prevValue is the enumerated character(s) so far
            if item.startswith(prevValue):
                commonValue = item
                countCommonValue += 1

                if len(item) > len(prevValue):
                    char = item[len(prevValue)]
                    predictionSet.add(char)

        # Reset single value if there is more than one possible common
        # output
        if countCommonValue > 1:
            commonValue = None

        commonCharset = []
        otherCharset = []

        # Split the original charset into common chars (commonCharset)
        # and other chars (otherCharset)
        for ordChar in originalCharset:
            if chr(ordChar) not in predictionSet:
                otherCharset.append(ordChar)
            else:
                commonCharset.append(ordChar)

        commonCharset.sort()

        return commonValue, commonPattern, commonCharset, originalCharset
    else:
        return None, None, None, originalCharset

def getCompiledRegex(regex, flags=0):
    """
    Returns compiled regular expression and stores it in cache for further
    usage
    >>> getCompiledRegex('test') # doctest: +ELLIPSIS
    <_sre.SRE_Pattern object at...
    """

    if (regex, flags) in kb.cache.regex:
        return kb.cache.regex[(regex, flags)]
    else:
        retVal = re.compile(regex, flags)
        kb.cache.regex[(regex, flags)] = retVal
        return retVal

def getPartRun():
    """
    Goes through call stack and finds constructs matching conf.dbmsHandler.*.
    Returns it or its alias used in txt/common-outputs.txt
    """

    retVal = None
    commonPartsDict = optDict["Enumeration"]
    stack = [item[4][0] if isinstance(item[4], list) else '' for item in inspect.stack()]
    reobj1 = getCompiledRegex('conf\.dbmsHandler\.([^(]+)\(\)')
    reobj2 = getCompiledRegex('self\.(get[^(]+)\(\)')

    # Goes backwards through the stack to find the conf.dbmsHandler method
    # calling this function
    for i in xrange(0, len(stack)-1):
        for reobj in (reobj2, reobj1):
            match = reobj.search(stack[i])

            if match:
                # This is the calling conf.dbmsHandler or self method
                # (e.g. 'getDbms')
                retVal = match.groups()[0]
                break

        if retVal is not None:
            break

    # Return the INI tag to consider for common outputs (e.g. 'Databases')
    return commonPartsDict[retVal][1] if retVal in commonPartsDict else retVal

def getUnicode(value, encoding=None):
    """
    Return the unicode representation of the supplied value:

    >>> getUnicode(u'test')
    u'test'
    >>> getUnicode('test')
    u'test'
    >>> getUnicode(1)
    u'1'
    """

    if isinstance(value, basestring):
        return value if isinstance(value, unicode) else unicode(value, encoding or kb.pageEncoding or conf.dataEncoding, errors='replace')
    else:
        return unicode(value) # encoding ignored for non-basestring instances

# http://boredzo.org/blog/archives/2007-01-06/longest-common-prefix-in-python-2
def longestCommonPrefix(*sequences):
    if len(sequences) == 1:
        return sequences[0]

    sequences = [pair[1] for pair in sorted((len(fi), fi) for fi in sequences)]

    if not sequences:
        return None

    for i, comparison_ch in enumerate(sequences[0]):
        for fi in sequences[1:]:
            ch = fi[i]

            if ch != comparison_ch:
                return fi[:i]

    return sequences[0]

def commonFinderOnly(initial, sequence):
    return longestCommonPrefix(*filter(lambda x: x.startswith(initial), sequence))

def pushValue(value):
    """
    Push value to the stack (thread dependent)
    """

    getCurrentThreadData().valueStack.append(value)

def popValue():
    """
    Pop value from the stack (thread dependent)
    """

    return getCurrentThreadData().valueStack.pop()

def wasLastRequestDBMSError():
    """
    Returns True if the last web request resulted in a (recognized) DBMS error page
    """

    threadData = getCurrentThreadData()
    return threadData.lastErrorPage and threadData.lastErrorPage[0] == threadData.lastRequestUID

def wasLastRequestHTTPError():
    """
    Returns True if the last web request resulted in an errornous HTTP code (like 500)
    """

    threadData = getCurrentThreadData()
    return threadData.lastHTTPError and threadData.lastHTTPError[0] == threadData.lastRequestUID

def wasLastRequestDelayed():
    """
    Returns True if the last web request resulted in a time-delay
    """

    # 99.9999999997440% of all non time-based sql injection
    # affected response times should be inside +-7*stdev([normal response times])
    # (Math reference: http://www.answers.com/topic/standard-deviation)
    deviation = stdev(kb.responseTimes)
    threadData = getCurrentThreadData()

    if deviation:
        if len(kb.responseTimes) < MIN_TIME_RESPONSES:
            warnMsg = "time-based standard deviation method used on a model "
            warnMsg += "with less than %d response times" % MIN_TIME_RESPONSES
            logger.warn(warnMsg)

        return (threadData.lastQueryDuration >= average(kb.responseTimes) + TIME_STDEV_COEFF * deviation)
    else:
        return threadData.lastQueryDuration - conf.timeSec

def extractErrorMessage(page):
    """
    Returns reported error message from page if it founds one
    """

    retVal = None

    if isinstance(page, basestring):
        for regex in ERROR_PARSING_REGEXES:
            match = re.search(regex, page, re.DOTALL | re.IGNORECASE)

            if match:
                retVal = htmlunescape(match.group("result")).replace("<br>", "\n").strip()
                break

    return retVal

def beep():
    """
    Does an audible beep sound
    Reference: http://de3.aminet.net/dev/src/clr.py.txt
    """

    if sys.platform == 'linux2':
        for dev in ('/dev/audio', '/dev/oss', '/dev/dsp', '/dev/sound'):
            if os.path.exists(dev):
                try:
                    audio = file(dev, 'wb')

                    for i in xrange(250):
                        audio.write(chr(32) * 4)
                        audio.write(chr(0) * 4)

                    audio.close()
                    return
                except:
                    pass

        try:
            import curses
            curses.initscr()
            curses.beep()
            curses.flash()
            curses.endwin()
            return
        except:
            dataToStdout('\a', True)

    else:
        dataToStdout('\a', True)

def runningAsAdmin():
    isAdmin = False

    if PLATFORM in ( "posix", "mac" ):
        isAdmin = os.geteuid()

        if isinstance(isAdmin, (int, float, long)) and isAdmin == 0:
            isAdmin = True
    elif IS_WIN:
        isAdmin = ctypes.windll.shell32.IsUserAnAdmin()

        if isinstance(isAdmin, (int, float, long)) and isAdmin == 1:
            isAdmin = True
    else:
        errMsg  = "sqlmap is not able to check if you are running it "
        errMsg += "as an administrator account on this platform. "
        errMsg += "sqlmap will assume that you are an administrator "
        errMsg += "which is mandatory for the requested takeover attack "
        errMsg += "to work properly"
        logger.error(errMsg)

        isAdmin = True

    return isAdmin

def logHTTPTraffic(requestLogMsg, responseLogMsg):
    kb.locks.logLock.acquire()

    dataToTrafficFile("%s\n" % requestLogMsg)
    dataToTrafficFile("%s\n" % responseLogMsg)
    dataToTrafficFile("\n%s\n\n" % (76 * '#'))

    kb.locks.logLock.release()

# cross-linked method
def getPageTemplate(payload, place):
    pass

def getPublicTypeMembers(type_, onlyValues=False):
    """
    Useful for getting members from types (e.g. in enums)
    """
    retVal = []

    for name, value in getmembers(type_):
        if not name.startswith('__'):
            if not onlyValues:
                retVal.append((name, value))
            else:
                retVal.append(value)

    return retVal

def enumValueToNameLookup(type_, value_):
    retVal = None

    for name, value in getPublicTypeMembers(type_):
        if value == value_:
            retVal = name
            break

    return retVal

def extractRegexResult(regex, content, flags=0):
    retVal = None

    if regex and content and '?P<result>' in regex:
        match = re.search(regex, content, flags)

        if match:
            retVal = match.group("result")

    return retVal

def trimAlphaNum(value):
    """
    Trims alpha numeric characters from start and ending of a given value
    """
    while value and value[-1].isalnum():
        value = value[:-1]

    while value and value[0].isalnum():
        value = value[1:]

    return value

def isNumPosStrValue(value):
    return value and isinstance(value, basestring) and value.isdigit() and value != "0"

def aliasToDbmsEnum(value):
    retVal = None

    for key, item in dbmsDict.items():
        if value in item[0]:
            retVal = key
            break

    return retVal

def findDynamicContent(firstPage, secondPage):
    """
    This function checks if the provided pages have dynamic content. If they
    are dynamic, proper markings will be made.
    """

    infoMsg = "searching for dynamic content"
    logger.info(infoMsg)

    blocks = SequenceMatcher(None, firstPage, secondPage).get_matching_blocks()
    kb.dynamicMarkings = []

    # Removing too small matching blocks
    i = 0
    while i < len(blocks):
        block = blocks[i]
        (_, _, length) = block

        if length <= DYNAMICITY_MARK_LENGTH:
            blocks.remove(block)

        else:
            i += 1

    # Making of dynamic markings based on prefix/suffix principle
    if len(blocks) > 0:
        blocks.insert(0, None)
        blocks.append(None)

        for i in xrange(len(blocks) - 1):
            prefix = firstPage[blocks[i][0]:blocks[i][0] + blocks[i][2]] if blocks[i] else None
            suffix = firstPage[blocks[i + 1][0]:blocks[i + 1][0] + blocks[i + 1][2]] if blocks[i + 1] else None

            if prefix is None and blocks[i + 1][0] == 0:
                continue

            if suffix is None and (blocks[i][0] + blocks[i][2] >= len(firstPage)):
                continue

            prefix = trimAlphaNum(prefix)
            suffix = trimAlphaNum(suffix)

            kb.dynamicMarkings.append((re.escape(prefix[-DYNAMICITY_MARK_LENGTH/2:]) if prefix else None, re.escape(suffix[:DYNAMICITY_MARK_LENGTH/2]) if suffix else None))

    if len(kb.dynamicMarkings) > 0:
        infoMsg = "dynamic content marked for removal (%d region%s)" % (len(kb.dynamicMarkings), 's' if len(kb.dynamicMarkings) > 1 else '')
        logger.info(infoMsg)

def removeDynamicContent(page):
    """
    Removing dynamic content from supplied page basing removal on
    precalculated dynamic markings
    """

    if page:
        for item in kb.dynamicMarkings:
            prefix, suffix = item

            if prefix is None and suffix is None:
                continue
            elif prefix is None:
                page = getCompiledRegex('(?s)^.+%s' % suffix).sub(suffix, page)
            elif suffix is None:
                page = getCompiledRegex('(?s)%s.+$' % prefix).sub(prefix, page)
            else:
                page = getCompiledRegex('(?s)%s.+%s' % (prefix, suffix)).sub('%s%s' % (prefix, suffix), page)

    return page

def filterStringValue(value, regex, replace=None):
    """
    Returns string value consisting only of chars satisfying supplied
    regular expression
    """

    retVal = ""

    if value:
        for char in value:
            if re.search(regex, char):
                retVal += char
            elif replace:
                retVal += replace

    return retVal

def filterControlChars(value):
    """
    Returns string value with control chars being supstituted with ' '
    """

    return filterStringValue(value, NON_CONTROL_CHAR_REGEX, ' ')

def isDBMSVersionAtLeast(version):
    """
    Checks if the recognized DBMS version is at least the version
    specified
    """

    retVal = None

    if kb.dbmsVersion and kb.dbmsVersion[0] != UNKNOWN_DBMS_VERSION and kb.dbmsVersion[0] != None:
        value = kb.dbmsVersion[0].replace(" ", "").rstrip('.')

        while True:
            index = value.find('.', value.find('.') + 1)

            if index > -1:
                value = value[0:index] + value[index + 1:]
            else:
                break

        value = filterStringValue(value, '[0-9.><=]')

        if isinstance(value, basestring):
            if value.startswith(">="):
                value = float(value.replace(">=", ""))
            elif value.startswith(">"):
                value = float(value.replace(">", "")) + 0.01
            elif value.startswith("<="):
                value = float(value.replace("<=", ""))
            elif value.startswith(">"):
                value = float(value.replace("<", "")) - 0.01

        retVal = getUnicode(value) >= getUnicode(version)

    return retVal

def parseSqliteTableSchema(value):
    """
    Parses table column names and types from specified SQLite table schema
    """

    if value:
        table = {}
        columns = {}

        for match in re.finditer(getCompiledRegex(r"(\w+) ([A-Z]+)[,\r\n]"), value):
            columns[match.group(1)] = match.group(2)

        table[conf.tbl] = columns
        kb.data.cachedColumns[conf.db] = table

def getTechniqueData(technique=None):
    """
    Returns injection data for technique specified
    """

    retVal = None

    if technique and technique in kb.injection.data:
        retVal = kb.injection.data[technique]

    return retVal

def isTechniqueAvailable(technique=None):
    """
    Returns True if there is injection data which sqlmap could use for
    technique specified
    """

    return getTechniqueData(technique) is not None

def initTechnique(technique=None):
    """
    Prepares proper page template and match ratio for technique specified
    """

    data = getTechniqueData(technique)

    if data:
        kb.pageTemplate, kb.errorIsNone = getPageTemplate(data.templatePayload, kb.injection.place)
        kb.matchRatio = data.matchRatio
    else:
        warnMsg = "there is no injection data available for technique "
        warnMsg += "'%s'" % enumValueToNameLookup(PAYLOAD.TECHNIQUE, technique)
        logger.warn(warnMsg)

def arrayizeValue(value):
    """
    Makes a list out of value if it is not already a list, tuple or set
    itself
    """

    if not isinstance(value, (list, tuple, set)):
        value = [ value ]

    return value

def getInjectionTests():
    """
    Returns prioritized test list by eventually detected DBMS from error
    messages
    """

    retVal = conf.tests

    if getErrorParsedDBMSes():
        retVal = sorted(retVal, key=lambda test: False \
          if 'details' in test and 'dbms' in test.details \
          and test.details.dbms in getErrorParsedDBMSes() else True)

    return retVal

def filterListValue(value, regex):
    """
    Returns list with items that have parts satisfying given regular
    expression
    """

    if regex:
        retVal = []
        filter = getCompiledRegex(regex, re.I)

        for word in value:
            if filter.search(word):
                retVal.append(word)

        return retVal
    else:
        return value

def unicodeToSafeHTMLValue(value):
    """
    Returns HTML representation of unicode string value safe for sending
    over HTTP(s)
    """

    retVal = value

    if value:
        for char in value:
            if ord(char) > 127:
                retVal = retVal.replace(char, "&#%d;" % ord(char))

    return retVal

def getErrorParsedDBMSes():
    """
    Returns array with parsed DBMS names till now
    """

    return kb.htmlFp

def showHttpErrorCodes():
    """
    Shows all HTTP error codes raised till now
    """

    if kb.httpErrorCodes:
        warnMsg = "HTTP error codes detected during testing:\n"
        warnMsg += ", ".join("%d (%s) - %d times" % (code, httplib.responses[code] \
          if code in httplib.responses else '?', count) \
          for code, count in kb.httpErrorCodes.items())
        logger.warn(warnMsg)

def getComparePageRatio(firstPage, secondPage, filtered=False):
    """
    Returns comparison ratio between two given pages
    """

    if filtered:
        firstPage = getFilteredPageContent(firstPage)
        secondPage = getFilteredPageContent(secondPage)

    conf.seqMatcher.set_seq1(firstPage)
    conf.seqMatcher.set_seq2(secondPage)

    return conf.seqMatcher.quick_ratio()
