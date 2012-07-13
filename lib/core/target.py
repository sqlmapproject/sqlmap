#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import binascii
import codecs
import os
import re
import tempfile
import time

from lib.core.common import Backend
from lib.core.common import hashDBRetrieve
from lib.core.common import intersect
from lib.core.common import paramToDict
from lib.core.common import readInput
from lib.core.common import resetCookieJar
from lib.core.convert import urldecode
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.dump import dumper
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HTTPMETHOD
from lib.core.enums import PLACE
from lib.core.exception import sqlmapFilePathException
from lib.core.exception import sqlmapGenericException
from lib.core.exception import sqlmapSyntaxException
from lib.core.exception import sqlmapUserQuitException
from lib.core.option import authHandler
from lib.core.option import __setDBMS
from lib.core.option import __setKnowledgeBaseAttributes
from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR
from lib.core.settings import HOST_ALIASES
from lib.core.settings import REFERER_ALIASES
from lib.core.settings import RESULTS_FILE_FORMAT
from lib.core.settings import SOAP_REGEX
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import UNENCODED_ORIGINAL_VALUE
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.core.settings import URI_INJECTABLE_REGEX
from lib.core.settings import USER_AGENT_ALIASES
from lib.utils.hashdb import HashDB
from lib.core.xmldump import dumper as xmldumper

def __setRequestParams():
    """
    Check and set the parameters and perform checks on 'data' option for
    HTTP method POST.
    """

    if conf.direct:
        conf.parameters[None] = "direct connection"
        return

    testableParameters = False

    # Perform checks on GET parameters
    if conf.parameters.has_key(PLACE.GET) and conf.parameters[PLACE.GET]:
        parameters = conf.parameters[PLACE.GET]
        paramDict = paramToDict(PLACE.GET, parameters)

        if paramDict:
            conf.paramDict[PLACE.GET] = paramDict
            testableParameters = True

    # Perform checks on POST parameters
    if conf.method == HTTPMETHOD.POST and not conf.data:
        errMsg = "HTTP POST method depends on HTTP data value to be posted"
        raise sqlmapSyntaxException, errMsg

    if conf.data:
        if hasattr(conf.data, UNENCODED_ORIGINAL_VALUE):
            original = getattr(conf.data, UNENCODED_ORIGINAL_VALUE)
            conf.data = type(conf.data)(conf.data.replace("\n", " "))
            setattr(conf.data, UNENCODED_ORIGINAL_VALUE, original)
        else:
            conf.data = conf.data.replace("\n", " ")

        place = PLACE.SOAP if re.match(SOAP_REGEX, conf.data, re.I | re.M) else PLACE.POST

        conf.parameters[place] = conf.data
        paramDict = paramToDict(place, conf.data)

        if paramDict:
            conf.paramDict[place] = paramDict
            testableParameters = True

        conf.method = HTTPMETHOD.POST

    if re.search(URI_INJECTABLE_REGEX, conf.url, re.I) and not any(map(lambda place: place in conf.parameters, [PLACE.GET, PLACE.POST])):
        warnMsg  = "you've provided target url without any GET "
        warnMsg += "parameters (e.g. www.site.com/article.php?id=1) "
        warnMsg += "and without providing any POST parameters "
        warnMsg += "through --data option"
        logger.warn(warnMsg)

        message = "do you want to try URI injections "
        message += "in the target url itself? [Y/n/q] "
        test = readInput(message, default="Y")

        if not test or test[0] not in ("n", "N"):
            conf.url = "%s%s" % (conf.url, CUSTOM_INJECTION_MARK_CHAR)
            kb.processUserMarks = True
        elif test[0] in ("q", "Q"):
            raise sqlmapUserQuitException

    for place, value in ((PLACE.URI, conf.url), (PLACE.CUSTOM_POST, conf.data)):
        if CUSTOM_INJECTION_MARK_CHAR in (value or ""):
            if kb.processUserMarks is None:
                message = "custom injection marking character ('%s') found in option " % CUSTOM_INJECTION_MARK_CHAR
                message += "'%s'. Do you want to process it? [Y/n/q] " % {PLACE.URI: '-u', PLACE.CUSTOM_POST: '--data'}[place]
                test = readInput(message, default="Y")
                if test and test[0] in ("q", "Q"):
                    raise sqlmapUserQuitException
                else:
                    kb.processUserMarks = not test or test[0] not in ("n", "N")

            if not kb.processUserMarks:
                continue

            conf.parameters[place] = value
            conf.paramDict[place] = {}
            parts = value.split(CUSTOM_INJECTION_MARK_CHAR)

            for i in xrange(len(parts) - 1):
                conf.paramDict[place]["#%d%s" % (i + 1, CUSTOM_INJECTION_MARK_CHAR)] = "".join("%s%s" % (parts[j], CUSTOM_INJECTION_MARK_CHAR if i == j else "") for j in xrange(len(parts)))

            if place == PLACE.URI and PLACE.GET in conf.paramDict:
                del conf.paramDict[PLACE.GET]
            elif place == PLACE.CUSTOM_POST and PLACE.POST in conf.paramDict:
                del conf.paramDict[PLACE.POST]

            testableParameters = True

    if kb.processUserMarks:
        conf.url = conf.url.replace(CUSTOM_INJECTION_MARK_CHAR, "")
        conf.data = conf.data.replace(CUSTOM_INJECTION_MARK_CHAR, "") if conf.data else conf.data

    # Perform checks on Cookie parameters
    if conf.cookie:
        conf.parameters[PLACE.COOKIE] = conf.cookie
        paramDict = paramToDict(PLACE.COOKIE, conf.cookie)

        if paramDict:
            conf.paramDict[PLACE.COOKIE] = paramDict
            testableParameters = True

    # Perform checks on header values
    if conf.httpHeaders:
        for httpHeader, headerValue in conf.httpHeaders:
            # Url encoding of the header values should be avoided
            # Reference: http://stackoverflow.com/questions/5085904/is-ok-to-urlencode-the-value-in-headerlocation-value

            if httpHeader == PLACE.UA:
                conf.parameters[PLACE.UA] = urldecode(headerValue)

                condition = any((not conf.testParameter, intersect(conf.testParameter, USER_AGENT_ALIASES)))

                if condition:
                    conf.paramDict[PLACE.UA] = {PLACE.UA: headerValue}
                    testableParameters = True

            elif httpHeader == PLACE.REFERER:
                conf.parameters[PLACE.REFERER] = urldecode(headerValue)

                condition = any((not conf.testParameter, intersect(conf.testParameter, REFERER_ALIASES)))

                if condition:
                    conf.paramDict[PLACE.REFERER] = {PLACE.REFERER: headerValue}
                    testableParameters = True

            elif httpHeader == PLACE.HOST:
                conf.parameters[PLACE.HOST] = urldecode(headerValue)

                condition = any((not conf.testParameter, intersect(conf.testParameter, HOST_ALIASES)))

                if condition:
                    conf.paramDict[PLACE.HOST] = {PLACE.HOST: headerValue}
                    testableParameters = True

    if not conf.parameters:
        errMsg = "you did not provide any GET, POST and Cookie "
        errMsg += "parameter, neither an User-Agent, Referer or Host header value"
        raise sqlmapGenericException, errMsg

    elif not testableParameters:
        errMsg = "all testable parameters you provided are not present "
        errMsg += "within the GET, POST and Cookie parameters"
        raise sqlmapGenericException, errMsg

def __setHashDB():
    """
    Check and set the HashDB SQLite file for query resume functionality.
    """

    if not conf.hashDBFile:
        conf.hashDBFile = "%s%ssession.sqlite" % (conf.outputPath, os.sep)

    if os.path.exists(conf.hashDBFile):
        if conf.flushSession:
            try:
                os.remove(conf.hashDBFile)
                logger.info("flushing session file")
            except OSError, msg:
                errMsg = "unable to flush the session file (%s)" % msg
                raise sqlmapFilePathException, errMsg

    conf.hashDB = HashDB(conf.hashDBFile)

def __resumeHashDBValues():
    """
    Resume stored data values from HashDB
    """

    kb.absFilePaths = hashDBRetrieve(HASHDB_KEYS.KB_ABS_FILE_PATHS, True) or kb.absFilePaths
    kb.chars = hashDBRetrieve(HASHDB_KEYS.KB_CHARS, True) or kb.chars
    kb.dynamicMarkings = hashDBRetrieve(HASHDB_KEYS.KB_DYNAMIC_MARKINGS, True) or kb.dynamicMarkings
    kb.brute.tables = hashDBRetrieve(HASHDB_KEYS.KB_BRUTE_TABLES, True) or kb.brute.tables
    kb.brute.columns = hashDBRetrieve(HASHDB_KEYS.KB_BRUTE_COLUMNS, True) or kb.brute.columns
    kb.xpCmdshellAvailable = hashDBRetrieve(HASHDB_KEYS.KB_XP_CMDSHELL_AVAILABLE) or kb.xpCmdshellAvailable

    conf.tmpPath = conf.tmpPath or hashDBRetrieve(HASHDB_KEYS.CONF_TMP_PATH)

    for injection in hashDBRetrieve(HASHDB_KEYS.KB_INJECTIONS, True) or []:
        if injection.place in conf.paramDict and \
            injection.parameter in conf.paramDict[injection.place]:

            if not conf.tech or intersect(conf.tech, injection.data.keys()):
                if intersect(conf.tech, injection.data.keys()):
                    injection.data = dict(filter(lambda (key, item): key in conf.tech, injection.data.items()))

                if injection not in kb.injections:
                    kb.injections.append(injection)

    __resumeDBMS()
    __resumeOS()

def __resumeDBMS():
    """
    Resume stored DBMS information from HashDB
    """

    value = hashDBRetrieve(HASHDB_KEYS.DBMS)

    if not value:
        return

    dbms = value.lower()
    dbmsVersion = [UNKNOWN_DBMS_VERSION]
    _ = "(%s)" % ("|".join([alias for alias in SUPPORTED_DBMS]))
    _ = re.search("%s ([\d\.]+)" % _, dbms, re.I)

    if _:
        dbms = _.group(1).lower()
        dbmsVersion = [_.group(2)]

    if conf.dbms:
        if conf.dbms.lower() != dbms:
            message = "you provided '%s' as back-end DBMS, " % conf.dbms
            message += "but from a past scan information on the target URL "
            message += "sqlmap assumes the back-end DBMS is %s. " % dbms
            message += "Do you really want to force the back-end "
            message += "DBMS value? [y/N] "
            test = readInput(message, default="N")

            if not test or test[0] in ("n", "N"):
                conf.dbms = None
                Backend.setDbms(dbms)
                Backend.setVersionList(dbmsVersion)
    else:
        infoMsg = "resuming back-end DBMS '%s' " % dbms
        logger.info(infoMsg)

        Backend.setDbms(dbms)
        Backend.setVersionList(dbmsVersion)

def __resumeOS():
    """
    Resume stored OS information from HashDB
    """

    value = hashDBRetrieve(HASHDB_KEYS.OS)

    if not value:
        return

    os = value

    if os and os != 'None':
        infoMsg = "resuming back-end DBMS operating system '%s' " % os
        logger.info(infoMsg)

        if conf.os and conf.os.lower() != os.lower():
            message = "you provided '%s' as back-end DBMS operating " % conf.os
            message += "system, but from a past scan information on the "
            message += "target URL sqlmap assumes the back-end DBMS "
            message += "operating system is %s. " % os
            message += "Do you really want to force the back-end DBMS "
            message += "OS value? [y/N] "
            test = readInput(message, default="N")

            if not test or test[0] in ("n", "N"):
                conf.os = os
        else:
            conf.os = os

        Backend.setOs(conf.os)

def __setResultsFile():
    """
    Create results file for storing results of running in a
    multiple target mode.
    """

    if not conf.multipleTargets:
        return

    if not conf.resultsFP:
        conf.resultsFilename = "%s%s%s" % (paths.SQLMAP_OUTPUT_PATH, os.sep, time.strftime(RESULTS_FILE_FORMAT).lower())
        conf.resultsFP = codecs.open(conf.resultsFilename, "w+", UNICODE_ENCODING)
        conf.resultsFP.writelines("Target url,Place,Parameter,Techniques%s" % os.linesep)

        logger.info("using '%s' as results file" % conf.resultsFilename)

def __setAuthCred():
    """
    Adds authentication credentials (if any) for current target to the password manager (used by connection handler).
    """

    if kb.passwordMgr:
        kb.passwordMgr.add_password(None, "%s://%s" % (conf.scheme, conf.hostname), conf.authUsername, conf.authPassword)

def __createFilesDir():
    """
    Create the file directory.
    """

    if not conf.rFile:
        return

    conf.filePath = paths.SQLMAP_FILES_PATH % conf.hostname

    if not os.path.isdir(conf.filePath):
        os.makedirs(conf.filePath, 0755)

def __createDumpDir():
    """
    Create the dump directory.
    """

    if not conf.dumpTable and not conf.dumpAll and not conf.search:
        return

    conf.dumpPath = paths.SQLMAP_DUMP_PATH % conf.hostname

    if not os.path.isdir(conf.dumpPath):
        os.makedirs(conf.dumpPath, 0755)

def __configureDumper():
    if hasattr(conf, 'xmlFile') and conf.xmlFile:
        conf.dumper = xmldumper
    else:
        conf.dumper = dumper

    conf.dumper.setOutputFile()

def __createTargetDirs():
    """
    Create the output directory.
    """

    if not os.path.isdir(paths.SQLMAP_OUTPUT_PATH):
        try:
            os.makedirs(paths.SQLMAP_OUTPUT_PATH, 0755)
        except OSError, msg:
            tempDir = tempfile.mkdtemp(prefix='output')
            warnMsg = "unable to create default root output directory "
            warnMsg += "'%s' (%s). " % (paths.SQLMAP_OUTPUT_PATH, msg)
            warnMsg += "using temporary directory '%s' instead" % tempDir
            logger.warn(warnMsg)

            paths.SQLMAP_OUTPUT_PATH = tempDir

    conf.outputPath = "%s%s%s" % (paths.SQLMAP_OUTPUT_PATH, os.sep, conf.hostname)

    if not os.path.isdir(conf.outputPath):
        try:
            os.makedirs(conf.outputPath, 0755)
        except OSError, msg:
            tempDir = tempfile.mkdtemp(prefix='output')
            warnMsg = "unable to create output directory "
            warnMsg += "'%s' (%s). " % (conf.outputPath, msg)
            warnMsg += "using temporary directory '%s' instead" % tempDir
            logger.warn(warnMsg)

            conf.outputPath = tempDir

    __createDumpDir()
    __createFilesDir()
    __configureDumper()

def __restoreCmdLineOptions():
    """
    Restore command line options that could be possibly
    changed during the testing of previous target.
    """
    conf.regexp = cmdLineOptions.regexp
    conf.string = cmdLineOptions.string
    conf.textOnly = cmdLineOptions.textOnly

def initTargetEnv():
    """
    Initialize target environment.
    """

    if conf.multipleTargets:
        if conf.sessionFP:
            conf.sessionFP.close()

        if conf.hashDB:
            conf.hashDB.close()

        if conf.cj:
            resetCookieJar(conf.cj)

        conf.paramDict = {}
        conf.parameters = {}
        conf.hashDBFile = None

        __setKnowledgeBaseAttributes(False)
        __restoreCmdLineOptions()
        __setDBMS()

def setupTargetEnv():
    __createTargetDirs()
    __setRequestParams()
    __setHashDB()
    __resumeHashDBValues()
    __setResultsFile()
    __setAuthCred()
