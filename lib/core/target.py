#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import binascii
import codecs
import os
import re
import tempfile
import time

from lib.core.common import dataToSessionFile
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
from lib.core.option import __setDBMS
from lib.core.option import __setKnowledgeBaseAttributes
from lib.core.session import resumeConfKb
from lib.core.settings import HOST_ALIASES
from lib.core.settings import REFERER_ALIASES
from lib.core.settings import RESULTS_FILE_FORMAT
from lib.core.settings import SOAP_REGEX
from lib.core.settings import UNENCODED_ORIGINAL_VALUE
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import URI_INJECTABLE_REGEX
from lib.core.settings import URI_INJECTION_MARK_CHAR
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

    __testableParameters = False

    # Perform checks on GET parameters
    if conf.parameters.has_key(PLACE.GET) and conf.parameters[PLACE.GET]:
        parameters = conf.parameters[PLACE.GET]
        __paramDict = paramToDict(PLACE.GET, parameters)

        if __paramDict:
            conf.paramDict[PLACE.GET] = __paramDict
            __testableParameters = True

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

        # Check if POST data is in xml syntax
        if re.match(SOAP_REGEX, conf.data, re.I | re.M):
            place = PLACE.SOAP
        else:
            place = PLACE.POST

        conf.parameters[place] = conf.data
        __paramDict = paramToDict(place, conf.data)

        if __paramDict:
            conf.paramDict[place] = __paramDict
            __testableParameters = True

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

        if not test or test[0] in ("y", "Y"):
            conf.url = "%s%s" % (conf.url, URI_INJECTION_MARK_CHAR)
        elif test[0] in ("n", "N"):
            pass
        elif test[0] in ("q", "Q"):
            raise sqlmapUserQuitException

    if URI_INJECTION_MARK_CHAR in conf.url:
        conf.parameters[PLACE.URI] = conf.url
        conf.paramDict[PLACE.URI] = {}
        parts = conf.url.split(URI_INJECTION_MARK_CHAR)

        for i in xrange(len(parts)-1):
            result = str()

            for j in xrange(len(parts)):
                result += parts[j]

                if i == j:
                    result += URI_INJECTION_MARK_CHAR

            conf.paramDict[PLACE.URI]["#%d%s" % (i+1, URI_INJECTION_MARK_CHAR)] = result

        conf.url = conf.url.replace(URI_INJECTION_MARK_CHAR, str())
        __testableParameters = True

    # Perform checks on Cookie parameters
    if conf.cookie:
        conf.parameters[PLACE.COOKIE] = conf.cookie
        __paramDict = paramToDict(PLACE.COOKIE, conf.cookie)

        if __paramDict:
            conf.paramDict[PLACE.COOKIE] = __paramDict
            __testableParameters = True

    # Perform checks on header values
    if conf.httpHeaders:
        for httpHeader, headerValue in conf.httpHeaders:
            # Url encoding of the header values should be avoided
            # Reference: http://stackoverflow.com/questions/5085904/is-ok-to-urlencode-the-value-in-headerlocation-value

            if httpHeader == PLACE.UA:
                conf.parameters[PLACE.UA] = urldecode(headerValue)

                condition = any((not conf.testParameter, intersect(conf.testParameter, USER_AGENT_ALIASES)))

                if condition:
                    conf.paramDict[PLACE.UA] = { PLACE.UA: headerValue }
                    __testableParameters = True

            elif httpHeader == PLACE.REFERER:
                conf.parameters[PLACE.REFERER] = urldecode(headerValue)

                condition = any((not conf.testParameter, intersect(conf.testParameter, REFERER_ALIASES)))

                if condition:
                    conf.paramDict[PLACE.REFERER] = { PLACE.REFERER: headerValue }
                    __testableParameters = True

            elif httpHeader == PLACE.HOST:
                conf.parameters[PLACE.HOST] = urldecode(headerValue)

                condition = any((not conf.testParameter, intersect(conf.testParameter, HOST_ALIASES)))

                if condition:
                    conf.paramDict[PLACE.HOST] = { PLACE.HOST: headerValue }
                    __testableParameters = True

    if not conf.parameters:
        errMsg = "you did not provide any GET, POST and Cookie "
        errMsg += "parameter, neither an User-Agent, Referer or Host header value"
        raise sqlmapGenericException, errMsg

    elif not __testableParameters:
        errMsg = "all testable parameters you provided are not present "
        errMsg += "within the GET, POST and Cookie parameters"
        raise sqlmapGenericException, errMsg

def __setHashDB():
    """
    Check and set the HashDB SQLite file for query resume functionality.
    """

    if not conf.hashDBFile:
        conf.hashDBFile = "%s%shashdb" % (conf.outputPath, os.sep)

    if os.path.exists(conf.hashDBFile):
        if conf.flushSession:
            try:
                os.remove(conf.hashDBFile)
                logger.info("flushing query storage file")
            except OSError, msg:
                errMsg = "unable to flush the hashdb file (%s)" % msg
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

def __setOutputResume():
    """
    Check and set the output text file and the resume functionality.
    """

    if not conf.sessionFile:
        conf.sessionFile = "%s%ssession" % (conf.outputPath, os.sep)

    logger.info("using '%s' as session file" % conf.sessionFile)

    if os.path.exists(conf.sessionFile):
        if not conf.flushSession:
            try:
                readSessionFP = codecs.open(conf.sessionFile, "r", UNICODE_ENCODING, 'replace')
                __url_cache = set()
                __expression_cache = {}

                for line in readSessionFP.readlines(): # xreadlines doesn't return unicode strings when codec.open() is used
                    if line.count("][") == 4:
                        line = line.split("][")

                        if len(line) != 5:
                            continue

                        url, _, _, expression, value = line

                        if not value:
                            continue

                        if url[0] == "[":
                            url = url[1:]

                        value = value.rstrip('\r\n') # Strips both chars independently

                        if url not in ( conf.url, conf.hostname ):
                            continue

                        if url not in __url_cache:
                            kb.resumedQueries[url] = {}
                            kb.resumedQueries[url][expression] = value
                            __url_cache.add(url)
                            __expression_cache[url] = set(expression)

                        resumeConfKb(expression, url, value)

                        if expression not in __expression_cache[url]:
                            kb.resumedQueries[url][expression] = value
                            __expression_cache[url].add(value)
                        elif len(value) >= len(kb.resumedQueries[url][expression]):
                            kb.resumedQueries[url][expression] = value

                if kb.injection.place is not None and kb.injection.parameter is not None:
                    kb.injections.append(kb.injection)
            except IOError, msg:
                errMsg = "unable to properly open the session file (%s)" % msg
                raise sqlmapFilePathException, errMsg
            else:
                readSessionFP.close()
        else:
            try:
                os.remove(conf.sessionFile)
                logger.info("flushing session file")
            except OSError, msg:
                errMsg = "unable to flush the session file (%s)" % msg
                raise sqlmapFilePathException, errMsg

    try:
        conf.sessionFP = codecs.open(conf.sessionFile, "a", UNICODE_ENCODING)
        dataToSessionFile("\n[%s]\n" % time.strftime("%X %x"))
    except IOError:
        errMsg = "unable to write on the session file specified"
        raise sqlmapFilePathException, errMsg

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
        conf.sessionFile = None
        conf.hashDBFile = None

        __setKnowledgeBaseAttributes(False)
        __restoreCmdLineOptions()
        __setDBMS()

def setupTargetEnv():
    __createTargetDirs()
    __setRequestParams()
    __setOutputResume()
    __setHashDB()
    __resumeHashDBValues()
    __setResultsFile()
