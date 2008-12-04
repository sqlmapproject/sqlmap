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



import cookielib
import logging
import os
import re
import socket
import time
import urllib2
import urlparse

from lib.core.common import parseTargetUrl
from lib.core.common import paths
from lib.core.common import randomRange
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import sanitizeStr
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.datatype import advancedDict
from lib.core.exception import sqlmapFilePathException
from lib.core.exception import sqlmapGenericException
from lib.core.exception import sqlmapSyntaxException
from lib.core.exception import sqlmapUnsupportedDBMSException
from lib.core.optiondict import optDict
from lib.core.settings import MSSQL_ALIASES
from lib.core.settings import MYSQL_ALIASES
from lib.core.settings import SITE
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import VERSION_STRING
from lib.core.update import update
from lib.parse.configfile import configFileParser
from lib.parse.queriesfile import queriesParser
from lib.request.proxy import ProxyHTTPSHandler
from lib.utils.google import Google


authHandler  = urllib2.BaseHandler()
proxyHandler = urllib2.BaseHandler()


def __urllib2Opener():
    """
    This function creates the urllib2 OpenerDirector.
    """

    global authHandler
    global proxyHandler

    debugMsg = "creating HTTP requests opener object"
    logger.debug(debugMsg)

    conf.cj = cookielib.LWPCookieJar()
    opener  = urllib2.build_opener(proxyHandler, authHandler, urllib2.HTTPCookieProcessor(conf.cj))

    urllib2.install_opener(opener)


def __feedTargetsDict(reqFile, addedTargetUrls):
    fp = open(reqFile, "r")

    fread = fp.read()
    fread = fread.replace("\r", "")

    reqResList = fread.split("======================================================")

    for request in reqResList:
        if not re.search ("^[\n]*(GET|POST).*?\sHTTP\/", request, re.I):
            continue

        getPostReq = False
        url        = None
        host       = None
        method     = None
        data       = None
        cookie     = None
        params     = False
        lines      = request.split("\n")

        for line in lines:
            if len(line) == 0 or line == "\n":
                continue

            if line.startswith("GET ") or line.startswith("POST "):
                if line.startswith("GET "):
                    index = 4
                else:
                    index = 5

                url    = line[index:line.index(" HTTP/")]
                method = line[:index-1]

                if "?" in line and "=" in line:
                    params = True

                getPostReq = True

            elif "?" in line and "=" in line and ": " not in line:
                data   = line
                params = True

            elif ": " in line:
                key, value = line.split(": ", 1)

                if key.lower() == "cookie":
                    cookie = value
                elif key.lower() == "host":
                    host = value

        if getPostReq and params:
            if not url.startswith("http"):
                url = "http://%s%s" % (host, url)

            if not kb.targetUrls or url not in addedTargetUrls:
                kb.targetUrls.add(( url, method, data, cookie ))
                addedTargetUrls.add(url)


def __setMultipleTargets():
    """
    Define a configuration parameter if we are running in multiple target
    mode.
    """

    initialTargetsCount = len(kb.targetUrls)
    addedTargetUrls = set()

    if not conf.list:
        return

    debugMsg = "parsing targets list from '%s'" % conf.list
    logger.debug(debugMsg)

    if not os.path.exists(conf.list):
        errMsg = "the specified list of targets does not exist"
        raise sqlmapFilePathException, errMsg

    if os.path.isfile(conf.list):
        __feedTargetsDict(conf.list, addedTargetUrls)

    elif os.path.isdir(conf.list):
        files = os.listdir(conf.list)
        files.sort()

        for reqFile in files:
            if not re.search("([\d]+)\-request", reqFile):
                continue

            __feedTargetsDict(os.path.join(conf.list, reqFile), addedTargetUrls)

    else:
        errMsg  = "the specified list of targets is not a file "
        errMsg += "nor a directory"
        raise sqlmapFilePathException, errMsg

    updatedTargetsCount = len(kb.targetUrls)

    if updatedTargetsCount > initialTargetsCount:
        infoMsg  = "sqlmap parsed %d " % (updatedTargetsCount - initialTargetsCount)
        infoMsg += "testable requests from the targets list"
        logger.info(infoMsg)


def __setGoogleDorking():
    """
    This function checks if the way to request testable hosts is through
    Google dorking then requests to Google the search parameter, parses
    the results and save the testable hosts into the knowledge base.
    """

    global proxyHandler

    if not conf.googleDork:
        return

    debugMsg = "initializing Google dorking requests"
    logger.debug(debugMsg)

    logMsg = "first request to Google to get the session cookie"
    logger.info(logMsg)

    googleObj = Google(proxyHandler)
    googleObj.getCookie()

    matches = googleObj.search(conf.googleDork)

    if not matches:
        errMsg  = "unable to find results for your "
        errMsg += "Google dork expression"
        raise sqlmapGenericException, errMsg

    googleObj.getTargetUrls()

    if kb.targetUrls:
        logMsg  = "sqlmap got %d results for your " % len(matches)
        logMsg += "Google dork expression, "

        if len(matches) == len(kb.targetUrls):
            logMsg += "all "
        else:
            logMsg += "%d " % len(kb.targetUrls)

        logMsg += "of them are testable targets"
        logger.info(logMsg)
    else:
        errMsg  = "sqlmap got %d results " % len(matches)
        errMsg += "for your Google dork expression, but none of them "
        errMsg += "have GET parameters to test for SQL injection"
        raise sqlmapGenericException, errMsg


def __setRemoteDBMS():
    """
    Checks and set the back-end DBMS option.
    """

    if not conf.dbms:
        return

    debugMsg = "forcing back-end DBMS to user defined value"
    logger.debug(debugMsg)

    conf.dbms = conf.dbms.lower()
    firstRegExp = "(%s|%s)" % ("|".join([alias for alias in MSSQL_ALIASES]),
                               "|".join([alias for alias in MYSQL_ALIASES]))
    dbmsRegExp = re.search("%s ([\d\.]+)" % firstRegExp, conf.dbms)

    if dbmsRegExp:
        conf.dbms = dbmsRegExp.group(1)
        kb.dbmsVersion = [dbmsRegExp.group(2)]

    if conf.dbms not in SUPPORTED_DBMS:
        errMsg  = "you provided an unsupported back-end database management "
        errMsg += "system. The supported DBMS are MySQL, PostgreSQL, "
        errMsg += "Microsoft SQL Server and Oracle. If you do not know "
        errMsg += "the back-end DBMS, do not provide it and sqlmap will "
        errMsg += "fingerprint it for you."
        raise sqlmapUnsupportedDBMSException, errMsg


def __setThreads():
    if not isinstance(conf.threads, int) or conf.threads <= 0:
        conf.threads = 1


def __setHTTPProxy():
    """
    Check and set the HTTP proxy to pass by all HTTP requests.
    """

    global proxyHandler

    if not conf.proxy:
        return

    parseTargetUrl()

    debugMsg = "setting the HTTP proxy to pass by all HTTP requests"
    logger.debug(debugMsg)

    __proxySplit   = urlparse.urlsplit(conf.proxy)
    __hostnamePort = __proxySplit[1].split(":")

    __scheme       = __proxySplit[0]
    __hostname     = __hostnamePort[0]
    __port         = None

    if len(__hostnamePort) == 2:
        __port = int(__hostnamePort[1])

    if not __scheme or not __hostname or not __port:
        errMsg = "proxy value must be in format 'http://url:port'"
        raise sqlmapSyntaxException, errMsg

    __proxyString = "%s:%d" % (__hostname, __port)

    # Workaround for http://bugs.python.org/issue1424152 (urllib/urllib2:
    # HTTPS over (Squid) Proxy fails) as long as HTTP over SSL requests
    # can't be tunneled over an HTTP proxy natively by Python urllib2
    # standard library
    if conf.scheme == "https":
        proxyHandler = ProxyHTTPSHandler(__proxyString)
    else:
        proxyHandler = urllib2.ProxyHandler({"http": __proxyString})


def __setHTTPAuthentication():
    """
    Check and set the HTTP authentication method (Basic or Digest),
    username and password to perform HTTP requests with.
    """

    global authHandler

    if not conf.aType and not conf.aCred:
        return

    elif conf.aType and not conf.aCred:
        errMsg  = "you specified the HTTP Authentication type, but "
        errMsg += "did not provide the credentials"
        raise sqlmapSyntaxException, errMsg

    elif not conf.aType and conf.aCred:
        errMsg  = "you specified the HTTP Authentication credentials, "
        errMsg += "but did not provide the type"
        raise sqlmapSyntaxException, errMsg

    parseTargetUrl()

    debugMsg = "setting the HTTP Authentication type and credentials"
    logger.debug(debugMsg)

    aTypeLower = conf.aType.lower()

    if aTypeLower not in ( "basic", "digest" ):
        errMsg  = "HTTP Authentication type value must be "
        errMsg += "Basic or Digest"
        raise sqlmapSyntaxException, errMsg

    aCredRegExp = re.search("^(.*?)\:(.*?)$", conf.aCred)

    if not aCredRegExp:
        errMsg  = "HTTP Authentication credentials value must be "
        errMsg += "in format username:password"
        raise sqlmapSyntaxException, errMsg

    authUsername = aCredRegExp.group(1)
    authPassword = aCredRegExp.group(2)

    passwordMgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
    passwordMgr.add_password(None, "%s://%s" % (conf.scheme, conf.hostname), authUsername, authPassword)

    if aTypeLower == "basic":
        authHandler = urllib2.HTTPBasicAuthHandler(passwordMgr)
    elif aTypeLower == "digest":
        authHandler = urllib2.HTTPDigestAuthHandler(passwordMgr)


def __setHTTPMethod():
    """
    Check and set the HTTP method to perform HTTP requests through.
    """

    if conf.method:
        conf.method = conf.method.upper()

        if conf.method not in ("GET", "POST"):
            warnMsg  = "'%s' " % conf.method
            warnMsg += "is an unsupported HTTP method, "
            warnMsg += "setting to default method, GET"
            logger.warn(warnMsg)

            conf.method = "GET"
    else:
        conf.method = "GET"

    debugMsg = "setting the HTTP method to %s" % conf.method
    logger.debug(debugMsg)


def __setHTTPStandardHeaders():
    conf.httpHeaders.append(("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"))
    conf.httpHeaders.append(("Accept-Language", "en-us,en;q=0.5"))
    conf.httpHeaders.append(("Accept-Encoding", "gzip,deflate"))
    conf.httpHeaders.append(("Accept-Charset", "ISO-8859-15,utf-8;q=0.7,*;q=0.7"))


def __defaultHTTPUserAgent():
    """
    @return: default sqlmap HTTP User-Agent header
    @rtype: C{str}
    """

    return "%s (%s)" % (VERSION_STRING, SITE)


def __setHTTPUserAgent():
    """
    Set the HTTP User-Agent header.
    Depending on the user options it can be:

        * The default sqlmap string
        * A default value read as user option
        * A random value read from a list of User-Agent headers from a
          file choosed as user option
    """

    if conf.agent:
        debugMsg = "setting the HTTP User-Agent header"
        logger.debug(debugMsg)

        conf.httpHeaders.append(("User-Agent", conf.agent))
        return

    if not conf.userAgentsFile:
        conf.httpHeaders.append(("User-Agent", __defaultHTTPUserAgent()))
        return

    debugMsg  = "fetching random HTTP User-Agent header from "
    debugMsg += "file '%s'" % conf.userAgentsFile
    logger.debug(debugMsg)

    try:
        fd = open(conf.userAgentsFile, "r")
    except IOError:
        warnMsg  = "unable to read HTTP User-Agent header "
        warnMsg += "file '%s'" % conf.userAgentsFile
        logger.warn(warnMsg)

        conf.httpHeaders.append(("User-Agent", __defaultHTTPUserAgent()))

        return

    __count = 0
    __userAgents = []

    while True:
        line = fd.readline()

        if not line:
            break

        __userAgents.append(line)
        __count += 1

    fd.close()

    if __count == 1:
        __userAgent = __userAgents[0]
    else:
        __userAgent = __userAgents[randomRange(stop=__count)]

    __userAgent = sanitizeStr(__userAgent)
    conf.httpHeaders.append(("User-Agent", __userAgent))

    logMsg  = "fetched random HTTP User-Agent header from "
    logMsg += "file '%s': %s" % (conf.userAgentsFile, __userAgent)
    logger.info(logMsg)


def __setHTTPReferer():
    """
    Set the HTTP Referer
    """

    if conf.referer:
        debugMsg = "setting the HTTP Referer header"
        logger.debug(debugMsg)

        conf.httpHeaders.append(("Referer", conf.referer))


def __setHTTPCookies():
    """
    Set the HTTP Cookie header
    """

    if conf.cookie:
        debugMsg = "setting the HTTP Cookie header"
        logger.debug(debugMsg)

        conf.httpHeaders.append(("Connection", "Keep-Alive"))
        conf.httpHeaders.append(("Cookie", conf.cookie))


def __setHTTPTimeout():
    """
    Set the HTTP timeout
    """

    if conf.timeout:
        debugMsg = "setting the HTTP timeout"
        logger.debug(debugMsg)

        conf.timeout = float(conf.timeout)

        if conf.timeout < 3.0:
            warnMsg  = "the minimum HTTP timeout is 3 seconds, sqlmap "
            warnMsg += "will going to reset it"
            logger.warn(warnMsg)

            conf.timeout = 3.0
    else:
        conf.timeout = 10.0

    socket.setdefaulttimeout(conf.timeout)


def __cleanupOptions():
    """
    Cleanup configuration attributes.
    """

    debugMsg = "cleaning up configuration parameters"
    logger.debug(debugMsg)

    if conf.testParameter:
        conf.testParameter = conf.testParameter.replace(" ", "")
        conf.testParameter = conf.testParameter.split(",")
    else:
        conf.testParameter = []

    if conf.db:
        conf.db = conf.db.replace(" ", "")

    if conf.tbl:
        conf.tbl = conf.tbl.replace(" ", "")

    if conf.col:
        conf.col = conf.col.replace(" ", "")

    if conf.user:
        conf.user = conf.user.replace(" ", "")

    if conf.delay:
        conf.delay = float(conf.delay)

    if conf.googleDork or conf.list:
        conf.multipleTargets = True


def __setConfAttributes():
    """
    This function set some needed attributes into the configuration
    singleton.
    """

    debugMsg = "initializing the configuration"
    logger.debug(debugMsg)

    conf.cj              = None
    conf.dbmsHandler     = None
    conf.dumpPath        = None
    conf.httpHeaders     = []
    conf.hostname        = None
    conf.loggedToOut     = None
    conf.multipleTargets = False
    conf.outputPath      = None
    conf.paramDict       = {}
    conf.parameters      = {}
    conf.paramNegative   = False
    conf.path            = None
    conf.port            = None
    conf.retries         = 0
    conf.scheme          = None
    conf.sessionFP       = None
    conf.start           = True
    conf.threadException = False


def __setKnowledgeBaseAttributes():
    """
    This function set some needed attributes into the knowledge base
    singleton.
    """

    debugMsg = "initializing the knowledge base"
    logger.debug(debugMsg)

    kb.absFilePaths   = set()
    kb.defaultResult  = None
    kb.docRoot        = None
    kb.dbms           = None
    kb.dbmsDetected   = False
    kb.dbmsVersion    = None
    kb.bannerFp       = {}
    kb.headersCount   = 0
    kb.headersFp      = {}
    kb.htmlFp         = []
    kb.injParameter   = None
    kb.injPlace       = None
    kb.injType        = None
    kb.parenthesis    = None
    kb.resumedQueries = {}
    kb.targetUrls     = set()
    kb.timeTest       = None
    kb.unionComment   = ""
    kb.unionCount     = None
    kb.unionPosition  = None


def __saveCmdline():
    """
    Saves the command line options on a sqlmap configuration INI file
    format.
    """

    if not conf.saveCmdline:
        return

    debugMsg = "saving command line options on a sqlmap configuration INI file"
    logger.debug(debugMsg)

    userOpts = {}

    for family in optDict.keys():
        userOpts[family] = []

    for option, value in conf.items():
        for family, optionData in optDict.items():
            if option in optionData:
                userOpts[family].append((option, value, optionData[option]))

    confFP = open(paths.SQLMAP_CONFIG, "w")

    for family, optionData in userOpts.items():
        confFP.write("[%s]\n" % family)

        optionData.sort()

        for option, value, datatype in optionData:
            if value == None:
                if datatype == "boolean":
                    value = "False"
                elif datatype in ( "integer", "float" ):
                    if option in ( "threads", "verbose" ):
                        value = "1"
                    else:
                        value = "0"
                elif datatype == "string":
                    value = ""

            confFP.write("%s = %s\n" % (option, value))

        confFP.write("\n")

    confFP.flush()
    confFP.close()

    infoMsg = "saved command line options on '%s' configuration file" % paths.SQLMAP_CONFIG
    logger.info(infoMsg)


def __setVerbosity():
    """
    This function set the verbosity of sqlmap output messages.
    """

    if conf.verbose == None:
        conf.verbose = 1

    conf.verbose = int(conf.verbose)

    if conf.verbose == 1:
        logger.setLevel(logging.INFO)
    elif conf.verbose > 1 and conf.eta:
        conf.verbose = 1
        logger.setLevel(logging.INFO)
    elif conf.verbose == 2:
        logger.setLevel(logging.DEBUG)
    elif conf.verbose == 3:
        logger.setLevel(9)
    elif conf.verbose >= 4:
        logger.setLevel(8)


def __mergeOptions(inputOptions):
    """
    Merge command line options with configuration file options.

    @param inputOptions: optparse object with command line options.
    @type inputOptions: C{instance}
    """

    if inputOptions.configFile:
        configFileParser(inputOptions.configFile)

    for key, value in inputOptions.__dict__.items():
        if not conf.has_key(key) or conf[key] == None or value != None:
            conf[key] = value


def init(inputOptions=advancedDict()):
    """
    Set attributes into both configuration and knowledge base singletons
    based upon command line and configuration file options.
    """

    __mergeOptions(inputOptions)
    __setVerbosity()
    __saveCmdline()
    __setConfAttributes()
    __setKnowledgeBaseAttributes()
    __cleanupOptions()
    __setHTTPTimeout()
    __setHTTPCookies()
    __setHTTPReferer()
    __setHTTPUserAgent()
    __setHTTPStandardHeaders()
    __setHTTPMethod()
    __setHTTPAuthentication()
    __setHTTPProxy()
    __setThreads()
    __setRemoteDBMS()
    __setGoogleDorking()
    __setMultipleTargets()
    __urllib2Opener()

    update()
    queriesParser()
