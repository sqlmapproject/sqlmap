#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import cookielib
import difflib
import inspect
import logging
import os
import re
import socket
import sys
import threading
import urllib2
import urlparse

from extra.keepalive import keepalive
from extra.xmlobject import xmlobject
from lib.core.common import getConsoleWidth
from lib.core.common import getFileItems
from lib.core.common import getFileType
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import parseTargetDirect
from lib.core.common import parseTargetUrl
from lib.core.common import paths
from lib.core.common import randomRange
from lib.core.common import readCachedFileContent
from lib.core.common import readInput
from lib.core.common import runningAsAdmin
from lib.core.common import sanitizeStr
from lib.core.common import UnicodeRawConfigParser
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.datatype import advancedDict
from lib.core.enums import HTTPMETHOD
from lib.core.enums import PRIORITY
from lib.core.exception import sqlmapFilePathException
from lib.core.exception import sqlmapGenericException
from lib.core.exception import sqlmapMissingDependence
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.exception import sqlmapMissingPrivileges
from lib.core.exception import sqlmapSyntaxException
from lib.core.exception import sqlmapUnsupportedDBMSException
from lib.core.exception import sqlmapUserQuitException
from lib.core.optiondict import optDict
from lib.core.settings import IS_WIN
from lib.core.settings import PLATFORM
from lib.core.settings import PYVERSION
from lib.core.settings import SITE
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import SUPPORTED_OS
from lib.core.settings import VERSION_STRING
from lib.core.update import update
from lib.parse.configfile import configFileParser
from lib.request.proxy import ProxyHTTPSHandler
from lib.request.certhandler import HTTPSCertAuthHandler
from lib.request.rangehandler import HTTPRangeHandler
from lib.request.redirecthandler import SmartRedirectHandler
from lib.utils.google import Google

authHandler = urllib2.BaseHandler()
keepAliveHandler = keepalive.HTTPHandler()
proxyHandler = urllib2.BaseHandler()
redirectHandler = SmartRedirectHandler()
rangeHandler = HTTPRangeHandler()

def __urllib2Opener():
    """
    This function creates the urllib2 OpenerDirector.
    """

    global authHandler
    global keepAliveHandler
    global proxyHandler
    global rangeHandler
    global redirectHandler

    debugMsg = "creating HTTP requests opener object"
    logger.debug(debugMsg)

    handlers = [proxyHandler, authHandler, redirectHandler, rangeHandler]

    if not conf.dropSetCookie:
        conf.cj = cookielib.LWPCookieJar()
        handlers.append(urllib2.HTTPCookieProcessor(conf.cj))

    # Reference: http://www.w3.org/Protocols/rfc2616/rfc2616-sec8.html
    if conf.keepAlive:
        if conf.proxy:
            warnMsg = "persistent HTTP(s) connections, Keep-Alive, has "
            warnMsg += "been disabled because of it's incompatibility "
            warnMsg += "with HTTP(s) proxy"
            logger.warn(warnMsg)
        else:
            handlers.append(keepAliveHandler)

    opener = urllib2.build_opener(*handlers)
    urllib2.install_opener(opener)

def __feedTargetsDict(reqFile, addedTargetUrls):
    fp = codecs.open(reqFile, "rb")

    fread = fp.read()
    fread = fread.replace("\r", "")

    reqResList = fread.split("======================================================")

    port   = None
    scheme = None

    if conf.scope:
        logger.info("using regular expression '%s' for filtering targets" % conf.scope)

    for request in reqResList:
        if scheme is None:
            schemePort = re.search("\d\d[\:|\.]\d\d[\:|\.]\d\d\s+(http[\w]*)\:\/\/.*?\:([\d]+)", request, re.I)

            if schemePort:
                scheme = schemePort.group(1)
                port   = schemePort.group(2)

        if not re.search ("^[\n]*(GET|POST).*?\sHTTP\/", request, re.I):
            continue

        if re.search("^[\n]*(GET|POST).*?\.(gif|jpg|png)\sHTTP\/", request, re.I):
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

                url = line[index:line.index(" HTTP/")]
                method = line[:index-1]

                if "?" in line and "=" in line:
                    params = True

                getPostReq = True

            # POST parameters
            elif data is not None and params:
                data += line

            # GET parameters
            elif "?" in line and "=" in line and ": " not in line:
                params = True

            # Headers
            elif ": " in line:
                key, value = line.split(": ", 1)

                # Cookie and Host headers
                if key.lower() == "cookie":
                    cookie = value
                elif key.lower() == "host":
                    host = value

                # Avoid to add a static content length header to
                # conf.httpHeaders and consider the following lines as
                # POSTed data
                if key == "Content-Length":
                    data = ""
                    params = True

                # Avoid proxy and connection type related headers
                elif key not in ( "Proxy-Connection", "Connection" ):
                    conf.httpHeaders.append((str(key), str(value)))

        if conf.scope:
            getPostReq &= re.search(conf.scope, host) is not None

        if getPostReq and params:
            if not url.startswith("http"):
                url    = "%s://%s:%s%s" % (scheme or "http", host, port or "80", url)
                scheme = None
                port   = None

            if not kb.targetUrls or url not in addedTargetUrls:
                kb.targetUrls.add((url, method, data, cookie))
                addedTargetUrls.add(url)

def __loadQueries():
    """
    Loads queries from 'xml/queries.xml' file.
    """

    for node in xmlobject.XMLFile(path=paths.QUERIES_XML, textfilter=sanitizeStr).root.dbms:
        queries[node.value] = node

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

def __setRequestFromFile():
    """
    This function checks if the way to make a HTTP request is through supplied
    textual file, parses it and saves the information into the knowledge base.
    """

    if not conf.requestFile:
        return

    addedTargetUrls = set()

    conf.requestFile = os.path.expanduser(conf.requestFile)

    infoMsg = "parsing HTTP request from '%s'" % conf.requestFile
    logger.info(infoMsg)

    if not os.path.isfile(conf.requestFile):
        errMsg  = "the specified HTTP request file "
        errMsg += "does not exist"
        raise sqlmapFilePathException, errMsg

    __feedTargetsDict(conf.requestFile, addedTargetUrls)

def __setGoogleDorking():
    """
    This function checks if the way to request testable hosts is through
    Google dorking then requests to Google the search parameter, parses
    the results and save the testable hosts into the knowledge base.
    """

    if not conf.googleDork:
        return

    global keepAliveHandler
    global proxyHandler

    debugMsg = "initializing Google dorking requests"
    logger.debug(debugMsg)

    logMsg = "first request to Google to get the session cookie"
    logger.info(logMsg)

    handlers = [ proxyHandler ]

    # Reference: http://www.w3.org/Protocols/rfc2616/rfc2616-sec8.html
    if conf.keepAlive:
        if conf.proxy:
            warnMsg = "persistent HTTP(s) connections, Keep-Alive, has "
            warnMsg += "been disabled because of it's incompatibility "
            warnMsg += "with HTTP(s) proxy"
            logger.warn(warnMsg)
        else:
            handlers.append(keepAliveHandler)

    googleObj = Google(handlers)
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

def __setMetasploit():
    if not conf.osPwn and not conf.osSmb and not conf.osBof:
        return

    debugMsg = "setting the takeover out-of-band functionality"
    logger.debug(debugMsg)

    msfEnvPathExists = False

    if IS_WIN:
        warnMsg  = "some sqlmap takeover functionalities are not yet "
        warnMsg += "supported on Windows. Please use Linux in a virtual "
        warnMsg += "machine for out-of-band features. sqlmap will now "
        warnMsg += "carry on ignoring out-of-band switches"
        logger.warn(warnMsg)

        conf.osPwn = None
        conf.osSmb = None
        conf.osBof = None

        return

    if conf.osSmb:
        isAdmin = runningAsAdmin()

        if isAdmin is not True:
            errMsg  = "you need to run sqlmap as an administrator "
            errMsg += "if you want to perform a SMB relay attack because "
            errMsg += "it will need to listen on a user-specified SMB "
            errMsg += "TCP port for incoming connection attempts"
            raise sqlmapMissingPrivileges, errMsg

    if conf.msfPath:
        condition  = os.path.exists(normalizePath(conf.msfPath))
        condition &= os.path.exists(normalizePath(os.path.join(conf.msfPath, "msfcli")))
        condition &= os.path.exists(normalizePath(os.path.join(conf.msfPath, "msfconsole")))
        condition &= os.path.exists(normalizePath(os.path.join(conf.msfPath, "msfencode")))
        condition &= os.path.exists(normalizePath(os.path.join(conf.msfPath, "msfpayload")))

        if condition:
            debugMsg  = "provided Metasploit Framework 3 path "
            debugMsg += "'%s' is valid" % conf.msfPath
            logger.debug(debugMsg)

            msfEnvPathExists = True
        else:
            warnMsg  = "the provided Metasploit Framework 3 path "
            warnMsg += "'%s' is not valid. The cause could " % conf.msfPath
            warnMsg += "be that the path does not exists or that one "
            warnMsg += "or more of the needed Metasploit executables "
            warnMsg += "within msfcli, msfconsole, msfencode and "
            warnMsg += "msfpayload do not exist"
            logger.warn(warnMsg)
    else:
        warnMsg  = "you did not provide the local path where Metasploit "
        warnMsg += "Framework 3 is installed"
        logger.warn(warnMsg)

    if not msfEnvPathExists:
        warnMsg  = "sqlmap is going to look for Metasploit Framework 3 "
        warnMsg += "installation into the environment paths"
        logger.warn(warnMsg)

        envPaths = os.environ["PATH"]

        if IS_WIN:
            envPaths = envPaths.split(";")
        else:
            envPaths = envPaths.split(":")

        for envPath in envPaths:
            envPath    = envPath.replace(";", "")
            condition  = os.path.exists(normalizePath(envPath))
            condition &= os.path.exists(normalizePath(os.path.join(envPath, "msfcli")))
            condition &= os.path.exists(normalizePath(os.path.join(envPath, "msfconsole")))
            condition &= os.path.exists(normalizePath(os.path.join(envPath, "msfencode")))
            condition &= os.path.exists(normalizePath(os.path.join(envPath, "msfpayload")))

            if condition:
                infoMsg  = "Metasploit Framework 3 has been found "
                infoMsg += "installed in the '%s' path" % envPath
                logger.info(infoMsg)

                msfEnvPathExists = True
                conf.msfPath     = envPath

                break

    if not msfEnvPathExists:
        errMsg  = "unable to locate Metasploit Framework 3 installation. "
        errMsg += "Get it from http://metasploit.com/framework/download/"
        raise sqlmapFilePathException, errMsg

def __setWriteFile():
    if not conf.wFile:
        return

    debugMsg = "setting the write file functionality"
    logger.debug(debugMsg)

    if not os.path.exists(conf.wFile):
        errMsg = "the provided local file '%s' does not exist" % conf.wFile
        raise sqlmapFilePathException, errMsg

    if not conf.dFile:
        errMsg  = "you did not provide the back-end DBMS absolute path "
        errMsg += "where you want to write the local file '%s'" % conf.wFile
        raise sqlmapMissingMandatoryOptionException, errMsg

    conf.wFileType = getFileType(conf.wFile)

def __setUnionTech():
    if conf.uTech is None:
        conf.uTech = "NULL"

        return

    debugMsg = "setting the UNION query SQL injection detection technique"
    logger.debug(debugMsg)

    uTechOriginal = conf.uTech
    conf.uTech    = conf.uTech.lower()

    if conf.uTech and conf.uTech not in ( "null", "orderby" ):
        infoMsg  = "resetting the UNION query detection technique to "
        infoMsg += "'NULL', '%s' is not a valid technique" % uTechOriginal
        logger.info(infoMsg)

        conf.uTech = "NULL"

    else:
        debugMsg  = "setting UNION query detection technique to "
        debugMsg += "'%s'" % uTechOriginal
        logger.debug(debugMsg)

def __setOS():
    """
    Force the back-end DBMS operating system option.
    """

    if not conf.os:
        return

    debugMsg = "forcing back-end DBMS operating system to user defined value"
    logger.debug(debugMsg)

    conf.os = conf.os.lower()

    if conf.os not in SUPPORTED_OS:
        errMsg  = "you provided an unsupported back-end DBMS operating "
        errMsg += "system. The supported DBMS operating systems for OS "
        errMsg += "and file system access are Linux and Windows. "
        errMsg += "If you do not know the back-end DBMS underlying OS, "
        errMsg += "do not provide it and sqlmap will fingerprint it for "
        errMsg += "you."
        raise sqlmapUnsupportedDBMSException, errMsg

def __setDBMS():
    """
    Force the back-end DBMS option.
    """

    if not conf.dbms:
        return

    debugMsg = "forcing back-end DBMS to user defined value"
    logger.debug(debugMsg)

    conf.dbms = conf.dbms.lower()
    firstRegExp = "(%s)" % "|".join([alias for alias in SUPPORTED_DBMS])
    dbmsRegExp = re.search("%s ([\d\.]+)" % firstRegExp, conf.dbms)

    if dbmsRegExp:
        conf.dbms      = dbmsRegExp.group(1)
        kb.dbmsVersion = [ dbmsRegExp.group(2) ]

    if conf.dbms not in SUPPORTED_DBMS:
        errMsg  = "you provided an unsupported back-end database management "
        errMsg += "system. The supported DBMS are MySQL, PostgreSQL, "
        errMsg += "Microsoft SQL Server and Oracle. If you do not know "
        errMsg += "the back-end DBMS, do not provide it and sqlmap will "
        errMsg += "fingerprint it for you."
        raise sqlmapUnsupportedDBMSException, errMsg

def __setTamperingFunctions():
    """
    Loads tampering functions from given script(s)
    """

    if conf.tamper:
        last_priority = PRIORITY.HIGHEST
        check_priority = True
        resolve_priorities = False
        priorities = []

        for tfile in conf.tamper.split(','):
            found = False

            tfile = tfile.strip()

            if not tfile:
                continue

            elif not os.path.exists(tfile):
                errMsg = "tamper script '%s' does not exist" % tfile
                raise sqlmapFilePathException, errMsg

            elif not tfile.endswith('.py'):
                errMsg = "tamper script '%s' should have an extension '.py'" % tfile
                raise sqlmapSyntaxException, errMsg

            dirname, filename = os.path.split(tfile)
            dirname = os.path.abspath(dirname)

            infoMsg  = "loading tamper script '%s'" % filename[:-3]
            logger.info(infoMsg)

            if not os.path.exists(os.path.join(dirname, '__init__.py')):
                errMsg  = "make sure that there is an empty file '__init__.py' "
                errMsg += "inside of tamper scripts directory '%s'" % dirname
                raise sqlmapGenericException, errMsg

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                module = __import__(filename[:-3])
            except ImportError, msg:
                raise sqlmapSyntaxException, "can not import tamper script '%s' (%s)" % (filename[:-3], msg)

            priority = PRIORITY.NORMAL if not hasattr(module, '__priority__') else module.__priority__

            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "tamper" and function.func_code.co_argcount == 1:
                    found = True
                    kb.tamperFunctions.append(function)

                    if check_priority and priority > last_priority:
                        message  = "it seems that you might have mixed "
                        message += "the order of tamper scripts.\n"
                        message += "Do you want to auto resolve this? [Y/n/q]"
                        test = readInput(message, default="Y")

                        if not test or test[0] in ("y", "Y"):
                            resolve_priorities = True
                        elif test[0] in ("n", "N"):
                            resolve_priorities = False
                        elif test[0] in ("q", "Q"):
                            raise sqlmapUserQuitException

                        check_priority = False

                    priorities.append((priority, function))
                    last_priority = priority

                    break

            if not found:
                raise sqlmapGenericException, "missing function 'tamper(value)' in tamper script '%s'" % tfile

        if resolve_priorities and priorities:
            priorities.sort(reverse=True)
            kb.tamperFunctions = []

            for _, function in priorities:
                kb.tamperFunctions.append(function)

def __setThreads():
    if not isinstance(conf.threads, int) or conf.threads <= 0:
        conf.threads = 1

def __setHTTPProxy():
    """
    Check and set the HTTP proxy to pass by all HTTP requests.
    """

    global proxyHandler

    if not conf.proxy:
        if conf.hostname in ('localhost', '127.0.0.1') or conf.ignoreProxy:
            proxyHandler = urllib2.ProxyHandler({})

        return

    debugMsg = "setting the HTTP proxy to pass by all HTTP requests"
    logger.debug(debugMsg)

    __proxySplit   = urlparse.urlsplit(conf.proxy)
    __hostnamePort = __proxySplit[1].split(":")

    __scheme       = __proxySplit[0]
    __hostname     = __hostnamePort[0]
    __port         = None
    __proxyString  = ""

    if len(__hostnamePort) == 2:
        try:
            __port = int(__hostnamePort[1])
        except:
            pass #drops into the next check block

    if not __scheme or not __hostname or not __port:
        errMsg = "proxy value must be in format 'http://url:port'"
        raise sqlmapSyntaxException, errMsg

    if conf.pCred:
        pCredRegExp = re.search("^(.*?):(.*?)$", conf.pCred)

        if not pCredRegExp:
            errMsg  = "Proxy authentication credentials "
            errMsg += "value must be in format username:password"
            raise sqlmapSyntaxException, errMsg

        # Reference: http://stackoverflow.com/questions/34079/how-to-specify-an-authenticated-proxy-for-a-python-http-connection
        __proxyString = "%s@" % conf.pCred

    __proxyString += "%s:%d" % (__hostname, __port)

    # Workaround for http://bugs.python.org/issue1424152 (urllib/urllib2:
    # HTTPS over (Squid) Proxy fails) as long as HTTP over SSL requests
    # can't be tunneled over an HTTP proxy natively by Python (<= 2.5)
    # urllib2 standard library
    if conf.scheme == "https":
        if PYVERSION >= "2.6":
            proxyHandler = urllib2.ProxyHandler({"https": __proxyString})
        else:
            proxyHandler = ProxyHTTPSHandler(__proxyString)
    else:
        proxyHandler = urllib2.ProxyHandler({"http": __proxyString})

def __setSafeUrl():
    """
    Check and set the safe URL options.
    """
    if not conf.safUrl:
        return

    if not re.search("^http[s]*://", conf.safUrl):
        if ":443/" in conf.safUrl:
            conf.safUrl = "https://" + conf.safUrl
        else:
            conf.safUrl = "http://" + conf.safUrl

    if conf.saFreq <= 0:
        errMsg = "please provide a valid value (>0) for safe frequency (--safe-freq) while using safe url feature"
        raise sqlmapSyntaxException, errMsg

def __setHTTPAuthentication():
    """
    Check and set the HTTP(s) authentication method (Basic, Digest, NTLM or Certificate),
    username and password for first three methods, or key file and certification file for
    certificate authentication
    """

    global authHandler

    if not conf.aType and not conf.aCred and not conf.aCert:
        return

    elif conf.aType and not conf.aCred:
        errMsg  = "you specified the HTTP authentication type, but "
        errMsg += "did not provide the credentials"
        raise sqlmapSyntaxException, errMsg

    elif not conf.aType and conf.aCred:
        errMsg  = "you specified the HTTP authentication credentials, "
        errMsg += "but did not provide the type"
        raise sqlmapSyntaxException, errMsg

    if not conf.aCert:
        debugMsg = "setting the HTTP authentication type and credentials"
        logger.debug(debugMsg)

        aTypeLower = conf.aType.lower()

        if aTypeLower not in ( "basic", "digest", "ntlm" ):
            errMsg  = "HTTP authentication type value must be "
            errMsg += "Basic, Digest or NTLM"
            raise sqlmapSyntaxException, errMsg
        elif aTypeLower in ( "basic", "digest" ):
            regExp = "^(.*?):(.*?)$"
            errMsg  = "HTTP %s authentication credentials " % aTypeLower
            errMsg += "value must be in format username:password"
        elif aTypeLower == "ntlm":
            regExp = "^(.*?)\\\(.*?):(.*?)$"
            errMsg  = "HTTP NTLM authentication credentials value must "
            errMsg += "be in format DOMAIN\username:password"

        aCredRegExp = re.search(regExp, conf.aCred)

        if not aCredRegExp:
            raise sqlmapSyntaxException, errMsg

        authUsername = aCredRegExp.group(1)
        authPassword = aCredRegExp.group(2)

        passwordMgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        passwordMgr.add_password(None, "%s://%s" % (conf.scheme, conf.hostname), authUsername, authPassword)

        if aTypeLower == "basic":
            authHandler = urllib2.HTTPBasicAuthHandler(passwordMgr)

        elif aTypeLower == "digest":
            authHandler = urllib2.HTTPDigestAuthHandler(passwordMgr)

        elif aTypeLower == "ntlm":
            try:
                from ntlm import HTTPNtlmAuthHandler
            except ImportError, _:
                errMsg  = "sqlmap requires Python NTLM third-party library "
                errMsg += "in order to authenticate via NTLM, "
                errMsg += "http://code.google.com/p/python-ntlm/"
                raise sqlmapMissingDependence, errMsg

            authHandler = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passwordMgr)
    else:
        debugMsg = "setting the HTTP(s) authentication certificate"
        logger.debug(debugMsg)

        aCertRegExp = re.search("^(.+?),\s*(.+?)$", conf.aCert)

        if not aCertRegExp:
            errMsg  = "HTTP authentication certificate option "
            errMsg += "must be in format key_file,cert_file"
            raise sqlmapSyntaxException, errMsg

        # os.path.expanduser for support of paths with ~
        key_file = os.path.expanduser(aCertRegExp.group(1))
        cert_file = os.path.expanduser(aCertRegExp.group(2))

        for ifile in (key_file, cert_file):
            if not os.path.exists(ifile):
                errMsg  = "File '%s' does not exist" % ifile
                raise sqlmapSyntaxException, errMsg

        authHandler = HTTPSCertAuthHandler(key_file, cert_file)

def __setHTTPMethod():
    """
    Check and set the HTTP method to perform HTTP requests through.
    """

    if conf.method:
        conf.method = conf.method.upper()

        if conf.method not in (HTTPMETHOD.GET, HTTPMETHOD.POST):
            warnMsg  = "'%s' " % conf.method
            warnMsg += "is an unsupported HTTP method, "
            warnMsg += "setting to default method, %s" % HTTPMETHOD.GET
            logger.warn(warnMsg)

            conf.method = HTTPMETHOD.GET
    else:
        conf.method = HTTPMETHOD.GET

    debugMsg = "setting the HTTP method to %s" % conf.method
    logger.debug(debugMsg)

def __setHTTPExtraHeaders():
    if conf.hostname:
        conf.httpHeaders.append(("Host", conf.hostname))

    if conf.headers:
        debugMsg = "setting extra HTTP headers"
        logger.debug(debugMsg)

        conf.headers = conf.headers.split("\n")

        for headerValue in conf.headers:
            header, value = headerValue.split(": ")

            if header and value:
                conf.httpHeaders.append((header, value))
    elif not conf.httpHeaders or len(conf.httpHeaders) == 1:
        conf.httpHeaders.append(("Accept", "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"))
        conf.httpHeaders.append(("Accept-Language", "en-us,en;q=0.5"))
        conf.httpHeaders.append(("Accept-Charset", "ISO-8859-15,utf-8;q=0.7,*;q=0.7"))

def __defaultHTTPUserAgent():
    """
    @return: default sqlmap HTTP User-Agent header
    @rtype: C{str}
    """

    return "%s (%s)" % (VERSION_STRING, SITE)

    # Firefox 3 running on Ubuntu 9.04 updated at April 2009
    #return "Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.9.0.9) Gecko/2009042113 Ubuntu/9.04 (jaunty) Firefox/3.0.9"

    # Internet Explorer 7.0 running on Windows 2003 Service Pack 2 english
    # updated at March 2009
    #return "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)"

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
        addDefaultUserAgent = True

        for header, _ in conf.httpHeaders:
            if header == "User-Agent":
                addDefaultUserAgent = False
                break

        if addDefaultUserAgent:
            conf.httpHeaders.append(("User-Agent", __defaultHTTPUserAgent()))

        return

    if not kb.userAgents:
        debugMsg  = "loading random HTTP User-Agent header(s) from "
        debugMsg += "file '%s'" % conf.userAgentsFile
        logger.debug(debugMsg)

        try:
            kb.userAgents = getFileItems(conf.userAgentsFile)
        except IOError:
            warnMsg  = "unable to read HTTP User-Agent header "
            warnMsg += "file '%s'" % conf.userAgentsFile
            logger.warn(warnMsg)

            conf.httpHeaders.append(("User-Agent", __defaultHTTPUserAgent()))

            return

    __count = len(kb.userAgents)

    if __count == 1:
        __userAgent = kb.userAgents[0]
    else:
        __userAgent = kb.userAgents[randomRange(stop=__count)]

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
        conf.timeout = 30.0

    socket.setdefaulttimeout(conf.timeout)

def __cleanupOptions():
    """
    Cleanup configuration attributes.
    """

    debugMsg = "cleaning up configuration parameters"
    logger.debug(debugMsg)

    width = getConsoleWidth()

    if conf.eta:
        conf.progressWidth = width-26
    else:
        conf.progressWidth = width-46

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

    if conf.rFile:
        conf.rFile = ntToPosixSlashes(normalizePath(conf.rFile))

    if conf.wFile:
        conf.wFile = ntToPosixSlashes(normalizePath(conf.wFile))

    if conf.dFile:
        conf.dFile = ntToPosixSlashes(normalizePath(conf.dFile))

    if conf.msfPath:
        conf.msfPath = ntToPosixSlashes(normalizePath(conf.msfPath))

    if conf.tmpPath:
        conf.tmpPath = ntToPosixSlashes(normalizePath(conf.tmpPath))

    if conf.googleDork or conf.list:
        conf.multipleTargets = True

    if conf.optimize:
        #conf.predictOutput = True
        conf.keepAlive = True
        conf.nullConnection = not (conf.textOnly or conf.longestCommon)
        conf.threads = 4 if conf.threads < 2 else conf.threads

def __setConfAttributes():
    """
    This function set some needed attributes into the configuration
    singleton.
    """

    debugMsg = "initializing the configuration"
    logger.debug(debugMsg)

    conf.cj               = None
    conf.dataEncoding     = "utf-8"
    conf.dbmsConnector    = None
    conf.dbmsHandler      = None
    conf.dumpPath         = None
    conf.minMatchBlock    = 8
    conf.dynMarkLength    = 32
    conf.httpHeaders      = []
    conf.hostname         = None
    conf.loggedToOut      = None
    conf.logic            = "AND"
    conf.matchRatio       = None
    conf.multipleTargets  = False
    conf.outputPath       = None
    conf.paramDict        = {}
    conf.parameters       = {}
    conf.path             = None
    conf.port             = None
    conf.redirectHandled  = False
    conf.retriesCount     = 0
    conf.scheme           = None
    #conf.seqMatcher       = difflib.SequenceMatcher(lambda x: x in " \t")
    conf.seqMatcher       = difflib.SequenceMatcher(None)
    conf.sessionFP        = None
    conf.start            = True
    conf.threadContinue   = True
    conf.threadException  = False
    conf.trafficFP        = None
    conf.wFileType        = None

def __setKnowledgeBaseAttributes():
    """
    This function set some needed attributes into the knowledge base
    singleton.
    """

    debugMsg = "initializing the knowledge base"
    logger.debug(debugMsg)

    kb.absFilePaths    = set()
    kb.assumeEmpty     = False
    kb.authHeader      = None
    kb.bannerFp        = advancedDict()

    kb.cache           = advancedDict()
    kb.cache.content   = {}
    kb.cache.regex     = {}

    kb.commonOutputs   = None

    kb.data            = advancedDict()

    # Basic back-end DBMS fingerprint
    kb.dbms            = None
    kb.dbmsDetected    = False

    # Active (extensive) back-end DBMS fingerprint
    kb.dbmsVersion     = [ "Unknown" ]

    kb.dep             = None
    kb.docRoot         = None
    kb.dynamicMarkings = []
    kb.errorTest       = None
    kb.headersCount    = 0
    kb.headersFp       = {}
    kb.hintValue       = None
    kb.htmlFp          = []
    kb.injParameter    = None
    kb.injPlace        = None
    kb.injType         = None
    kb.injections      = xmlobject.XMLFile(path=paths.INJECTIONS_XML)
    kb.keywords        = set(getFileItems(paths.SQL_KEYWORDS))
    kb.lastErrorPage   = None
    kb.lastRequestUID  = 0

    kb.locks           = advancedDict()
    kb.locks.cacheLock = threading.Lock()
    kb.locks.reqLock   = threading.Lock()
    kb.locks.seqLock   = None

    kb.nullConnection  = None

    # Back-end DBMS underlying operating system fingerprint via banner (-b)
    # parsing
    kb.os              = None
    kb.osVersion       = None
    kb.osSP            = None

    kb.pageStable      = None
    kb.paramMatchRatio = {}
    kb.parenthesis     = None
    kb.partRun         = None
    kb.proxyAuthHeader = None
    kb.queryCounter    = 0
    kb.resumedQueries  = {}
    kb.stackedTest     = None
    kb.tamperFunctions = []
    kb.targetUrls      = set()
    kb.testedParams    = set()
    kb.timeTest        = None
    kb.unionComment    = ""
    kb.unionCount      = None
    kb.unionPosition   = None
    kb.unionNegative   = False
    kb.unionFalseCond  = False
    kb.unionTest       = None
    kb.userAgents      = None
    kb.valueStack      = []

def __saveCmdline():
    """
    Saves the command line options on a sqlmap configuration INI file
    format.
    """

    if not conf.saveCmdline:
        return

    debugMsg = "saving command line options on a sqlmap configuration INI file"
    logger.debug(debugMsg)

    config = UnicodeRawConfigParser()
    userOpts = {}

    for family in optDict.keys():
        userOpts[family] = []

    for option, value in conf.items():
        for family, optionData in optDict.items():
            if option in optionData:
                userOpts[family].append((option, value, optionData[option]))

    for family, optionData in userOpts.items():
        config.add_section(family)

        optionData.sort()

        for option, value, datatype in optionData:
            if isinstance(datatype, (list, tuple, set)):
                datatype = datatype[0]

            if value is None:
                if datatype == "boolean":
                    value = "False"
                elif datatype in ( "integer", "float" ):
                    if option in ( "threads", "verbose" ):
                        value = "1"
                    elif option == "timeout":
                        value = "10"
                    else:
                        value = "0"
                elif datatype == "string":
                    value = ""

            if isinstance(value, basestring):
                value = value.replace("\n", "\n ")

            config.set(family, option, value)

    confFP = codecs.open(paths.SQLMAP_CONFIG, "wb", conf.dataEncoding)
    config.write(confFP)

    infoMsg = "saved command line options on '%s' configuration file" % paths.SQLMAP_CONFIG
    logger.info(infoMsg)

def __setVerbosity():
    """
    This function set the verbosity of sqlmap output messages.
    """

    if conf.verbose is None:
        conf.verbose = 1

    conf.verbose = int(conf.verbose)

    if conf.verbose == 0:
        logger.setLevel(logging.CRITICAL)
    elif conf.verbose == 1:
        logger.setLevel(logging.INFO)
    elif conf.verbose > 2 and conf.eta:
        conf.verbose = 2
        logger.setLevel(logging.DEBUG)
    elif conf.verbose == 2:
        logger.setLevel(logging.DEBUG)
    elif conf.verbose == 3:
        logger.setLevel(9)
    elif conf.verbose == 4:
        logger.setLevel(8)
    elif conf.verbose >= 5:
        logger.setLevel(7)

def __mergeOptions(inputOptions):
    """
    Merge command line options with configuration file options.

    @param inputOptions: optparse object with command line options.
    @type inputOptions: C{instance}
    """

    if inputOptions.configFile:
        configFileParser(inputOptions.configFile)

    if hasattr(inputOptions, "items"):
        inputOptionsItems = inputOptions.items()
    else:
        inputOptionsItems = inputOptions.__dict__.items()

    for key, value in inputOptionsItems:
        if not conf.has_key(key) or conf[key] is None or value is not None:
            conf[key] = value

def __setTrafficOutputFP():
    if conf.trafficFile:
        conf.trafficFP = codecs.open(conf.trafficFile, "w+", conf.dataEncoding)

def __basicOptionValidation():
    if conf.limitStart is not None and not (isinstance(conf.limitStart, int) and conf.limitStart > 0):
        errMsg = "value for --start (limitStart) option must be an integer value greater than zero (>0)"
        raise sqlmapSyntaxException, errMsg

    if conf.limitStop is not None and not (isinstance(conf.limitStop, int) and conf.limitStop > 0):
        errMsg = "value for --stop (limitStop) option must be an integer value greater than zero (>0)"
        raise sqlmapSyntaxException, errMsg

    if conf.limitStart is not None and isinstance(conf.limitStart, int) and conf.limitStart > 0 and \
       conf.limitStop is not None and isinstance(conf.limitStop, int) and conf.limitStop <= conf.limitStart:
        errMsg = "value for --start (limitStart) option must be smaller than value for --stop (limitStop) option"
        raise sqlmapSyntaxException, errMsg

    if conf.firstChar is not None and isinstance(conf.firstChar, int) and conf.firstChar > 0 and \
       conf.lastChar is not None and isinstance(conf.lastChar, int) and conf.lastChar < conf.firstChar:
        errMsg = "value for --first (firstChar) option must be smaller than or equal to value for --last (lastChar) option"
        raise sqlmapSyntaxException, errMsg

    if conf.cpuThrottle is not None and isinstance(conf.cpuThrottle, int) and (conf.cpuThrottle > 100 or conf.cpuThrottle < 0):
        errMsg = "value for --cpu-throttle (cpuThrottle) option must be in range [0,100]"
        raise sqlmapSyntaxException, errMsg

    if conf.thold is not None and isinstance(conf.thold, float) and (conf.thold > 1 or conf.cpuThrottle < 0):
        errMsg = "value for --threshold (thold) option must be in range [0,1]"
        raise sqlmapSyntaxException, errMsg

    if conf.textOnly and conf.nullConnection:
        errMsg = "switch --text-only is incompatible with switch --null-connection"
        raise sqlmapSyntaxException, errMsg

    if conf.longestCommon and conf.nullConnection:
        errMsg = "switch --longest-common is incompatible with switch --null-connection"
        raise sqlmapSyntaxException, errMsg

    if conf.data and conf.nullConnection:
        errMsg = "switch --data is incompatible with switch --null-connection"
        raise sqlmapSyntaxException, errMsg

    if conf.predictOutput and conf.threads > 1:
        errMsg = "switch --predict-output is incompatible with switch --threads"
        raise sqlmapSyntaxException, errMsg

def init(inputOptions=advancedDict()):
    """
    Set attributes into both configuration and knowledge base singletons
    based upon command line and configuration file options.
    """

    __setConfAttributes()
    __setKnowledgeBaseAttributes()
    __mergeOptions(inputOptions)
    __setVerbosity()
    __saveCmdline()
    __cleanupOptions()
    __basicOptionValidation()
    __setRequestFromFile()
    __setMultipleTargets()
    __setTamperingFunctions()
    __setTrafficOutputFP()

    parseTargetUrl()
    parseTargetDirect()

    if conf.url or conf.list or conf.requestFile or conf.googleDork or conf.liveTest:
        __setHTTPTimeout()
        __setHTTPExtraHeaders()
        __setHTTPCookies()
        __setHTTPReferer()
        __setHTTPUserAgent()
        __setHTTPMethod()
        __setHTTPAuthentication()
        __setHTTPProxy()
        __setSafeUrl()
        __setUnionTech()
        __setGoogleDorking()
        __urllib2Opener()
        __setDBMS()

    __setThreads()
    __setOS()
    __setWriteFile()
    __setMetasploit()

    update()
    __loadQueries()
