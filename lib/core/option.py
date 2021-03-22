#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import codecs
import functools
import glob
import inspect
import logging
import os
import random
import re
import socket
import sys
import tempfile
import threading
import time
import traceback

from lib.controller.checks import checkConnection
from lib.core.common import Backend
from lib.core.common import boldifyMessage
from lib.core.common import checkFile
from lib.core.common import dataToStdout
from lib.core.common import decodeStringEscape
from lib.core.common import fetchRandomAgent
from lib.core.common import filterNone
from lib.core.common import findLocalPort
from lib.core.common import findPageForms
from lib.core.common import getConsoleWidth
from lib.core.common import getFileItems
from lib.core.common import getFileType
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSafeExString
from lib.core.common import intersect
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import openFile
from lib.core.common import parseRequestFile
from lib.core.common import parseTargetDirect
from lib.core.common import paths
from lib.core.common import randomStr
from lib.core.common import readCachedFileContent
from lib.core.common import readInput
from lib.core.common import resetCookieJar
from lib.core.common import runningAsAdmin
from lib.core.common import safeExpandUser
from lib.core.common import safeFilepathEncode
from lib.core.common import saveConfig
from lib.core.common import setColor
from lib.core.common import setOptimize
from lib.core.common import setPaths
from lib.core.common import singleTimeWarnMessage
from lib.core.common import urldecode
from lib.core.compat import cmp
from lib.core.compat import round
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import mergedOptions
from lib.core.data import queries
from lib.core.datatype import AttribDict
from lib.core.datatype import InjectionDict
from lib.core.datatype import OrderedSet
from lib.core.defaults import defaults
from lib.core.dicts import DBMS_DICT
from lib.core.dicts import DUMP_REPLACEMENTS
from lib.core.enums import ADJUST_TIME_DELAY
from lib.core.enums import AUTH_TYPE
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import DUMP_FORMAT
from lib.core.enums import FORK
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.enums import MOBILES
from lib.core.enums import OPTION_TYPE
from lib.core.enums import PAYLOAD
from lib.core.enums import PRIORITY
from lib.core.enums import PROXY_TYPE
from lib.core.enums import REFLECTIVE_COUNTER
from lib.core.enums import WIZARD
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapInstallationException
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapMissingPrivileges
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSyntaxException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.core.exception import SqlmapUserQuitException
from lib.core.exception import SqlmapValueException
from lib.core.log import FORMATTER
from lib.core.optiondict import optDict
from lib.core.settings import CODECS_LIST_PAGE
from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR
from lib.core.settings import DBMS_ALIASES
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import DEFAULT_PAGE_ENCODING
from lib.core.settings import DEFAULT_TOR_HTTP_PORTS
from lib.core.settings import DEFAULT_TOR_SOCKS_PORTS
from lib.core.settings import DEFAULT_USER_AGENT
from lib.core.settings import DUMMY_URL
from lib.core.settings import IGNORE_CODE_WILDCARD
from lib.core.settings import IS_WIN
from lib.core.settings import KB_CHARS_BOUNDARY_CHAR
from lib.core.settings import KB_CHARS_LOW_FREQUENCY_ALPHABET
from lib.core.settings import LOCALHOST
from lib.core.settings import MAX_CONNECT_RETRIES
from lib.core.settings import MAX_NUMBER_OF_THREADS
from lib.core.settings import NULL
from lib.core.settings import PARAMETER_SPLITTING_REGEX
from lib.core.settings import PRECONNECT_CANDIDATE_TIMEOUT
from lib.core.settings import PROXY_ENVIRONMENT_VARIABLES
from lib.core.settings import SOCKET_PRE_CONNECT_QUEUE_SIZE
from lib.core.settings import SQLMAP_ENVIRONMENT_PREFIX
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import SUPPORTED_OS
from lib.core.settings import TIME_DELAY_CANDIDATES
from lib.core.settings import UNION_CHAR_REGEX
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.core.settings import URI_INJECTABLE_REGEX
from lib.core.threads import getCurrentThreadData
from lib.core.threads import setDaemon
from lib.core.update import update
from lib.parse.configfile import configFileParser
from lib.parse.payloads import loadBoundaries
from lib.parse.payloads import loadPayloads
from lib.request.basic import checkCharEncoding
from lib.request.basicauthhandler import SmartHTTPBasicAuthHandler
from lib.request.chunkedhandler import ChunkedHandler
from lib.request.connect import Connect as Request
from lib.request.dns import DNSServer
from lib.request.httpshandler import HTTPSHandler
from lib.request.pkihandler import HTTPSPKIAuthHandler
from lib.request.rangehandler import HTTPRangeHandler
from lib.request.redirecthandler import SmartRedirectHandler
from lib.utils.crawler import crawl
from lib.utils.deps import checkDependencies
from lib.utils.har import HTTPCollectorFactory
from lib.utils.purge import purge
from lib.utils.search import search
from thirdparty import six
from thirdparty.keepalive import keepalive
from thirdparty.multipart import multipartpost
from thirdparty.six.moves import collections_abc as _collections
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import http_cookiejar as _http_cookiejar
from thirdparty.six.moves import urllib as _urllib
from thirdparty.socks import socks
from xml.etree.ElementTree import ElementTree

authHandler = _urllib.request.BaseHandler()
chunkedHandler = ChunkedHandler()
httpsHandler = HTTPSHandler()
keepAliveHandler = keepalive.HTTPHandler()
proxyHandler = _urllib.request.ProxyHandler()
redirectHandler = SmartRedirectHandler()
rangeHandler = HTTPRangeHandler()
multipartPostHandler = multipartpost.MultipartPostHandler()

# Reference: https://mail.python.org/pipermail/python-list/2009-November/558615.html
try:
    WindowsError
except NameError:
    WindowsError = None

def _loadQueries():
    """
    Loads queries from 'xml/queries.xml' file.
    """

    def iterate(node, retVal=None):
        class DictObject(object):
            def __init__(self):
                self.__dict__ = {}

            def __contains__(self, name):
                return name in self.__dict__

        if retVal is None:
            retVal = DictObject()

        for child in node.findall("*"):
            instance = DictObject()
            retVal.__dict__[child.tag] = instance
            if child.attrib:
                instance.__dict__.update(child.attrib)
            else:
                iterate(child, instance)

        return retVal

    tree = ElementTree()
    try:
        tree.parse(paths.QUERIES_XML)
    except Exception as ex:
        errMsg = "something appears to be wrong with "
        errMsg += "the file '%s' ('%s'). Please make " % (paths.QUERIES_XML, getSafeExString(ex))
        errMsg += "sure that you haven't made any changes to it"
        raise SqlmapInstallationException(errMsg)

    for node in tree.findall("*"):
        queries[node.attrib['value']] = iterate(node)

def _setMultipleTargets():
    """
    Define a configuration parameter if we are running in multiple target
    mode.
    """

    initialTargetsCount = len(kb.targets)
    seen = set()

    if not conf.logFile:
        return

    debugMsg = "parsing targets list from '%s'" % conf.logFile
    logger.debug(debugMsg)

    if not os.path.exists(conf.logFile):
        errMsg = "the specified list of targets does not exist"
        raise SqlmapFilePathException(errMsg)

    if checkFile(conf.logFile, False):
        for target in parseRequestFile(conf.logFile):
            url, _, data, _, _ = target
            key = re.sub(r"(\w+=)[^%s ]*" % (conf.paramDel or DEFAULT_GET_POST_DELIMITER), r"\g<1>", "%s %s" % (url, data))
            if key not in seen:
                kb.targets.add(target)
                seen.add(key)

    elif os.path.isdir(conf.logFile):
        files = os.listdir(conf.logFile)
        files.sort()

        for reqFile in files:
            if not re.search(r"([\d]+)\-request", reqFile):
                continue

            for target in parseRequestFile(os.path.join(conf.logFile, reqFile)):
                url, _, data, _, _ = target
                key = re.sub(r"(\w+=)[^%s ]*" % (conf.paramDel or DEFAULT_GET_POST_DELIMITER), r"\g<1>", "%s %s" % (url, data))
                if key not in seen:
                    kb.targets.add(target)
                    seen.add(key)

    else:
        errMsg = "the specified list of targets is not a file "
        errMsg += "nor a directory"
        raise SqlmapFilePathException(errMsg)

    updatedTargetsCount = len(kb.targets)

    if updatedTargetsCount > initialTargetsCount:
        infoMsg = "sqlmap parsed %d " % (updatedTargetsCount - initialTargetsCount)
        infoMsg += "(parameter unique) requests from the "
        infoMsg += "targets list ready to be tested"
        logger.info(infoMsg)

def _adjustLoggingFormatter():
    """
    Solves problem of line deletition caused by overlapping logging messages
    and retrieved data info in inference mode
    """

    if hasattr(FORMATTER, '_format'):
        return

    def format(record):
        message = FORMATTER._format(record)
        message = boldifyMessage(message)
        if kb.get("prependFlag"):
            message = "\n%s" % message
            kb.prependFlag = False
        return message

    FORMATTER._format = FORMATTER.format
    FORMATTER.format = format

def _setRequestFromFile():
    """
    This function checks if the way to make a HTTP request is through supplied
    textual file, parses it and saves the information into the knowledge base.
    """

    if conf.requestFile:
        for requestFile in re.split(PARAMETER_SPLITTING_REGEX, conf.requestFile):
            requestFile = safeExpandUser(requestFile)
            url = None
            seen = set()

            if not checkFile(requestFile, False):
                errMsg = "specified HTTP request file '%s' " % requestFile
                errMsg += "does not exist"
                raise SqlmapFilePathException(errMsg)

            infoMsg = "parsing HTTP request from '%s'" % requestFile
            logger.info(infoMsg)

            for target in parseRequestFile(requestFile):
                url = target[0]
                if url not in seen:
                    kb.targets.add(target)
                    if len(kb.targets) > 1:
                        conf.multipleTargets = True
                    seen.add(url)

            if url is None:
                errMsg = "specified file '%s' " % requestFile
                errMsg += "does not contain a usable HTTP request (with parameters)"
                raise SqlmapDataException(errMsg)

    if conf.secondReq:
        conf.secondReq = safeExpandUser(conf.secondReq)

        if not checkFile(conf.secondReq, False):
            errMsg = "specified second-order HTTP request file '%s' " % conf.secondReq
            errMsg += "does not exist"
            raise SqlmapFilePathException(errMsg)

        infoMsg = "parsing second-order HTTP request from '%s'" % conf.secondReq
        logger.info(infoMsg)

        try:
            target = next(parseRequestFile(conf.secondReq, False))
            kb.secondReq = target
        except StopIteration:
            errMsg = "specified second-order HTTP request file '%s' " % conf.secondReq
            errMsg += "does not contain a valid HTTP request"
            raise SqlmapDataException(errMsg)

def _setCrawler():
    if not conf.crawlDepth:
        return

    if not conf.bulkFile:
        if conf.url:
            crawl(conf.url)
        elif conf.requestFile and kb.targets:
            target = next(iter(kb.targets))
            crawl(target[0], target[2], target[3])

def _doSearch():
    """
    This function performs search dorking, parses results
    and saves the testable hosts into the knowledge base.
    """

    if not conf.googleDork:
        return

    kb.data.onlyGETs = None

    def retrieve():
        links = search(conf.googleDork)

        if not links:
            errMsg = "unable to find results for your "
            errMsg += "search dork expression"
            raise SqlmapGenericException(errMsg)

        for link in links:
            link = urldecode(link)
            if re.search(r"(.*?)\?(.+)", link) or conf.forms:
                kb.targets.add((link, conf.method, conf.data, conf.cookie, None))
            elif re.search(URI_INJECTABLE_REGEX, link, re.I):
                if kb.data.onlyGETs is None and conf.data is None and not conf.googleDork:
                    message = "do you want to scan only results containing GET parameters? [Y/n] "
                    kb.data.onlyGETs = readInput(message, default='Y', boolean=True)
                if not kb.data.onlyGETs or conf.googleDork:
                    kb.targets.add((link, conf.method, conf.data, conf.cookie, None))

        return links

    while True:
        links = retrieve()

        if kb.targets:
            infoMsg = "found %d results for your " % len(links)
            infoMsg += "search dork expression"

            if not conf.forms:
                infoMsg += ", "

                if len(links) == len(kb.targets):
                    infoMsg += "all "
                else:
                    infoMsg += "%d " % len(kb.targets)

                infoMsg += "of them are testable targets"

            logger.info(infoMsg)
            break

        else:
            message = "found %d results " % len(links)
            message += "for your search dork expression, but none of them "
            message += "have GET parameters to test for SQL injection. "
            message += "Do you want to skip to the next result page? [Y/n]"

            if not readInput(message, default='Y', boolean=True):
                raise SqlmapSilentQuitException
            else:
                conf.googlePage += 1

def _setStdinPipeTargets():
    if isinstance(conf.stdinPipe, _collections.Iterable):
        infoMsg = "using 'STDIN' for parsing targets list"
        logger.info(infoMsg)

        class _(object):
            def __init__(self):
                self.__rest = OrderedSet()

            def __iter__(self):
                return self

            def __next__(self):
                return self.next()

            def next(self):
                try:
                    line = next(conf.stdinPipe)
                except (IOError, OSError):
                    line = None

                if line:
                    match = re.search(r"\b(https?://[^\s'\"]+|[\w.]+\.\w{2,3}[/\w+]*\?[^\s'\"]+)", line, re.I)
                    if match:
                        return (match.group(0), conf.method, conf.data, conf.cookie, None)
                elif self.__rest:
                    return self.__rest.pop()

                raise StopIteration()

            def add(self, elem):
                self.__rest.add(elem)

        kb.targets = _()

def _setBulkMultipleTargets():
    if not conf.bulkFile:
        return

    conf.bulkFile = safeExpandUser(conf.bulkFile)

    infoMsg = "parsing multiple targets list from '%s'" % conf.bulkFile
    logger.info(infoMsg)

    if not checkFile(conf.bulkFile, False):
        errMsg = "the specified bulk file "
        errMsg += "does not exist"
        raise SqlmapFilePathException(errMsg)

    found = False
    for line in getFileItems(conf.bulkFile):
        if conf.scope and not re.search(conf.scope, line, re.I):
            continue

        if re.match(r"[^ ]+\?(.+)", line, re.I) or kb.customInjectionMark in line or conf.data:
            found = True
            kb.targets.add((line.strip(), conf.method, conf.data, conf.cookie, None))

    if not found and not conf.forms and not conf.crawlDepth:
        warnMsg = "no usable links found (with GET parameters)"
        logger.warn(warnMsg)

def _findPageForms():
    if not conf.forms or conf.crawlDepth:
        return

    if conf.url and not checkConnection():
        return

    found = False
    infoMsg = "searching for forms"
    logger.info(infoMsg)

    if not any((conf.bulkFile, conf.googleDork)):
        page, _, _ = Request.queryPage(content=True, ignoreSecondOrder=True)
        if findPageForms(page, conf.url, True, True):
            found = True
    else:
        if conf.bulkFile:
            targets = getFileItems(conf.bulkFile)
        elif conf.googleDork:
            targets = [_[0] for _ in kb.targets]
            kb.targets.clear()
        else:
            targets = []

        for i in xrange(len(targets)):
            try:
                target = targets[i].strip()

                if not re.search(r"(?i)\Ahttp[s]*://", target):
                    target = "http://%s" % target

                page, _, _ = Request.getPage(url=target.strip(), cookie=conf.cookie, crawling=True, raise404=False)
                if findPageForms(page, target, False, True):
                    found = True

                if conf.verbose in (1, 2):
                    status = '%d/%d links visited (%d%%)' % (i + 1, len(targets), round(100.0 * (i + 1) / len(targets)))
                    dataToStdout("\r[%s] [INFO] %s" % (time.strftime("%X"), status), True)
            except KeyboardInterrupt:
                break
            except Exception as ex:
                errMsg = "problem occurred while searching for forms at '%s' ('%s')" % (target, getSafeExString(ex))
                logger.error(errMsg)

    if not found:
        warnMsg = "no forms found"
        logger.warn(warnMsg)

def _setDBMSAuthentication():
    """
    Check and set the DBMS authentication credentials to run statements as
    another user, not the session user
    """

    if not conf.dbmsCred:
        return

    debugMsg = "setting the DBMS authentication credentials"
    logger.debug(debugMsg)

    match = re.search(r"^(.+?):(.*?)$", conf.dbmsCred)

    if not match:
        errMsg = "DBMS authentication credentials value must be in format "
        errMsg += "username:password"
        raise SqlmapSyntaxException(errMsg)

    conf.dbmsUsername = match.group(1)
    conf.dbmsPassword = match.group(2)

def _setMetasploit():
    if not conf.osPwn and not conf.osSmb and not conf.osBof:
        return

    debugMsg = "setting the takeover out-of-band functionality"
    logger.debug(debugMsg)

    msfEnvPathExists = False

    if IS_WIN:
        try:
            __import__("win32file")
        except ImportError:
            errMsg = "sqlmap requires third-party module 'pywin32' "
            errMsg += "in order to use Metasploit functionalities on "
            errMsg += "Windows. You can download it from "
            errMsg += "'https://github.com/mhammond/pywin32'"
            raise SqlmapMissingDependence(errMsg)

        if not conf.msfPath:
            for candidate in os.environ.get("PATH", "").split(';'):
                if all(_ in candidate for _ in ("metasploit", "bin")):
                    conf.msfPath = os.path.dirname(candidate.rstrip('\\'))
                    break

    if conf.osSmb:
        isAdmin = runningAsAdmin()

        if not isAdmin:
            errMsg = "you need to run sqlmap as an administrator "
            errMsg += "if you want to perform a SMB relay attack because "
            errMsg += "it will need to listen on a user-specified SMB "
            errMsg += "TCP port for incoming connection attempts"
            raise SqlmapMissingPrivileges(errMsg)

    if conf.msfPath:
        for path in (conf.msfPath, os.path.join(conf.msfPath, "bin")):
            if any(os.path.exists(normalizePath(os.path.join(path, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfcli", "msfconsole")):
                msfEnvPathExists = True
                if all(os.path.exists(normalizePath(os.path.join(path, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfvenom",)):
                    kb.oldMsf = False
                elif all(os.path.exists(normalizePath(os.path.join(path, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfencode", "msfpayload")):
                    kb.oldMsf = True
                else:
                    msfEnvPathExists = False

                conf.msfPath = path
                break

        if msfEnvPathExists:
            debugMsg = "provided Metasploit Framework path "
            debugMsg += "'%s' is valid" % conf.msfPath
            logger.debug(debugMsg)
        else:
            warnMsg = "the provided Metasploit Framework path "
            warnMsg += "'%s' is not valid. The cause could " % conf.msfPath
            warnMsg += "be that the path does not exists or that one "
            warnMsg += "or more of the needed Metasploit executables "
            warnMsg += "within msfcli, msfconsole, msfencode and "
            warnMsg += "msfpayload do not exist"
            logger.warn(warnMsg)
    else:
        warnMsg = "you did not provide the local path where Metasploit "
        warnMsg += "Framework is installed"
        logger.warn(warnMsg)

    if not msfEnvPathExists:
        warnMsg = "sqlmap is going to look for Metasploit Framework "
        warnMsg += "installation inside the environment path(s)"
        logger.warn(warnMsg)

        envPaths = os.environ.get("PATH", "").split(";" if IS_WIN else ":")

        for envPath in envPaths:
            envPath = envPath.replace(";", "")

            if any(os.path.exists(normalizePath(os.path.join(envPath, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfcli", "msfconsole")):
                msfEnvPathExists = True
                if all(os.path.exists(normalizePath(os.path.join(envPath, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfvenom",)):
                    kb.oldMsf = False
                elif all(os.path.exists(normalizePath(os.path.join(envPath, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfencode", "msfpayload")):
                    kb.oldMsf = True
                else:
                    msfEnvPathExists = False

                if msfEnvPathExists:
                    infoMsg = "Metasploit Framework has been found "
                    infoMsg += "installed in the '%s' path" % envPath
                    logger.info(infoMsg)

                    conf.msfPath = envPath

                    break

    if not msfEnvPathExists:
        errMsg = "unable to locate Metasploit Framework installation. "
        errMsg += "You can get it at 'https://www.metasploit.com/download/'"
        raise SqlmapFilePathException(errMsg)

def _setWriteFile():
    if not conf.fileWrite:
        return

    debugMsg = "setting the write file functionality"
    logger.debug(debugMsg)

    if not os.path.exists(conf.fileWrite):
        errMsg = "the provided local file '%s' does not exist" % conf.fileWrite
        raise SqlmapFilePathException(errMsg)

    if not conf.fileDest:
        errMsg = "you did not provide the back-end DBMS absolute path "
        errMsg += "where you want to write the local file '%s'" % conf.fileWrite
        raise SqlmapMissingMandatoryOptionException(errMsg)

    conf.fileWriteType = getFileType(conf.fileWrite)

def _setOS():
    """
    Force the back-end DBMS operating system option.
    """

    if not conf.os:
        return

    if conf.os.lower() not in SUPPORTED_OS:
        errMsg = "you provided an unsupported back-end DBMS operating "
        errMsg += "system. The supported DBMS operating systems for OS "
        errMsg += "and file system access are %s. " % ', '.join([o.capitalize() for o in SUPPORTED_OS])
        errMsg += "If you do not know the back-end DBMS underlying OS, "
        errMsg += "do not provide it and sqlmap will fingerprint it for "
        errMsg += "you."
        raise SqlmapUnsupportedDBMSException(errMsg)

    debugMsg = "forcing back-end DBMS operating system to user defined "
    debugMsg += "value '%s'" % conf.os
    logger.debug(debugMsg)

    Backend.setOs(conf.os)

def _setTechnique():
    validTechniques = sorted(getPublicTypeMembers(PAYLOAD.TECHNIQUE), key=lambda x: x[1])
    validLetters = [_[0][0].upper() for _ in validTechniques]

    if conf.technique and isinstance(conf.technique, six.string_types):
        _ = []

        for letter in conf.technique.upper():
            if letter not in validLetters:
                errMsg = "value for --technique must be a string composed "
                errMsg += "by the letters %s. Refer to the " % ", ".join(validLetters)
                errMsg += "user's manual for details"
                raise SqlmapSyntaxException(errMsg)

            for validTech, validInt in validTechniques:
                if letter == validTech[0]:
                    _.append(validInt)
                    break

        conf.technique = _

def _setDBMS():
    """
    Force the back-end DBMS option.
    """

    if not conf.dbms:
        return

    debugMsg = "forcing back-end DBMS to user defined value"
    logger.debug(debugMsg)

    conf.dbms = conf.dbms.lower()
    regex = re.search(r"%s ([\d\.]+)" % ("(%s)" % "|".join(SUPPORTED_DBMS)), conf.dbms, re.I)

    if regex:
        conf.dbms = regex.group(1)
        Backend.setVersion(regex.group(2))

    if conf.dbms not in SUPPORTED_DBMS:
        errMsg = "you provided an unsupported back-end database management "
        errMsg += "system. Supported DBMSes are as follows: %s. " % ', '.join(sorted((_ for _ in (list(DBMS_DICT) + getPublicTypeMembers(FORK, True))), key=str.lower))
        errMsg += "If you do not know the back-end DBMS, do not provide "
        errMsg += "it and sqlmap will fingerprint it for you."
        raise SqlmapUnsupportedDBMSException(errMsg)

    for dbms, aliases in DBMS_ALIASES:
        if conf.dbms in aliases:
            conf.dbms = dbms

            break

def _listTamperingFunctions():
    """
    Lists available tamper functions
    """

    if conf.listTampers:
        infoMsg = "listing available tamper scripts\n"
        logger.info(infoMsg)

        for script in sorted(glob.glob(os.path.join(paths.SQLMAP_TAMPER_PATH, "*.py"))):
            content = openFile(script, "rb").read()
            match = re.search(r'(?s)__priority__.+"""(.+)"""', content)
            if match:
                comment = match.group(1).strip()
                dataToStdout("* %s - %s\n" % (setColor(os.path.basename(script), "yellow"), re.sub(r" *\n *", " ", comment.split("\n\n")[0].strip())))

def _setTamperingFunctions():
    """
    Loads tampering functions from given script(s)
    """

    if conf.tamper:
        last_priority = PRIORITY.HIGHEST
        check_priority = True
        resolve_priorities = False
        priorities = []

        for script in re.split(PARAMETER_SPLITTING_REGEX, conf.tamper):
            found = False

            path = safeFilepathEncode(paths.SQLMAP_TAMPER_PATH)
            script = safeFilepathEncode(script.strip())

            try:
                if not script:
                    continue

                elif os.path.exists(os.path.join(path, script if script.endswith(".py") else "%s.py" % script)):
                    script = os.path.join(path, script if script.endswith(".py") else "%s.py" % script)

                elif not os.path.exists(script):
                    errMsg = "tamper script '%s' does not exist" % script
                    raise SqlmapFilePathException(errMsg)

                elif not script.endswith(".py"):
                    errMsg = "tamper script '%s' should have an extension '.py'" % script
                    raise SqlmapSyntaxException(errMsg)
            except UnicodeDecodeError:
                errMsg = "invalid character provided in option '--tamper'"
                raise SqlmapSyntaxException(errMsg)

            dirname, filename = os.path.split(script)
            dirname = os.path.abspath(dirname)

            infoMsg = "loading tamper module '%s'" % filename[:-3]
            logger.info(infoMsg)

            if not os.path.exists(os.path.join(dirname, "__init__.py")):
                errMsg = "make sure that there is an empty file '__init__.py' "
                errMsg += "inside of tamper scripts directory '%s'" % dirname
                raise SqlmapGenericException(errMsg)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                module = __import__(safeFilepathEncode(filename[:-3]))
            except Exception as ex:
                raise SqlmapSyntaxException("cannot import tamper module '%s' (%s)" % (getUnicode(filename[:-3]), getSafeExString(ex)))

            priority = PRIORITY.NORMAL if not hasattr(module, "__priority__") else module.__priority__

            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "tamper" and inspect.getargspec(function).args and inspect.getargspec(function).keywords == "kwargs":
                    found = True
                    kb.tamperFunctions.append(function)
                    function.__name__ = module.__name__

                    if check_priority and priority > last_priority:
                        message = "it appears that you might have mixed "
                        message += "the order of tamper scripts. "
                        message += "Do you want to auto resolve this? [Y/n/q] "
                        choice = readInput(message, default='Y').upper()

                        if choice == 'N':
                            resolve_priorities = False
                        elif choice == 'Q':
                            raise SqlmapUserQuitException
                        else:
                            resolve_priorities = True

                        check_priority = False

                    priorities.append((priority, function))
                    last_priority = priority

                    break
                elif name == "dependencies":
                    try:
                        function()
                    except Exception as ex:
                        errMsg = "error occurred while checking dependencies "
                        errMsg += "for tamper module '%s' ('%s')" % (getUnicode(filename[:-3]), getSafeExString(ex))
                        raise SqlmapGenericException(errMsg)

            if not found:
                errMsg = "missing function 'tamper(payload, **kwargs)' "
                errMsg += "in tamper script '%s'" % script
                raise SqlmapGenericException(errMsg)

        if kb.tamperFunctions and len(kb.tamperFunctions) > 3:
            warnMsg = "using too many tamper scripts is usually not "
            warnMsg += "a good idea"
            logger.warning(warnMsg)

        if resolve_priorities and priorities:
            priorities.sort(key=functools.cmp_to_key(lambda a, b: cmp(a[0], b[0])), reverse=True)
            kb.tamperFunctions = []

            for _, function in priorities:
                kb.tamperFunctions.append(function)

def _setPreprocessFunctions():
    """
    Loads preprocess function(s) from given script(s)
    """

    if conf.preprocess:
        for script in re.split(PARAMETER_SPLITTING_REGEX, conf.preprocess):
            found = False
            function = None

            script = safeFilepathEncode(script.strip())

            try:
                if not script:
                    continue

                if not os.path.exists(script):
                    errMsg = "preprocess script '%s' does not exist" % script
                    raise SqlmapFilePathException(errMsg)

                elif not script.endswith(".py"):
                    errMsg = "preprocess script '%s' should have an extension '.py'" % script
                    raise SqlmapSyntaxException(errMsg)
            except UnicodeDecodeError:
                errMsg = "invalid character provided in option '--preprocess'"
                raise SqlmapSyntaxException(errMsg)

            dirname, filename = os.path.split(script)
            dirname = os.path.abspath(dirname)

            infoMsg = "loading preprocess module '%s'" % filename[:-3]
            logger.info(infoMsg)

            if not os.path.exists(os.path.join(dirname, "__init__.py")):
                errMsg = "make sure that there is an empty file '__init__.py' "
                errMsg += "inside of preprocess scripts directory '%s'" % dirname
                raise SqlmapGenericException(errMsg)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                module = __import__(safeFilepathEncode(filename[:-3]))
            except Exception as ex:
                raise SqlmapSyntaxException("cannot import preprocess module '%s' (%s)" % (getUnicode(filename[:-3]), getSafeExString(ex)))

            for name, function in inspect.getmembers(module, inspect.isfunction):
                try:
                    if name == "preprocess" and inspect.getargspec(function).args and all(_ in inspect.getargspec(function).args for _ in ("req",)):
                        found = True

                        kb.preprocessFunctions.append(function)
                        function.__name__ = module.__name__

                        break
                except ValueError:  # Note: https://github.com/sqlmapproject/sqlmap/issues/4357
                    pass

            if not found:
                errMsg = "missing function 'preprocess(req)' "
                errMsg += "in preprocess script '%s'" % script
                raise SqlmapGenericException(errMsg)
            else:
                try:
                    function(_urllib.request.Request("http://localhost"))
                except:
                    tbMsg = traceback.format_exc()

                    if conf.debug:
                        dataToStdout(tbMsg)

                    handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.PREPROCESS, suffix=".py")
                    os.close(handle)

                    openFile(filename, "w+b").write("#!/usr/bin/env\n\ndef preprocess(req):\n    pass\n")
                    openFile(os.path.join(os.path.dirname(filename), "__init__.py"), "w+b").write("pass")

                    errMsg = "function 'preprocess(req)' "
                    errMsg += "in preprocess script '%s' " % script
                    errMsg += "appears to be invalid "
                    errMsg += "(Note: find template script at '%s')" % filename
                    raise SqlmapGenericException(errMsg)

def _setPostprocessFunctions():
    """
    Loads postprocess function(s) from given script(s)
    """

    if conf.postprocess:
        for script in re.split(PARAMETER_SPLITTING_REGEX, conf.postprocess):
            found = False
            function = None

            script = safeFilepathEncode(script.strip())

            try:
                if not script:
                    continue

                if not os.path.exists(script):
                    errMsg = "postprocess script '%s' does not exist" % script
                    raise SqlmapFilePathException(errMsg)

                elif not script.endswith(".py"):
                    errMsg = "postprocess script '%s' should have an extension '.py'" % script
                    raise SqlmapSyntaxException(errMsg)
            except UnicodeDecodeError:
                errMsg = "invalid character provided in option '--postprocess'"
                raise SqlmapSyntaxException(errMsg)

            dirname, filename = os.path.split(script)
            dirname = os.path.abspath(dirname)

            infoMsg = "loading postprocess module '%s'" % filename[:-3]
            logger.info(infoMsg)

            if not os.path.exists(os.path.join(dirname, "__init__.py")):
                errMsg = "make sure that there is an empty file '__init__.py' "
                errMsg += "inside of postprocess scripts directory '%s'" % dirname
                raise SqlmapGenericException(errMsg)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                module = __import__(safeFilepathEncode(filename[:-3]))
            except Exception as ex:
                raise SqlmapSyntaxException("cannot import postprocess module '%s' (%s)" % (getUnicode(filename[:-3]), getSafeExString(ex)))

            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "postprocess" and inspect.getargspec(function).args and all(_ in inspect.getargspec(function).args for _ in ("page", "headers", "code")):
                    found = True

                    kb.postprocessFunctions.append(function)
                    function.__name__ = module.__name__

                    break

            if not found:
                errMsg = "missing function 'postprocess(page, headers=None, code=None)' "
                errMsg += "in postprocess script '%s'" % script
                raise SqlmapGenericException(errMsg)
            else:
                try:
                    _, _, _ = function("", {}, None)
                except:
                    handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.PREPROCESS, suffix=".py")
                    os.close(handle)

                    openFile(filename, "w+b").write("#!/usr/bin/env\n\ndef postprocess(page, headers=None, code=None):\n    return page, headers, code\n")
                    openFile(os.path.join(os.path.dirname(filename), "__init__.py"), "w+b").write("pass")

                    errMsg = "function 'postprocess(page, headers=None, code=None)' "
                    errMsg += "in postprocess script '%s' " % script
                    errMsg += "should return a tuple '(page, headers, code)' "
                    errMsg += "(Note: find template script at '%s')" % filename
                    raise SqlmapGenericException(errMsg)

def _setThreads():
    if not isinstance(conf.threads, int) or conf.threads <= 0:
        conf.threads = 1

def _setDNSCache():
    """
    Makes a cached version of socket._getaddrinfo to avoid subsequent DNS requests.
    """

    def _getaddrinfo(*args, **kwargs):
        if args in kb.cache.addrinfo:
            return kb.cache.addrinfo[args]

        else:
            kb.cache.addrinfo[args] = socket._getaddrinfo(*args, **kwargs)
            return kb.cache.addrinfo[args]

    if not hasattr(socket, "_getaddrinfo"):
        socket._getaddrinfo = socket.getaddrinfo
        socket.getaddrinfo = _getaddrinfo

def _setSocketPreConnect():
    """
    Makes a pre-connect version of socket.create_connection
    """

    if conf.disablePrecon:
        return

    def _thread():
        while kb.get("threadContinue") and not conf.get("disablePrecon"):
            try:
                for key in socket._ready:
                    if len(socket._ready[key]) < SOCKET_PRE_CONNECT_QUEUE_SIZE:
                        s = socket.create_connection(*key[0], **dict(key[1]))
                        with kb.locks.socket:
                            socket._ready[key].append((s, time.time()))
            except KeyboardInterrupt:
                break
            except:
                pass
            finally:
                time.sleep(0.01)

    def create_connection(*args, **kwargs):
        retVal = None

        key = (tuple(args), frozenset(kwargs.items()))
        with kb.locks.socket:
            if key not in socket._ready:
                socket._ready[key] = []

            while len(socket._ready[key]) > 0:
                candidate, created = socket._ready[key].pop(0)
                if (time.time() - created) < PRECONNECT_CANDIDATE_TIMEOUT:
                    retVal = candidate
                    break
                else:
                    try:
                        candidate.shutdown(socket.SHUT_RDWR)
                        candidate.close()
                    except socket.error:
                        pass

        if not retVal:
            retVal = socket._create_connection(*args, **kwargs)

        return retVal

    if not hasattr(socket, "_create_connection"):
        socket._ready = {}
        socket._create_connection = socket.create_connection
        socket.create_connection = create_connection

        thread = threading.Thread(target=_thread)
        setDaemon(thread)
        thread.start()

def _setHTTPHandlers():
    """
    Check and set the HTTP/SOCKS proxy for all HTTP requests.
    """

    with kb.locks.handlers:
        if conf.proxyList:
            conf.proxy = conf.proxyList[0]
            conf.proxyList = conf.proxyList[1:] + conf.proxyList[:1]

            if len(conf.proxyList) > 1:
                infoMsg = "loading proxy '%s' from a supplied proxy list file" % conf.proxy
                logger.info(infoMsg)

        elif not conf.proxy:
            if conf.hostname in ("localhost", "127.0.0.1") or conf.ignoreProxy:
                proxyHandler.proxies = {}

        if conf.proxy:
            debugMsg = "setting the HTTP/SOCKS proxy for all HTTP requests"
            logger.debug(debugMsg)

            try:
                _ = _urllib.parse.urlsplit(conf.proxy)
            except Exception as ex:
                errMsg = "invalid proxy address '%s' ('%s')" % (conf.proxy, getSafeExString(ex))
                raise SqlmapSyntaxException(errMsg)

            hostnamePort = _.netloc.rsplit(":", 1)

            scheme = _.scheme.upper()
            hostname = hostnamePort[0]
            port = None
            username = None
            password = None

            if len(hostnamePort) == 2:
                try:
                    port = int(hostnamePort[1])
                except:
                    pass  # drops into the next check block

            if not all((scheme, hasattr(PROXY_TYPE, scheme), hostname, port)):
                errMsg = "proxy value must be in format '(%s)://address:port'" % "|".join(_[0].lower() for _ in getPublicTypeMembers(PROXY_TYPE))
                raise SqlmapSyntaxException(errMsg)

            if conf.proxyCred:
                _ = re.search(r"\A(.*?):(.*?)\Z", conf.proxyCred)
                if not _:
                    errMsg = "proxy authentication credentials "
                    errMsg += "value must be in format username:password"
                    raise SqlmapSyntaxException(errMsg)
                else:
                    username = _.group(1)
                    password = _.group(2)

            if scheme in (PROXY_TYPE.SOCKS4, PROXY_TYPE.SOCKS5):
                proxyHandler.proxies = {}

                if scheme == PROXY_TYPE.SOCKS4:
                    warnMsg = "SOCKS4 does not support resolving (DNS) names (i.e. causing DNS leakage)"
                    singleTimeWarnMessage(warnMsg)

                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5 if scheme == PROXY_TYPE.SOCKS5 else socks.PROXY_TYPE_SOCKS4, hostname, port, username=username, password=password)
                socks.wrapmodule(_http_client)
            else:
                socks.unwrapmodule(_http_client)

                if conf.proxyCred:
                    # Reference: http://stackoverflow.com/questions/34079/how-to-specify-an-authenticated-proxy-for-a-python-http-connection
                    proxyString = "%s@" % conf.proxyCred
                else:
                    proxyString = ""

                proxyString += "%s:%d" % (hostname, port)
                proxyHandler.proxies = {"http": proxyString, "https": proxyString}

            proxyHandler.__init__(proxyHandler.proxies)

        if not proxyHandler.proxies:
            for _ in ("http", "https"):
                if hasattr(proxyHandler, "%s_open" % _):
                    delattr(proxyHandler, "%s_open" % _)

        debugMsg = "creating HTTP requests opener object"
        logger.debug(debugMsg)

        handlers = filterNone([multipartPostHandler, proxyHandler if proxyHandler.proxies else None, authHandler, redirectHandler, rangeHandler, chunkedHandler if conf.chunked else None, httpsHandler])

        if not conf.dropSetCookie:
            if not conf.loadCookies:
                conf.cj = _http_cookiejar.CookieJar()
            else:
                conf.cj = _http_cookiejar.MozillaCookieJar()
                resetCookieJar(conf.cj)

            handlers.append(_urllib.request.HTTPCookieProcessor(conf.cj))

        # Reference: http://www.w3.org/Protocols/rfc2616/rfc2616-sec8.html
        if conf.keepAlive:
            warnMsg = "persistent HTTP(s) connections, Keep-Alive, has "
            warnMsg += "been disabled because of its incompatibility "

            if conf.proxy:
                warnMsg += "with HTTP(s) proxy"
                logger.warn(warnMsg)
            elif conf.authType:
                warnMsg += "with authentication methods"
                logger.warn(warnMsg)
            else:
                handlers.append(keepAliveHandler)

        opener = _urllib.request.build_opener(*handlers)
        opener.addheaders = []  # Note: clearing default "User-Agent: Python-urllib/X.Y"
        _urllib.request.install_opener(opener)

def _setSafeVisit():
    """
    Check and set the safe visit options.
    """
    if not any((conf.safeUrl, conf.safeReqFile)):
        return

    if conf.safeReqFile:
        checkFile(conf.safeReqFile)

        raw = readCachedFileContent(conf.safeReqFile)
        match = re.search(r"\A([A-Z]+) ([^ ]+) HTTP/[0-9.]+\Z", raw.split('\n')[0].strip())

        if match:
            kb.safeReq.method = match.group(1)
            kb.safeReq.url = match.group(2)
            kb.safeReq.headers = {}

            for line in raw.split('\n')[1:]:
                line = line.strip()
                if line and ':' in line:
                    key, value = line.split(':', 1)
                    value = value.strip()
                    kb.safeReq.headers[key] = value
                    if key.upper() == HTTP_HEADER.HOST.upper():
                        if not value.startswith("http"):
                            scheme = "http"
                            if value.endswith(":443"):
                                scheme = "https"
                            value = "%s://%s" % (scheme, value)
                        kb.safeReq.url = _urllib.parse.urljoin(value, kb.safeReq.url)
                else:
                    break

            post = None

            if '\r\n\r\n' in raw:
                post = raw[raw.find('\r\n\r\n') + 4:]
            elif '\n\n' in raw:
                post = raw[raw.find('\n\n') + 2:]

            if post and post.strip():
                kb.safeReq.post = post
            else:
                kb.safeReq.post = None
        else:
            errMsg = "invalid format of a safe request file"
            raise SqlmapSyntaxException(errMsg)
    else:
        if not re.search(r"(?i)\Ahttp[s]*://", conf.safeUrl):
            if ":443/" in conf.safeUrl:
                conf.safeUrl = "https://%s" % conf.safeUrl
            else:
                conf.safeUrl = "http://%s" % conf.safeUrl

    if (conf.safeFreq or 0) <= 0:
        errMsg = "please provide a valid value (>0) for safe frequency ('--safe-freq') while using safe visit features"
        raise SqlmapSyntaxException(errMsg)

def _setPrefixSuffix():
    if conf.prefix is not None and conf.suffix is not None:
        # Create a custom boundary object for user's supplied prefix
        # and suffix
        boundary = AttribDict()

        boundary.level = 1
        boundary.clause = [0]
        boundary.where = [1, 2, 3]
        boundary.prefix = conf.prefix
        boundary.suffix = conf.suffix

        if " like" in boundary.suffix.lower():
            if "'" in boundary.suffix.lower():
                boundary.ptype = 3
            elif '"' in boundary.suffix.lower():
                boundary.ptype = 5
        elif "'" in boundary.suffix:
            boundary.ptype = 2
        elif '"' in boundary.suffix:
            boundary.ptype = 4
        else:
            boundary.ptype = 1

        # user who provides --prefix/--suffix does not want other boundaries
        # to be tested for
        conf.boundaries = [boundary]

def _setAuthCred():
    """
    Adds authentication credentials (if any) for current target to the password manager
    (used by connection handler)
    """

    if kb.passwordMgr and all(_ is not None for _ in (conf.scheme, conf.hostname, conf.port, conf.authUsername, conf.authPassword)):
        kb.passwordMgr.add_password(None, "%s://%s:%d" % (conf.scheme, conf.hostname, conf.port), conf.authUsername, conf.authPassword)

def _setHTTPAuthentication():
    """
    Check and set the HTTP(s) authentication method (Basic, Digest, Bearer, NTLM or PKI),
    username and password for first three methods, or PEM private key file for
    PKI authentication
    """

    global authHandler

    if not conf.authType and not conf.authCred and not conf.authFile:
        return

    if conf.authFile and not conf.authType:
        conf.authType = AUTH_TYPE.PKI

    elif conf.authType and not conf.authCred and not conf.authFile:
        errMsg = "you specified the HTTP authentication type, but "
        errMsg += "did not provide the credentials"
        raise SqlmapSyntaxException(errMsg)

    elif not conf.authType and conf.authCred:
        errMsg = "you specified the HTTP authentication credentials, "
        errMsg += "but did not provide the type (e.g. --auth-type=\"basic\")"
        raise SqlmapSyntaxException(errMsg)

    elif (conf.authType or "").lower() not in (AUTH_TYPE.BASIC, AUTH_TYPE.DIGEST, AUTH_TYPE.BEARER, AUTH_TYPE.NTLM, AUTH_TYPE.PKI):
        errMsg = "HTTP authentication type value must be "
        errMsg += "Basic, Digest, Bearer, NTLM or PKI"
        raise SqlmapSyntaxException(errMsg)

    if not conf.authFile:
        debugMsg = "setting the HTTP authentication type and credentials"
        logger.debug(debugMsg)

        authType = conf.authType.lower()

        if authType in (AUTH_TYPE.BASIC, AUTH_TYPE.DIGEST):
            regExp = "^(.*?):(.*?)$"
            errMsg = "HTTP %s authentication credentials " % authType
            errMsg += "value must be in format 'username:password'"
        elif authType == AUTH_TYPE.BEARER:
            conf.httpHeaders.append((HTTP_HEADER.AUTHORIZATION, "Bearer %s" % conf.authCred.strip()))
            return
        elif authType == AUTH_TYPE.NTLM:
            regExp = "^(.*\\\\.*):(.*?)$"
            errMsg = "HTTP NTLM authentication credentials value must "
            errMsg += "be in format 'DOMAIN\\username:password'"
        elif authType == AUTH_TYPE.PKI:
            errMsg = "HTTP PKI authentication require "
            errMsg += "usage of option `--auth-pki`"
            raise SqlmapSyntaxException(errMsg)

        aCredRegExp = re.search(regExp, conf.authCred)

        if not aCredRegExp:
            raise SqlmapSyntaxException(errMsg)

        conf.authUsername = aCredRegExp.group(1)
        conf.authPassword = aCredRegExp.group(2)

        kb.passwordMgr = _urllib.request.HTTPPasswordMgrWithDefaultRealm()

        _setAuthCred()

        if authType == AUTH_TYPE.BASIC:
            authHandler = SmartHTTPBasicAuthHandler(kb.passwordMgr)

        elif authType == AUTH_TYPE.DIGEST:
            authHandler = _urllib.request.HTTPDigestAuthHandler(kb.passwordMgr)

        elif authType == AUTH_TYPE.NTLM:
            try:
                from ntlm import HTTPNtlmAuthHandler
            except ImportError:
                errMsg = "sqlmap requires Python NTLM third-party library "
                errMsg += "in order to authenticate via NTLM. Download from "
                errMsg += "'https://github.com/mullender/python-ntlm'"
                raise SqlmapMissingDependence(errMsg)

            authHandler = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(kb.passwordMgr)
    else:
        debugMsg = "setting the HTTP(s) authentication PEM private key"
        logger.debug(debugMsg)

        _ = safeExpandUser(conf.authFile)
        checkFile(_)
        authHandler = HTTPSPKIAuthHandler(_)

def _setHTTPExtraHeaders():
    if conf.headers:
        debugMsg = "setting extra HTTP headers"
        logger.debug(debugMsg)

        conf.headers = conf.headers.split("\n") if "\n" in conf.headers else conf.headers.split("\\n")

        for headerValue in conf.headers:
            if not headerValue.strip():
                continue

            if headerValue.count(':') >= 1:
                header, value = (_.lstrip() for _ in headerValue.split(":", 1))

                if header and value:
                    conf.httpHeaders.append((header, value))
            elif headerValue.startswith('@'):
                checkFile(headerValue[1:])
                kb.headersFile = headerValue[1:]
            else:
                errMsg = "invalid header value: %s. Valid header format is 'name:value'" % repr(headerValue).lstrip('u')
                raise SqlmapSyntaxException(errMsg)

    elif not conf.requestFile and len(conf.httpHeaders or []) < 2:
        if conf.encoding:
            conf.httpHeaders.append((HTTP_HEADER.ACCEPT_CHARSET, "%s;q=0.7,*;q=0.1" % conf.encoding))

        # Invalidating any caching mechanism in between
        # Reference: http://stackoverflow.com/a/1383359
        conf.httpHeaders.append((HTTP_HEADER.CACHE_CONTROL, "no-cache"))

def _setHTTPUserAgent():
    """
    Set the HTTP User-Agent header.
    Depending on the user options it can be:

        * The default sqlmap string
        * A default value read as user option
        * A random value read from a list of User-Agent headers from a
          file choosed as user option
    """

    debugMsg = "setting the HTTP User-Agent header"
    logger.debug(debugMsg)

    if conf.mobile:
        if conf.randomAgent:
            _ = random.sample([_[1] for _ in getPublicTypeMembers(MOBILES, True)], 1)[0]
            conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, _))
        else:
            message = "which smartphone do you want sqlmap to imitate "
            message += "through HTTP User-Agent header?\n"
            items = sorted(getPublicTypeMembers(MOBILES, True))

            for count in xrange(len(items)):
                item = items[count]
                message += "[%d] %s%s\n" % (count + 1, item[0], " (default)" if item == MOBILES.IPHONE else "")

            test = readInput(message.rstrip('\n'), default=items.index(MOBILES.IPHONE) + 1)

            try:
                item = items[int(test) - 1]
            except:
                item = MOBILES.IPHONE

            conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, item[1]))

    elif conf.agent:
        conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, conf.agent))

    elif not conf.randomAgent:
        _ = True

        for header, _ in conf.httpHeaders:
            if header.upper() == HTTP_HEADER.USER_AGENT.upper():
                _ = False
                break

        if _:
            conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, DEFAULT_USER_AGENT))

    else:
        userAgent = fetchRandomAgent()

        infoMsg = "fetched random HTTP User-Agent header value '%s' from " % userAgent
        infoMsg += "file '%s'" % paths.USER_AGENTS
        logger.info(infoMsg)

        conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, userAgent))

def _setHTTPReferer():
    """
    Set the HTTP Referer
    """

    if conf.referer:
        debugMsg = "setting the HTTP Referer header"
        logger.debug(debugMsg)

        conf.httpHeaders.append((HTTP_HEADER.REFERER, conf.referer))

def _setHTTPHost():
    """
    Set the HTTP Host
    """

    if conf.host:
        debugMsg = "setting the HTTP Host header"
        logger.debug(debugMsg)

        conf.httpHeaders.append((HTTP_HEADER.HOST, conf.host))

def _setHTTPCookies():
    """
    Set the HTTP Cookie header
    """

    if conf.cookie:
        debugMsg = "setting the HTTP Cookie header"
        logger.debug(debugMsg)

        conf.httpHeaders.append((HTTP_HEADER.COOKIE, conf.cookie))

def _setHostname():
    """
    Set value conf.hostname
    """

    if conf.url:
        try:
            conf.hostname = _urllib.parse.urlsplit(conf.url).netloc.split(':')[0]
        except ValueError as ex:
            errMsg = "problem occurred while "
            errMsg += "parsing an URL '%s' ('%s')" % (conf.url, getSafeExString(ex))
            raise SqlmapDataException(errMsg)

def _setHTTPTimeout():
    """
    Set the HTTP timeout
    """

    if conf.timeout:
        debugMsg = "setting the HTTP timeout"
        logger.debug(debugMsg)

        conf.timeout = float(conf.timeout)

        if conf.timeout < 3.0:
            warnMsg = "the minimum HTTP timeout is 3 seconds, sqlmap "
            warnMsg += "will going to reset it"
            logger.warn(warnMsg)

            conf.timeout = 3.0
    else:
        conf.timeout = 30.0

    try:
        socket.setdefaulttimeout(conf.timeout)
    except OverflowError as ex:
        raise SqlmapValueException("invalid value used for option '--timeout' ('%s')" % getSafeExString(ex))

def _checkDependencies():
    """
    Checks for missing dependencies.
    """

    if conf.dependencies:
        checkDependencies()

def _createHomeDirectories():
    """
    Creates directories inside sqlmap's home directory
    """

    if conf.get("purge"):
        return

    for context in ("output", "history"):
        directory = paths["SQLMAP_%s_PATH" % getUnicode(context).upper()]   # NOTE: https://github.com/sqlmapproject/sqlmap/issues/4363
        try:
            if not os.path.isdir(directory):
                os.makedirs(directory)

            _ = os.path.join(directory, randomStr())
            open(_, "w+b").close()
            os.remove(_)

            if conf.get("outputDir") and context == "output":
                warnMsg = "using '%s' as the %s directory" % (directory, context)
                logger.warn(warnMsg)
        except (OSError, IOError) as ex:
            tempDir = tempfile.mkdtemp(prefix="sqlmap%s" % context)
            warnMsg = "unable to %s %s directory " % ("create" if not os.path.isdir(directory) else "write to the", context)
            warnMsg += "'%s' (%s). " % (directory, getUnicode(ex))
            warnMsg += "Using temporary directory '%s' instead" % getUnicode(tempDir)
            logger.warn(warnMsg)

            paths["SQLMAP_%s_PATH" % context.upper()] = tempDir

def _pympTempLeakPatch(tempDir):  # Cross-referenced function
    raise NotImplementedError

def _createTemporaryDirectory():
    """
    Creates temporary directory for this run.
    """

    if conf.tmpDir:
        try:
            if not os.path.isdir(conf.tmpDir):
                os.makedirs(conf.tmpDir)

            _ = os.path.join(conf.tmpDir, randomStr())

            open(_, "w+b").close()
            os.remove(_)

            tempfile.tempdir = conf.tmpDir

            warnMsg = "using '%s' as the temporary directory" % conf.tmpDir
            logger.warn(warnMsg)
        except (OSError, IOError) as ex:
            errMsg = "there has been a problem while accessing "
            errMsg += "temporary directory location(s) ('%s')" % getSafeExString(ex)
            raise SqlmapSystemException(errMsg)
    else:
        try:
            if not os.path.isdir(tempfile.gettempdir()):
                os.makedirs(tempfile.gettempdir())
        except Exception as ex:
            warnMsg = "there has been a problem while accessing "
            warnMsg += "system's temporary directory location(s) ('%s'). Please " % getSafeExString(ex)
            warnMsg += "make sure that there is enough disk space left. If problem persists, "
            warnMsg += "try to set environment variable 'TEMP' to a location "
            warnMsg += "writeable by the current user"
            logger.warn(warnMsg)

    if "sqlmap" not in (tempfile.tempdir or "") or conf.tmpDir and tempfile.tempdir == conf.tmpDir:
        try:
            tempfile.tempdir = tempfile.mkdtemp(prefix="sqlmap", suffix=str(os.getpid()))
        except:
            tempfile.tempdir = os.path.join(paths.SQLMAP_HOME_PATH, "tmp", "sqlmap%s%d" % (randomStr(6), os.getpid()))

    kb.tempDir = tempfile.tempdir

    if not os.path.isdir(tempfile.tempdir):
        try:
            os.makedirs(tempfile.tempdir)
        except Exception as ex:
            errMsg = "there has been a problem while setting "
            errMsg += "temporary directory location ('%s')" % getSafeExString(ex)
            raise SqlmapSystemException(errMsg)

    if six.PY3:
        _pympTempLeakPatch(kb.tempDir)

def _cleanupOptions():
    """
    Cleanup configuration attributes.
    """

    if conf.encoding:
        try:
            codecs.lookup(conf.encoding)
        except LookupError:
            errMsg = "unknown encoding '%s'" % conf.encoding
            raise SqlmapValueException(errMsg)

    debugMsg = "cleaning up configuration parameters"
    logger.debug(debugMsg)

    width = getConsoleWidth()

    if conf.eta:
        conf.progressWidth = width - 26
    else:
        conf.progressWidth = width - 46

    for key, value in conf.items():
        if value and any(key.endswith(_) for _ in ("Path", "File", "Dir")):
            if isinstance(value, str):
                conf[key] = safeExpandUser(value)

    if conf.testParameter:
        conf.testParameter = urldecode(conf.testParameter)
        conf.testParameter = [_.strip() for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.testParameter)]
    else:
        conf.testParameter = []

    if conf.ignoreCode:
        if conf.ignoreCode == IGNORE_CODE_WILDCARD:
            conf.ignoreCode = xrange(0, 1000)
        else:
            try:
                conf.ignoreCode = [int(_) for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.ignoreCode)]
            except ValueError:
                errMsg = "options '--ignore-code' should contain a list of integer values or a wildcard value '%s'" % IGNORE_CODE_WILDCARD
                raise SqlmapSyntaxException(errMsg)
    else:
        conf.ignoreCode = []

    if conf.paramFilter:
        conf.paramFilter = [_.strip() for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.paramFilter.upper())]
    else:
        conf.paramFilter = []

    if conf.base64Parameter:
        conf.base64Parameter = urldecode(conf.base64Parameter)
        conf.base64Parameter = conf.base64Parameter.strip()
        conf.base64Parameter = re.split(PARAMETER_SPLITTING_REGEX, conf.base64Parameter)
    else:
        conf.base64Parameter = []

    if conf.agent:
        conf.agent = re.sub(r"[\r\n]", "", conf.agent)

    if conf.user:
        conf.user = conf.user.replace(" ", "")

    if conf.rParam:
        if all(_ in conf.rParam for _ in ('=', ',')):
            original = conf.rParam
            conf.rParam = []
            for part in original.split(';'):
                if '=' in part:
                    left, right = part.split('=', 1)
                    conf.rParam.append(left)
                    kb.randomPool[left] = filterNone(_.strip() for _ in right.split(','))
                else:
                    conf.rParam.append(part)
        else:
            conf.rParam = conf.rParam.replace(" ", "")
            conf.rParam = re.split(PARAMETER_SPLITTING_REGEX, conf.rParam)
    else:
        conf.rParam = []

    if conf.paramDel:
        conf.paramDel = decodeStringEscape(conf.paramDel)

    if conf.skip:
        conf.skip = conf.skip.replace(" ", "")
        conf.skip = re.split(PARAMETER_SPLITTING_REGEX, conf.skip)
    else:
        conf.skip = []

    if conf.cookie:
        conf.cookie = re.sub(r"[\r\n]", "", conf.cookie)

    if conf.delay:
        conf.delay = float(conf.delay)

    if conf.url:
        conf.url = conf.url.strip().lstrip('/')
        if not re.search(r"\A\w+://", conf.url):
            conf.url = "http://%s" % conf.url

    if conf.fileRead:
        conf.fileRead = ntToPosixSlashes(normalizePath(conf.fileRead))

    if conf.fileWrite:
        conf.fileWrite = ntToPosixSlashes(normalizePath(conf.fileWrite))

    if conf.fileDest:
        conf.fileDest = ntToPosixSlashes(normalizePath(conf.fileDest))

    if conf.msfPath:
        conf.msfPath = ntToPosixSlashes(normalizePath(conf.msfPath))

    if conf.tmpPath:
        conf.tmpPath = ntToPosixSlashes(normalizePath(conf.tmpPath))

    if any((conf.googleDork, conf.logFile, conf.bulkFile, conf.forms, conf.crawlDepth, conf.stdinPipe)):
        conf.multipleTargets = True

    if conf.optimize:
        setOptimize()

    if conf.os:
        conf.os = conf.os.capitalize()

    if conf.forceDbms:
        conf.dbms = conf.forceDbms

    if conf.dbms:
        kb.dbmsFilter = []
        for _ in conf.dbms.split(','):
            for dbms, aliases in DBMS_ALIASES:
                if _.strip().lower() in aliases:
                    kb.dbmsFilter.append(dbms)
                    conf.dbms = dbms if conf.dbms and ',' not in conf.dbms else None
                    break

    if conf.testFilter:
        conf.testFilter = conf.testFilter.strip('*+')
        conf.testFilter = re.sub(r"([^.])([*+])", r"\g<1>.\g<2>", conf.testFilter)

        try:
            re.compile(conf.testFilter)
        except re.error:
            conf.testFilter = re.escape(conf.testFilter)

    if conf.csrfToken:
        original = conf.csrfToken
        try:
            re.compile(conf.csrfToken)

            if re.escape(conf.csrfToken) != conf.csrfToken:
                message = "provided value for option '--csrf-token' is a regular expression? [y/N] "
                if not readInput(message, default='N', boolean=True):
                    conf.csrfToken = re.escape(conf.csrfToken)
        except re.error:
            conf.csrfToken = re.escape(conf.csrfToken)
        finally:
            class _(six.text_type):
                pass
            conf.csrfToken = _(conf.csrfToken)
            conf.csrfToken._original = original

    if conf.testSkip:
        conf.testSkip = conf.testSkip.strip('*+')
        conf.testSkip = re.sub(r"([^.])([*+])", r"\g<1>.\g<2>", conf.testSkip)

        try:
            re.compile(conf.testSkip)
        except re.error:
            conf.testSkip = re.escape(conf.testSkip)

    if "timeSec" not in kb.explicitSettings:
        if conf.tor:
            conf.timeSec = 2 * conf.timeSec
            kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE

            warnMsg = "increasing default value for "
            warnMsg += "option '--time-sec' to %d because " % conf.timeSec
            warnMsg += "switch '--tor' was provided"
            logger.warn(warnMsg)
    else:
        kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE

    if conf.retries:
        conf.retries = min(conf.retries, MAX_CONNECT_RETRIES)

    if conf.code:
        conf.code = int(conf.code)

    if conf.csvDel:
        conf.csvDel = decodeStringEscape(conf.csvDel)

    if conf.torPort and hasattr(conf.torPort, "isdigit") and conf.torPort.isdigit():
        conf.torPort = int(conf.torPort)

    if conf.torType:
        conf.torType = conf.torType.upper()

    if conf.outputDir:
        paths.SQLMAP_OUTPUT_PATH = os.path.realpath(os.path.expanduser(conf.outputDir))
        setPaths(paths.SQLMAP_ROOT_PATH)

    if conf.string:
        conf.string = decodeStringEscape(conf.string)

    if conf.getAll:
        for _ in WIZARD.ALL:
            conf.__setitem__(_, True)

    if conf.noCast:
        DUMP_REPLACEMENTS.clear()

    if conf.dumpFormat:
        conf.dumpFormat = conf.dumpFormat.upper()

    if conf.torType:
        conf.torType = conf.torType.upper()

    if conf.col:
        conf.col = re.sub(r"\s*,\s*", ',', conf.col)

    if conf.exclude:
        regex = False
        original = conf.exclude

        if any(_ in conf.exclude for _ in ('+', '*')):
            try:
                re.compile(conf.exclude)
            except re.error:
                pass
            else:
                regex = True

        if not regex:
            conf.exclude = re.sub(r"\s*,\s*", ',', conf.exclude)
            conf.exclude = r"\A%s\Z" % '|'.join(re.escape(_) for _ in conf.exclude.split(','))
        else:
            conf.exclude = re.sub(r"(\w+)\$", r"\g<1>\$", conf.exclude)

        class _(six.text_type):
            pass

        conf.exclude = _(conf.exclude)
        conf.exclude._original = original

    if conf.binaryFields:
        conf.binaryFields = conf.binaryFields.replace(" ", "")
        conf.binaryFields = re.split(PARAMETER_SPLITTING_REGEX, conf.binaryFields)

    envProxy = max(os.environ.get(_, "") for _ in PROXY_ENVIRONMENT_VARIABLES)
    if re.search(r"\A(https?|socks[45])://.+:\d+\Z", envProxy) and conf.proxy is None:
        debugMsg = "using environment proxy '%s'" % envProxy
        logger.debug(debugMsg)

        conf.proxy = envProxy

    if any((conf.proxy, conf.proxyFile, conf.tor)):
        conf.disablePrecon = True

    if conf.dummy:
        conf.batch = True

    threadData = getCurrentThreadData()
    threadData.reset()

def _cleanupEnvironment():
    """
    Cleanup environment (e.g. from leftovers after --shell).
    """

    if issubclass(_http_client.socket.socket, socks.socksocket):
        socks.unwrapmodule(_http_client)

    if hasattr(socket, "_ready"):
        socket._ready.clear()

def _purge():
    """
    Safely removes (purges) sqlmap data directory.
    """

    if conf.purge:
        purge(paths.SQLMAP_HOME_PATH)

def _setConfAttributes():
    """
    This function set some needed attributes into the configuration
    singleton.
    """

    debugMsg = "initializing the configuration"
    logger.debug(debugMsg)

    conf.authUsername = None
    conf.authPassword = None
    conf.boundaries = []
    conf.cj = None
    conf.dbmsConnector = None
    conf.dbmsHandler = None
    conf.dnsServer = None
    conf.dumpPath = None
    conf.hashDB = None
    conf.hashDBFile = None
    conf.httpCollector = None
    conf.httpHeaders = []
    conf.hostname = None
    conf.ipv6 = False
    conf.multipleTargets = False
    conf.outputPath = None
    conf.paramDict = {}
    conf.parameters = {}
    conf.path = None
    conf.port = None
    conf.proxyList = None
    conf.resultsFP = None
    conf.scheme = None
    conf.tests = []
    conf.trafficFP = None
    conf.HARCollectorFactory = None
    conf.fileWriteType = None

def _setKnowledgeBaseAttributes(flushAll=True):
    """
    This function set some needed attributes into the knowledge base
    singleton.
    """

    debugMsg = "initializing the knowledge base"
    logger.debug(debugMsg)

    kb.absFilePaths = set()
    kb.adjustTimeDelay = None
    kb.alerted = False
    kb.aliasName = randomStr()
    kb.alwaysRefresh = None
    kb.arch = None
    kb.authHeader = None
    kb.bannerFp = AttribDict()
    kb.base64Originals = {}
    kb.binaryField = False
    kb.browserVerification = None

    kb.brute = AttribDict({"tables": [], "columns": []})
    kb.bruteMode = False

    kb.cache = AttribDict()
    kb.cache.addrinfo = {}
    kb.cache.content = {}
    kb.cache.comparison = {}
    kb.cache.encoding = {}
    kb.cache.alphaBoundaries = None
    kb.cache.hashRegex = None
    kb.cache.intBoundaries = None
    kb.cache.parsedDbms = {}
    kb.cache.regex = {}
    kb.cache.stdev = {}

    kb.captchaDetected = None

    kb.chars = AttribDict()
    kb.chars.delimiter = randomStr(length=6, lowercase=True)
    kb.chars.start = "%s%s%s" % (KB_CHARS_BOUNDARY_CHAR, randomStr(length=3, alphabet=KB_CHARS_LOW_FREQUENCY_ALPHABET), KB_CHARS_BOUNDARY_CHAR)
    kb.chars.stop = "%s%s%s" % (KB_CHARS_BOUNDARY_CHAR, randomStr(length=3, alphabet=KB_CHARS_LOW_FREQUENCY_ALPHABET), KB_CHARS_BOUNDARY_CHAR)
    kb.chars.at, kb.chars.space, kb.chars.dollar, kb.chars.hash_ = ("%s%s%s" % (KB_CHARS_BOUNDARY_CHAR, _, KB_CHARS_BOUNDARY_CHAR) for _ in randomStr(length=4, lowercase=True))

    kb.choices = AttribDict(keycheck=False)
    kb.codePage = None
    kb.commonOutputs = None
    kb.connErrorCounter = 0
    kb.copyExecTest = None
    kb.counters = {}
    kb.customInjectionMark = CUSTOM_INJECTION_MARK_CHAR
    kb.data = AttribDict()
    kb.dataOutputFlag = False

    # Active back-end DBMS fingerprint
    kb.dbms = None
    kb.dbmsFilter = []
    kb.dbmsVersion = [UNKNOWN_DBMS_VERSION]

    kb.delayCandidates = TIME_DELAY_CANDIDATES * [0]
    kb.dep = None
    kb.disableHtmlDecoding = False
    kb.dnsMode = False
    kb.dnsTest = None
    kb.docRoot = None
    kb.droppingRequests = False
    kb.dumpColumns = None
    kb.dumpTable = None
    kb.dumpKeyboardInterrupt = False
    kb.dynamicMarkings = []
    kb.dynamicParameter = False
    kb.endDetection = False
    kb.explicitSettings = set()
    kb.extendTests = None
    kb.errorChunkLength = None
    kb.errorIsNone = True
    kb.falsePositives = []
    kb.fileReadMode = False
    kb.fingerprinted = False
    kb.followSitemapRecursion = None
    kb.forcedDbms = None
    kb.forcePartialUnion = False
    kb.forceThreads = None
    kb.forceWhere = None
    kb.forkNote = None
    kb.futileUnion = None
    kb.fuzzUnionTest = None
    kb.heavilyDynamic = False
    kb.headersFile = None
    kb.headersFp = {}
    kb.heuristicDbms = None
    kb.heuristicExtendedDbms = None
    kb.heuristicMode = False
    kb.heuristicPage = False
    kb.heuristicTest = None
    kb.hintValue = ""
    kb.htmlFp = []
    kb.httpErrorCodes = {}
    kb.inferenceMode = False
    kb.ignoreCasted = None
    kb.ignoreNotFound = False
    kb.ignoreTimeout = False
    kb.identifiedWafs = set()
    kb.injection = InjectionDict()
    kb.injections = []
    kb.jsonAggMode = False
    kb.laggingChecked = False
    kb.lastParserStatus = None

    kb.locks = AttribDict()
    for _ in ("cache", "connError", "count", "handlers", "hint", "index", "io", "limit", "liveCookies", "log", "socket", "redirect", "request", "value"):
        kb.locks[_] = threading.Lock()

    kb.matchRatio = None
    kb.maxConnectionsFlag = False
    kb.mergeCookies = None
    kb.multipleCtrlC = False
    kb.negativeLogic = False
    kb.nchar = True
    kb.nullConnection = None
    kb.oldMsf = None
    kb.orderByColumns = None
    kb.originalCode = None
    kb.originalPage = None
    kb.originalPageTime = None
    kb.originalTimeDelay = None
    kb.originalUrls = dict()

    # Back-end DBMS underlying operating system fingerprint via banner (-b)
    # parsing
    kb.os = None
    kb.osVersion = None
    kb.osSP = None

    kb.pageCompress = True
    kb.pageTemplate = None
    kb.pageTemplates = dict()
    kb.pageEncoding = DEFAULT_PAGE_ENCODING
    kb.pageStable = None
    kb.partRun = None
    kb.permissionFlag = False
    kb.postHint = None
    kb.postSpaceToPlus = False
    kb.postUrlEncode = True
    kb.prependFlag = False
    kb.processResponseCounter = 0
    kb.previousMethod = None
    kb.processUserMarks = None
    kb.proxyAuthHeader = None
    kb.queryCounter = 0
    kb.randomPool = {}
    kb.reflectiveMechanism = True
    kb.reflectiveCounters = {REFLECTIVE_COUNTER.MISS: 0, REFLECTIVE_COUNTER.HIT: 0}
    kb.requestCounter = 0
    kb.resendPostOnRedirect = None
    kb.resolutionDbms = None
    kb.responseTimes = {}
    kb.responseTimeMode = None
    kb.responseTimePayload = None
    kb.resumeValues = True
    kb.safeCharEncode = False
    kb.safeReq = AttribDict()
    kb.secondReq = None
    kb.serverHeader = None
    kb.singleLogFlags = set()
    kb.skipSeqMatcher = False
    kb.smokeMode = False
    kb.reduceTests = None
    kb.sslSuccess = False
    kb.stickyDBMS = False
    kb.suppressResumeInfo = False
    kb.tableFrom = None
    kb.technique = None
    kb.tempDir = None
    kb.testMode = False
    kb.testOnlyCustom = False
    kb.testQueryCount = 0
    kb.testType = None
    kb.threadContinue = True
    kb.threadException = False
    kb.tlsSNI = {}
    kb.uChar = NULL
    kb.udfFail = False
    kb.unionDuplicates = False
    kb.unionTemplate = None
    kb.webSocketRecvCount = None
    kb.wizardMode = False
    kb.xpCmdshellAvailable = False

    if flushAll:
        kb.checkSitemap = None
        kb.headerPaths = {}
        kb.keywords = set(getFileItems(paths.SQL_KEYWORDS))
        kb.lastCtrlCTime = None
        kb.normalizeCrawlingChoice = None
        kb.passwordMgr = None
        kb.postprocessFunctions = []
        kb.preprocessFunctions = []
        kb.skipVulnHost = None
        kb.storeCrawlingChoice = None
        kb.tamperFunctions = []
        kb.targets = OrderedSet()
        kb.testedParams = set()
        kb.userAgents = None
        kb.vainRun = True
        kb.vulnHosts = set()
        kb.wafFunctions = []
        kb.wordlists = None

def _useWizardInterface():
    """
    Presents simple wizard interface for beginner users
    """

    if not conf.wizard:
        return

    logger.info("starting wizard interface")

    while not conf.url:
        message = "Please enter full target URL (-u): "
        conf.url = readInput(message, default=None)

    message = "%s data (--data) [Enter for None]: " % ((conf.method if conf.method != HTTPMETHOD.GET else None) or HTTPMETHOD.POST)
    conf.data = readInput(message, default=None)

    if not (any('=' in _ for _ in (conf.url, conf.data)) or '*' in conf.url):
        warnMsg = "no GET and/or %s parameter(s) found for testing " % ((conf.method if conf.method != HTTPMETHOD.GET else None) or HTTPMETHOD.POST)
        warnMsg += "(e.g. GET parameter 'id' in 'http://www.site.com/vuln.php?id=1'). "
        if not conf.crawlDepth and not conf.forms:
            warnMsg += "Will search for forms"
            conf.forms = True
        logger.warn(warnMsg)

    choice = None

    while choice is None or choice not in ("", "1", "2", "3"):
        message = "Injection difficulty (--level/--risk). Please choose:\n"
        message += "[1] Normal (default)\n[2] Medium\n[3] Hard"
        choice = readInput(message, default='1')

        if choice == '2':
            conf.risk = 2
            conf.level = 3
        elif choice == '3':
            conf.risk = 3
            conf.level = 5
        else:
            conf.risk = 1
            conf.level = 1

    if not conf.getAll:
        choice = None

        while choice is None or choice not in ("", "1", "2", "3"):
            message = "Enumeration (--banner/--current-user/etc). Please choose:\n"
            message += "[1] Basic (default)\n[2] Intermediate\n[3] All"
            choice = readInput(message, default='1')

            if choice == '2':
                options = WIZARD.INTERMEDIATE
            elif choice == '3':
                options = WIZARD.ALL
            else:
                options = WIZARD.BASIC

            for _ in options:
                conf.__setitem__(_, True)

    logger.debug("muting sqlmap.. it will do the magic for you")
    conf.verbose = 0

    conf.batch = True
    conf.threads = 4

    dataToStdout("\nsqlmap is running, please wait..\n\n")

    kb.wizardMode = True

def _saveConfig():
    """
    Saves the command line options to a sqlmap configuration INI file
    Format.
    """

    if not conf.saveConfig:
        return

    debugMsg = "saving command line options to a sqlmap configuration INI file"
    logger.debug(debugMsg)

    saveConfig(conf, conf.saveConfig)

    infoMsg = "saved command line options to the configuration file '%s'" % conf.saveConfig
    logger.info(infoMsg)

def setVerbosity():
    """
    This function set the verbosity of sqlmap output messages.
    """

    if conf.verbose is None:
        conf.verbose = 1

    conf.verbose = int(conf.verbose)

    if conf.verbose == 0:
        logger.setLevel(logging.ERROR)
    elif conf.verbose == 1:
        logger.setLevel(logging.INFO)
    elif conf.verbose > 2 and conf.eta:
        conf.verbose = 2
        logger.setLevel(logging.DEBUG)
    elif conf.verbose == 2:
        logger.setLevel(logging.DEBUG)
    elif conf.verbose == 3:
        logger.setLevel(CUSTOM_LOGGING.PAYLOAD)
    elif conf.verbose == 4:
        logger.setLevel(CUSTOM_LOGGING.TRAFFIC_OUT)
    elif conf.verbose >= 5:
        logger.setLevel(CUSTOM_LOGGING.TRAFFIC_IN)

def _normalizeOptions(inputOptions):
    """
    Sets proper option types
    """

    types_ = {}
    for group in optDict.keys():
        types_.update(optDict[group])

    for key in inputOptions:
        if key in types_:
            value = inputOptions[key]
            if value is None:
                continue

            type_ = types_[key]
            if type_ and isinstance(type_, tuple):
                type_ = type_[0]

            if type_ == OPTION_TYPE.BOOLEAN:
                try:
                    value = bool(value)
                except (TypeError, ValueError):
                    value = False
            elif type_ == OPTION_TYPE.INTEGER:
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    value = 0
            elif type_ == OPTION_TYPE.FLOAT:
                try:
                    value = float(value)
                except (TypeError, ValueError):
                    value = 0.0

            inputOptions[key] = value

def _mergeOptions(inputOptions, overrideOptions):
    """
    Merge command line options with configuration file and default options.

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
        if key not in conf or value not in (None, False) or overrideOptions:
            conf[key] = value

    if not conf.api:
        for key, value in conf.items():
            if value is not None:
                kb.explicitSettings.add(key)

    for key, value in defaults.items():
        if hasattr(conf, key) and conf[key] is None:
            conf[key] = value

            if conf.unstable:
                if key in ("timeSec", "retries", "timeout"):
                    conf[key] *= 2

    if conf.unstable:
        conf.forcePartial = True

    lut = {}
    for group in optDict.keys():
        lut.update((_.upper(), _) for _ in optDict[group])

    envOptions = {}
    for key, value in os.environ.items():
        if key.upper().startswith(SQLMAP_ENVIRONMENT_PREFIX):
            _ = key[len(SQLMAP_ENVIRONMENT_PREFIX):].upper()
            if _ in lut:
                envOptions[lut[_]] = value

    if envOptions:
        _normalizeOptions(envOptions)
        for key, value in envOptions.items():
            conf[key] = value

    mergedOptions.update(conf)

def _setTrafficOutputFP():
    if conf.trafficFile:
        infoMsg = "setting file for logging HTTP traffic"
        logger.info(infoMsg)

        conf.trafficFP = openFile(conf.trafficFile, "w+")

def _setupHTTPCollector():
    if not conf.harFile:
        return

    conf.httpCollector = HTTPCollectorFactory(conf.harFile).create()

def _setDNSServer():
    if not conf.dnsDomain:
        return

    infoMsg = "setting up DNS server instance"
    logger.info(infoMsg)

    isAdmin = runningAsAdmin()

    if isAdmin:
        try:
            conf.dnsServer = DNSServer()
            conf.dnsServer.run()
        except socket.error as ex:
            errMsg = "there was an error while setting up "
            errMsg += "DNS server instance ('%s')" % getSafeExString(ex)
            raise SqlmapGenericException(errMsg)
    else:
        errMsg = "you need to run sqlmap as an administrator "
        errMsg += "if you want to perform a DNS data exfiltration attack "
        errMsg += "as it will need to listen on privileged UDP port 53 "
        errMsg += "for incoming address resolution attempts"
        raise SqlmapMissingPrivileges(errMsg)

def _setProxyList():
    if not conf.proxyFile:
        return

    conf.proxyList = []
    for match in re.finditer(r"(?i)((http[^:]*|socks[^:]*)://)?([\w\-.]+):(\d+)", readCachedFileContent(conf.proxyFile)):
        _, type_, address, port = match.groups()
        conf.proxyList.append("%s://%s:%s" % (type_ or "http", address, port))

def _setTorProxySettings():
    if not conf.tor:
        return

    if conf.torType == PROXY_TYPE.HTTP:
        _setTorHttpProxySettings()
    else:
        _setTorSocksProxySettings()

def _setTorHttpProxySettings():
    infoMsg = "setting Tor HTTP proxy settings"
    logger.info(infoMsg)

    port = findLocalPort(DEFAULT_TOR_HTTP_PORTS if not conf.torPort else (conf.torPort,))

    if port:
        conf.proxy = "http://%s:%d" % (LOCALHOST, port)
    else:
        errMsg = "can't establish connection with the Tor HTTP proxy. "
        errMsg += "Please make sure that you have Tor (bundle) installed and setup "
        errMsg += "so you could be able to successfully use switch '--tor' "
        raise SqlmapConnectionException(errMsg)

    if not conf.checkTor:
        warnMsg = "use switch '--check-tor' at "
        warnMsg += "your own convenience when accessing "
        warnMsg += "Tor anonymizing network because of "
        warnMsg += "known issues with default settings of various 'bundles' "
        warnMsg += "(e.g. Vidalia)"
        logger.warn(warnMsg)

def _setTorSocksProxySettings():
    infoMsg = "setting Tor SOCKS proxy settings"
    logger.info(infoMsg)

    port = findLocalPort(DEFAULT_TOR_SOCKS_PORTS if not conf.torPort else (conf.torPort,))

    if not port:
        errMsg = "can't establish connection with the Tor SOCKS proxy. "
        errMsg += "Please make sure that you have Tor service installed and setup "
        errMsg += "so you could be able to successfully use switch '--tor' "
        raise SqlmapConnectionException(errMsg)

    # SOCKS5 to prevent DNS leaks (http://en.wikipedia.org/wiki/Tor_%28anonymity_network%29)
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5 if conf.torType == PROXY_TYPE.SOCKS5 else socks.PROXY_TYPE_SOCKS4, LOCALHOST, port)
    socks.wrapmodule(_http_client)

def _setHttpChunked():
    if conf.chunked and conf.data:
        if hasattr(_http_client.HTTPConnection, "_set_content_length"):
            _http_client.HTTPConnection._set_content_length = lambda self, *args, **kwargs: None
        else:
            def putheader(self, header, *values):
                if header != HTTP_HEADER.CONTENT_LENGTH:
                    self._putheader(header, *values)

            if not hasattr(_http_client.HTTPConnection, "_putheader"):
                _http_client.HTTPConnection._putheader = _http_client.HTTPConnection.putheader

            _http_client.HTTPConnection.putheader = putheader

def _checkWebSocket():
    if conf.url and (conf.url.startswith("ws:/") or conf.url.startswith("wss:/")):
        try:
            from websocket import ABNF
        except ImportError:
            errMsg = "sqlmap requires third-party module 'websocket-client' "
            errMsg += "in order to use WebSocket functionality"
            raise SqlmapMissingDependence(errMsg)

def _checkTor():
    if not conf.checkTor:
        return

    infoMsg = "checking Tor connection"
    logger.info(infoMsg)

    try:
        page, _, _ = Request.getPage(url="https://check.torproject.org/", raise404=False)
    except SqlmapConnectionException:
        page = None

    if not page or "Congratulations" not in page:
        errMsg = "it appears that Tor is not properly set. Please try using options '--tor-type' and/or '--tor-port'"
        raise SqlmapConnectionException(errMsg)
    else:
        infoMsg = "Tor is properly being used"
        logger.info(infoMsg)

def _basicOptionValidation():
    if conf.limitStart is not None and not (isinstance(conf.limitStart, int) and conf.limitStart > 0):
        errMsg = "value for option '--start' (limitStart) must be an integer value greater than zero (>0)"
        raise SqlmapSyntaxException(errMsg)

    if conf.limitStop is not None and not (isinstance(conf.limitStop, int) and conf.limitStop > 0):
        errMsg = "value for option '--stop' (limitStop) must be an integer value greater than zero (>0)"
        raise SqlmapSyntaxException(errMsg)

    if conf.level is not None and not (isinstance(conf.level, int) and conf.level >= 1 and conf.level <= 5):
        errMsg = "value for option '--level' must be an integer value from range [1, 5]"
        raise SqlmapSyntaxException(errMsg)

    if conf.risk is not None and not (isinstance(conf.risk, int) and conf.risk >= 1 and conf.risk <= 3):
        errMsg = "value for option '--risk' must be an integer value from range [1, 3]"
        raise SqlmapSyntaxException(errMsg)

    if isinstance(conf.limitStart, int) and conf.limitStart > 0 and \
       isinstance(conf.limitStop, int) and conf.limitStop < conf.limitStart:
        warnMsg = "usage of option '--start' (limitStart) which is bigger than value for --stop (limitStop) option is considered unstable"
        logger.warn(warnMsg)

    if isinstance(conf.firstChar, int) and conf.firstChar > 0 and \
       isinstance(conf.lastChar, int) and conf.lastChar < conf.firstChar:
        errMsg = "value for option '--first' (firstChar) must be smaller than or equal to value for --last (lastChar) option"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxyFile and not any((conf.randomAgent, conf.mobile, conf.agent, conf.requestFile)):
        warnMsg = "usage of switch '--random-agent' is strongly recommended when "
        warnMsg += "using option '--proxy-file'"
        logger.warn(warnMsg)

    if conf.textOnly and conf.nullConnection:
        errMsg = "switch '--text-only' is incompatible with switch '--null-connection'"
        raise SqlmapSyntaxException(errMsg)

    if conf.base64Parameter and conf.tamper:
        errMsg = "option '--base64' is incompatible with option '--tamper'"
        raise SqlmapSyntaxException(errMsg)

    if conf.eta and conf.verbose > defaults.verbose:
        errMsg = "switch '--eta' is incompatible with option '-v'"
        raise SqlmapSyntaxException(errMsg)

    if conf.secondUrl and conf.secondReq:
        errMsg = "option '--second-url' is incompatible with option '--second-req')"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.url:
        errMsg = "option '-d' is incompatible with option '-u' ('--url')"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.dbms:
        errMsg = "option '-d' is incompatible with option '--dbms'"
        raise SqlmapSyntaxException(errMsg)

    if conf.titles and conf.nullConnection:
        errMsg = "switch '--titles' is incompatible with switch '--null-connection'"
        raise SqlmapSyntaxException(errMsg)

    if conf.dumpTable and conf.search:
        errMsg = "switch '--dump' is incompatible with switch '--search'"
        raise SqlmapSyntaxException(errMsg)

    if conf.chunked and not any((conf.data, conf.requestFile, conf.forms)):
        errMsg = "switch '--chunked' requires usage of (POST) options/switches '--data', '-r' or '--forms'"
        raise SqlmapSyntaxException(errMsg)

    if conf.api and not conf.configFile:
        errMsg = "switch '--api' requires usage of option '-c'"
        raise SqlmapSyntaxException(errMsg)

    if conf.data and conf.nullConnection:
        errMsg = "option '--data' is incompatible with switch '--null-connection'"
        raise SqlmapSyntaxException(errMsg)

    if conf.string and conf.nullConnection:
        errMsg = "option '--string' is incompatible with switch '--null-connection'"
        raise SqlmapSyntaxException(errMsg)

    if conf.notString and conf.nullConnection:
        errMsg = "option '--not-string' is incompatible with switch '--null-connection'"
        raise SqlmapSyntaxException(errMsg)

    if conf.tor and conf.osPwn:
        errMsg = "option '--tor' is incompatible with switch '--os-pwn'"
        raise SqlmapSyntaxException(errMsg)

    if conf.noCast and conf.hexConvert:
        errMsg = "switch '--no-cast' is incompatible with switch '--hex'"
        raise SqlmapSyntaxException(errMsg)

    if conf.crawlDepth:
        try:
            xrange(conf.crawlDepth)
        except OverflowError as ex:
            errMsg = "invalid value used for option '--crawl' ('%s')" % getSafeExString(ex)
            raise SqlmapSyntaxException(errMsg)

    if conf.dumpAll and conf.search:
        errMsg = "switch '--dump-all' is incompatible with switch '--search'"
        raise SqlmapSyntaxException(errMsg)

    if conf.string and conf.notString:
        errMsg = "option '--string' is incompatible with switch '--not-string'"
        raise SqlmapSyntaxException(errMsg)

    if conf.regexp and conf.nullConnection:
        errMsg = "option '--regexp' is incompatible with switch '--null-connection'"
        raise SqlmapSyntaxException(errMsg)

    if conf.regexp:
        try:
            re.compile(conf.regexp)
        except Exception as ex:
            errMsg = "invalid regular expression '%s' ('%s')" % (conf.regexp, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.paramExclude:
        try:
            re.compile(conf.paramExclude)
        except Exception as ex:
            errMsg = "invalid regular expression '%s' ('%s')" % (conf.paramExclude, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.cookieDel and len(conf.cookieDel):
        errMsg = "option '--cookie-del' should contain a single character (e.g. ';')"
        raise SqlmapSyntaxException(errMsg)

    if conf.crawlExclude:
        try:
            re.compile(conf.crawlExclude)
        except Exception as ex:
            errMsg = "invalid regular expression '%s' ('%s')" % (conf.crawlExclude, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.scope:
        try:
            re.compile(conf.scope)
        except Exception as ex:
            errMsg = "invalid regular expression '%s' ('%s')" % (conf.scope, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.dumpTable and conf.dumpAll:
        errMsg = "switch '--dump' is incompatible with switch '--dump-all'"
        raise SqlmapSyntaxException(errMsg)

    if conf.predictOutput and (conf.threads > 1 or conf.optimize):
        errMsg = "switch '--predict-output' is incompatible with option '--threads' and switch '-o'"
        raise SqlmapSyntaxException(errMsg)

    if conf.threads > MAX_NUMBER_OF_THREADS and not conf.get("skipThreadCheck"):
        errMsg = "maximum number of used threads is %d avoiding potential connection issues" % MAX_NUMBER_OF_THREADS
        raise SqlmapSyntaxException(errMsg)

    if conf.forms and not any((conf.url, conf.googleDork, conf.bulkFile)):
        errMsg = "switch '--forms' requires usage of option '-u' ('--url'), '-g' or '-m'"
        raise SqlmapSyntaxException(errMsg)

    if conf.crawlExclude and not conf.crawlDepth:
        errMsg = "option '--crawl-exclude' requires usage of switch '--crawl'"
        raise SqlmapSyntaxException(errMsg)

    if conf.safePost and not conf.safeUrl:
        errMsg = "option '--safe-post' requires usage of option '--safe-url'"
        raise SqlmapSyntaxException(errMsg)

    if conf.safeFreq and not any((conf.safeUrl, conf.safeReqFile)):
        errMsg = "option '--safe-freq' requires usage of option '--safe-url' or '--safe-req'"
        raise SqlmapSyntaxException(errMsg)

    if conf.safeReqFile and any((conf.safeUrl, conf.safePost)):
        errMsg = "option '--safe-req' is incompatible with option '--safe-url' and option '--safe-post'"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfUrl and not conf.csrfToken:
        errMsg = "option '--csrf-url' requires usage of option '--csrf-token'"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfMethod and not conf.csrfToken:
        errMsg = "option '--csrf-method' requires usage of option '--csrf-token'"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfToken and conf.threads > 1:
        errMsg = "option '--csrf-url' is incompatible with option '--threads'"
        raise SqlmapSyntaxException(errMsg)

    if conf.requestFile and conf.url and conf.url != DUMMY_URL:
        errMsg = "option '-r' is incompatible with option '-u' ('--url')"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.proxy:
        errMsg = "option '-d' is incompatible with option '--proxy'"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.tor:
        errMsg = "option '-d' is incompatible with switch '--tor'"
        raise SqlmapSyntaxException(errMsg)

    if not conf.technique:
        errMsg = "option '--technique' can't be empty"
        raise SqlmapSyntaxException(errMsg)

    if conf.tor and conf.ignoreProxy:
        errMsg = "switch '--tor' is incompatible with switch '--ignore-proxy'"
        raise SqlmapSyntaxException(errMsg)

    if conf.tor and conf.proxy:
        errMsg = "switch '--tor' is incompatible with option '--proxy'"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxy and conf.proxyFile:
        errMsg = "switch '--proxy' is incompatible with option '--proxy-file'"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxyFreq and not conf.proxyFile:
        errMsg = "option '--proxy-freq' requires usage of option '--proxy-file'"
        raise SqlmapSyntaxException(errMsg)

    if conf.checkTor and not any((conf.tor, conf.proxy)):
        errMsg = "switch '--check-tor' requires usage of switch '--tor' (or option '--proxy' with HTTP proxy address of Tor service)"
        raise SqlmapSyntaxException(errMsg)

    if conf.torPort is not None and not (isinstance(conf.torPort, int) and conf.torPort >= 0 and conf.torPort <= 65535):
        errMsg = "value for option '--tor-port' must be in range [0, 65535]"
        raise SqlmapSyntaxException(errMsg)

    if conf.torType not in getPublicTypeMembers(PROXY_TYPE, True):
        errMsg = "option '--tor-type' accepts one of following values: %s" % ", ".join(getPublicTypeMembers(PROXY_TYPE, True))
        raise SqlmapSyntaxException(errMsg)

    if conf.dumpFormat not in getPublicTypeMembers(DUMP_FORMAT, True):
        errMsg = "option '--dump-format' accepts one of following values: %s" % ", ".join(getPublicTypeMembers(DUMP_FORMAT, True))
        raise SqlmapSyntaxException(errMsg)

    if conf.skip and conf.testParameter:
        if intersect(conf.skip, conf.testParameter):
            errMsg = "option '--skip' is incompatible with option '-p'"
            raise SqlmapSyntaxException(errMsg)

    if conf.rParam and conf.testParameter:
        if intersect(conf.rParam, conf.testParameter):
            errMsg = "option '--randomize' is incompatible with option '-p'"
            raise SqlmapSyntaxException(errMsg)

    if conf.mobile and conf.agent:
        errMsg = "switch '--mobile' is incompatible with option '--user-agent'"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxy and conf.ignoreProxy:
        errMsg = "option '--proxy' is incompatible with switch '--ignore-proxy'"
        raise SqlmapSyntaxException(errMsg)

    if conf.alert and conf.alert.startswith('-'):
        errMsg = "value for option '--alert' must be valid operating system command(s)"
        raise SqlmapSyntaxException(errMsg)

    if conf.timeSec < 1:
        errMsg = "value for option '--time-sec' must be a positive integer"
        raise SqlmapSyntaxException(errMsg)

    if conf.uChar and not re.match(UNION_CHAR_REGEX, conf.uChar):
        errMsg = "value for option '--union-char' must be an alpha-numeric value (e.g. 1)"
        raise SqlmapSyntaxException(errMsg)

    if conf.hashFile and any((conf.direct, conf.url, conf.logFile, conf.bulkFile, conf.googleDork, conf.configFile, conf.requestFile, conf.updateAll, conf.smokeTest, conf.wizard, conf.dependencies, conf.purge, conf.listTampers)):
        errMsg = "option '--crack' should be used as a standalone"
        raise SqlmapSyntaxException(errMsg)

    if isinstance(conf.uCols, six.string_types):
        if not conf.uCols.isdigit() and ("-" not in conf.uCols or len(conf.uCols.split("-")) != 2):
            errMsg = "value for option '--union-cols' must be a range with hyphon "
            errMsg += "(e.g. 1-10) or integer value (e.g. 5)"
            raise SqlmapSyntaxException(errMsg)

    if conf.dbmsCred and ':' not in conf.dbmsCred:
        errMsg = "value for option '--dbms-cred' must be in "
        errMsg += "format <username>:<password> (e.g. \"root:pass\")"
        raise SqlmapSyntaxException(errMsg)

    if conf.encoding:
        _ = checkCharEncoding(conf.encoding, False)
        if _ is None:
            errMsg = "unknown encoding '%s'. Please visit " % conf.encoding
            errMsg += "'%s' to get the full list of " % CODECS_LIST_PAGE
            errMsg += "supported encodings"
            raise SqlmapSyntaxException(errMsg)
        else:
            conf.encoding = _

    if conf.loadCookies:
        if not os.path.exists(conf.loadCookies):
            errMsg = "cookies file '%s' does not exist" % conf.loadCookies
            raise SqlmapFilePathException(errMsg)

def initOptions(inputOptions=AttribDict(), overrideOptions=False):
    _setConfAttributes()
    _setKnowledgeBaseAttributes()
    _mergeOptions(inputOptions, overrideOptions)

def init():
    """
    Set attributes into both configuration and knowledge base singletons
    based upon command line and configuration file options.
    """

    _useWizardInterface()
    setVerbosity()
    _saveConfig()
    _setRequestFromFile()
    _cleanupOptions()
    _cleanupEnvironment()
    _purge()
    _checkDependencies()
    _createHomeDirectories()
    _createTemporaryDirectory()
    _basicOptionValidation()
    _setProxyList()
    _setTorProxySettings()
    _setDNSServer()
    _adjustLoggingFormatter()
    _setMultipleTargets()
    _listTamperingFunctions()
    _setTamperingFunctions()
    _setPreprocessFunctions()
    _setPostprocessFunctions()
    _setTrafficOutputFP()
    _setupHTTPCollector()
    _setHttpChunked()
    _checkWebSocket()

    parseTargetDirect()

    if any((conf.url, conf.logFile, conf.bulkFile, conf.requestFile, conf.googleDork, conf.stdinPipe)):
        _setHostname()
        _setHTTPTimeout()
        _setHTTPExtraHeaders()
        _setHTTPCookies()
        _setHTTPReferer()
        _setHTTPHost()
        _setHTTPUserAgent()
        _setHTTPAuthentication()
        _setHTTPHandlers()
        _setDNSCache()
        _setSocketPreConnect()
        _setSafeVisit()
        _doSearch()
        _setStdinPipeTargets()
        _setBulkMultipleTargets()
        _checkTor()
        _setCrawler()
        _findPageForms()
        _setDBMS()
        _setTechnique()

    _setThreads()
    _setOS()
    _setWriteFile()
    _setMetasploit()
    _setDBMSAuthentication()
    loadBoundaries()
    loadPayloads()
    _setPrefixSuffix()
    update()
    _loadQueries()
