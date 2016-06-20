#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import contextlib
import cookielib
import copy
import getpass
import hashlib
import httplib
import inspect
import json
import locale
import logging
import ntpath
import os
import posixpath
import random
import re
import socket
import string
import sys
import tempfile
import time
import urllib
import urllib2
import urlparse
import unicodedata

from ConfigParser import DEFAULTSECT
from ConfigParser import RawConfigParser
from StringIO import StringIO
from difflib import SequenceMatcher
from math import sqrt
from optparse import OptionValueError
from subprocess import PIPE
from subprocess import Popen as execute
from xml.dom import minidom
from xml.sax import parse
from xml.sax import SAXParseException

from extra.beep.beep import beep
from extra.cloak.cloak import decloak
from extra.safe2bin.safe2bin import safecharencode
from lib.core.bigarray import BigArray
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.convert import base64pickle
from lib.core.convert import base64unpickle
from lib.core.convert import hexdecode
from lib.core.convert import htmlunescape
from lib.core.convert import stdoutencode
from lib.core.convert import unicodeencode
from lib.core.convert import utf8encode
from lib.core.decorators import cachedmethod
from lib.core.defaults import defaults
from lib.core.dicts import DBMS_DICT
from lib.core.dicts import DEFAULT_DOC_ROOTS
from lib.core.dicts import DEPRECATED_OPTIONS
from lib.core.dicts import SQL_STATEMENTS
from lib.core.enums import ADJUST_TIME_DELAY
from lib.core.enums import CONTENT_STATUS
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import HEURISTIC_TEST
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.enums import OS
from lib.core.enums import PLACE
from lib.core.enums import PAYLOAD
from lib.core.enums import REFLECTIVE_COUNTER
from lib.core.enums import SORT_ORDER
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapInstallationException
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSyntaxException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUserQuitException
from lib.core.exception import SqlmapValueException
from lib.core.log import LOGGER_HANDLER
from lib.core.optiondict import optDict
from lib.core.settings import BANNER
from lib.core.settings import BOLD_PATTERNS
from lib.core.settings import BOUNDED_INJECTION_MARKER
from lib.core.settings import BRUTE_DOC_ROOT_PREFIXES
from lib.core.settings import BRUTE_DOC_ROOT_SUFFIXES
from lib.core.settings import BRUTE_DOC_ROOT_TARGET_MARK
from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR
from lib.core.settings import DBMS_DIRECTORY_DICT
from lib.core.settings import DEFAULT_COOKIE_DELIMITER
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import DEFAULT_MSSQL_SCHEMA
from lib.core.settings import DUMMY_USER_INJECTION
from lib.core.settings import DYNAMICITY_MARK_LENGTH
from lib.core.settings import ERROR_PARSING_REGEXES
from lib.core.settings import FILE_PATH_REGEXES
from lib.core.settings import FORCE_COOKIE_EXPIRATION_TIME
from lib.core.settings import FORM_SEARCH_REGEX
from lib.core.settings import GENERIC_DOC_ROOT_DIRECTORY_NAMES
from lib.core.settings import GIT_PAGE
from lib.core.settings import GITHUB_REPORT_OAUTH_TOKEN
from lib.core.settings import GOOGLE_ANALYTICS_COOKIE_PREFIX
from lib.core.settings import HASHDB_MILESTONE_VALUE
from lib.core.settings import HOST_ALIASES
from lib.core.settings import INFERENCE_UNKNOWN_CHAR
from lib.core.settings import INVALID_UNICODE_CHAR_FORMAT
from lib.core.settings import IP_ADDRESS_REGEX
from lib.core.settings import ISSUES_PAGE
from lib.core.settings import IS_WIN
from lib.core.settings import LARGE_OUTPUT_THRESHOLD
from lib.core.settings import MIN_ENCODED_LEN_CHECK
from lib.core.settings import MIN_TIME_RESPONSES
from lib.core.settings import MIN_VALID_DELAYED_RESPONSE
from lib.core.settings import NETSCAPE_FORMAT_HEADER_COOKIES
from lib.core.settings import NULL
from lib.core.settings import PARAMETER_AMP_MARKER
from lib.core.settings import PARAMETER_SEMICOLON_MARKER
from lib.core.settings import PARTIAL_HEX_VALUE_MARKER
from lib.core.settings import PARTIAL_VALUE_MARKER
from lib.core.settings import PAYLOAD_DELIMITER
from lib.core.settings import PLATFORM
from lib.core.settings import PRINTABLE_CHAR_REGEX
from lib.core.settings import PUSH_VALUE_EXCEPTION_RETRY_COUNT
from lib.core.settings import PYVERSION
from lib.core.settings import REFERER_ALIASES
from lib.core.settings import REFLECTED_BORDER_REGEX
from lib.core.settings import REFLECTED_MAX_REGEX_PARTS
from lib.core.settings import REFLECTED_REPLACEMENT_REGEX
from lib.core.settings import REFLECTED_VALUE_MARKER
from lib.core.settings import REFLECTIVE_MISS_THRESHOLD
from lib.core.settings import SENSITIVE_DATA_REGEX
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import TEXT_TAG_REGEX
from lib.core.settings import TIME_STDEV_COEFF
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.core.settings import URI_QUESTION_MARKER
from lib.core.settings import URLENCODE_CHAR_LIMIT
from lib.core.settings import URLENCODE_FAILSAFE_CHARS
from lib.core.settings import USER_AGENT_ALIASES
from lib.core.settings import VERSION_STRING
from lib.core.threads import getCurrentThreadData
from lib.utils.sqlalchemy import _sqlalchemy
from thirdparty.clientform.clientform import ParseResponse
from thirdparty.clientform.clientform import ParseError
from thirdparty.colorama.initialise import init as coloramainit
from thirdparty.magic import magic
from thirdparty.odict.odict import OrderedDict
from thirdparty.termcolor.termcolor import colored

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
                fp.write("%s = %s\n" % (key, getUnicode(value, UNICODE_ENCODING).replace('\n', '\n\t')))

            fp.write("\n")

        for section in self._sections:
            fp.write("[%s]\n" % section)

            for (key, value) in self._sections[section].items():
                if key != "__name__":
                    if value is None:
                        fp.write("%s\n" % (key))
                    else:
                        fp.write("%s = %s\n" % (key, getUnicode(value, UNICODE_ENCODING).replace('\n', '\n\t')))

            fp.write("\n")

class Format(object):
    @staticmethod
    def humanize(values, chain=" or "):
        return chain.join(values)

    # Get methods
    @staticmethod
    def getDbms(versions=None):
        """
        Format the back-end DBMS fingerprint value and return its
        values formatted as a human readable string.

        @return: detected back-end DBMS based upon fingerprint techniques.
        @rtype: C{str}
        """

        if versions is None and Backend.getVersionList():
            versions = Backend.getVersionList()

        return Backend.getDbms() if versions is None else "%s %s" % (Backend.getDbms(), " and ".join(filter(None, versions)))

    @staticmethod
    def getErrorParsedDBMSes():
        """
        Parses the knowledge base htmlFp list and return its values
        formatted as a human readable string.

        @return: list of possible back-end DBMS based upon error messages
        parsing.
        @rtype: C{str}
        """

        htmlParsed = None

        if len(kb.htmlFp) == 0 or kb.heuristicTest != HEURISTIC_TEST.POSITIVE:
            pass
        elif len(kb.htmlFp) == 1:
            htmlParsed = kb.htmlFp[0]
        elif len(kb.htmlFp) > 1:
            htmlParsed = " or ".join(kb.htmlFp)

        return htmlParsed

    @staticmethod
    def getOs(target, info):
        """
        Formats the back-end operating system fingerprint value
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
        infoApi = {}

        if info and "type" in info:
            if hasattr(conf, "api"):
                infoApi["%s operating system" % target] = info
            else:
                infoStr += "%s operating system: %s" % (target, Format.humanize(info["type"]))

                if "distrib" in info:
                    infoStr += " %s" % Format.humanize(info["distrib"])

                if "release" in info:
                    infoStr += " %s" % Format.humanize(info["release"])

                if "sp" in info:
                    infoStr += " %s" % Format.humanize(info["sp"])

                if "codename" in info:
                    infoStr += " (%s)" % Format.humanize(info["codename"])

        if "technology" in info:
            if hasattr(conf, "api"):
                infoApi["web application technology"] = Format.humanize(info["technology"], ", ")
            else:
                infoStr += "\nweb application technology: %s" % Format.humanize(info["technology"], ", ")

        if hasattr(conf, "api"):
            return infoApi
        else:
            return infoStr.lstrip()

class Backend:
    # Set methods
    @staticmethod
    def setDbms(dbms):
        dbms = aliasToDbmsEnum(dbms)

        if dbms is None:
            return None

        # Little precaution, in theory this condition should always be false
        elif kb.dbms is not None and kb.dbms != dbms:
            warnMsg = "there appears to be a high probability that "
            warnMsg += "this could be a false positive case"
            logger.warn(warnMsg)

            msg = "sqlmap previously fingerprinted back-end DBMS as "
            msg += "%s. However now it has been fingerprinted " % kb.dbms
            msg += "as %s. " % dbms
            msg += "Please, specify which DBMS should be "
            msg += "correct [%s (default)/%s] " % (kb.dbms, dbms)

            while True:
                _ = readInput(msg, default=kb.dbms)

                if aliasToDbmsEnum(_) == kb.dbms:
                    kb.dbmsVersion = []
                    kb.resolutionDbms = kb.dbms
                    break
                elif aliasToDbmsEnum(_) == dbms:
                    kb.dbms = aliasToDbmsEnum(_)
                    break
                else:
                    warnMsg = "invalid value"
                    logger.warn(warnMsg)

        elif kb.dbms is None:
            kb.dbms = aliasToDbmsEnum(dbms)

        return kb.dbms

    @staticmethod
    def setVersion(version):
        if isinstance(version, basestring):
            kb.dbmsVersion = [version]

        return kb.dbmsVersion

    @staticmethod
    def setVersionList(versionsList):
        if isinstance(versionsList, list):
            kb.dbmsVersion = versionsList
        elif isinstance(versionsList, basestring):
            Backend.setVersion(versionsList)
        else:
            logger.error("invalid format of versionsList")

    @staticmethod
    def forceDbms(dbms, sticky=False):
        if not kb.stickyDBMS:
            kb.forcedDbms = aliasToDbmsEnum(dbms)
            kb.stickyDBMS = sticky

    @staticmethod
    def flushForcedDbms(force=False):
        if not kb.stickyDBMS or force:
            kb.forcedDbms = None
            kb.stickyDBMS = False

    @staticmethod
    def setOs(os):
        if os is None:
            return None

        # Little precaution, in theory this condition should always be false
        elif kb.os is not None and isinstance(os, basestring) and kb.os.lower() != os.lower():
            msg = "sqlmap previously fingerprinted back-end DBMS "
            msg += "operating system %s. However now it has " % kb.os
            msg += "been fingerprinted to be %s. " % os
            msg += "Please, specify which OS is "
            msg += "correct [%s (default)/%s] " % (kb.os, os)

            while True:
                _ = readInput(msg, default=kb.os)

                if _ == kb.os:
                    break
                elif _ == os:
                    kb.os = _.capitalize()
                    break
                else:
                    warnMsg = "invalid value"
                    logger.warn(warnMsg)

        elif kb.os is None and isinstance(os, basestring):
            kb.os = os.capitalize()

        return kb.os

    @staticmethod
    def setOsVersion(version):
        if version is None:
            return None

        elif kb.osVersion is None and isinstance(version, basestring):
            kb.osVersion = version

    @staticmethod
    def setOsServicePack(sp):
        if sp is None:
            return None

        elif kb.osSP is None and isinstance(sp, int):
            kb.osSP = sp

    @staticmethod
    def setArch():
        msg = "what is the back-end database management system architecture?"
        msg += "\n[1] 32-bit (default)"
        msg += "\n[2] 64-bit"

        while True:
            _ = readInput(msg, default='1')

            if isinstance(_, basestring) and _.isdigit() and int(_) in (1, 2):
                kb.arch = 32 if int(_) == 1 else 64
                break
            else:
                warnMsg = "invalid value. Valid values are 1 and 2"
                logger.warn(warnMsg)

        return kb.arch

    # Get methods
    @staticmethod
    def getForcedDbms():
        return aliasToDbmsEnum(kb.get("forcedDbms"))

    @staticmethod
    def getDbms():
        return aliasToDbmsEnum(kb.get("dbms"))

    @staticmethod
    def getErrorParsedDBMSes():
        """
        Returns array with parsed DBMS names till now

        This functions is called to:

        1. Ask user whether or not skip specific DBMS tests in detection phase,
           lib/controller/checks.py - detection phase.
        2. Sort the fingerprint of the DBMS, lib/controller/handler.py -
           fingerprint phase.
        """

        return kb.htmlFp if kb.get("heuristicTest") == HEURISTIC_TEST.POSITIVE else []

    @staticmethod
    def getIdentifiedDbms():
        """
        This functions is called to:

        1. Sort the tests, getSortedInjectionTests() - detection phase.
        2. Etc.
        """

        dbms = None

        if not kb:
            pass
        elif Backend.getForcedDbms() is not None:
            dbms = Backend.getForcedDbms()
        elif Backend.getDbms() is not None:
            dbms = Backend.getDbms()
        elif kb.get("injection") and kb.injection.dbms:
            dbms = unArrayizeValue(kb.injection.dbms)
        elif Backend.getErrorParsedDBMSes():
            dbms = unArrayizeValue(Backend.getErrorParsedDBMSes())
        elif conf.get("dbms"):
            dbms = conf.get("dbms")

        return aliasToDbmsEnum(dbms)

    @staticmethod
    def getVersion():
        versions = filter(None, flattenValue(kb.dbmsVersion))
        if not isNoneValue(versions):
            return versions[0]
        else:
            return None

    @staticmethod
    def getVersionList():
        versions = filter(None, flattenValue(kb.dbmsVersion))
        if not isNoneValue(versions):
            return versions
        else:
            return None

    @staticmethod
    def getOs():
        return kb.os

    @staticmethod
    def getOsVersion():
        return kb.osVersion

    @staticmethod
    def getOsServicePack():
        return kb.osSP

    @staticmethod
    def getArch():
        if kb.arch is None:
            Backend.setArch()
        return kb.arch

    # Comparison methods
    @staticmethod
    def isDbms(dbms):
        if Backend.getDbms() is not None:
            return Backend.getDbms() == aliasToDbmsEnum(dbms)
        else:
            return Backend.getIdentifiedDbms() == aliasToDbmsEnum(dbms)

    @staticmethod
    def isDbmsWithin(aliases):
        return Backend.getDbms() is not None and Backend.getDbms().lower() in aliases

    @staticmethod
    def isVersion(version):
        return Backend.getVersion() is not None and Backend.getVersion() == version

    @staticmethod
    def isVersionWithin(versionList):
        if Backend.getVersionList() is None:
            return False

        for _ in Backend.getVersionList():
            if _ != UNKNOWN_DBMS_VERSION and _ in versionList:
                return True

        return False

    @staticmethod
    def isVersionGreaterOrEqualThan(version):
        return Backend.getVersion() is not None and str(Backend.getVersion()) >= str(version)

    @staticmethod
    def isOs(os):
        return Backend.getOs() is not None and Backend.getOs().lower() == os.lower()

def paramToDict(place, parameters=None):
    """
    Split the parameters into names and values, check if these parameters
    are within the testable parameters and return in a dictionary.
    """

    testableParameters = OrderedDict()

    if place in conf.parameters and not parameters:
        parameters = conf.parameters[place]

    parameters = re.sub(r"&(\w{1,4});", r"%s\g<1>%s" % (PARAMETER_AMP_MARKER, PARAMETER_SEMICOLON_MARKER), parameters)
    if place == PLACE.COOKIE:
        splitParams = parameters.split(conf.cookieDel or DEFAULT_COOKIE_DELIMITER)
    else:
        splitParams = parameters.split(conf.paramDel or DEFAULT_GET_POST_DELIMITER)

    for element in splitParams:
        element = re.sub(r"%s(.+?)%s" % (PARAMETER_AMP_MARKER, PARAMETER_SEMICOLON_MARKER), r"&\g<1>;", element)
        parts = element.split("=")

        if len(parts) >= 2:
            parameter = urldecode(parts[0].replace(" ", ""))

            if not parameter:
                continue

            if conf.paramDel and conf.paramDel == '\n':
                parts[-1] = parts[-1].rstrip()

            condition = not conf.testParameter
            condition |= conf.testParameter is not None and parameter in conf.testParameter
            condition |= place == PLACE.COOKIE and len(intersect((PLACE.COOKIE,), conf.testParameter, True)) > 0

            if condition:
                testableParameters[parameter] = "=".join(parts[1:])
                if not conf.multipleTargets and not (conf.csrfToken and parameter == conf.csrfToken):
                    _ = urldecode(testableParameters[parameter], convall=True)
                    if (_.endswith("'") and _.count("'") == 1
                      or re.search(r'\A9{3,}', _) or re.search(r'\A-\d+\Z', _) or re.search(DUMMY_USER_INJECTION, _))\
                      and not parameter.upper().startswith(GOOGLE_ANALYTICS_COOKIE_PREFIX):
                        warnMsg = "it appears that you have provided tainted parameter values "
                        warnMsg += "('%s') with most probably leftover " % element
                        warnMsg += "chars/statements from manual SQL injection test(s). "
                        warnMsg += "Please, always use only valid parameter values "
                        warnMsg += "so sqlmap could be able to run properly"
                        logger.warn(warnMsg)

                        message = "are you really sure that you want to continue (sqlmap could have problems)? [y/N] "
                        test = readInput(message, default="N")
                        if test[0] not in ("y", "Y"):
                            raise SqlmapSilentQuitException
                    elif not _:
                        warnMsg = "provided value for parameter '%s' is empty. " % parameter
                        warnMsg += "Please, always use only valid parameter values "
                        warnMsg += "so sqlmap could be able to run properly"
                        logger.warn(warnMsg)

                if place in (PLACE.POST, PLACE.GET):
                    for regex in (r"\A((?:<[^>]+>)+\w+)((?:<[^>]+>)+)\Z", r"\A([^\w]+.*\w+)([^\w]+)\Z"):
                        match = re.search(regex, testableParameters[parameter])
                        if match:
                            try:
                                candidates = OrderedDict()

                                def walk(head, current=None):
                                    current = current or head
                                    if isListLike(current):
                                        for _ in current:
                                            walk(head, _)
                                    elif isinstance(current, dict):
                                        for key in current.keys():
                                            value = current[key]
                                            if isinstance(value, (list, tuple, set, dict)):
                                                walk(head, value)
                                            elif isinstance(value, (bool, int, float, basestring)):
                                                original = current[key]
                                                if isinstance(value, bool):
                                                    current[key] = "%s%s" % (str(value).lower(), BOUNDED_INJECTION_MARKER)
                                                else:
                                                    current[key] = "%s%s" % (value, BOUNDED_INJECTION_MARKER)
                                                candidates["%s (%s)" % (parameter, key)] = json.dumps(deserialized)
                                                current[key] = original

                                deserialized = json.loads(testableParameters[parameter])
                                walk(deserialized)

                                if candidates:
                                    message = "it appears that provided value for %s parameter '%s' " % (place, parameter)
                                    message += "is JSON deserializable. Do you want to inject inside? [y/N] "
                                    test = readInput(message, default="N")
                                    if test[0] in ("y", "Y"):
                                        del testableParameters[parameter]
                                        testableParameters.update(candidates)
                                    break
                            except (KeyboardInterrupt, SqlmapUserQuitException):
                                raise
                            except Exception:
                                pass

                            _ = re.sub(regex, "\g<1>%s\g<%d>" % (CUSTOM_INJECTION_MARK_CHAR, len(match.groups())), testableParameters[parameter])
                            message = "it appears that provided value for %s parameter '%s' " % (place, parameter)
                            message += "has boundaries. Do you want to inject inside? ('%s') [y/N] " % _
                            test = readInput(message, default="N")
                            if test[0] in ("y", "Y"):
                                testableParameters[parameter] = re.sub(regex, "\g<1>%s\g<2>" % BOUNDED_INJECTION_MARKER, testableParameters[parameter])
                            break

    if conf.testParameter:
        if not testableParameters:
            paramStr = ", ".join(test for test in conf.testParameter)

            if len(conf.testParameter) > 1:
                warnMsg = "provided parameters '%s' " % paramStr
                warnMsg += "are not inside the %s" % place
                logger.warn(warnMsg)
            else:
                parameter = conf.testParameter[0]

                if not intersect(USER_AGENT_ALIASES + REFERER_ALIASES + HOST_ALIASES, parameter, True):
                    debugMsg = "provided parameter '%s' " % paramStr
                    debugMsg += "is not inside the %s" % place
                    logger.debug(debugMsg)

        elif len(conf.testParameter) != len(testableParameters.keys()):
            for parameter in conf.testParameter:
                if parameter not in testableParameters:
                    debugMsg = "provided parameter '%s' " % parameter
                    debugMsg += "is not inside the %s" % place
                    logger.debug(debugMsg)

    if testableParameters:
        for parameter, value in testableParameters.items():
            if value and not value.isdigit():
                for encoding in ("hex", "base64"):
                    try:
                        decoded = value.decode(encoding)
                        if len(decoded) > MIN_ENCODED_LEN_CHECK and all(_ in string.printable for _ in decoded):
                            warnMsg = "provided parameter '%s' " % parameter
                            warnMsg += "appears to be '%s' encoded" % encoding
                            logger.warn(warnMsg)
                            break
                    except:
                        pass

    return testableParameters

def getManualDirectories():
    directories = None
    pagePath = directoryPath(conf.path)

    defaultDocRoot = DEFAULT_DOC_ROOTS.get(Backend.getOs(), DEFAULT_DOC_ROOTS[OS.LINUX])

    if kb.absFilePaths:
        for absFilePath in kb.absFilePaths:
            if directories:
                break

            if directoryPath(absFilePath) == '/':
                continue

            absFilePath = normalizePath(absFilePath)
            windowsDriveLetter = None

            if isWindowsDriveLetterPath(absFilePath):
                windowsDriveLetter, absFilePath = absFilePath[:2], absFilePath[2:]
                absFilePath = ntToPosixSlashes(posixToNtSlashes(absFilePath))

            if any("/%s/" % _ in absFilePath for _ in GENERIC_DOC_ROOT_DIRECTORY_NAMES):
                for _ in GENERIC_DOC_ROOT_DIRECTORY_NAMES:
                    _ = "/%s/" % _

                    if _ in absFilePath:
                        directories = "%s%s" % (absFilePath.split(_)[0], _)
                        break

            if pagePath and pagePath in absFilePath:
                directories = absFilePath.split(pagePath)[0]
                if windowsDriveLetter:
                    directories = "%s/%s" % (windowsDriveLetter, ntToPosixSlashes(directories))

    directories = normalizePath(directories)

    if directories:
        infoMsg = "retrieved the web server document root: '%s'" % directories
        logger.info(infoMsg)
    else:
        warnMsg = "unable to automatically retrieve the web server "
        warnMsg += "document root"
        logger.warn(warnMsg)

        directories = []

        message = "what do you want to use for writable directory?\n"
        message += "[1] common location(s) ('%s') (default)\n" % ", ".join(root for root in defaultDocRoot)
        message += "[2] custom location(s)\n"
        message += "[3] custom directory list file\n"
        message += "[4] brute force search"
        choice = readInput(message, default="1").strip()

        if choice == "2":
            message = "please provide a comma separate list of absolute directory paths: "
            directories = readInput(message, default="").split(',')
        elif choice == "3":
            message = "what's the list file location?\n"
            listPath = readInput(message, default="")
            checkFile(listPath)
            directories = getFileItems(listPath)
        elif choice == "4":
            targets = set([conf.hostname])
            _ = conf.hostname.split('.')

            if _[0] == "www":
                targets.add('.'.join(_[1:]))
                targets.add('.'.join(_[1:-1]))
            else:
                targets.add('.'.join(_[:-1]))

            targets = filter(None, targets)

            for prefix in BRUTE_DOC_ROOT_PREFIXES.get(Backend.getOs(), DEFAULT_DOC_ROOTS[OS.LINUX]):
                if BRUTE_DOC_ROOT_TARGET_MARK in prefix and re.match(IP_ADDRESS_REGEX, conf.hostname):
                    continue

                for suffix in BRUTE_DOC_ROOT_SUFFIXES:
                    for target in targets:
                        if not prefix.endswith("/%s" % suffix):
                            item = "%s/%s" % (prefix, suffix)
                        else:
                            item = prefix

                        item = item.replace(BRUTE_DOC_ROOT_TARGET_MARK, target).replace("//", '/').rstrip('/')
                        if item not in directories:
                            directories.append(item)

                        if BRUTE_DOC_ROOT_TARGET_MARK not in prefix:
                            break

            infoMsg = "using generated directory list: %s" % ','.join(directories)
            logger.info(infoMsg)

            msg = "use any additional custom directories [Enter for None]: "
            answer = readInput(msg)

            if answer:
                directories.extend(answer.split(','))

        else:
            directories = defaultDocRoot

    return directories

def getAutoDirectories():
    retVal = set()

    if kb.absFilePaths:
        infoMsg = "retrieved web server absolute paths: "
        infoMsg += "'%s'" % ", ".join(ntToPosixSlashes(path) for path in kb.absFilePaths)
        logger.info(infoMsg)

        for absFilePath in kb.absFilePaths:
            if absFilePath:
                directory = directoryPath(absFilePath)
                directory = ntToPosixSlashes(directory)
                retVal.add(directory)
    else:
        warnMsg = "unable to automatically parse any web server path"
        logger.warn(warnMsg)

    _ = extractRegexResult(r"//[^/]+?(?P<result>/.*)/", conf.url)  # web directory

    if _:
        retVal.add(_)

    return list(retVal)

def filePathToSafeString(filePath):
    """
    Returns string representation of a given filepath safe for a single filename usage

    >>> filePathToSafeString('C:/Windows/system32')
    'C__Windows_system32'
    """

    retVal = filePath.replace("/", "_").replace("\\", "_")
    retVal = retVal.replace(" ", "_").replace(":", "_")

    return retVal

def singleTimeDebugMessage(message):
    singleTimeLogMessage(message, logging.DEBUG)

def singleTimeWarnMessage(message):
    singleTimeLogMessage(message, logging.WARN)

def singleTimeLogMessage(message, level=logging.INFO, flag=None):
    if flag is None:
        flag = hash(message)

    if not conf.smokeTest and flag not in kb.singleLogFlags:
        kb.singleLogFlags.add(flag)
        logger.log(level, message)

def boldifyMessage(message):
    retVal = message

    if any(_ in message for _ in BOLD_PATTERNS):
        retVal = setColor(message, True)

    return retVal

def setColor(message, bold=False):
    retVal = message
    level = extractRegexResult(r"\[(?P<result>[A-Z ]+)\]", message) or kb.get("stickyLevel")

    if message and getattr(LOGGER_HANDLER, "is_tty", False):  # colorizing handler
        if bold:
            retVal = colored(message, color=None, on_color=None, attrs=("bold",))
        elif level:
            level = getattr(logging, level, None) if isinstance(level, basestring) else level
            _ = LOGGER_HANDLER.level_map.get(level)
            if _:
                background, foreground, bold = _
                retVal = colored(message, color=foreground, on_color="on_%s" % background if background else None, attrs=("bold",) if bold else None)

            kb.stickyLevel = level if message and message[-1] != "\n" else None

    return retVal

def dataToStdout(data, forceOutput=False, bold=False, content_type=None, status=CONTENT_STATUS.IN_PROGRESS):
    """
    Writes text to the stdout (console) stream
    """

    message = ""

    if not kb.get("threadException"):
        if forceOutput or not getCurrentThreadData().disableStdOut:
            if kb.get("multiThreadMode"):
                logging._acquireLock()

            if isinstance(data, unicode):
                message = stdoutencode(data)
            else:
                message = data

            if hasattr(conf, "api"):
                sys.stdout.write(message, status, content_type)
            else:
                sys.stdout.write(setColor(message, bold))

            try:
                sys.stdout.flush()
            except IOError:
                pass

            if kb.get("multiThreadMode"):
                logging._releaseLock()

            kb.prependFlag = isinstance(data, basestring) and (len(data) == 1 and data not in ('\n', '\r') or len(data) > 2 and data[0] == '\r' and data[-1] != '\n')

def dataToTrafficFile(data):
    if not conf.trafficFile:
        return

    try:
        conf.trafficFP.write(data)
        conf.trafficFP.flush()
    except IOError, ex:
        errMsg = "something went wrong while trying "
        errMsg += "to write to the traffic file '%s' ('%s')" % (conf.trafficFile, getSafeExString(ex))
        raise SqlmapSystemException(errMsg)

def dataToDumpFile(dumpFile, data):
    try:
        dumpFile.write(data)
        dumpFile.flush()
    except IOError, ex:
        if "No space left" in getUnicode(ex):
            errMsg = "no space left on output device"
            logger.error(errMsg)
        elif "Permission denied" in getUnicode(ex):
            errMsg = "permission denied when flushing dump data"
            logger.error(errMsg)
        else:
            raise

def dataToOutFile(filename, data):
    retVal = None

    if data:
        retVal = os.path.join(conf.filePath, filePathToSafeString(filename))

        try:
            with open(retVal, "w+b") as f:  # has to stay as non-codecs because data is raw ASCII encoded data
                f.write(unicodeencode(data))
        except IOError, ex:
            errMsg = "something went wrong while trying to write "
            errMsg += "to the output file ('%s')" % getSafeExString(ex)
            raise SqlmapGenericException(errMsg)

    return retVal

def readInput(message, default=None, checkBatch=True):
    """
    Reads input from terminal
    """

    retVal = None
    kb.stickyLevel = None

    message = getUnicode(message)

    if "\n" in message:
        message += "%s> " % ("\n" if message.count("\n") > 1 else "")
    elif message[-1] == ']':
        message += " "

    if kb.get("prependFlag"):
        message = "\n%s" % message
        kb.prependFlag = False

    if conf.get("answers"):
        for item in conf.answers.split(','):
            question = item.split('=')[0].strip()
            answer = item.split('=')[1] if len(item.split('=')) > 1 else None
            if answer and question.lower() in message.lower():
                retVal = getUnicode(answer, UNICODE_ENCODING)
            elif answer is None and retVal:
                retVal = "%s,%s" % (retVal, getUnicode(item, UNICODE_ENCODING))

    if retVal:
        dataToStdout("\r%s%s\n" % (message, retVal), forceOutput=True, bold=True)

        debugMsg = "used the given answer"
        logger.debug(debugMsg)

    if retVal is None:
        if checkBatch and conf.get("batch"):
            if isListLike(default):
                options = ",".join(getUnicode(opt, UNICODE_ENCODING) for opt in default)
            elif default:
                options = getUnicode(default, UNICODE_ENCODING)
            else:
                options = unicode()

            dataToStdout("\r%s%s\n" % (message, options), forceOutput=True, bold=True)

            debugMsg = "used the default behaviour, running in batch mode"
            logger.debug(debugMsg)

            retVal = default
        else:
            logging._acquireLock()

            if conf.get("beep"):
                beep()

            dataToStdout("\r%s" % message, forceOutput=True, bold=True)
            kb.prependFlag = False

            try:
                retVal = raw_input() or default
                retVal = getUnicode(retVal, encoding=sys.stdin.encoding) if retVal else retVal
            except:
                try:
                    time.sleep(0.05)  # Reference: http://www.gossamer-threads.com/lists/python/python/781893
                except:
                    pass
                finally:
                    kb.prependFlag = True
                    raise SqlmapUserQuitException

            finally:
                logging._releaseLock()

    return retVal

def randomRange(start=0, stop=1000, seed=None):
    """
    Returns random integer value in given range

    >>> random.seed(0)
    >>> randomRange(1, 500)
    423
    """

    if seed is not None:
        _ = getCurrentThreadData().random
        _.seed(seed)
        randint = _.randint
    else:
        randint = random.randint

    return int(randint(start, stop))

def randomInt(length=4, seed=None):
    """
    Returns random integer value with provided number of digits

    >>> random.seed(0)
    >>> randomInt(6)
    874254
    """

    if seed is not None:
        _ = getCurrentThreadData().random
        _.seed(seed)
        choice = _.choice
    else:
        choice = random.choice

    return int("".join(choice(string.digits if _ != 0 else string.digits.replace('0', '')) for _ in xrange(0, length)))

def randomStr(length=4, lowercase=False, alphabet=None, seed=None):
    """
    Returns random string value with provided number of characters

    >>> random.seed(0)
    >>> randomStr(6)
    'RNvnAv'
    """

    if seed is not None:
        _ = getCurrentThreadData().random
        _.seed(seed)
        choice = _.choice
    else:
        choice = random.choice

    if alphabet:
        retVal = "".join(choice(alphabet) for _ in xrange(0, length))
    elif lowercase:
        retVal = "".join(choice(string.ascii_lowercase) for _ in xrange(0, length))
    else:
        retVal = "".join(choice(string.ascii_letters) for _ in xrange(0, length))

    return retVal

def sanitizeStr(value):
    """
    Sanitizes string value in respect to newline and line-feed characters

    >>> sanitizeStr('foo\\n\\rbar')
    u'foo bar'
    """

    return getUnicode(value).replace("\n", " ").replace("\r", "")

def getHeader(headers, key):
    retVal = None
    for _ in (headers or {}):
        if _.upper() == key.upper():
            retVal = headers[_]
            break
    return retVal

def checkFile(filename, raiseOnError=True):
    """
    Checks for file existence and readability
    """

    valid = True

    try:
        if filename is None or not os.path.isfile(filename):
            valid = False
    except UnicodeError:
        valid = False

    if valid:
        try:
            with open(filename, "rb"):
                pass
        except:
            valid = False

    if not valid and raiseOnError:
        raise SqlmapSystemException("unable to read file '%s'" % filename)

    return valid

def banner():
    """
    This function prints sqlmap banner with its version
    """

    if not any(_ in sys.argv for _ in ("--version", "--pickled-options")):
        _ = BANNER

        if not getattr(LOGGER_HANDLER, "is_tty", False) or "--disable-coloring" in sys.argv:
            _ = re.sub("\033.+?m", "", _)
        elif IS_WIN:
            coloramainit()

        dataToStdout(_, forceOutput=True)

def parsePasswordHash(password):
    """
    In case of Microsoft SQL Server password hash value is expanded to its components
    """

    blank = " " * 8

    if not password or password == " ":
        password = NULL

    if Backend.isDbms(DBMS.MSSQL) and password != NULL and isHexEncodedString(password):
        hexPassword = password
        password = "%s\n" % hexPassword
        password += "%sheader: %s\n" % (blank, hexPassword[:6])
        password += "%ssalt: %s\n" % (blank, hexPassword[6:14])
        password += "%smixedcase: %s\n" % (blank, hexPassword[14:54])

        if not Backend.isVersionWithin(("2005", "2008")):
            password += "%suppercase: %s" % (blank, hexPassword[54:])

    return password

def cleanQuery(query):
    """
    Switch all SQL statement (alike) keywords to upper case
    """

    retVal = query

    for sqlStatements in SQL_STATEMENTS.values():
        for sqlStatement in sqlStatements:
            sqlStatementEsc = sqlStatement.replace("(", "\\(")
            queryMatch = re.search("(%s)" % sqlStatementEsc, query, re.I)

            if queryMatch and "sys_exec" not in query:
                retVal = retVal.replace(queryMatch.group(1), sqlStatement.upper())

    return retVal

def setPaths():
    """
    Sets absolute paths for project directories and files
    """

    # sqlmap paths
    paths.SQLMAP_EXTRAS_PATH = os.path.join(paths.SQLMAP_ROOT_PATH, "extra")
    paths.SQLMAP_PROCS_PATH = os.path.join(paths.SQLMAP_ROOT_PATH, "procs")
    paths.SQLMAP_SHELL_PATH = os.path.join(paths.SQLMAP_ROOT_PATH, "shell")
    paths.SQLMAP_TAMPER_PATH = os.path.join(paths.SQLMAP_ROOT_PATH, "tamper")
    paths.SQLMAP_WAF_PATH = os.path.join(paths.SQLMAP_ROOT_PATH, "waf")
    paths.SQLMAP_TXT_PATH = os.path.join(paths.SQLMAP_ROOT_PATH, "txt")
    paths.SQLMAP_UDF_PATH = os.path.join(paths.SQLMAP_ROOT_PATH, "udf")
    paths.SQLMAP_XML_PATH = os.path.join(paths.SQLMAP_ROOT_PATH, "xml")
    paths.SQLMAP_XML_BANNER_PATH = os.path.join(paths.SQLMAP_XML_PATH, "banner")
    paths.SQLMAP_XML_PAYLOADS_PATH = os.path.join(paths.SQLMAP_XML_PATH, "payloads")

    _ = os.path.join(os.path.expandvars(os.path.expanduser("~")), ".sqlmap")
    paths.SQLMAP_OUTPUT_PATH = getUnicode(paths.get("SQLMAP_OUTPUT_PATH", os.path.join(_, "output")), encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)
    paths.SQLMAP_DUMP_PATH = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "dump")
    paths.SQLMAP_FILES_PATH = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "files")

    # sqlmap files
    paths.OS_SHELL_HISTORY = os.path.join(_, "os.hst")
    paths.SQL_SHELL_HISTORY = os.path.join(_, "sql.hst")
    paths.SQLMAP_SHELL_HISTORY = os.path.join(_, "sqlmap.hst")
    paths.GITHUB_HISTORY = os.path.join(_, "github.hst")
    paths.COMMON_COLUMNS = os.path.join(paths.SQLMAP_TXT_PATH, "common-columns.txt")
    paths.COMMON_TABLES = os.path.join(paths.SQLMAP_TXT_PATH, "common-tables.txt")
    paths.COMMON_OUTPUTS = os.path.join(paths.SQLMAP_TXT_PATH, 'common-outputs.txt')
    paths.SQL_KEYWORDS = os.path.join(paths.SQLMAP_TXT_PATH, "keywords.txt")
    paths.SMALL_DICT = os.path.join(paths.SQLMAP_TXT_PATH, "smalldict.txt")
    paths.USER_AGENTS = os.path.join(paths.SQLMAP_TXT_PATH, "user-agents.txt")
    paths.WORDLIST = os.path.join(paths.SQLMAP_TXT_PATH, "wordlist.zip")
    paths.ERRORS_XML = os.path.join(paths.SQLMAP_XML_PATH, "errors.xml")
    paths.BOUNDARIES_XML = os.path.join(paths.SQLMAP_XML_PATH, "boundaries.xml")
    paths.LIVE_TESTS_XML = os.path.join(paths.SQLMAP_XML_PATH, "livetests.xml")
    paths.QUERIES_XML = os.path.join(paths.SQLMAP_XML_PATH, "queries.xml")
    paths.GENERIC_XML = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "generic.xml")
    paths.MSSQL_XML = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "mssql.xml")
    paths.MYSQL_XML = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "mysql.xml")
    paths.ORACLE_XML = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "oracle.xml")
    paths.PGSQL_XML = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "postgresql.xml")

    for path in paths.values():
        if any(path.endswith(_) for _ in (".txt", ".xml", ".zip")):
            checkFile(path)

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
        details = re.search("^(?P<dbms>%s)://(?P<credentials>(?P<user>.+?)\:(?P<pass>.*)\@)?(?P<remote>(?P<hostname>.+?)\:(?P<port>[\d]+)\/)?(?P<db>[\w\d\ \:\.\_\-\/\\\\]+?)$" % dbms, conf.direct, re.I)

        if details:
            conf.dbms = details.group("dbms")

            if details.group('credentials'):
                conf.dbmsUser = details.group("user")
                conf.dbmsPass = details.group("pass")
            else:
                if conf.dbmsCred:
                    conf.dbmsUser, conf.dbmsPass = conf.dbmsCred.split(':')
                else:
                    conf.dbmsUser = unicode()
                    conf.dbmsPass = unicode()

            if not conf.dbmsPass:
                conf.dbmsPass = None

            if details.group("remote"):
                remote = True
                conf.hostname = details.group("hostname").strip()
                conf.port = int(details.group("port"))
            else:
                conf.hostname = "localhost"
                conf.port = 0

            conf.dbmsDb = details.group("db")
            conf.parameters[None] = "direct connection"

            break

    if not details:
        errMsg = "invalid target details, valid syntax is for instance "
        errMsg += "'mysql://USER:PASSWORD@DBMS_IP:DBMS_PORT/DATABASE_NAME' "
        errMsg += "or 'access://DATABASE_FILEPATH'"
        raise SqlmapSyntaxException(errMsg)

    for dbmsName, data in DBMS_DICT.items():
        if dbmsName == conf.dbms or conf.dbms.lower() in data[0]:
            try:
                if dbmsName in (DBMS.ACCESS, DBMS.SQLITE, DBMS.FIREBIRD):
                    if remote:
                        warnMsg = "direct connection over the network for "
                        warnMsg += "%s DBMS is not supported" % dbmsName
                        logger.warn(warnMsg)

                        conf.hostname = "localhost"
                        conf.port = 0
                elif not remote:
                    errMsg = "missing remote connection details (e.g. "
                    errMsg += "'mysql://USER:PASSWORD@DBMS_IP:DBMS_PORT/DATABASE_NAME' "
                    errMsg += "or 'access://DATABASE_FILEPATH')"
                    raise SqlmapSyntaxException(errMsg)

                if dbmsName in (DBMS.MSSQL, DBMS.SYBASE):
                    import _mssql
                    import pymssql

                    if not hasattr(pymssql, "__version__") or pymssql.__version__ < "1.0.2":
                        errMsg = "'%s' third-party library must be " % data[1]
                        errMsg += "version >= 1.0.2 to work properly. "
                        errMsg += "Download from '%s'" % data[2]
                        raise SqlmapMissingDependence(errMsg)

                elif dbmsName == DBMS.MYSQL:
                    import pymysql
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
            except ImportError:
                if _sqlalchemy and data[3] in _sqlalchemy.dialects.__all__:
                    pass
                else:
                    errMsg = "sqlmap requires '%s' third-party library " % data[1]
                    errMsg += "in order to directly connect to the DBMS "
                    errMsg += "%s. You can download it from '%s'" % (dbmsName, data[2])
                    errMsg += ". Alternative is to use a package 'python-sqlalchemy' "
                    errMsg += "with support for dialect '%s' installed" % data[3]
                    raise SqlmapMissingDependence(errMsg)

def parseTargetUrl():
    """
    Parse target URL and set some attributes into the configuration singleton.
    """

    if not conf.url:
        return

    originalUrl = conf.url

    if re.search("\[.+\]", conf.url) and not socket.has_ipv6:
        errMsg = "IPv6 addressing is not supported "
        errMsg += "on this platform"
        raise SqlmapGenericException(errMsg)

    if not re.search("^http[s]*://", conf.url, re.I) and \
            not re.search("^ws[s]*://", conf.url, re.I):
        if ":443/" in conf.url:
            conf.url = "https://" + conf.url
        else:
            conf.url = "http://" + conf.url

    if CUSTOM_INJECTION_MARK_CHAR in conf.url:
        conf.url = conf.url.replace('?', URI_QUESTION_MARKER)

    try:
        urlSplit = urlparse.urlsplit(conf.url)
    except ValueError, ex:
        errMsg = "invalid URL '%s' has been given ('%s'). " % (conf.url, getSafeExString(ex))
        errMsg += "Please be sure that you don't have any leftover characters (e.g. '[' or ']') "
        errMsg += "in the hostname part"
        raise SqlmapGenericException(errMsg)

    hostnamePort = urlSplit.netloc.split(":") if not re.search("\[.+\]", urlSplit.netloc) else filter(None, (re.search("\[.+\]", urlSplit.netloc).group(0), re.search("\](:(?P<port>\d+))?", urlSplit.netloc).group("port")))

    conf.scheme = urlSplit.scheme.strip().lower() if not conf.forceSSL else "https"
    conf.path = urlSplit.path.strip()
    conf.hostname = hostnamePort[0].strip()

    conf.ipv6 = conf.hostname != conf.hostname.strip("[]")
    conf.hostname = conf.hostname.strip("[]").replace(CUSTOM_INJECTION_MARK_CHAR, "")

    try:
        _ = conf.hostname.encode("idna")
    except LookupError:
        _ = conf.hostname.encode(UNICODE_ENCODING)
    except UnicodeError:
        _ = None

    if any((_ is None, re.search(r'\s', conf.hostname), '..' in conf.hostname, conf.hostname.startswith('.'), '\n' in originalUrl)):
        errMsg = "invalid target URL ('%s')" % originalUrl
        raise SqlmapSyntaxException(errMsg)

    if len(hostnamePort) == 2:
        try:
            conf.port = int(hostnamePort[1])
        except:
            errMsg = "invalid target URL"
            raise SqlmapSyntaxException(errMsg)
    elif conf.scheme == "https":
        conf.port = 443
    else:
        conf.port = 80

    if conf.port < 0 or conf.port > 65535:
        errMsg = "invalid target URL's port (%d)" % conf.port
        raise SqlmapSyntaxException(errMsg)

    conf.url = getUnicode("%s://%s:%d%s" % (conf.scheme, ("[%s]" % conf.hostname) if conf.ipv6 else conf.hostname, conf.port, conf.path))
    conf.url = conf.url.replace(URI_QUESTION_MARKER, '?')

    if urlSplit.query:
        if '=' not in urlSplit.query:
            conf.url = "%s?%s" % (conf.url, getUnicode(urlSplit.query))
        else:
            conf.parameters[PLACE.GET] = urldecode(urlSplit.query) if urlSplit.query and urlencode(DEFAULT_GET_POST_DELIMITER, None) not in urlSplit.query else urlSplit.query

    if not conf.referer and (intersect(REFERER_ALIASES, conf.testParameter, True) or conf.level >= 3):
        debugMsg = "setting the HTTP Referer header to the target URL"
        logger.debug(debugMsg)
        conf.httpHeaders = filter(lambda (key, value): key != HTTP_HEADER.REFERER, conf.httpHeaders)
        conf.httpHeaders.append((HTTP_HEADER.REFERER, conf.url.replace(CUSTOM_INJECTION_MARK_CHAR, "")))

    if not conf.host and (intersect(HOST_ALIASES, conf.testParameter, True) or conf.level >= 5):
        debugMsg = "setting the HTTP Host header to the target URL"
        logger.debug(debugMsg)
        conf.httpHeaders = filter(lambda (key, value): key != HTTP_HEADER.HOST, conf.httpHeaders)
        conf.httpHeaders.append((HTTP_HEADER.HOST, getHostHeader(conf.url)))

    if conf.url != originalUrl:
        kb.originalUrls[conf.url] = originalUrl

def expandAsteriskForColumns(expression):
    """
    If the user provided an asterisk rather than the column(s)
    name, sqlmap will retrieve the columns itself and reprocess
    the SQL query string (expression)
    """

    asterisk = re.search("^SELECT(\s+TOP\s+[\d]+)?\s+\*\s+FROM\s+`?([^`\s()]+)", expression, re.I)

    if asterisk:
        infoMsg = "you did not provide the fields in your query. "
        infoMsg += "sqlmap will retrieve the column names itself"
        logger.info(infoMsg)

        _ = asterisk.group(2).replace("..", ".").replace(".dbo.", ".")
        db, conf.tbl = _.split(".", 1) if '.' in _ else (None, _)
        if db is None:
            if expression != conf.query:
                conf.db = db
            else:
                expression = re.sub(r"([^\w])%s" % re.escape(conf.tbl), "\g<1>%s.%s" % (conf.db, conf.tbl), expression)
        else:
            conf.db = db
        conf.db = safeSQLIdentificatorNaming(conf.db)
        conf.tbl = safeSQLIdentificatorNaming(conf.tbl, True)

        columnsDict = conf.dbmsHandler.getColumns(onlyColNames=True)

        if columnsDict and conf.db in columnsDict and conf.tbl in columnsDict[conf.db]:
            columns = columnsDict[conf.db][conf.tbl].keys()
            columns.sort()
            columnsStr = ", ".join(column for column in columns)
            expression = expression.replace("*", columnsStr, 1)

            infoMsg = "the query with expanded column name(s) is: "
            infoMsg += "%s" % expression
            logger.info(infoMsg)

    return expression

def getLimitRange(count, plusOne=False):
    """
    Returns range of values used in limit/offset constructs

    >>> [_ for _ in getLimitRange(10)]
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    """

    retVal = None
    count = int(count)
    limitStart, limitStop = 1, count

    if isinstance(conf.limitStop, int) and conf.limitStop > 0 and conf.limitStop < limitStop:
        limitStop = conf.limitStop

    if isinstance(conf.limitStart, int) and conf.limitStart > 0 and conf.limitStart <= limitStop:
        limitStart = conf.limitStart

    retVal = xrange(limitStart, limitStop + 1) if plusOne else xrange(limitStart - 1, limitStop)

    return retVal

def parseUnionPage(page):
    """
    Returns resulting items from UNION query inside provided page content
    """

    if page is None:
        return None

    if re.search("(?si)\A%s.*%s\Z" % (kb.chars.start, kb.chars.stop), page):
        if len(page) > LARGE_OUTPUT_THRESHOLD:
            warnMsg = "large output detected. This might take a while"
            logger.warn(warnMsg)

        data = BigArray()
        keys = set()

        for match in re.finditer("%s(.*?)%s" % (kb.chars.start, kb.chars.stop), page, re.DOTALL | re.IGNORECASE):
            entry = match.group(1)

            if kb.chars.start in entry:
                entry = entry.split(kb.chars.start)[-1]

            if kb.unionDuplicates:
                key = entry.lower()
                if key not in keys:
                    keys.add(key)
                else:
                    continue

            entry = entry.split(kb.chars.delimiter)

            if conf.hexConvert:
                entry = applyFunctionRecursively(entry, decodeHexValue)

            if kb.safeCharEncode:
                entry = applyFunctionRecursively(entry, safecharencode)

            data.append(entry[0] if len(entry) == 1 else entry)
    else:
        data = page

    if len(data) == 1 and isinstance(data[0], basestring):
        data = data[0]

    return data

def parseFilePaths(page):
    """
    Detects (possible) absolute system paths inside the provided page content
    """

    if page:
        for regex in FILE_PATH_REGEXES:
            for match in re.finditer(regex, page):
                absFilePath = match.group("result").strip()
                page = page.replace(absFilePath, "")

                if isWindowsDriveLetterPath(absFilePath):
                    absFilePath = posixToNtSlashes(absFilePath)

                if absFilePath not in kb.absFilePaths:
                    kb.absFilePaths.add(absFilePath)

def getLocalIP():
    """
    Get local IP address (exposed to the remote/target)
    """

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
    """
    Get remote/target IP address
    """

    retVal = None

    try:
        retVal = socket.gethostbyname(conf.hostname)
    except socket.gaierror:
        errMsg = "address resolution problem "
        errMsg += "occurred for hostname '%s'" % conf.hostname
        singleTimeLogMessage(errMsg, logging.ERROR)

    return retVal

def getFileType(filePath):
    try:
        _ = magic.from_file(filePath)
    except:
        return "unknown"

    return "text" if "ASCII" in _ or "text" in _ else "binary"

def getCharset(charsetType=None):
    """
    Returns list with integers representing characters of a given
    charset type appropriate for inference techniques

    >>> getCharset(CHARSET_TYPE.BINARY)
    [0, 1, 47, 48, 49]
    """

    asciiTbl = []

    if charsetType is None:
        asciiTbl.extend(xrange(0, 128))

    # 0 or 1
    elif charsetType == CHARSET_TYPE.BINARY:
        asciiTbl.extend([0, 1])
        asciiTbl.extend(xrange(47, 50))

    # Digits
    elif charsetType == CHARSET_TYPE.DIGITS:
        asciiTbl.extend([0, 1])
        asciiTbl.extend(xrange(47, 58))

    # Hexadecimal
    elif charsetType == CHARSET_TYPE.HEXADECIMAL:
        asciiTbl.extend([0, 1])
        asciiTbl.extend(xrange(47, 58))
        asciiTbl.extend(xrange(64, 71))
        asciiTbl.extend([87, 88])  # X
        asciiTbl.extend(xrange(96, 103))
        asciiTbl.extend([119, 120])  # x

    # Characters
    elif charsetType == CHARSET_TYPE.ALPHA:
        asciiTbl.extend([0, 1])
        asciiTbl.extend(xrange(64, 91))
        asciiTbl.extend(xrange(96, 123))

    # Characters and digits
    elif charsetType == CHARSET_TYPE.ALPHANUM:
        asciiTbl.extend([0, 1])
        asciiTbl.extend(xrange(47, 58))
        asciiTbl.extend(xrange(64, 91))
        asciiTbl.extend(xrange(96, 123))

    return asciiTbl

def directoryPath(filepath):
    """
    Returns directory path for a given filepath

    >>> directoryPath('/var/log/apache.log')
    '/var/log'
    """

    retVal = filepath

    if filepath:
        retVal = ntpath.dirname(filepath) if isWindowsDriveLetterPath(filepath) else posixpath.dirname(filepath)

    return retVal

def normalizePath(filepath):
    """
    Returns normalized string representation of a given filepath

    >>> normalizePath('//var///log/apache.log')
    '//var/log/apache.log'
    """

    retVal = filepath

    if retVal:
        retVal = retVal.strip("\r\n")
        retVal = ntpath.normpath(retVal) if isWindowsDriveLetterPath(retVal) else posixpath.normpath(retVal)

    return retVal

def safeExpandUser(filepath):
    """
    Patch for a Python Issue18171 (http://bugs.python.org/issue18171)
    """

    retVal = filepath

    try:
        retVal = os.path.expanduser(filepath)
    except UnicodeError:
        _ = locale.getdefaultlocale()
        encoding = _[1] if _ and len(_) > 1 else UNICODE_ENCODING
        retVal = getUnicode(os.path.expanduser(filepath.encode(encoding)), encoding=encoding)

    return retVal

def safeStringFormat(format_, params):
    """
    Avoids problems with inappropriate string format strings

    >>> safeStringFormat('SELECT foo FROM %s LIMIT %d', ('bar', '1'))
    u'SELECT foo FROM bar LIMIT 1'
    """

    if format_.count(PAYLOAD_DELIMITER) == 2:
        _ = format_.split(PAYLOAD_DELIMITER)
        _[1] = re.sub(r"(\A|[^A-Za-z0-9])(%d)([^A-Za-z0-9]|\Z)", r"\g<1>%s\g<3>", _[1])
        retVal = PAYLOAD_DELIMITER.join(_)
    else:
        retVal = re.sub(r"(\A|[^A-Za-z0-9])(%d)([^A-Za-z0-9]|\Z)", r"\g<1>%s\g<3>", format_)

    if isinstance(params, basestring):
        retVal = retVal.replace("%s", params, 1)
    elif not isListLike(params):
        retVal = retVal.replace("%s", str(params), 1)
    else:
        start, end = 0, len(retVal)
        match = re.search(r"%s(.+)%s" % (PAYLOAD_DELIMITER, PAYLOAD_DELIMITER), retVal)
        if match and PAYLOAD_DELIMITER not in match.group(1):
            start, end = match.start(), match.end()
        if retVal.count("%s", start, end) == len(params):
            for param in params:
                index = retVal.find("%s", start)
                retVal = retVal[:index] + getUnicode(param) + retVal[index + 2:]
        else:
            if any('%s' in _ for _ in conf.parameters.values()):
                parts = format_.split(' ')
                for i in xrange(len(parts)):
                    if PAYLOAD_DELIMITER in parts[i]:
                        parts[i] = parts[i].replace(PAYLOAD_DELIMITER, "")
                        parts[i] = "%s%s" % (parts[i], PAYLOAD_DELIMITER)
                        break
                format_ = ' '.join(parts)

            count = 0
            while True:
                match = re.search(r"(\A|[^A-Za-z0-9])(%s)([^A-Za-z0-9]|\Z)", retVal)
                if match:
                    if count >= len(params):
                        warnMsg = "wrong number of parameters during string formatting. "
                        warnMsg += "Please report by e-mail content \"%r | %r | %r\" to 'dev@sqlmap.org'" % (format_, params, retVal)
                        raise SqlmapValueException(warnMsg)
                    else:
                        retVal = re.sub(r"(\A|[^A-Za-z0-9])(%s)([^A-Za-z0-9]|\Z)", r"\g<1>%s\g<3>" % params[count], retVal, 1)
                        count += 1
                else:
                    break
    return retVal

def getFilteredPageContent(page, onlyText=True):
    """
    Returns filtered page content without script, style and/or comments
    or all HTML tags

    >>> getFilteredPageContent(u'<html><title>foobar</title><body>test</body></html>')
    u'foobar test'
    """

    retVal = page

    # only if the page's charset has been successfully identified
    if isinstance(page, unicode):
        retVal = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>%s" % (r"|<[^>]+>|\t|\n|\r" if onlyText else ""), " ", page)
        while retVal.find("  ") != -1:
            retVal = retVal.replace("  ", " ")
        retVal = htmlunescape(retVal.strip())

    return retVal

def getPageWordSet(page):
    """
    Returns word set used in page content

    >>> sorted(getPageWordSet(u'<html><title>foobar</title><body>test</body></html>'))
    [u'foobar', u'test']
    """

    retVal = set()

    # only if the page's charset has been successfully identified
    if isinstance(page, unicode):
        _ = getFilteredPageContent(page)
        retVal = set(re.findall(r"\w+", _))

    return retVal

def showStaticWords(firstPage, secondPage):
    """
    Prints words appearing in two different response pages
    """

    infoMsg = "finding static words in longest matching part of dynamic page content"
    logger.info(infoMsg)

    firstPage = getFilteredPageContent(firstPage)
    secondPage = getFilteredPageContent(secondPage)

    infoMsg = "static words: "

    if firstPage and secondPage:
        match = SequenceMatcher(None, firstPage, secondPage).find_longest_match(0, len(firstPage), 0, len(secondPage))
        commonText = firstPage[match[0]:match[0] + match[2]]
        commonWords = getPageWordSet(commonText)
    else:
        commonWords = None

    if commonWords:
        commonWords = list(commonWords)
        commonWords.sort(lambda a, b: cmp(a.lower(), b.lower()))

        for word in commonWords:
            if len(word) > 2:
                infoMsg += "'%s', " % word

        infoMsg = infoMsg.rstrip(", ")
    else:
        infoMsg += "None"

    logger.info(infoMsg)

def isWindowsDriveLetterPath(filepath):
    """
    Returns True if given filepath starts with a Windows drive letter

    >>> isWindowsDriveLetterPath('C:\\boot.ini')
    True
    >>> isWindowsDriveLetterPath('/var/log/apache.log')
    False
    """

    return re.search("\A[\w]\:", filepath) is not None

def posixToNtSlashes(filepath):
    """
    Replaces all occurances of Posix slashes (/) in provided
    filepath with NT ones (\)

    >>> posixToNtSlashes('C:/Windows')
    'C:\\\\Windows'
    """

    return filepath.replace('/', '\\') if filepath else filepath

def ntToPosixSlashes(filepath):
    """
    Replaces all occurances of NT slashes (\) in provided
    filepath with Posix ones (/)

    >>> ntToPosixSlashes('C:\\Windows')
    'C:/Windows'
    """

    return filepath.replace('\\', '/') if filepath else filepath

def isHexEncodedString(subject):
    """
    Checks if the provided string is hex encoded

    >>> isHexEncodedString('DEADBEEF')
    True
    >>> isHexEncodedString('test')
    False
    """

    return re.match(r"\A[0-9a-fA-Fx]+\Z", subject) is not None

@cachedmethod
def getConsoleWidth(default=80):
    """
    Returns console width
    """

    width = None

    if os.getenv("COLUMNS", "").isdigit():
        width = int(os.getenv("COLUMNS"))
    else:
        try:
            try:
                FNULL = open(os.devnull, 'w')
            except IOError:
                FNULL = None
            process = execute("stty size", shell=True, stdout=PIPE, stderr=FNULL or PIPE)
            stdout, _ = process.communicate()
            items = stdout.split()

            if len(items) == 2 and items[1].isdigit():
                width = int(items[1])
        except (OSError, MemoryError):
            pass

    if width is None:
        try:
            import curses

            stdscr = curses.initscr()
            _, width = stdscr.getmaxyx()
            curses.endwin()
        except:
            pass

    return width or default

def clearConsoleLine(forceOutput=False):
    """
    Clears current console line
    """

    if getattr(LOGGER_HANDLER, "is_tty", False):
        dataToStdout("\r%s\r" % (" " * (getConsoleWidth() - 1)), forceOutput)

    kb.prependFlag = False
    kb.stickyLevel = None

def parseXmlFile(xmlFile, handler):
    """
    Parses XML file by a given handler
    """

    try:
        with contextlib.closing(StringIO(readCachedFileContent(xmlFile))) as stream:
            parse(stream, handler)
    except (SAXParseException, UnicodeError), ex:
        errMsg = "something appears to be wrong with "
        errMsg += "the file '%s' ('%s'). Please make " % (xmlFile, getSafeExString(ex))
        errMsg += "sure that you haven't made any changes to it"
        raise SqlmapInstallationException, errMsg

def getSQLSnippet(dbms, sfile, **variables):
    """
    Returns content of SQL snippet located inside 'procs/' directory
    """

    if sfile.endswith('.sql') and os.path.exists(sfile):
        filename = sfile
    elif not sfile.endswith('.sql') and os.path.exists("%s.sql" % sfile):
        filename = "%s.sql" % sfile
    else:
        filename = os.path.join(paths.SQLMAP_PROCS_PATH, DBMS_DIRECTORY_DICT[dbms], sfile if sfile.endswith('.sql') else "%s.sql" % sfile)
        checkFile(filename)

    retVal = readCachedFileContent(filename)
    retVal = re.sub(r"#.+", "", retVal)
    retVal = re.sub(r"(?s);\s+", "; ", retVal).strip("\r\n")

    for _ in variables.keys():
        retVal = re.sub(r"%%%s%%" % _, variables[_], retVal)

    for _ in re.findall(r"%RANDSTR\d+%", retVal, re.I):
        retVal = retVal.replace(_, randomStr())

    for _ in re.findall(r"%RANDINT\d+%", retVal, re.I):
        retVal = retVal.replace(_, randomInt())

    variables = re.findall(r"(?<!\bLIKE ')%(\w+)%", retVal, re.I)

    if variables:
        errMsg = "unresolved variable%s '%s' in SQL file '%s'" % ("s" if len(variables) > 1 else "", ", ".join(variables), sfile)
        logger.error(errMsg)

        msg = "do you want to provide the substitution values? [y/N] "
        choice = readInput(msg, default="N")

        if choice and choice[0].lower() == "y":
            for var in variables:
                msg = "insert value for variable '%s': " % var
                val = readInput(msg, default="")
                retVal = retVal.replace(r"%%%s%%" % var, val)

    return retVal

def readCachedFileContent(filename, mode='rb'):
    """
    Cached reading of file content (avoiding multiple same file reading)
    """

    if filename not in kb.cache.content:
        with kb.locks.cache:
            if filename not in kb.cache.content:
                checkFile(filename)
                try:
                    with openFile(filename, mode) as f:
                        kb.cache.content[filename] = f.read()
                except (IOError, OSError, MemoryError), ex:
                    errMsg = "something went wrong while trying "
                    errMsg += "to read the content of file '%s' ('%s')" % (filename, getSafeExString(ex))
                    raise SqlmapSystemException(errMsg)

    return kb.cache.content[filename]

def readXmlFile(xmlFile):
    """
    Reads XML file content and returns its DOM representation
    """

    checkFile(xmlFile)
    retVal = minidom.parse(xmlFile).documentElement

    return retVal

def stdev(values):
    """
    Computes standard deviation of a list of numbers.
    Reference: http://www.goldb.org/corestats.html

    >>> stdev([0.9, 0.9, 0.9, 1.0, 0.8, 0.9])
    0.06324555320336757
    """

    if not values or len(values) < 2:
        return None

    key = (values[0], values[-1], len(values))

    if kb.get("cache") and key in kb.cache.stdev:
        retVal = kb.cache.stdev[key]
    else:
        avg = average(values)
        _ = reduce(lambda x, y: x + pow((y or 0) - avg, 2), values, 0.0)
        retVal = sqrt(_ / (len(values) - 1))
        if kb.get("cache"):
            kb.cache.stdev[key] = retVal

    return retVal

def average(values):
    """
    Computes the arithmetic mean of a list of numbers.

    >>> average([0.9, 0.9, 0.9, 1.0, 0.8, 0.9])
    0.9
    """

    return (sum(values) / len(values)) if values else None

def calculateDeltaSeconds(start):
    """
    Returns elapsed time from start till now
    """

    return time.time() - start

def initCommonOutputs():
    """
    Initializes dictionary containing common output values used by "good samaritan" feature
    """

    kb.commonOutputs = {}
    key = None

    with openFile(paths.COMMON_OUTPUTS, 'r') as f:
        for line in f.readlines():  # xreadlines doesn't return unicode strings when codec.open() is used
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

def getFileItems(filename, commentPrefix='#', unicode_=True, lowercase=False, unique=False):
    """
    Returns newline delimited items contained inside file
    """

    retVal = list() if not unique else OrderedDict()

    checkFile(filename)

    try:
        with openFile(filename, 'r', errors="ignore") if unicode_ else open(filename, 'r') as f:
            for line in (f.readlines() if unicode_ else f.xreadlines()):  # xreadlines doesn't return unicode strings when codec.open() is used
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

                    if unique:
                        retVal[line] = True
                    else:
                        retVal.append(line)
    except (IOError, OSError, MemoryError), ex:
        errMsg = "something went wrong while trying "
        errMsg += "to read the content of file '%s' ('%s')" % (filename, getSafeExString(ex))
        raise SqlmapSystemException(errMsg)

    return retVal if not unique else retVal.keys()

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

def getPartRun(alias=True):
    """
    Goes through call stack and finds constructs matching conf.dbmsHandler.*.
    Returns it or its alias used in txt/common-outputs.txt
    """

    retVal = None
    commonPartsDict = optDict["Enumeration"]

    try:
        stack = [item[4][0] if isinstance(item[4], list) else '' for item in inspect.stack()]

        # Goes backwards through the stack to find the conf.dbmsHandler method
        # calling this function
        for i in xrange(0, len(stack) - 1):
            for regex in (r"self\.(get[^(]+)\(\)", r"conf\.dbmsHandler\.([^(]+)\(\)"):
                match = re.search(regex, stack[i])

                if match:
                    # This is the calling conf.dbmsHandler or self method
                    # (e.g. 'getDbms')
                    retVal = match.groups()[0]
                    break

            if retVal is not None:
                break

    # Reference: http://coding.derkeiler.com/Archive/Python/comp.lang.python/2004-06/2267.html
    except TypeError:
        pass

    # Return the INI tag to consider for common outputs (e.g. 'Databases')
    if alias:
        return commonPartsDict[retVal][1] if isinstance(commonPartsDict.get(retVal), tuple) else retVal
    else:
        return retVal

def getUnicode(value, encoding=None, noneToNull=False):
    """
    Return the unicode representation of the supplied value:

    >>> getUnicode(u'test')
    u'test'
    >>> getUnicode('test')
    u'test'
    >>> getUnicode(1)
    u'1'
    """

    if noneToNull and value is None:
        return NULL

    if isListLike(value):
        value = list(getUnicode(_, encoding, noneToNull) for _ in value)
        return value

    if isinstance(value, unicode):
        return value
    elif isinstance(value, basestring):
        while True:
            try:
                return unicode(value, encoding or (kb.get("pageEncoding") if kb.get("originalPage") else None) or UNICODE_ENCODING)
            except UnicodeDecodeError, ex:
                try:
                    return unicode(value, UNICODE_ENCODING)
                except:
                    value = value[:ex.start] + "".join(INVALID_UNICODE_CHAR_FORMAT % ord(_) for _ in value[ex.start:ex.end]) + value[ex.end:]
    else:
        try:
            return unicode(value)
        except UnicodeDecodeError:
            return unicode(str(value), errors="ignore")  # encoding ignored for non-basestring instances

def longestCommonPrefix(*sequences):
    """
    Returns longest common prefix occuring in given sequences
    Reference: http://boredzo.org/blog/archives/2007-01-06/longest-common-prefix-in-python-2

    >>> longestCommonPrefix('foobar', 'fobar')
    'fo'
    """

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

    _ = None
    success = False

    for i in xrange(PUSH_VALUE_EXCEPTION_RETRY_COUNT):
        try:
            getCurrentThreadData().valueStack.append(copy.deepcopy(value))
            success = True
            break
        except Exception, ex:
            _ = ex

    if not success:
        getCurrentThreadData().valueStack.append(None)

        if _:
            raise _

def popValue():
    """
    Pop value from the stack (thread dependent)

    >>> pushValue('foobar')
    >>> popValue()
    'foobar'
    """

    return getCurrentThreadData().valueStack.pop()

def wasLastResponseDBMSError():
    """
    Returns True if the last web request resulted in a (recognized) DBMS error page
    """

    threadData = getCurrentThreadData()
    return threadData.lastErrorPage and threadData.lastErrorPage[0] == threadData.lastRequestUID

def wasLastResponseHTTPError():
    """
    Returns True if the last web request resulted in an errornous HTTP code (like 500)
    """

    threadData = getCurrentThreadData()
    return threadData.lastHTTPError and threadData.lastHTTPError[0] == threadData.lastRequestUID

def wasLastResponseDelayed():
    """
    Returns True if the last web request resulted in a time-delay
    """

    # 99.9999999997440% of all non time-based SQL injection affected
    # response times should be inside +-7*stdev([normal response times])
    # Math reference: http://www.answers.com/topic/standard-deviation

    deviation = stdev(kb.responseTimes.get(kb.responseTimeMode, []))
    threadData = getCurrentThreadData()

    if deviation and not conf.direct:
        if len(kb.responseTimes[kb.responseTimeMode]) < MIN_TIME_RESPONSES:
            warnMsg = "time-based standard deviation method used on a model "
            warnMsg += "with less than %d response times" % MIN_TIME_RESPONSES
            logger.warn(warnMsg)

        lowerStdLimit = average(kb.responseTimes[kb.responseTimeMode]) + TIME_STDEV_COEFF * deviation
        retVal = (threadData.lastQueryDuration >= max(MIN_VALID_DELAYED_RESPONSE, lowerStdLimit))

        if not kb.testMode and retVal:
            if kb.adjustTimeDelay is None:
                msg = "do you want sqlmap to try to optimize value(s) "
                msg += "for DBMS delay responses (option '--time-sec')? [Y/n] "
                choice = readInput(msg, default='Y')
                kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE if choice.upper() == 'N' else ADJUST_TIME_DELAY.YES
            if kb.adjustTimeDelay is ADJUST_TIME_DELAY.YES:
                adjustTimeDelay(threadData.lastQueryDuration, lowerStdLimit)

        return retVal
    else:
        return (threadData.lastQueryDuration - conf.timeSec) >= 0

def adjustTimeDelay(lastQueryDuration, lowerStdLimit):
    """
    Provides tip for adjusting time delay in time-based data retrieval
    """

    candidate = 1 + int(round(lowerStdLimit))

    if candidate:
        kb.delayCandidates = [candidate] + kb.delayCandidates[:-1]

        if all((x == candidate for x in kb.delayCandidates)) and candidate < conf.timeSec:
            conf.timeSec = candidate

            infoMsg = "adjusting time delay to "
            infoMsg += "%d second%s due to good response times" % (conf.timeSec, 's' if conf.timeSec > 1 else '')
            logger.info(infoMsg)

def getLastRequestHTTPError():
    """
    Returns last HTTP error code
    """

    threadData = getCurrentThreadData()
    return threadData.lastHTTPError[1] if threadData.lastHTTPError else None

def extractErrorMessage(page):
    """
    Returns reported error message from page if it founds one

    >>> extractErrorMessage(u'<html><title>Test</title>\\n<b>Warning</b>: oci_parse() [function.oci-parse]: ORA-01756: quoted string not properly terminated<br><p>Only a test page</p></html>')
    u'oci_parse() [function.oci-parse]: ORA-01756: quoted string not properly terminated'
    """

    retVal = None

    if isinstance(page, basestring):
        for regex in ERROR_PARSING_REGEXES:
            match = re.search(regex, page, re.DOTALL | re.IGNORECASE)

            if match:
                retVal = htmlunescape(match.group("result")).replace("<br>", "\n").strip()
                break

    return retVal

def findMultipartPostBoundary(post):
    """
    Finds value for a boundary parameter in given multipart POST body
    """

    retVal = None

    done = set()
    candidates = []

    for match in re.finditer(r"(?m)^--(.+?)(--)?$", post or ""):
        _ = match.group(1).strip().strip('-')

        if _ in done:
            continue
        else:
            candidates.append((post.count(_), _))
            done.add(_)

    if candidates:
        candidates.sort(key=lambda _: _[0], reverse=True)
        retVal = candidates[0][1]

    return retVal

def urldecode(value, encoding=None, unsafe="%%&=;+%s" % CUSTOM_INJECTION_MARK_CHAR, convall=False, plusspace=True):
    """
    URL decodes given value

    >>> urldecode('AND%201%3E%282%2B3%29%23', convall=True)
    u'AND 1>(2+3)#'
    """

    result = value

    if value:
        try:
            # for cases like T%C3%BCrk%C3%A7e
            value = str(value)
        except ValueError:
            pass
        finally:
            if convall:
                result = urllib.unquote_plus(value) if plusspace else urllib.unquote(value)
            else:
                def _(match):
                    charset = reduce(lambda x, y: x.replace(y, ""), unsafe, string.printable)
                    char = chr(ord(match.group(1).decode("hex")))
                    return char if char in charset else match.group(0)
                result = value
                if plusspace:
                    result = result.replace("+", " ")  # plus sign has a special meaning in URL encoded data (hence the usage of urllib.unquote_plus in convall case)
                result = re.sub("%([0-9a-fA-F]{2})", _, result)

    if isinstance(result, str):
        result = unicode(result, encoding or UNICODE_ENCODING, "replace")

    return result

def urlencode(value, safe="%&=-_", convall=False, limit=False, spaceplus=False):
    """
    URL encodes given value

    >>> urlencode('AND 1>(2+3)#')
    'AND%201%3E%282%2B3%29%23'
    """

    if conf.get("direct"):
        return value

    count = 0
    result = None if value is None else ""

    if value:
        if Backend.isDbms(DBMS.MSSQL) and not kb.tamperFunctions and any(ord(_) > 255 for _ in value):
            warnMsg = "if you experience problems with "
            warnMsg += "non-ASCII identifier names "
            warnMsg += "you are advised to rerun with '--tamper=charunicodeencode'"
            singleTimeWarnMessage(warnMsg)

        if convall or safe is None:
            safe = ""

        # corner case when character % really needs to be
        # encoded (when not representing URL encoded char)
        # except in cases when tampering scripts are used
        if all(map(lambda x: '%' in x, [safe, value])) and not kb.tamperFunctions:
            value = re.sub("%(?![0-9a-fA-F]{2})", "%25", value)

        while True:
            result = urllib.quote(utf8encode(value), safe)

            if limit and len(result) > URLENCODE_CHAR_LIMIT:
                if count >= len(URLENCODE_FAILSAFE_CHARS):
                    break

                while count < len(URLENCODE_FAILSAFE_CHARS):
                    safe += URLENCODE_FAILSAFE_CHARS[count]
                    count += 1
                    if safe[-1] in value:
                        break
            else:
                break

        if spaceplus:
            result = result.replace(urllib.quote(' '), '+')

    return result

def runningAsAdmin():
    """
    Returns True if the current process is run under admin privileges
    """

    isAdmin = None

    if PLATFORM in ("posix", "mac"):
        _ = os.geteuid()

        isAdmin = isinstance(_, (int, float, long)) and _ == 0
    elif IS_WIN:
        import ctypes

        _ = ctypes.windll.shell32.IsUserAnAdmin()

        isAdmin = isinstance(_, (int, float, long)) and _ == 1
    else:
        errMsg = "sqlmap is not able to check if you are running it "
        errMsg += "as an administrator account on this platform. "
        errMsg += "sqlmap will assume that you are an administrator "
        errMsg += "which is mandatory for the requested takeover attack "
        errMsg += "to work properly"
        logger.error(errMsg)

        isAdmin = True

    return isAdmin

def logHTTPTraffic(requestLogMsg, responseLogMsg):
    """
    Logs HTTP traffic to the output file
    """

    if not conf.trafficFile:
        return

    with kb.locks.log:
        dataToTrafficFile("%s%s" % (requestLogMsg, os.linesep))
        dataToTrafficFile("%s%s" % (responseLogMsg, os.linesep))
        dataToTrafficFile("%s%s%s%s" % (os.linesep, 76 * '#', os.linesep, os.linesep))

def getPageTemplate(payload, place):  # Cross-linked function
    raise NotImplementedError

def getPublicTypeMembers(type_, onlyValues=False):
    """
    Useful for getting members from types (e.g. in enums)

    >>> [_ for _ in getPublicTypeMembers(OS, True)]
    ['Linux', 'Windows']
    """

    for name, value in inspect.getmembers(type_):
        if not name.startswith('__'):
            if not onlyValues:
                yield (name, value)
            else:
                yield value

def enumValueToNameLookup(type_, value_):
    """
    Returns name of a enum member with a given value

    >>> enumValueToNameLookup(SORT_ORDER, 100)
    'LAST'
    """

    retVal = None

    for name, value in getPublicTypeMembers(type_):
        if value == value_:
            retVal = name
            break

    return retVal

def extractRegexResult(regex, content, flags=0):
    """
    Returns 'result' group value from a possible match with regex on a given
    content

    >>> extractRegexResult(r'a(?P<result>[^g]+)g', 'abcdefg')
    'bcdef'
    """

    retVal = None

    if regex and content and "?P<result>" in regex:
        match = re.search(regex, content, flags)

        if match:
            retVal = match.group("result")

    return retVal

def extractTextTagContent(page):
    """
    Returns list containing content from "textual" tags

    >>> extractTextTagContent(u'<html><head><title>Title</title></head><body><pre>foobar</pre><a href="#link">Link</a></body></html>')
    [u'Title', u'foobar']
    """

    page = page or ""

    if REFLECTED_VALUE_MARKER in page:
        try:
            page = re.sub(r"(?i)[^\s>]*%s[^\s<]*" % REFLECTED_VALUE_MARKER, "", page)
        except MemoryError:
            page = page.replace(REFLECTED_VALUE_MARKER, "")

    return filter(None, (_.group('result').strip() for _ in re.finditer(TEXT_TAG_REGEX, page)))

def trimAlphaNum(value):
    """
    Trims alpha numeric characters from start and ending of a given value

    >>> trimAlphaNum(u'AND 1>(2+3)-- foobar')
    u' 1>(2+3)-- '
    """

    while value and value[-1].isalnum():
        value = value[:-1]

    while value and value[0].isalnum():
        value = value[1:]

    return value

def isNumPosStrValue(value):
    """
    Returns True if value is a string (or integer) with a positive integer representation

    >>> isNumPosStrValue(1)
    True
    >>> isNumPosStrValue('1')
    True
    >>> isNumPosStrValue(0)
    False
    >>> isNumPosStrValue('-2')
    False
    """

    return (value and isinstance(value, basestring) and value.isdigit() and int(value) > 0) or (isinstance(value, int) and value > 0)

@cachedmethod
def aliasToDbmsEnum(dbms):
    """
    Returns major DBMS name from a given alias

    >>> aliasToDbmsEnum('mssql')
    'Microsoft SQL Server'
    """

    retVal = None

    if dbms:
        for key, item in DBMS_DICT.items():
            if dbms.lower() in item[0] or dbms.lower() == key.lower():
                retVal = key
                break

    return retVal

def findDynamicContent(firstPage, secondPage):
    """
    This function checks if the provided pages have dynamic content. If they
    are dynamic, proper markings will be made
    """

    if not firstPage or not secondPage:
        return

    infoMsg = "searching for dynamic content"
    logger.info(infoMsg)

    blocks = SequenceMatcher(None, firstPage, secondPage).get_matching_blocks()
    kb.dynamicMarkings = []

    # Removing too small matching blocks
    for block in blocks[:]:
        (_, _, length) = block

        if length <= DYNAMICITY_MARK_LENGTH:
            blocks.remove(block)

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

            kb.dynamicMarkings.append((prefix[-DYNAMICITY_MARK_LENGTH / 2:] if prefix else None, suffix[:DYNAMICITY_MARK_LENGTH / 2] if suffix else None))

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
                page = re.sub(r'(?s)^.+%s' % re.escape(suffix), suffix.replace('\\', r'\\'), page)
            elif suffix is None:
                page = re.sub(r'(?s)%s.+$' % re.escape(prefix), prefix.replace('\\', r'\\'), page)
            else:
                page = re.sub(r'(?s)%s.+%s' % (re.escape(prefix), re.escape(suffix)), '%s%s' % (prefix.replace('\\', r'\\'), suffix.replace('\\', r'\\')), page)

    return page

def filterStringValue(value, charRegex, replacement=""):
    """
    Returns string value consisting only of chars satisfying supplied
    regular expression (note: it has to be in form [...])

    >>> filterStringValue(u'wzydeadbeef0123#', r'[0-9a-f]')
    u'deadbeef0123'
    """

    retVal = value

    if value:
        retVal = re.sub(charRegex.replace("[", "[^") if "[^" not in charRegex else charRegex.replace("[^", "["), replacement, value)

    return retVal

def filterControlChars(value):
    """
    Returns string value with control chars being supstituted with ' '

    >>> filterControlChars(u'AND 1>(2+3)\\n--')
    u'AND 1>(2+3) --'
    """

    return filterStringValue(value, PRINTABLE_CHAR_REGEX, ' ')

def isDBMSVersionAtLeast(version):
    """
    Checks if the recognized DBMS version is at least the version
    specified
    """

    retVal = None

    if Backend.getVersion() and Backend.getVersion() != UNKNOWN_DBMS_VERSION:
        value = Backend.getVersion().replace(" ", "").rstrip('.')

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

        for match in re.finditer(r"(\w+)[\"'`]?\s+(INT|INTEGER|TINYINT|SMALLINT|MEDIUMINT|BIGINT|UNSIGNED BIG INT|INT2|INT8|INTEGER|CHARACTER|VARCHAR|VARYING CHARACTER|NCHAR|NATIVE CHARACTER|NVARCHAR|TEXT|CLOB|LONGTEXT|BLOB|NONE|REAL|DOUBLE|DOUBLE PRECISION|FLOAT|REAL|NUMERIC|DECIMAL|BOOLEAN|DATE|DATETIME|NUMERIC)\b", value, re.I):
            columns[match.group(1)] = match.group(2)

        table[conf.tbl] = columns
        kb.data.cachedColumns[conf.db] = table

def getTechniqueData(technique=None):
    """
    Returns injection data for technique specified
    """

    return kb.injection.data.get(technique)

def isTechniqueAvailable(technique):
    """
    Returns True if there is injection data which sqlmap could use for
    technique specified
    """

    if conf.tech and isinstance(conf.tech, list) and technique not in conf.tech:
        return False
    else:
        return getTechniqueData(technique) is not None

def isStackingAvailable():
    """
    Returns True whether techniques using stacking are available
    """

    retVal = False

    if PAYLOAD.TECHNIQUE.STACKED in kb.injection.data:
        retVal = True
    else:
        for technique in getPublicTypeMembers(PAYLOAD.TECHNIQUE, True):
            _ = getTechniqueData(technique)
            if _ and "stacked" in _["title"].lower():
                retVal = True
                break

    return retVal

def isInferenceAvailable():
    """
    Returns True whether techniques using inference technique are available
    """

    return any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.BOOLEAN, PAYLOAD.TECHNIQUE.STACKED, PAYLOAD.TECHNIQUE.TIME))

def setOptimize():
    """
    Sets options turned on by switch '-o'
    """

    #conf.predictOutput = True
    conf.keepAlive = True
    conf.threads = 3 if conf.threads < 3 else conf.threads
    conf.nullConnection = not any((conf.data, conf.textOnly, conf.titles, conf.string, conf.notString, conf.regexp, conf.tor))

    if not conf.nullConnection:
        debugMsg = "turning off switch '--null-connection' used indirectly by switch '-o'"
        logger.debug(debugMsg)

def initTechnique(technique=None):
    """
    Prepares data for technique specified
    """

    try:
        data = getTechniqueData(technique)
        resetCounter(technique)

        if data:
            kb.pageTemplate, kb.errorIsNone = getPageTemplate(data.templatePayload, kb.injection.place)
            kb.matchRatio = data.matchRatio
            kb.negativeLogic = (technique == PAYLOAD.TECHNIQUE.BOOLEAN) and (data.where == PAYLOAD.WHERE.NEGATIVE)

            # Restoring stored conf options
            for key, value in kb.injection.conf.items():
                if value and (not hasattr(conf, key) or (hasattr(conf, key) and not getattr(conf, key))):
                    setattr(conf, key, value)
                    debugMsg = "resuming configuration option '%s' (%s)" % (key, value)
                    logger.debug(debugMsg)

                    if value and key == "optimize":
                        setOptimize()
        else:
            warnMsg = "there is no injection data available for technique "
            warnMsg += "'%s'" % enumValueToNameLookup(PAYLOAD.TECHNIQUE, technique)
            logger.warn(warnMsg)

    except SqlmapDataException:
        errMsg = "missing data in old session file(s). "
        errMsg += "Please use '--flush-session' to deal "
        errMsg += "with this error"
        raise SqlmapNoneDataException(errMsg)

def arrayizeValue(value):
    """
    Makes a list out of value if it is not already a list or tuple itself

    >>> arrayizeValue(u'1')
    [u'1']
    """

    if not isListLike(value):
        value = [value]

    return value

def unArrayizeValue(value):
    """
    Makes a value out of iterable if it is a list or tuple itself

    >>> unArrayizeValue([u'1'])
    u'1'
    """

    if isListLike(value):
        if not value:
            value = None
        elif len(value) == 1 and not isListLike(value[0]):
            value = value[0]
        else:
            _ = filter(lambda _: _ is not None, (_ for _ in flattenValue(value)))
            value = _[0] if len(_) > 0 else None

    return value

def flattenValue(value):
    """
    Returns an iterator representing flat representation of a given value

    >>> [_ for _ in flattenValue([[u'1'], [[u'2'], u'3']])]
    [u'1', u'2', u'3']
    """

    for i in iter(value):
        if isListLike(i):
            for j in flattenValue(i):
                yield j
        else:
            yield i

def isListLike(value):
    """
    Returns True if the given value is a list-like instance

    >>> isListLike([1, 2, 3])
    True
    >>> isListLike(u'2')
    False
    """

    return isinstance(value, (list, tuple, set, BigArray))

def getSortedInjectionTests():
    """
    Returns prioritized test list by eventually detected DBMS from error
    messages
    """

    retVal = copy.deepcopy(conf.tests)

    def priorityFunction(test):
        retVal = SORT_ORDER.FIRST

        if test.stype == PAYLOAD.TECHNIQUE.UNION:
            retVal = SORT_ORDER.LAST

        elif 'details' in test and 'dbms' in test.details:
            if intersect(test.details.dbms, Backend.getIdentifiedDbms()):
                retVal = SORT_ORDER.SECOND
            else:
                retVal = SORT_ORDER.THIRD

        return retVal

    if Backend.getIdentifiedDbms():
        retVal = sorted(retVal, key=priorityFunction)

    return retVal

def filterListValue(value, regex):
    """
    Returns list with items that have parts satisfying given regular
    expression

    >>> filterListValue(['users', 'admins', 'logs'], r'(users|admins)')
    ['users', 'admins']
    """

    if isinstance(value, list) and regex:
        retVal = filter(lambda _: re.search(regex, _, re.I), value)
    else:
        retVal = value

    return retVal

def showHttpErrorCodes():
    """
    Shows all HTTP error codes raised till now
    """

    if kb.httpErrorCodes:
        warnMsg = "HTTP error codes detected during run:\n"
        warnMsg += ", ".join("%d (%s) - %d times" % (code, httplib.responses[code] \
          if code in httplib.responses else '?', count) \
          for code, count in kb.httpErrorCodes.items())
        logger.warn(warnMsg)
        if any((str(_).startswith('4') or str(_).startswith('5')) and _ != httplib.INTERNAL_SERVER_ERROR and _ != kb.originalCode for _ in kb.httpErrorCodes.keys()):
            msg = "too many 4xx and/or 5xx HTTP error codes "
            msg += "could mean that some kind of protection is involved (e.g. WAF)"
            logger.debug(msg)

def openFile(filename, mode='r', encoding=UNICODE_ENCODING, errors="replace", buffering=1):  # "buffering=1" means line buffered (Reference: http://stackoverflow.com/a/3168436)
    """
    Returns file handle of a given filename
    """

    try:
        return codecs.open(filename, mode, encoding, errors, buffering)
    except IOError:
        errMsg = "there has been a file opening error for filename '%s'. " % filename
        errMsg += "Please check %s permissions on a file " % ("write" if \
          mode and ('w' in mode or 'a' in mode or '+' in mode) else "read")
        errMsg += "and that it's not locked by another process."
        raise SqlmapSystemException(errMsg)

def decodeIntToUnicode(value):
    """
    Decodes inferenced integer value to an unicode character

    >>> decodeIntToUnicode(35)
    u'#'
    >>> decodeIntToUnicode(64)
    u'@'
    """
    retVal = value

    if isinstance(value, int):
        try:
            if value > 255:
                _ = "%x" % value
                if len(_) % 2 == 1:
                    _ = "0%s" % _
                raw = hexdecode(_)

                if Backend.isDbms(DBMS.MYSQL):
                    # https://github.com/sqlmapproject/sqlmap/issues/1531
                    retVal = getUnicode(raw, conf.charset or UNICODE_ENCODING)
                elif Backend.isDbms(DBMS.MSSQL):
                    retVal = getUnicode(raw, "UTF-16-BE")
                elif Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.ORACLE):
                    retVal = unichr(value)
                else:
                    retVal = getUnicode(raw, conf.charset)
            else:
                retVal = getUnicode(chr(value))
        except:
            retVal = INFERENCE_UNKNOWN_CHAR

    return retVal

def unhandledExceptionMessage():
    """
    Returns detailed message about occurred unhandled exception
    """

    errMsg = "unhandled exception occurred in %s. It is recommended to retry your " % VERSION_STRING
    errMsg += "run with the latest development version from official GitHub "
    errMsg += "repository at '%s'. If the exception persists, please open a new issue " % GIT_PAGE
    errMsg += "at '%s' " % ISSUES_PAGE
    errMsg += "with the following text and any other information required to "
    errMsg += "reproduce the bug. The "
    errMsg += "developers will try to reproduce the bug, fix it accordingly "
    errMsg += "and get back to you\n"
    errMsg += "sqlmap version: %s\n" % VERSION_STRING[VERSION_STRING.find('/') + 1:]
    errMsg += "Python version: %s\n" % PYVERSION
    errMsg += "Operating system: %s\n" % PLATFORM
    errMsg += "Command line: %s\n" % re.sub(r".+?\bsqlmap.py\b", "sqlmap.py", getUnicode(" ".join(sys.argv), encoding=sys.stdin.encoding))
    errMsg += "Technique: %s\n" % (enumValueToNameLookup(PAYLOAD.TECHNIQUE, kb.technique) if kb.get("technique") else ("DIRECT" if conf.get("direct") else None))
    errMsg += "Back-end DBMS: %s" % ("%s (fingerprinted)" % Backend.getDbms() if Backend.getDbms() is not None else "%s (identified)" % Backend.getIdentifiedDbms())

    return errMsg

def createGithubIssue(errMsg, excMsg):
    """
    Automatically create a Github issue with unhandled exception information
    """

    issues = []
    try:
        issues = getFileItems(paths.GITHUB_HISTORY, unique=True)
    except:
        pass
    finally:
        issues = set(issues)

    _ = re.sub(r"'[^']+'", "''", excMsg)
    _ = re.sub(r"\s+line \d+", "", _)
    _ = re.sub(r'File ".+?/(\w+\.py)', "\g<1>", _)
    _ = re.sub(r".+\Z", "", _)
    key = hashlib.md5(_).hexdigest()[:8]

    if key in issues:
        return

    msg = "\ndo you want to automatically create a new (anonymized) issue "
    msg += "with the unhandled exception information at "
    msg += "the official Github repository? [y/N] "
    try:
        test = readInput(msg, default="N")
    except:
        test = None

    if test and test[0] in ("y", "Y"):
        ex = None
        errMsg = errMsg[errMsg.find("\n"):]


        data = {"title": "Unhandled exception (#%s)" % key, "body": "```%s\n```\n```\n%s```" % (errMsg, excMsg)}
        req = urllib2.Request(url="https://api.github.com/repos/sqlmapproject/sqlmap/issues", data=json.dumps(data), headers={"Authorization": "token %s" % GITHUB_REPORT_OAUTH_TOKEN.decode("base64")})

        try:
            f = urllib2.urlopen(req)
            content = f.read()
        except Exception, ex:
            content = None

        issueUrl = re.search(r"https://github.com/sqlmapproject/sqlmap/issues/\d+", content or "")
        if issueUrl:
            infoMsg = "created Github issue can been found at the address '%s'" % issueUrl.group(0)
            logger.info(infoMsg)

            try:
                with open(paths.GITHUB_HISTORY, "a+b") as f:
                    f.write("%s\n" % key)
            except:
                pass
        else:
            warnMsg = "something went wrong while creating a Github issue"
            if ex:
                warnMsg += " ('%s')" % getSafeExString(ex)
            if "Unauthorized" in warnMsg:
                warnMsg += ". Please update to the latest revision"
            logger.warn(warnMsg)

def maskSensitiveData(msg):
    """
    Masks sensitive data in the supplied message
    """

    retVal = getUnicode(msg)

    for item in filter(None, map(lambda x: conf.get(x), ("hostname", "data", "googleDork", "authCred", "proxyCred", "tbl", "db", "col", "user", "cookie", "proxy", "rFile", "wFile", "dFile"))):
        regex = SENSITIVE_DATA_REGEX % re.sub("(\W)", r"\\\1", getUnicode(item))
        while extractRegexResult(regex, retVal):
            value = extractRegexResult(regex, retVal)
            retVal = retVal.replace(value, '*' * len(value))

    if not conf.get("hostname"):
        match = re.search(r"(?i)sqlmap.+(-u|--url)(\s+|=)([^ ]+)", retVal)
        if match:
            retVal = retVal.replace(match.group(3), '*' * len(match.group(3)))

    if getpass.getuser():
        retVal = re.sub(r"(?i)\b%s\b" % re.escape(getpass.getuser()), "*" * len(getpass.getuser()), retVal)

    return retVal

def listToStrValue(value):
    """
    Flattens list to a string value

    >>> listToStrValue([1,2,3])
    '1, 2, 3'
    """

    if isinstance(value, (set, tuple)):
        value = list(value)

    if isinstance(value, list):
        retVal = value.__str__().lstrip('[').rstrip(']')
    else:
        retVal = value

    return retVal

def getExceptionFrameLocals():
    """
    Returns dictionary with local variable content from frame
    where exception has been raised
    """

    retVal = {}

    if sys.exc_info():
        trace = sys.exc_info()[2]
        while trace.tb_next:
            trace = trace.tb_next
        retVal = trace.tb_frame.f_locals

    return retVal

def intersect(valueA, valueB, lowerCase=False):
    """
    Returns intersection of the array-ized values

    >>> intersect([1, 2, 3], set([1,3]))
    [1, 3]
    """

    retVal = []

    if valueA and valueB:
        valueA = arrayizeValue(valueA)
        valueB = arrayizeValue(valueB)

        if lowerCase:
            valueA = [val.lower() if isinstance(val, basestring) else val for val in valueA]
            valueB = [val.lower() if isinstance(val, basestring) else val for val in valueB]

        retVal = [val for val in valueA if val in valueB]

    return retVal

def removeReflectiveValues(content, payload, suppressWarning=False):
    """
    Neutralizes reflective values in a given content based on a payload
    (e.g. ..search.php?q=1 AND 1=2 --> "...searching for <b>1%20AND%201%3D2</b>..." --> "...searching for <b>__REFLECTED_VALUE__</b>...")
    """

    retVal = content

    try:
        if all([content, payload]) and isinstance(content, unicode) and kb.reflectiveMechanism and not kb.heuristicMode:
            def _(value):
                while 2 * REFLECTED_REPLACEMENT_REGEX in value:
                    value = value.replace(2 * REFLECTED_REPLACEMENT_REGEX, REFLECTED_REPLACEMENT_REGEX)
                return value

            payload = getUnicode(urldecode(payload.replace(PAYLOAD_DELIMITER, ''), convall=True))
            regex = _(filterStringValue(payload, r"[A-Za-z0-9]", REFLECTED_REPLACEMENT_REGEX.encode("string-escape")))

            if regex != payload:
                if all(part.lower() in content.lower() for part in filter(None, regex.split(REFLECTED_REPLACEMENT_REGEX))[1:]):  # fast optimization check
                    parts = regex.split(REFLECTED_REPLACEMENT_REGEX)
                    retVal = content.replace(payload, REFLECTED_VALUE_MARKER)  # dummy approach

                    if len(parts) > REFLECTED_MAX_REGEX_PARTS:  # preventing CPU hogs
                        regex = _("%s%s%s" % (REFLECTED_REPLACEMENT_REGEX.join(parts[:REFLECTED_MAX_REGEX_PARTS / 2]), REFLECTED_REPLACEMENT_REGEX, REFLECTED_REPLACEMENT_REGEX.join(parts[-REFLECTED_MAX_REGEX_PARTS / 2:])))

                    parts = filter(None, regex.split(REFLECTED_REPLACEMENT_REGEX))

                    if regex.startswith(REFLECTED_REPLACEMENT_REGEX):
                        regex = r"%s%s" % (REFLECTED_BORDER_REGEX, regex[len(REFLECTED_REPLACEMENT_REGEX):])
                    else:
                        regex = r"\b%s" % regex

                    if regex.endswith(REFLECTED_REPLACEMENT_REGEX):
                        regex = r"%s%s" % (regex[:-len(REFLECTED_REPLACEMENT_REGEX)], REFLECTED_BORDER_REGEX)
                    else:
                        regex = r"%s\b" % regex

                    retVal = re.sub(r"(?i)%s" % regex, REFLECTED_VALUE_MARKER, retVal)

                    if len(parts) > 2:
                        regex = REFLECTED_REPLACEMENT_REGEX.join(parts[1:])
                        retVal = re.sub(r"(?i)\b%s\b" % regex, REFLECTED_VALUE_MARKER, retVal)

                if retVal != content:
                    kb.reflectiveCounters[REFLECTIVE_COUNTER.HIT] += 1
                    if not suppressWarning:
                        warnMsg = "reflective value(s) found and filtering out"
                        singleTimeWarnMessage(warnMsg)

                    if re.search(r"FRAME[^>]+src=[^>]*%s" % REFLECTED_VALUE_MARKER, retVal, re.I):
                        warnMsg = "frames detected containing attacked parameter values. Please be sure to "
                        warnMsg += "test those separately in case that attack on this page fails"
                        singleTimeWarnMessage(warnMsg)

                elif not kb.testMode and not kb.reflectiveCounters[REFLECTIVE_COUNTER.HIT]:
                    kb.reflectiveCounters[REFLECTIVE_COUNTER.MISS] += 1
                    if kb.reflectiveCounters[REFLECTIVE_COUNTER.MISS] > REFLECTIVE_MISS_THRESHOLD:
                        kb.reflectiveMechanism = False
                        if not suppressWarning:
                            debugMsg = "turning off reflection removal mechanism (for optimization purposes)"
                            logger.debug(debugMsg)
    except MemoryError:
        kb.reflectiveMechanism = False
        if not suppressWarning:
            debugMsg = "turning off reflection removal mechanism (because of low memory issues)"
            logger.debug(debugMsg)

    return retVal

def normalizeUnicode(value):
    """
    Does an ASCII normalization of unicode strings
    Reference: http://www.peterbe.com/plog/unicode-to-ascii

    >>> normalizeUnicode(u'\u0161u\u0107uraj')
    'sucuraj'
    """

    return unicodedata.normalize('NFKD', value).encode('ascii', 'ignore') if isinstance(value, unicode) else value

def safeSQLIdentificatorNaming(name, isTable=False):
    """
    Returns a safe representation of SQL identificator name (internal data format)
    Reference: http://stackoverflow.com/questions/954884/what-special-characters-are-allowed-in-t-sql-column-retVal
    """

    retVal = name

    if isinstance(name, basestring):
        retVal = getUnicode(name)
        _ = isTable and Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE)

        if _:
            retVal = re.sub(r"(?i)\A%s\." % DEFAULT_MSSQL_SCHEMA, "", retVal)

        if retVal.upper() in kb.keywords or (retVal or " ")[0].isdigit() or not re.match(r"\A[A-Za-z0-9_@%s\$]+\Z" % ("." if _ else ""), retVal):  # MsSQL is the only DBMS where we automatically prepend schema to table name (dot is normal)
            if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.ACCESS):
                retVal = "`%s`" % retVal.strip("`")
            elif Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.DB2):
                retVal = "\"%s\"" % retVal.strip("\"")
            elif Backend.getIdentifiedDbms() in (DBMS.ORACLE,):
                retVal = "\"%s\"" % retVal.strip("\"").upper()
            elif Backend.getIdentifiedDbms() in (DBMS.MSSQL,) and ((retVal or " ")[0].isdigit() or not re.match(r"\A\w+\Z", retVal, re.U)):
                retVal = "[%s]" % retVal.strip("[]")

        if _ and DEFAULT_MSSQL_SCHEMA not in retVal and '.' not in re.sub(r"\[[^]]+\]", "", retVal):
            retVal = "%s.%s" % (DEFAULT_MSSQL_SCHEMA, retVal)

    return retVal

def unsafeSQLIdentificatorNaming(name):
    """
    Extracts identificator's name from its safe SQL representation
    """

    retVal = name

    if isinstance(name, basestring):
        if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.ACCESS):
            retVal = name.replace("`", "")
        elif Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.DB2):
            retVal = name.replace("\"", "")
        elif Backend.getIdentifiedDbms() in (DBMS.ORACLE,):
            retVal = name.replace("\"", "").upper()
        elif Backend.getIdentifiedDbms() in (DBMS.MSSQL,):
            retVal = name.replace("[", "").replace("]", "")

        if Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
            prefix = "%s." % DEFAULT_MSSQL_SCHEMA
            if retVal.startswith(prefix):
                retVal = retVal[len(prefix):]

    return retVal

def isNoneValue(value):
    """
    Returns whether the value is unusable (None or '')

    >>> isNoneValue(None)
    True
    >>> isNoneValue('None')
    True
    >>> isNoneValue('')
    True
    >>> isNoneValue([])
    True
    >>> isNoneValue([2])
    False
    """

    if isinstance(value, basestring):
        return value in ("None", "")
    elif isListLike(value):
        return all(isNoneValue(_) for _ in value)
    elif isinstance(value, dict):
        return not any(value)
    else:
        return value is None

def isNullValue(value):
    """
    Returns whether the value contains explicit 'NULL' value

    >>> isNullValue(u'NULL')
    True
    >>> isNullValue(u'foobar')
    False
    """

    return isinstance(value, basestring) and value.upper() == NULL

def expandMnemonics(mnemonics, parser, args):
    """
    Expands mnemonic options
    """

    class MnemonicNode(object):
        def __init__(self):
            self.next = {}
            self.current = []

    head = MnemonicNode()
    pointer = None

    for group in parser.option_groups:
        for option in group.option_list:
            for opt in option._long_opts + option._short_opts:
                pointer = head

                for char in opt:
                    if char == "-":
                        continue
                    elif char not in pointer.next:
                        pointer.next[char] = MnemonicNode()

                    pointer = pointer.next[char]
                    pointer.current.append(option)

    for mnemonic in (mnemonics or "").split(','):
        found = None
        name = mnemonic.split('=')[0].replace("-", "").strip()
        value = mnemonic.split('=')[1] if len(mnemonic.split('=')) > 1 else None
        pointer = head

        for char in name:
            if char in pointer.next:
                pointer = pointer.next[char]
            else:
                pointer = None
                break

        if pointer in (None, head):
            errMsg = "mnemonic '%s' can't be resolved to any parameter name" % name
            raise SqlmapSyntaxException(errMsg)

        elif len(pointer.current) > 1:
            options = {}

            for option in pointer.current:
                for opt in option._long_opts + option._short_opts:
                    opt = opt.strip('-')
                    if opt.startswith(name):
                        options[opt] = option

            if not options:
                warnMsg = "mnemonic '%s' can't be resolved" % name
                logger.warn(warnMsg)
            elif name in options:
                found = name
                debugMsg = "mnemonic '%s' resolved to %s). " % (name, found)
                logger.debug(debugMsg)
            else:
                found = sorted(options.keys(), key=lambda x: len(x))[0]
                warnMsg = "detected ambiguity (mnemonic '%s' can be resolved to: %s). " % (name, ", ".join("'%s'" % key for key in options.keys()))
                warnMsg += "Resolved to shortest of those ('%s')" % found
                logger.warn(warnMsg)

            if found:
                found = options[found]
        else:
            found = pointer.current[0]
            debugMsg = "mnemonic '%s' resolved to %s). " % (name, found)
            logger.debug(debugMsg)

        if found:
            try:
                value = found.convert_value(found, value)
            except OptionValueError:
                value = None

            if value is not None:
                setattr(args, found.dest, value)
            elif not found.type:  # boolean
                setattr(args, found.dest, True)
            else:
                errMsg = "mnemonic '%s' requires value of type '%s'" % (name, found.type)
                raise SqlmapSyntaxException(errMsg)

def safeCSValue(value):
    """
    Returns value safe for CSV dumping
    Reference: http://tools.ietf.org/html/rfc4180

    >>> safeCSValue(u'foo, bar')
    u'"foo, bar"'
    >>> safeCSValue(u'foobar')
    u'foobar'
    """

    retVal = value

    if retVal and isinstance(retVal, basestring):
        if not (retVal[0] == retVal[-1] == '"'):
            if any(_ in retVal for _ in (conf.get("csvDel", defaults.csvDel), '"', '\n')):
                retVal = '"%s"' % retVal.replace('"', '""')

    return retVal

def filterPairValues(values):
    """
    Returns only list-like values with length 2

    >>> filterPairValues([[1, 2], [3], 1, [4, 5]])
    [[1, 2], [4, 5]]
    """

    retVal = []

    if not isNoneValue(values) and hasattr(values, '__iter__'):
        retVal = filter(lambda x: isinstance(x, (tuple, list, set)) and len(x) == 2, values)

    return retVal

def randomizeParameterValue(value):
    """
    Randomize a parameter value based on occurances of alphanumeric characters

    >>> random.seed(0)
    >>> randomizeParameterValue('foobar')
    'rnvnav'
    >>> randomizeParameterValue('17')
    '83'
    """

    retVal = value

    value = re.sub(r"%[0-9a-fA-F]{2}", "", value)

    for match in re.finditer('[A-Z]+', value):
        retVal = retVal.replace(match.group(), randomStr(len(match.group())).upper())

    for match in re.finditer('[a-z]+', value):
        retVal = retVal.replace(match.group(), randomStr(len(match.group())).lower())

    for match in re.finditer('[0-9]+', value):
        retVal = retVal.replace(match.group(), str(randomInt(len(match.group()))))

    return retVal

def asciifyUrl(url, forceQuote=False):
    """
    Attempts to make a unicode URL usuable with ``urllib/urllib2``.

    More specifically, it attempts to convert the unicode object ``url``,
    which is meant to represent a IRI, to an unicode object that,
    containing only ASCII characters, is a valid URI. This involves:

        * IDNA/Puny-encoding the domain name.
        * UTF8-quoting the path and querystring parts.

    See also RFC 3987.

    Reference: http://blog.elsdoerfer.name/2008/12/12/opening-iris-in-python/

    >>> asciifyUrl(u'http://www.\u0161u\u0107uraj.com')
    u'http://www.xn--uuraj-gxa24d.com'
    """

    parts = urlparse.urlsplit(url)
    if not parts.scheme or not parts.netloc:
        # apparently not an url
        return url

    if all(char in string.printable for char in url):
        return url

    # idna-encode domain
    try:
        hostname = parts.hostname.encode("idna")
    except LookupError:
        hostname = parts.hostname.encode(UNICODE_ENCODING)

    # UTF8-quote the other parts. We check each part individually if
    # if needs to be quoted - that should catch some additional user
    # errors, say for example an umlaut in the username even though
    # the path *is* already quoted.
    def quote(s, safe):
        s = s or ''
        # Triggers on non-ascii characters - another option would be:
        #     urllib.quote(s.replace('%', '')) != s.replace('%', '')
        # which would trigger on all %-characters, e.g. "&".
        if s.encode("ascii", "replace") != s or forceQuote:
            return urllib.quote(s.encode(UNICODE_ENCODING), safe=safe)
        return s

    username = quote(parts.username, '')
    password = quote(parts.password, safe='')
    path = quote(parts.path, safe='/')
    query = quote(parts.query, safe="&=")

    # put everything back together
    netloc = hostname
    if username or password:
        netloc = '@' + netloc
        if password:
            netloc = ':' + password + netloc
        netloc = username + netloc

    try:
        port = parts.port
    except:
        port = None

    if port:
        netloc += ':' + str(port)

    return urlparse.urlunsplit([parts.scheme, netloc, path, query, parts.fragment])

def isAdminFromPrivileges(privileges):
    """
    Inspects privileges to see if those are comming from an admin user
    """

    # In PostgreSQL the usesuper privilege means that the
    # user is DBA
    retVal = (Backend.isDbms(DBMS.PGSQL) and "super" in privileges)

    # In Oracle the DBA privilege means that the
    # user is DBA
    retVal |= (Backend.isDbms(DBMS.ORACLE) and "DBA" in privileges)

    # In MySQL >= 5.0 the SUPER privilege means
    # that the user is DBA
    retVal |= (Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema and "SUPER" in privileges)

    # In MySQL < 5.0 the super_priv privilege means
    # that the user is DBA
    retVal |= (Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema and "super_priv" in privileges)

    # In Firebird there is no specific privilege that means
    # that the user is DBA
    # TODO: confirm
    retVal |= (Backend.isDbms(DBMS.FIREBIRD) and all(_ in privileges for _ in ("SELECT", "INSERT", "UPDATE", "DELETE", "REFERENCES", "EXECUTE")))

    return retVal

def findPageForms(content, url, raise_=False, addToTargets=False):
    """
    Parses given page content for possible forms
    """

    class _(StringIO):
        def __init__(self, content, url):
            StringIO.__init__(self, unicodeencode(content, kb.pageEncoding) if isinstance(content, unicode) else content)
            self._url = url
        def geturl(self):
            return self._url

    if not content:
        errMsg = "can't parse forms as the page content appears to be blank"
        if raise_:
            raise SqlmapGenericException(errMsg)
        else:
            logger.debug(errMsg)

    forms = None
    retVal = set()
    response = _(content, url)

    try:
        forms = ParseResponse(response, backwards_compat=False)
    except (UnicodeError, ValueError):
        pass
    except ParseError:
        if "<html" in (content or ""):
            warnMsg = "badly formed HTML at the given URL ('%s'). Going to filter it" % url
            logger.warning(warnMsg)
            filtered = _("".join(re.findall(FORM_SEARCH_REGEX, content)), url)
            try:
                forms = ParseResponse(filtered, backwards_compat=False)
            except ParseError:
                errMsg = "no success"
                if raise_:
                    raise SqlmapGenericException(errMsg)
                else:
                    logger.debug(errMsg)

    if forms:
        for form in forms:
            try:
                for control in form.controls:
                    if hasattr(control, "items") and not any((control.disabled, control.readonly)):
                        # if control has selectable items select first non-disabled
                        for item in control.items:
                            if not item.disabled:
                                if not item.selected:
                                    item.selected = True
                                break

                request = form.click()
            except (ValueError, TypeError), ex:
                errMsg = "there has been a problem while "
                errMsg += "processing page forms ('%s')" % getSafeExString(ex)
                if raise_:
                    raise SqlmapGenericException(errMsg)
                else:
                    logger.debug(errMsg)
            else:
                url = urldecode(request.get_full_url(), kb.pageEncoding)
                method = request.get_method()
                data = request.get_data() if request.has_data() else None
                data = urldecode(data, kb.pageEncoding, plusspace=False)

                if not data and method and method.upper() == HTTPMETHOD.POST:
                    debugMsg = "invalid POST form with blank data detected"
                    logger.debug(debugMsg)
                    continue

                # flag to know if we are dealing with the same target host
                _ = reduce(lambda x, y: x == y, map(lambda x: urlparse.urlparse(x).netloc.split(':')[0], (response.geturl(), url)))

                if conf.scope:
                    if not re.search(conf.scope, url, re.I):
                        continue
                elif not _:
                    continue
                else:
                    target = (url, method, data, conf.cookie, None)
                    retVal.add(target)
    else:
        errMsg = "there were no forms found at the given target URL"
        if raise_:
            raise SqlmapGenericException(errMsg)
        else:
            logger.debug(errMsg)

    if addToTargets and retVal:
        for target in retVal:
            kb.targets.add(target)

    return retVal

def getHostHeader(url):
    """
    Returns proper Host header value for a given target URL

    >>> getHostHeader('http://www.target.com/vuln.php?id=1')
    'www.target.com'
    """

    retVal = url

    if url:
        retVal = urlparse.urlparse(url).netloc

        if re.search("http(s)?://\[.+\]", url, re.I):
            retVal = extractRegexResult("http(s)?://\[(?P<result>.+)\]", url)
        elif any(retVal.endswith(':%d' % _) for _ in (80, 443)):
            retVal = retVal.split(':')[0]

    return retVal

def checkDeprecatedOptions(args):
    """
    Checks for deprecated options
    """

    for _ in args:
        if _ in DEPRECATED_OPTIONS:
            errMsg = "switch/option '%s' is deprecated" % _
            if DEPRECATED_OPTIONS[_]:
                errMsg += " (hint: %s)" % DEPRECATED_OPTIONS[_]
            raise SqlmapSyntaxException(errMsg)

def checkSystemEncoding():
    """
    Checks for problematic encodings
    """

    if sys.getdefaultencoding() == "cp720":
        try:
            codecs.lookup("cp720")
        except LookupError:
            errMsg = "there is a known Python issue (#1616979) related "
            errMsg += "to support for charset 'cp720'. Please visit "
            errMsg += "'http://blog.oneortheother.info/tip/python-fix-cp720-encoding/index.html' "
            errMsg += "and follow the instructions to be able to fix it"
            logger.critical(errMsg)

            warnMsg = "temporary switching to charset 'cp1256'"
            logger.warn(warnMsg)

            reload(sys)
            sys.setdefaultencoding("cp1256")

def evaluateCode(code, variables=None):
    """
    Executes given python code given in a string form
    """

    try:
        exec(code, variables)
    except KeyboardInterrupt:
        raise
    except Exception, ex:
        errMsg = "an error occurred while evaluating provided code ('%s') " % getSafeExString(ex)
        raise SqlmapGenericException(errMsg)

def serializeObject(object_):
    """
    Serializes given object
    """

    return base64pickle(object_)

def unserializeObject(value):
    """
    Unserializes object from given serialized form

    >>> unserializeObject(serializeObject([1, 2, 3])) == [1, 2, 3]
    True
    """

    return base64unpickle(value) if value else None

def resetCounter(technique):
    """
    Resets query counter for a given technique
    """

    kb.counters[technique] = 0

def incrementCounter(technique):
    """
    Increments query counter for a given technique
    """

    kb.counters[technique] = getCounter(technique) + 1

def getCounter(technique):
    """
    Returns query counter for a given technique
    """

    return kb.counters.get(technique, 0)

def applyFunctionRecursively(value, function):
    """
    Applies function recursively through list-like structures

    >>> applyFunctionRecursively([1, 2, [3, 4, [19]], -9], lambda _: _ > 0)
    [True, True, [True, True, [True]], False]
    """

    if isListLike(value):
        retVal = [applyFunctionRecursively(_, function) for _ in value]
    else:
        retVal = function(value)

    return retVal

def decodeHexValue(value, raw=False):
    """
    Returns value decoded from DBMS specific hexadecimal representation

    >>> decodeHexValue('3132332031')
    u'123 1'
    """

    retVal = value

    def _(value):
        retVal = value
        if value and isinstance(value, basestring):
            if len(value) % 2 != 0:
                retVal = "%s?" % hexdecode(value[:-1])
                singleTimeWarnMessage("there was a problem decoding value '%s' from expected hexadecimal form" % value)
            else:
                retVal = hexdecode(value)

            if not kb.binaryField and not raw:
                if Backend.isDbms(DBMS.MSSQL) and value.startswith("0x"):
                    try:
                        retVal = retVal.decode("utf-16-le")
                    except UnicodeDecodeError:
                        pass
                elif Backend.isDbms(DBMS.HSQLDB):
                    try:
                        retVal = retVal.decode("utf-16-be")
                    except UnicodeDecodeError:
                        pass
                if not isinstance(retVal, unicode):
                    retVal = getUnicode(retVal, "utf8")

        return retVal

    try:
        retVal = applyFunctionRecursively(value, _)
    except:
        singleTimeWarnMessage("there was a problem decoding value '%s' from expected hexadecimal form" % value)

    return retVal

def extractExpectedValue(value, expected):
    """
    Extracts and returns expected value by a given type

    >>> extractExpectedValue(['1'], EXPECTED.BOOL)
    True
    >>> extractExpectedValue('1', EXPECTED.INT)
    1
    """

    if expected:
        value = unArrayizeValue(value)

        if isNoneValue(value):
            value = None
        elif expected == EXPECTED.BOOL:
            if isinstance(value, int):
                value = bool(value)
            elif isinstance(value, basestring):
                value = value.strip().lower()
                if value in ("true", "false"):
                    value = value == "true"
                elif value in ("1", "-1"):
                    value = True
                elif value == "0":
                    value = False
                else:
                    value = None
        elif expected == EXPECTED.INT:
            if isinstance(value, basestring):
                value = int(value) if value.isdigit() else None

    return value

def hashDBWrite(key, value, serialize=False):
    """
    Helper function for writing session data to HashDB
    """

    _ = "%s%s%s" % (conf.url or "%s%s" % (conf.hostname, conf.port), key, HASHDB_MILESTONE_VALUE)
    conf.hashDB.write(_, value, serialize)

def hashDBRetrieve(key, unserialize=False, checkConf=False):
    """
    Helper function for restoring session data from HashDB
    """

    _ = "%s%s%s" % (conf.url or "%s%s" % (conf.hostname, conf.port), key, HASHDB_MILESTONE_VALUE)
    retVal = conf.hashDB.retrieve(_, unserialize) if kb.resumeValues and not (checkConf and any((conf.flushSession, conf.freshQueries))) else None
    if not kb.inferenceMode and not kb.fileReadMode and isinstance(retVal, basestring) and any(_ in retVal for _ in (PARTIAL_VALUE_MARKER, PARTIAL_HEX_VALUE_MARKER)):
        retVal = None
    return retVal

def resetCookieJar(cookieJar):
    """
    Cleans cookies from a given cookie jar
    """

    if not conf.loadCookies:
        cookieJar.clear()
    else:
        try:
            if not cookieJar.filename:
                infoMsg = "loading cookies from '%s'" % conf.loadCookies
                logger.info(infoMsg)

                content = readCachedFileContent(conf.loadCookies)
                lines = filter(None, (line.strip() for line in content.split("\n") if not line.startswith('#')))
                handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.COOKIE_JAR)
                os.close(handle)

                # Reference: http://www.hashbangcode.com/blog/netscape-http-cooke-file-parser-php-584.html
                with openFile(filename, "w+b") as f:
                    f.write("%s\n" % NETSCAPE_FORMAT_HEADER_COOKIES)
                    for line in lines:
                        _ = line.split("\t")
                        if len(_) == 7:
                            _[4] = FORCE_COOKIE_EXPIRATION_TIME
                            f.write("\n%s" % "\t".join(_))

                cookieJar.filename = filename

            cookieJar.load(cookieJar.filename, ignore_expires=True)

            for cookie in cookieJar:
                if cookie.expires < time.time():
                    warnMsg = "cookie '%s' has expired" % cookie
                    singleTimeWarnMessage(warnMsg)

            cookieJar.clear_expired_cookies()

            if not cookieJar._cookies:
                errMsg = "no valid cookies found"
                raise SqlmapGenericException(errMsg)

        except cookielib.LoadError, msg:
            errMsg = "there was a problem loading "
            errMsg += "cookies file ('%s')" % re.sub(r"(cookies) file '[^']+'", "\g<1>", str(msg))
            raise SqlmapGenericException(errMsg)

def decloakToTemp(filename):
    """
    Decloaks content of a given file to a temporary file with similar name and extension
    """

    content = decloak(filename)

    _ = utf8encode(os.path.split(filename[:-1])[-1])

    prefix, suffix = os.path.splitext(_)
    prefix = prefix.split(os.extsep)[0]

    handle, filename = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    os.close(handle)

    with open(filename, "w+b") as f:
        f.write(content)

    return filename

def prioritySortColumns(columns):
    """
    Sorts given column names by length in ascending order while those containing
    string 'id' go first

    >>> prioritySortColumns(['password', 'userid', 'name'])
    ['userid', 'name', 'password']
    """

    _ = lambda x: x and "id" in x.lower()
    return sorted(sorted(columns, key=len), lambda x, y: -1 if _(x) and not _(y) else 1 if not _(x) and _(y) else 0)

def getRequestHeader(request, name):
    """
    Solving an issue with an urllib2 Request header case sensitivity

    Reference: http://bugs.python.org/issue2275
    """

    retVal = None
    if request and name:
        retVal = max(value if name.upper() == key.upper() else None for key, value in request.header_items())
    return retVal

def isNumber(value):
    """
    Returns True if the given value is a number-like object

    >>> isNumber(1)
    True
    >>> isNumber('0')
    True
    >>> isNumber('foobar')
    False
    """

    try:
        float(value)
    except:
        return False
    else:
        return True

def zeroDepthSearch(expression, value):
    """
    Searches occurrences of value inside expression at 0-depth level
    regarding the parentheses
    """

    retVal = []

    depth = 0
    for index in xrange(len(expression)):
        if expression[index] == '(':
            depth += 1
        elif expression[index] == ')':
            depth -= 1
        elif depth == 0 and expression[index:index + len(value)] == value:
            retVal.append(index)

    return retVal

def splitFields(fields, delimiter=','):
    """
    Returns list of (0-depth) fields splitted by delimiter

    >>> splitFields('foo, bar, max(foo, bar)')
    ['foo', 'bar', 'max(foo,bar)']
    """

    fields = fields.replace("%s " % delimiter, delimiter)
    commas = [-1, len(fields)]
    commas.extend(zeroDepthSearch(fields, ','))
    commas = sorted(commas)

    return [fields[x + 1:y] for (x, y) in zip(commas, commas[1:])]

def pollProcess(process, suppress_errors=False):
    """
    Checks for process status (prints . if still running)
    """

    while True:
        dataToStdout(".")
        time.sleep(1)

        returncode = process.poll()

        if returncode is not None:
            if not suppress_errors:
                if returncode == 0:
                    dataToStdout(" done\n")
                elif returncode < 0:
                    dataToStdout(" process terminated by signal %d\n" % returncode)
                elif returncode > 0:
                    dataToStdout(" quit unexpectedly with return code %d\n" % returncode)

            break

def getSafeExString(ex, encoding=None):
    """
    Safe way how to get the proper exception represtation as a string
    (Note: errors to be avoided: 1) "%s" % Exception(u'\u0161') and 2) "%s" % str(Exception(u'\u0161'))
    """

    retVal = ex

    if getattr(ex, "message", None):
        retVal = ex.message
    elif getattr(ex, "msg", None):
        retVal = ex.msg

    return getUnicode(retVal, encoding=encoding)
