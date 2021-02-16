#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import binascii
import codecs
import contextlib
import copy
import distutils.version
import functools
import getpass
import hashlib
import inspect
import io
import json
import keyword
import locale
import logging
import ntpath
import os
import platform
import posixpath
import random
import re
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
import types
import unicodedata

from difflib import SequenceMatcher
from math import sqrt
from optparse import OptionValueError
from xml.sax import parse
from xml.sax import SAXParseException

from extra.beep.beep import beep
from extra.cloak.cloak import decloak
from lib.core.bigarray import BigArray
from lib.core.compat import cmp
from lib.core.compat import round
from lib.core.compat import xrange
from lib.core.convert import base64pickle
from lib.core.convert import base64unpickle
from lib.core.convert import decodeBase64
from lib.core.convert import decodeHex
from lib.core.convert import getBytes
from lib.core.convert import getText
from lib.core.convert import getUnicode
from lib.core.convert import htmlUnescape
from lib.core.convert import stdoutEncode
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.datatype import OrderedSet
from lib.core.decorators import cachedmethod
from lib.core.defaults import defaults
from lib.core.dicts import DBMS_DICT
from lib.core.dicts import DEFAULT_DOC_ROOTS
from lib.core.dicts import DEPRECATED_OPTIONS
from lib.core.dicts import OBSOLETE_OPTIONS
from lib.core.dicts import SQL_STATEMENTS
from lib.core.enums import ADJUST_TIME_DELAY
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import CONTENT_STATUS
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HEURISTIC_TEST
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import LOGGING_LEVELS
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.enums import OPTION_TYPE
from lib.core.enums import OS
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.enums import POST_HINT
from lib.core.enums import REFLECTIVE_COUNTER
from lib.core.enums import SORT_ORDER
from lib.core.exception import SqlmapBaseException
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapInstallationException
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapNoneDataException
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
from lib.core.settings import BURP_REQUEST_REGEX
from lib.core.settings import BURP_XML_HISTORY_REGEX
from lib.core.settings import CRAWL_EXCLUDE_EXTENSIONS
from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR
from lib.core.settings import DBMS_DIRECTORY_DICT
from lib.core.settings import DEFAULT_COOKIE_DELIMITER
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import DEFAULT_MSSQL_SCHEMA
from lib.core.settings import DEV_EMAIL_ADDRESS
from lib.core.settings import DOLLAR_MARKER
from lib.core.settings import DUMMY_USER_INJECTION
from lib.core.settings import DYNAMICITY_BOUNDARY_LENGTH
from lib.core.settings import ERROR_PARSING_REGEXES
from lib.core.settings import EVALCODE_ENCODED_PREFIX
from lib.core.settings import FILE_PATH_REGEXES
from lib.core.settings import FORCE_COOKIE_EXPIRATION_TIME
from lib.core.settings import FORM_SEARCH_REGEX
from lib.core.settings import GENERIC_DOC_ROOT_DIRECTORY_NAMES
from lib.core.settings import GIT_PAGE
from lib.core.settings import GITHUB_REPORT_OAUTH_TOKEN
from lib.core.settings import GOOGLE_ANALYTICS_COOKIE_PREFIX
from lib.core.settings import HASHDB_MILESTONE_VALUE
from lib.core.settings import HOST_ALIASES
from lib.core.settings import HTTP_CHUNKED_SPLIT_KEYWORDS
from lib.core.settings import IGNORE_PARAMETERS
from lib.core.settings import IGNORE_SAVE_OPTIONS
from lib.core.settings import INFERENCE_UNKNOWN_CHAR
from lib.core.settings import IP_ADDRESS_REGEX
from lib.core.settings import ISSUES_PAGE
from lib.core.settings import IS_TTY
from lib.core.settings import IS_WIN
from lib.core.settings import LARGE_OUTPUT_THRESHOLD
from lib.core.settings import LOCALHOST
from lib.core.settings import MAX_INT
from lib.core.settings import MIN_ENCODED_LEN_CHECK
from lib.core.settings import MIN_ERROR_PARSING_NON_WRITING_RATIO
from lib.core.settings import MIN_TIME_RESPONSES
from lib.core.settings import MIN_VALID_DELAYED_RESPONSE
from lib.core.settings import NETSCAPE_FORMAT_HEADER_COOKIES
from lib.core.settings import NULL
from lib.core.settings import PARAMETER_AMP_MARKER
from lib.core.settings import PARAMETER_SEMICOLON_MARKER
from lib.core.settings import PARAMETER_PERCENTAGE_MARKER
from lib.core.settings import PARTIAL_HEX_VALUE_MARKER
from lib.core.settings import PARTIAL_VALUE_MARKER
from lib.core.settings import PAYLOAD_DELIMITER
from lib.core.settings import PLATFORM
from lib.core.settings import PRINTABLE_CHAR_REGEX
from lib.core.settings import PROBLEMATIC_CUSTOM_INJECTION_PATTERNS
from lib.core.settings import PUSH_VALUE_EXCEPTION_RETRY_COUNT
from lib.core.settings import PYVERSION
from lib.core.settings import RANDOMIZATION_TLDS
from lib.core.settings import REFERER_ALIASES
from lib.core.settings import REFLECTED_BORDER_REGEX
from lib.core.settings import REFLECTED_MAX_REGEX_PARTS
from lib.core.settings import REFLECTED_REPLACEMENT_REGEX
from lib.core.settings import REFLECTED_REPLACEMENT_TIMEOUT
from lib.core.settings import REFLECTED_VALUE_MARKER
from lib.core.settings import REFLECTIVE_MISS_THRESHOLD
from lib.core.settings import SENSITIVE_DATA_REGEX
from lib.core.settings import SENSITIVE_OPTIONS
from lib.core.settings import STDIN_PIPE_DASH
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import TEXT_TAG_REGEX
from lib.core.settings import TIME_STDEV_COEFF
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.core.settings import URI_QUESTION_MARKER
from lib.core.settings import URLENCODE_CHAR_LIMIT
from lib.core.settings import URLENCODE_FAILSAFE_CHARS
from lib.core.settings import USER_AGENT_ALIASES
from lib.core.settings import VERSION_COMPARISON_CORRECTION
from lib.core.settings import VERSION_STRING
from lib.core.settings import ZIP_HEADER
from lib.core.settings import WEBSCARAB_SPLITTER
from lib.core.threads import getCurrentThreadData
from lib.utils.safe2bin import safecharencode
from lib.utils.sqlalchemy import _sqlalchemy
from thirdparty import six
from thirdparty.clientform.clientform import ParseResponse
from thirdparty.clientform.clientform import ParseError
from thirdparty.colorama.initialise import init as coloramainit
from thirdparty.magic import magic
from thirdparty.odict import OrderedDict
from thirdparty.six import unichr as _unichr
from thirdparty.six.moves import collections_abc as _collections
from thirdparty.six.moves import configparser as _configparser
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import input as _input
from thirdparty.six.moves import reload_module as _reload_module
from thirdparty.six.moves import urllib as _urllib
from thirdparty.six.moves import zip as _zip
from thirdparty.termcolor.termcolor import colored

class UnicodeRawConfigParser(_configparser.RawConfigParser):
    """
    RawConfigParser with unicode writing support
    """

    def write(self, fp):
        """
        Write an .ini-format representation of the configuration state.
        """

        if self._defaults:
            fp.write("[%s]\n" % _configparser.DEFAULTSECT)

            for (key, value) in self._defaults.items():
                fp.write("%s = %s" % (key, getUnicode(value, UNICODE_ENCODING)))

            fp.write("\n")

        for section in self._sections:
            fp.write("[%s]\n" % section)

            for (key, value) in self._sections[section].items():
                if key != "__name__":
                    if value is None:
                        fp.write("%s\n" % (key))
                    elif not isListLike(value):
                        fp.write("%s = %s\n" % (key, getUnicode(value, UNICODE_ENCODING)))

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

        return Backend.getDbms() if versions is None else "%s %s" % (Backend.getDbms(), " and ".join(filterNone(versions)))

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
            if conf.api:
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
            if conf.api:
                infoApi["web application technology"] = Format.humanize(info["technology"], ", ")
            else:
                infoStr += "\nweb application technology: %s" % Format.humanize(info["technology"], ", ")

        if conf.api:
            return infoApi
        else:
            return infoStr.lstrip()

class Backend(object):
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
                choice = readInput(msg, default=kb.dbms)

                if aliasToDbmsEnum(choice) == kb.dbms:
                    kb.dbmsVersion = []
                    kb.resolutionDbms = kb.dbms
                    break
                elif aliasToDbmsEnum(choice) == dbms:
                    kb.dbms = aliasToDbmsEnum(choice)
                    break
                else:
                    warnMsg = "invalid value"
                    logger.warn(warnMsg)

        elif kb.dbms is None:
            kb.dbms = aliasToDbmsEnum(dbms)

        return kb.dbms

    @staticmethod
    def setVersion(version):
        if isinstance(version, six.string_types):
            kb.dbmsVersion = [version]

        return kb.dbmsVersion

    @staticmethod
    def setVersionList(versionsList):
        if isinstance(versionsList, list):
            kb.dbmsVersion = versionsList
        elif isinstance(versionsList, six.string_types):
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
        elif kb.os is not None and isinstance(os, six.string_types) and kb.os.lower() != os.lower():
            msg = "sqlmap previously fingerprinted back-end DBMS "
            msg += "operating system %s. However now it has " % kb.os
            msg += "been fingerprinted to be %s. " % os
            msg += "Please, specify which OS is "
            msg += "correct [%s (default)/%s] " % (kb.os, os)

            while True:
                choice = readInput(msg, default=kb.os)

                if choice == kb.os:
                    break
                elif choice == os:
                    kb.os = choice.capitalize()
                    break
                else:
                    warnMsg = "invalid value"
                    logger.warn(warnMsg)

        elif kb.os is None and isinstance(os, six.string_types):
            kb.os = os.capitalize()

        return kb.os

    @staticmethod
    def setOsVersion(version):
        if version is None:
            return None

        elif kb.osVersion is None and isinstance(version, six.string_types):
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
            choice = readInput(msg, default='1')

            if hasattr(choice, "isdigit") and choice.isdigit() and int(choice) in (1, 2):
                kb.arch = 32 if int(choice) == 1 else 64
                break
            else:
                warnMsg = "invalid value. Valid values are 1 and 2"
                logger.warn(warnMsg)

        return kb.arch

    # Get methods
    @staticmethod
    def getForcedDbms():
        return aliasToDbmsEnum(conf.get("forceDbms")) or aliasToDbmsEnum(kb.get("forcedDbms"))

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
        elif not kb.get("testMode") and conf.get("dbmsHandler") and getattr(conf.dbmsHandler, "_dbms", None):
            dbms = conf.dbmsHandler._dbms
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
        versions = filterNone(flattenValue(kb.dbmsVersion)) if not isinstance(kb.dbmsVersion, six.string_types) else [kb.dbmsVersion]
        if not isNoneValue(versions):
            return versions[0]
        else:
            return None

    @staticmethod
    def getVersionList():
        versions = filterNone(flattenValue(kb.dbmsVersion)) if not isinstance(kb.dbmsVersion, six.string_types) else [kb.dbmsVersion]
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
        if not kb.get("testMode") and all((Backend.getDbms(), Backend.getIdentifiedDbms())) and Backend.getDbms() != Backend.getIdentifiedDbms():
            singleTimeWarnMessage("identified ('%s') and fingerprinted ('%s') DBMSes differ. If you experience problems in enumeration phase please rerun with '--flush-session'" % (Backend.getIdentifiedDbms(), Backend.getDbms()))
        return Backend.getIdentifiedDbms() == aliasToDbmsEnum(dbms)

    @staticmethod
    def isFork(fork):
        return hashDBRetrieve(HASHDB_KEYS.DBMS_FORK) == fork

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
        retVal = False

        if Backend.getVersion() is not None and version is not None:
            try:
                retVal = distutils.version.LooseVersion(Backend.getVersion()) >= distutils.version.LooseVersion(version)
            except:
                retVal = str(Backend.getVersion()) >= str(version)

        return retVal

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
                value = "=".join(parts[1:])

                if parameter in (conf.base64Parameter or []):
                    try:
                        kb.base64Originals[parameter] = oldValue = value
                        value = urldecode(value, convall=True)
                        value = decodeBase64(value, binary=False, encoding=conf.encoding or UNICODE_ENCODING)
                        parameters = re.sub(r"\b%s(\b|\Z)" % re.escape(oldValue), value, parameters)
                    except:
                        errMsg = "parameter '%s' does not contain " % parameter
                        errMsg += "valid Base64 encoded value ('%s')" % value
                        raise SqlmapValueException(errMsg)

                testableParameters[parameter] = value

                if not conf.multipleTargets and not (conf.csrfToken and re.search(conf.csrfToken, parameter, re.I)):
                    _ = urldecode(testableParameters[parameter], convall=True)
                    if (_.endswith("'") and _.count("'") == 1 or re.search(r'\A9{3,}', _) or re.search(r'\A-\d+\Z', _) or re.search(DUMMY_USER_INJECTION, _)) and not parameter.upper().startswith(GOOGLE_ANALYTICS_COOKIE_PREFIX):
                        warnMsg = "it appears that you have provided tainted parameter values "
                        warnMsg += "('%s') with most likely leftover " % element
                        warnMsg += "chars/statements from manual SQL injection test(s). "
                        warnMsg += "Please, always use only valid parameter values "
                        warnMsg += "so sqlmap could be able to run properly"
                        logger.warn(warnMsg)

                        message = "are you really sure that you want to continue (sqlmap could have problems)? [y/N] "

                        if not readInput(message, default='N', boolean=True):
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
                                    if current is None:
                                        current = head
                                    if isListLike(current):
                                        for _ in current:
                                            walk(head, _)
                                    elif isinstance(current, dict):
                                        for key in current.keys():
                                            value = current[key]
                                            if isinstance(value, (bool, int, float, six.string_types)) or value in (None, []):
                                                original = current[key]
                                                if isinstance(value, bool):
                                                    current[key] = "%s%s" % (getUnicode(value).lower(), BOUNDED_INJECTION_MARKER)
                                                elif value is None:
                                                    current[key] = "%s%s" % (randomInt(), BOUNDED_INJECTION_MARKER)
                                                elif value == []:
                                                    current[key] = ["%s%s" % (randomInt(), BOUNDED_INJECTION_MARKER)]
                                                else:
                                                    current[key] = "%s%s" % (value, BOUNDED_INJECTION_MARKER)
                                                candidates["%s (%s)" % (parameter, key)] = re.sub(r"\b(%s\s*=\s*)%s" % (re.escape(parameter), re.escape(testableParameters[parameter])), r"\g<1>%s" % json.dumps(deserialized, separators=(',', ':') if ", " not in testableParameters[parameter] else None), parameters)
                                                current[key] = original
                                            elif isinstance(value, (list, tuple, set, dict)):
                                                if value:
                                                    walk(head, value)

                                deserialized = json.loads(testableParameters[parameter])
                                walk(deserialized)

                                if candidates:
                                    message = "it appears that provided value for %sparameter '%s' " % ("%s " % place if place != parameter else "", parameter)
                                    message += "is JSON deserializable. Do you want to inject inside? [y/N] "

                                    if readInput(message, default='N', boolean=True):
                                        del testableParameters[parameter]
                                        testableParameters.update(candidates)
                                    break
                            except (KeyboardInterrupt, SqlmapUserQuitException):
                                raise
                            except Exception:
                                pass

                            _ = re.sub(regex, r"\g<1>%s\g<%d>" % (kb.customInjectionMark, len(match.groups())), testableParameters[parameter])
                            message = "it appears that provided value for %sparameter '%s' " % ("%s " % place if place != parameter else "", parameter)
                            message += "has boundaries. Do you want to inject inside? ('%s') [y/N] " % getUnicode(_)

                            if readInput(message, default='N', boolean=True):
                                testableParameters[parameter] = re.sub(r"\b(%s\s*=\s*)%s" % (re.escape(parameter), re.escape(testableParameters[parameter])), (r"\g<1>%s" % re.sub(regex, r"\g<1>%s\g<2>" % BOUNDED_INJECTION_MARKER, testableParameters[parameter].replace("\\", r"\\"))), parameters)
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

        elif len(conf.testParameter) != len(testableParameters):
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
                        decoded = codecs.decode(value, encoding)
                        if len(decoded) > MIN_ENCODED_LEN_CHECK and all(_ in getBytes(string.printable) for _ in decoded):
                            warnMsg = "provided parameter '%s' " % parameter
                            warnMsg += "appears to be '%s' encoded" % encoding
                            logger.warn(warnMsg)
                            break
                    except:
                        pass

    return testableParameters

def getManualDirectories():
    directories = None
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

            for _ in list(GENERIC_DOC_ROOT_DIRECTORY_NAMES) + [conf.hostname]:
                _ = "/%s/" % _

                if _ in absFilePath:
                    directories = "%s%s" % (absFilePath.split(_)[0], _)
                    break

            if not directories and conf.path.strip('/') and conf.path in absFilePath:
                directories = absFilePath.split(conf.path)[0]

            if directories and windowsDriveLetter:
                directories = "%s/%s" % (windowsDriveLetter, ntToPosixSlashes(directories))

    directories = normalizePath(directories)

    if conf.webRoot:
        directories = [conf.webRoot]
        infoMsg = "using '%s' as web server document root" % conf.webRoot
        logger.info(infoMsg)
    elif directories:
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
        choice = readInput(message, default='1')

        if choice == '2':
            message = "please provide a comma separate list of absolute directory paths: "
            directories = readInput(message, default="").split(',')
        elif choice == '3':
            message = "what's the list file location?\n"
            listPath = readInput(message, default="")
            checkFile(listPath)
            directories = getFileItems(listPath)
        elif choice == '4':
            targets = set([conf.hostname])
            _ = conf.hostname.split('.')

            if _[0] == "www":
                targets.add('.'.join(_[1:]))
                targets.add('.'.join(_[1:-1]))
            else:
                targets.add('.'.join(_[:-1]))

            targets = filterNone(targets)

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
    """
    >>> pushValue(kb.absFilePaths)
    >>> kb.absFilePaths = ["C:\\inetpub\\wwwroot\\index.asp", "/var/www/html"]
    >>> getAutoDirectories()
    ['C:/inetpub/wwwroot', '/var/www/html']
    >>> kb.absFilePaths = popValue()
    """

    retVal = OrderedSet()

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

def boldifyMessage(message, istty=None):
    """
    Sets ANSI bold marking on entire message if parts found in predefined BOLD_PATTERNS

    >>> boldifyMessage("Hello World", istty=True)
    'Hello World'

    >>> boldifyMessage("GET parameter id is not injectable", istty=True)
    '\\x1b[1mGET parameter id is not injectable\\x1b[0m'
    """

    retVal = message

    if any(_ in message for _ in BOLD_PATTERNS):
        retVal = setColor(message, bold=True, istty=istty)

    return retVal

def setColor(message, color=None, bold=False, level=None, istty=None):
    """
    Sets ANSI color codes

    >>> setColor("Hello World", color="red", istty=True)
    '\\x1b[31mHello World\\x1b[0m'
    >>> setColor("[INFO] Hello World", istty=True)
    '[\\x1b[32mINFO\\x1b[0m] Hello World'
    >>> setColor("[INFO] Hello [CRITICAL] World", istty=True)
    '[INFO] Hello [CRITICAL] World'
    """

    retVal = message

    if message:
        if (IS_TTY or istty) and not conf.get("disableColoring"):  # colorizing handler
            if level is None:
                levels = re.findall(r"\[(?P<result>%s)\]" % '|'.join(_[0] for _ in getPublicTypeMembers(LOGGING_LEVELS)), message)

                if len(levels) == 1:
                    level = levels[0]

            if bold or color:
                retVal = colored(message, color=color, on_color=None, attrs=("bold",) if bold else None)
            elif level:
                try:
                    level = getattr(logging, level, None)
                except:
                    level = None
                retVal = LOGGER_HANDLER.colorize(message, level, True)
            else:
                match = re.search(r"\(([^)]*)\s*fork\)", message)
                if match:
                    retVal = retVal.replace(match.group(1), colored(match.group(1), color="lightgrey"))

                if not any(_ in message for _ in ("Payload: ",)):
                    for match in re.finditer(r"([^\w])'([^\n']+)'", message):  # single-quoted (Note: watch-out for the banner)
                        retVal = retVal.replace(match.group(0), "%s'%s'" % (match.group(1), colored(match.group(2), color="lightgrey")))

        message = message.strip()

    return retVal

def clearColors(message):
    """
    Clears ANSI color codes

    >>> clearColors("\x1b[38;5;82mHello \x1b[38;5;198mWorld")
    'Hello World'
    """

    retVal = message

    if isinstance(message, str):
        retVal = re.sub(r"\x1b\[[\d;]+m", "", message)

    return retVal

def dataToStdout(data, forceOutput=False, bold=False, contentType=None, status=CONTENT_STATUS.IN_PROGRESS, coloring=True):
    """
    Writes text to the stdout (console) stream
    """

    if not IS_TTY and isinstance(data, six.string_types) and data.startswith("\r"):
        if re.search(r"\(\d+%\)", data):
            data = ""
        else:
            data = "\n%s" % data.strip("\r")

    if not kb.get("threadException"):
        if forceOutput or not (getCurrentThreadData().disableStdOut or kb.get("wizardMode")):
            multiThreadMode = isMultiThreadMode()
            if multiThreadMode:
                logging._acquireLock()

            try:
                if conf.get("api"):
                    sys.stdout.write(stdoutEncode(clearColors(data)), status, contentType)
                else:
                    sys.stdout.write(stdoutEncode(setColor(data, bold=bold) if coloring else clearColors(data)))

                sys.stdout.flush()
            except IOError:
                pass

            if multiThreadMode:
                logging._releaseLock()

            kb.prependFlag = isinstance(data, six.string_types) and (len(data) == 1 and data not in ('\n', '\r') or len(data) > 2 and data[0] == '\r' and data[-1] != '\n')

def dataToTrafficFile(data):
    if not conf.trafficFile:
        return

    try:
        conf.trafficFP.write(data)
        conf.trafficFP.flush()
    except IOError as ex:
        errMsg = "something went wrong while trying "
        errMsg += "to write to the traffic file '%s' ('%s')" % (conf.trafficFile, getSafeExString(ex))
        raise SqlmapSystemException(errMsg)

def dataToDumpFile(dumpFile, data):
    try:
        dumpFile.write(data)
        dumpFile.flush()
    except IOError as ex:
        if "No space left" in getUnicode(ex):
            errMsg = "no space left on output device"
            logger.error(errMsg)
        elif "Permission denied" in getUnicode(ex):
            errMsg = "permission denied when flushing dump data"
            logger.error(errMsg)
        else:
            errMsg = "error occurred when writing dump data to file ('%s')" % getUnicode(ex)
            logger.error(errMsg)

def dataToOutFile(filename, data):
    """
    Saves data to filename

    >>> pushValue(conf.get("filePath"))
    >>> conf.filePath = tempfile.gettempdir()
    >>> "_etc_passwd" in dataToOutFile("/etc/passwd", b":::*")
    True
    >>> conf.filePath = popValue()
    """

    retVal = None

    if data:
        while True:
            retVal = os.path.join(conf.filePath, filePathToSafeString(filename))

            try:
                with open(retVal, "w+b") as f:  # has to stay as non-codecs because data is raw ASCII encoded data
                    f.write(getBytes(data))
            except UnicodeEncodeError as ex:
                _ = normalizeUnicode(filename)
                if filename != _:
                    filename = _
                else:
                    errMsg = "couldn't write to the "
                    errMsg += "output file ('%s')" % getSafeExString(ex)
                    raise SqlmapGenericException(errMsg)
            except IOError as ex:
                errMsg = "something went wrong while trying to write "
                errMsg += "to the output file ('%s')" % getSafeExString(ex)
                raise SqlmapGenericException(errMsg)
            else:
                break

    return retVal

def readInput(message, default=None, checkBatch=True, boolean=False):
    """
    Reads input from terminal
    """

    retVal = None

    message = getUnicode(message)

    if "\n" in message:
        message += "%s> " % ("\n" if message.count("\n") > 1 else "")
    elif message[-1] == ']':
        message += " "

    if kb.get("prependFlag"):
        message = "\n%s" % message
        kb.prependFlag = False

    if conf.get("answers"):
        if not any(_ in conf.answers for _ in ",="):
            return conf.answers

        for item in conf.answers.split(','):
            question = item.split('=')[0].strip()
            answer = item.split('=')[1] if len(item.split('=')) > 1 else None
            if answer and question.lower() in message.lower():
                retVal = getUnicode(answer, UNICODE_ENCODING)
            elif answer is None and retVal:
                retVal = "%s,%s" % (retVal, getUnicode(item, UNICODE_ENCODING))

    if message and IS_TTY:
        message = "\r%s" % message

    if retVal:
        dataToStdout("%s%s\n" % (message, retVal), forceOutput=not kb.wizardMode, bold=True)

        debugMsg = "used the given answer"
        logger.debug(debugMsg)

    if retVal is None:
        if checkBatch and conf.get("batch") or any(conf.get(_) for _ in ("api", "nonInteractive")):
            if isListLike(default):
                options = ','.join(getUnicode(opt, UNICODE_ENCODING) for opt in default)
            elif default:
                options = getUnicode(default, UNICODE_ENCODING)
            else:
                options = six.text_type()

            dataToStdout("%s%s\n" % (message, options), forceOutput=not kb.wizardMode, bold=True)

            debugMsg = "used the default behavior, running in batch mode"
            logger.debug(debugMsg)

            retVal = default
        else:
            try:
                logging._acquireLock()

                if conf.get("beep"):
                    beep()

                dataToStdout("%s" % message, forceOutput=not kb.wizardMode, bold=True)
                kb.prependFlag = False

                retVal = _input()
                if not retVal:  # Note: Python doesn't print newline on empty input
                    dataToStdout("\n")
                retVal = retVal.strip() or default
                retVal = getUnicode(retVal, encoding=getattr(sys.stdin, "encoding", None)) if retVal else retVal
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

    if retVal and default and isinstance(default, six.string_types) and len(default) == 1:
        retVal = retVal.strip()

    if boolean:
        retVal = retVal.strip().upper() == 'Y'
    else:
        retVal = retVal or ""

    return retVal

def setTechnique(technique):
    """
    Thread-safe setting of currently used technique (Note: dealing with cases of per-thread technique switching)
    """

    getCurrentThreadData().technique = technique

def getTechnique():
    """
    Thread-safe getting of currently used technique
    """

    return getCurrentThreadData().technique or kb.get("technique")

def randomRange(start=0, stop=1000, seed=None):
    """
    Returns random integer value in given range

    >>> random.seed(0)
    >>> randomRange(1, 500)
    152
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
    963638
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
    'FUPGpY'
    """

    if seed is not None:
        _random = getCurrentThreadData().random
        _random.seed(seed)
        choice = _random.choice
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

    >>> sanitizeStr('foo\\n\\rbar') == 'foo bar'
    True
    >>> sanitizeStr(None) == 'None'
    True
    """

    return getUnicode(value).replace("\n", " ").replace("\r", "")

def getHeader(headers, key):
    """
    Returns header value ignoring the letter case

    >>> getHeader({"Foo": "bar"}, "foo")
    'bar'
    """

    retVal = None

    for header in (headers or {}):
        if header.upper() == key.upper():
            retVal = headers[header]
            break

    return retVal

def checkPipedInput():
    """
    Checks whether input to program has been provided via standard input (e.g. cat /tmp/req.txt | python sqlmap.py -r -)
    # Reference: https://stackoverflow.com/a/33873570
    """

    return hasattr(sys.stdin, "fileno") and not os.isatty(sys.stdin.fileno())

def isZipFile(filename):
    """
    Checks if file contains zip compressed content

    >>> isZipFile(paths.WORDLIST)
    True
    """

    checkFile(filename)

    return openFile(filename, "rb", encoding=None).read(len(ZIP_HEADER)) == ZIP_HEADER

def isDigit(value):
    """
    Checks if provided (string) value consists of digits (Note: Python's isdigit() is problematic)

    >>> u'\xb2'.isdigit()
    True
    >>> isDigit(u'\xb2')
    False
    >>> isDigit('123456')
    True
    >>> isDigit('3b3')
    False
    """

    return re.search(r"\A[0-9]+\Z", value or "") is not None

def checkFile(filename, raiseOnError=True):
    """
    Checks for file existence and readability

    >>> checkFile(__file__)
    True
    """

    valid = True

    if filename:
        filename = filename.strip('"\'')

    if filename == STDIN_PIPE_DASH:
        return checkPipedInput()
    else:
        try:
            if filename is None or not os.path.isfile(filename):
                valid = False
        except:
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

    if not any(_ in sys.argv for _ in ("--version", "--api")) and not conf.get("disableBanner"):
        result = BANNER

        if not IS_TTY or any(_ in sys.argv for _ in ("--disable-coloring", "--disable-colouring")):
            result = clearColors(result)
        elif IS_WIN:
            coloramainit()

        dataToStdout(result, forceOutput=True)

def parsePasswordHash(password):
    """
    In case of Microsoft SQL Server password hash value is expanded to its components

    >>> pushValue(kb.forcedDbms)
    >>> kb.forcedDbms = DBMS.MSSQL
    >>> "salt: 4086ceb6" in parsePasswordHash("0x01004086ceb60c90646a8ab9889fe3ed8e5c150b5460ece8425a")
    True
    >>> kb.forcedDbms = popValue()
    """

    blank = ' ' * 8

    if isNoneValue(password) or password == ' ':
        retVal = NULL
    else:
        retVal = password

    if Backend.isDbms(DBMS.MSSQL) and retVal != NULL and isHexEncodedString(password):
        retVal = "%s\n" % password
        retVal += "%sheader: %s\n" % (blank, password[:6])
        retVal += "%ssalt: %s\n" % (blank, password[6:14])
        retVal += "%smixedcase: %s\n" % (blank, password[14:54])

        if password[54:]:
            retVal += "%suppercase: %s" % (blank, password[54:])

    return retVal

def cleanQuery(query):
    """
    Switch all SQL statement (alike) keywords to upper case

    >>> cleanQuery("select id from users")
    'SELECT id FROM users'
    """

    retVal = query

    for sqlStatements in SQL_STATEMENTS.values():
        for sqlStatement in sqlStatements:
            candidate = sqlStatement.replace("(", "").replace(")", "").strip()
            queryMatch = re.search(r"(?i)\b(%s)\b" % candidate, query)

            if queryMatch and "sys_exec" not in query:
                retVal = retVal.replace(queryMatch.group(1), candidate.upper())

    return retVal

def setPaths(rootPath):
    """
    Sets absolute paths for project directories and files
    """

    paths.SQLMAP_ROOT_PATH = rootPath

    # sqlmap paths
    paths.SQLMAP_DATA_PATH = os.path.join(paths.SQLMAP_ROOT_PATH, "data")
    paths.SQLMAP_EXTRAS_PATH = os.path.join(paths.SQLMAP_ROOT_PATH, "extra")
    paths.SQLMAP_SETTINGS_PATH = os.path.join(paths.SQLMAP_ROOT_PATH, "lib", "core", "settings.py")
    paths.SQLMAP_TAMPER_PATH = os.path.join(paths.SQLMAP_ROOT_PATH, "tamper")

    paths.SQLMAP_PROCS_PATH = os.path.join(paths.SQLMAP_DATA_PATH, "procs")
    paths.SQLMAP_SHELL_PATH = os.path.join(paths.SQLMAP_DATA_PATH, "shell")
    paths.SQLMAP_TXT_PATH = os.path.join(paths.SQLMAP_DATA_PATH, "txt")
    paths.SQLMAP_UDF_PATH = os.path.join(paths.SQLMAP_DATA_PATH, "udf")
    paths.SQLMAP_XML_PATH = os.path.join(paths.SQLMAP_DATA_PATH, "xml")
    paths.SQLMAP_XML_BANNER_PATH = os.path.join(paths.SQLMAP_XML_PATH, "banner")
    paths.SQLMAP_XML_PAYLOADS_PATH = os.path.join(paths.SQLMAP_XML_PATH, "payloads")

    # sqlmap files
    paths.COMMON_COLUMNS = os.path.join(paths.SQLMAP_TXT_PATH, "common-columns.txt")
    paths.COMMON_FILES = os.path.join(paths.SQLMAP_TXT_PATH, "common-files.txt")
    paths.COMMON_TABLES = os.path.join(paths.SQLMAP_TXT_PATH, "common-tables.txt")
    paths.COMMON_OUTPUTS = os.path.join(paths.SQLMAP_TXT_PATH, 'common-outputs.txt')
    paths.SQL_KEYWORDS = os.path.join(paths.SQLMAP_TXT_PATH, "keywords.txt")
    paths.SMALL_DICT = os.path.join(paths.SQLMAP_TXT_PATH, "smalldict.txt")
    paths.USER_AGENTS = os.path.join(paths.SQLMAP_TXT_PATH, "user-agents.txt")
    paths.WORDLIST = os.path.join(paths.SQLMAP_TXT_PATH, "wordlist.tx_")
    paths.ERRORS_XML = os.path.join(paths.SQLMAP_XML_PATH, "errors.xml")
    paths.BOUNDARIES_XML = os.path.join(paths.SQLMAP_XML_PATH, "boundaries.xml")
    paths.QUERIES_XML = os.path.join(paths.SQLMAP_XML_PATH, "queries.xml")
    paths.GENERIC_XML = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "generic.xml")
    paths.MSSQL_XML = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "mssql.xml")
    paths.MYSQL_XML = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "mysql.xml")
    paths.ORACLE_XML = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "oracle.xml")
    paths.PGSQL_XML = os.path.join(paths.SQLMAP_XML_BANNER_PATH, "postgresql.xml")

    for path in paths.values():
        if any(path.endswith(_) for _ in (".txt", ".xml", ".tx_")):
            checkFile(path)

    if IS_WIN:
        # Reference: https://pureinfotech.com/list-environment-variables-windows-10/
        if os.getenv("LOCALAPPDATA"):
            paths.SQLMAP_HOME_PATH = os.path.expandvars("%LOCALAPPDATA%\\sqlmap")
        elif os.getenv("USERPROFILE"):
            paths.SQLMAP_HOME_PATH = os.path.expandvars("%USERPROFILE%\\Local Settings\\sqlmap")
        else:
            paths.SQLMAP_HOME_PATH = os.path.join(os.path.expandvars(os.path.expanduser("~")), "sqlmap")
    else:
        paths.SQLMAP_HOME_PATH = os.path.join(os.path.expandvars(os.path.expanduser("~")), ".sqlmap")

        if not os.path.isdir(paths.SQLMAP_HOME_PATH):
            if "XDG_DATA_HOME" in os.environ:
                paths.SQLMAP_HOME_PATH = os.path.join(os.environ["XDG_DATA_HOME"], "sqlmap")
            else:
                paths.SQLMAP_HOME_PATH = os.path.join(os.path.expandvars(os.path.expanduser("~")), ".local", "share", "sqlmap")

    paths.SQLMAP_OUTPUT_PATH = getUnicode(paths.get("SQLMAP_OUTPUT_PATH", os.path.join(paths.SQLMAP_HOME_PATH, "output")), encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)
    paths.SQLMAP_DUMP_PATH = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "dump")
    paths.SQLMAP_FILES_PATH = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "files")

    # History files
    paths.SQLMAP_HISTORY_PATH = getUnicode(os.path.join(paths.SQLMAP_HOME_PATH, "history"), encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)
    paths.API_SHELL_HISTORY = os.path.join(paths.SQLMAP_HISTORY_PATH, "api.hst")
    paths.OS_SHELL_HISTORY = os.path.join(paths.SQLMAP_HISTORY_PATH, "os.hst")
    paths.SQL_SHELL_HISTORY = os.path.join(paths.SQLMAP_HISTORY_PATH, "sql.hst")
    paths.SQLMAP_SHELL_HISTORY = os.path.join(paths.SQLMAP_HISTORY_PATH, "sqlmap.hst")
    paths.GITHUB_HISTORY = os.path.join(paths.SQLMAP_HISTORY_PATH, "github.hst")

def weAreFrozen():
    """
    Returns whether we are frozen via py2exe.
    This will affect how we find out where we are located.

    # Reference: http://www.py2exe.org/index.cgi/WhereAmI
    """

    return hasattr(sys, "frozen")

def parseTargetDirect():
    """
    Parse target dbms and set some attributes into the configuration singleton

    >>> pushValue(conf.direct)
    >>> conf.direct = "mysql://root:testpass@127.0.0.1:3306/testdb"
    >>> parseTargetDirect()
    >>> conf.dbmsDb
    'testdb'
    >>> conf.dbmsPass
    'testpass'
    >>> conf.direct = popValue()
    """

    if not conf.direct:
        return

    details = None
    remote = False

    for dbms in SUPPORTED_DBMS:
        details = re.search(r"^(?P<dbms>%s)://(?P<credentials>(?P<user>.*?)\:(?P<pass>.*)\@)?(?P<remote>(?P<hostname>[\w.-]+?)\:(?P<port>[\d]+)\/)?(?P<db>[\w\d\ \:\.\_\-\/\\]*)$" % dbms, conf.direct, re.I)

        if details:
            conf.dbms = details.group("dbms")

            if details.group("credentials"):
                conf.dbmsUser = details.group("user")
                conf.dbmsPass = details.group("pass")
            else:
                if conf.dbmsCred:
                    conf.dbmsUser, conf.dbmsPass = conf.dbmsCred.split(':')
                else:
                    conf.dbmsUser = ""
                    conf.dbmsPass = ""

            if not conf.dbmsPass:
                conf.dbmsPass = None

            if details.group("remote"):
                remote = True
                conf.hostname = details.group("hostname").strip()
                conf.port = int(details.group("port"))
            else:
                conf.hostname = "localhost"
                conf.port = 0

            conf.dbmsDb = details.group("db").strip() if details.group("db") is not None else None
            conf.parameters[None] = "direct connection"

            break

    if kb.smokeMode:
        return

    if not details:
        errMsg = "invalid target details, valid syntax is for instance "
        errMsg += "'mysql://USER:PASSWORD@DBMS_IP:DBMS_PORT/DATABASE_NAME' "
        errMsg += "or 'access://DATABASE_FILEPATH'"
        raise SqlmapSyntaxException(errMsg)

    for dbmsName, data in DBMS_DICT.items():
        if dbmsName == conf.dbms or conf.dbms.lower() in data[0]:
            try:
                conf.dbms = dbmsName

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
                    __import__("_mssql")
                    pymssql = __import__("pymssql")

                    if not hasattr(pymssql, "__version__") or pymssql.__version__ < "1.0.2":
                        errMsg = "'%s' third-party library must be " % data[1]
                        errMsg += "version >= 1.0.2 to work properly. "
                        errMsg += "Download from '%s'" % data[2]
                        raise SqlmapMissingDependence(errMsg)

                elif dbmsName == DBMS.MYSQL:
                    __import__("pymysql")
                elif dbmsName == DBMS.PGSQL:
                    __import__("psycopg2")
                elif dbmsName == DBMS.ORACLE:
                    __import__("cx_Oracle")

                    # Reference: http://itsiti.com/ora-28009-connection-sys-sysdba-sysoper
                    if (conf.dbmsUser or "").upper() == "SYS":
                        conf.direct = "%s?mode=SYSDBA" % conf.direct
                elif dbmsName == DBMS.SQLITE:
                    __import__("sqlite3")
                elif dbmsName == DBMS.ACCESS:
                    __import__("pyodbc")
                elif dbmsName == DBMS.FIREBIRD:
                    __import__("kinterbasdb")
            except (SqlmapSyntaxException, SqlmapMissingDependence):
                raise
            except:
                if _sqlalchemy and data[3] and any(_ in _sqlalchemy.dialects.__all__ for _ in (data[3], data[3].split('+')[0])):
                    pass
                else:
                    errMsg = "sqlmap requires '%s' third-party library " % data[1]
                    errMsg += "in order to directly connect to the DBMS "
                    errMsg += "'%s'. You can download it from '%s'" % (dbmsName, data[2])
                    errMsg += ". Alternative is to use a package 'python-sqlalchemy' "
                    errMsg += "with support for dialect '%s' installed" % data[3]
                    raise SqlmapMissingDependence(errMsg)

def parseTargetUrl():
    """
    Parse target URL and set some attributes into the configuration singleton

    >>> pushValue(conf.url)
    >>> conf.url = "https://www.test.com/?id=1"
    >>> parseTargetUrl()
    >>> conf.hostname
    'www.test.com'
    >>> conf.scheme
    'https'
    >>> conf.url = popValue()
    """

    if not conf.url:
        return

    originalUrl = conf.url

    if re.search(r"://\[.+\]", conf.url) and not socket.has_ipv6:
        errMsg = "IPv6 communication is not supported "
        errMsg += "on this platform"
        raise SqlmapGenericException(errMsg)

    if not re.search(r"^(http|ws)s?://", conf.url, re.I):
        if re.search(r":443\b", conf.url):
            conf.url = "https://%s" % conf.url
        else:
            conf.url = "http://%s" % conf.url

    if kb.customInjectionMark in conf.url:
        conf.url = conf.url.replace('?', URI_QUESTION_MARKER)

    try:
        urlSplit = _urllib.parse.urlsplit(conf.url)
    except ValueError as ex:
        errMsg = "invalid URL '%s' has been given ('%s'). " % (conf.url, getSafeExString(ex))
        errMsg += "Please be sure that you don't have any leftover characters (e.g. '[' or ']') "
        errMsg += "in the hostname part"
        raise SqlmapGenericException(errMsg)

    hostnamePort = urlSplit.netloc.split(":") if not re.search(r"\[.+\]", urlSplit.netloc) else filterNone((re.search(r"\[.+\]", urlSplit.netloc).group(0), re.search(r"\](:(?P<port>\d+))?", urlSplit.netloc).group("port")))

    conf.scheme = (urlSplit.scheme.strip().lower() or "http")
    conf.path = urlSplit.path.strip()
    conf.hostname = hostnamePort[0].strip()

    if conf.forceSSL:
        conf.scheme = re.sub(r"(?i)\A(http|ws)\Z", r"\g<1>s", conf.scheme)

    conf.ipv6 = conf.hostname != conf.hostname.strip("[]")
    conf.hostname = conf.hostname.strip("[]").replace(kb.customInjectionMark, "")

    try:
        conf.hostname.encode("idna")
        conf.hostname.encode(UNICODE_ENCODING)
    except (LookupError, UnicodeError):
        invalid = True
    else:
        invalid = False

    if any((invalid, re.search(r"\s", conf.hostname), '..' in conf.hostname, conf.hostname.startswith('.'), '\n' in originalUrl)):
        errMsg = "invalid target URL ('%s')" % originalUrl
        raise SqlmapSyntaxException(errMsg)

    if len(hostnamePort) == 2:
        try:
            conf.port = int(hostnamePort[1])
        except:
            errMsg = "invalid target URL"
            raise SqlmapSyntaxException(errMsg)
    elif conf.scheme in ("https", "wss"):
        conf.port = 443
    else:
        conf.port = 80

    if conf.port < 1 or conf.port > 65535:
        errMsg = "invalid target URL port (%d)" % conf.port
        raise SqlmapSyntaxException(errMsg)

    conf.url = getUnicode("%s://%s:%d%s" % (conf.scheme, ("[%s]" % conf.hostname) if conf.ipv6 else conf.hostname, conf.port, conf.path))
    conf.url = conf.url.replace(URI_QUESTION_MARKER, '?')

    if urlSplit.query:
        if '=' not in urlSplit.query:
            conf.url = "%s?%s" % (conf.url, getUnicode(urlSplit.query))
        else:
            conf.parameters[PLACE.GET] = urldecode(urlSplit.query, spaceplus=not conf.base64Parameter) if urlSplit.query and urlencode(DEFAULT_GET_POST_DELIMITER, None) not in urlSplit.query else urlSplit.query

    if (intersect(REFERER_ALIASES, conf.testParameter, True) or conf.level >= 3) and not any(_[0].upper() == HTTP_HEADER.REFERER.upper() for _ in conf.httpHeaders):
        debugMsg = "setting the HTTP Referer header to the target URL"
        logger.debug(debugMsg)
        conf.httpHeaders = [_ for _ in conf.httpHeaders if _[0] != HTTP_HEADER.REFERER]
        conf.httpHeaders.append((HTTP_HEADER.REFERER, conf.url.replace(kb.customInjectionMark, "")))

    if (intersect(HOST_ALIASES, conf.testParameter, True) or conf.level >= 5) and not any(_[0].upper() == HTTP_HEADER.HOST.upper() for _ in conf.httpHeaders):
        debugMsg = "setting the HTTP Host header to the target URL"
        logger.debug(debugMsg)
        conf.httpHeaders = [_ for _ in conf.httpHeaders if _[0] != HTTP_HEADER.HOST]
        conf.httpHeaders.append((HTTP_HEADER.HOST, getHostHeader(conf.url)))

    if conf.url != originalUrl:
        kb.originalUrls[conf.url] = originalUrl

def escapeJsonValue(value):
    """
    Escapes JSON value (used in payloads)

    # Reference: https://stackoverflow.com/a/16652683

    >>> "\\n" in escapeJsonValue("foo\\nbar")
    False
    >>> "\\\\t" in escapeJsonValue("foo\\tbar")
    True
    """

    retVal = ""

    for char in value:
        if char < ' ' or char == '"':
            retVal += json.dumps(char)[1:-1]
        else:
            retVal += char

    return retVal

def expandAsteriskForColumns(expression):
    """
    If the user provided an asterisk rather than the column(s)
    name, sqlmap will retrieve the columns itself and reprocess
    the SQL query string (expression)
    """

    match = re.search(r"(?i)\ASELECT(\s+TOP\s+[\d]+)?\s+\*\s+FROM\s+((`[^`]+`|[^\s]+)+)", expression)

    if match:
        infoMsg = "you did not provide the fields in your query. "
        infoMsg += "sqlmap will retrieve the column names itself"
        logger.info(infoMsg)

        _ = match.group(2).replace("..", '.').replace(".dbo.", '.')
        db, conf.tbl = _.split('.', 1) if '.' in _ else (None, _)

        if db is None:
            if expression != conf.sqlQuery:
                conf.db = db
            elif conf.db:
                expression = re.sub(r"([^\w])%s" % re.escape(conf.tbl), r"\g<1>%s.%s" % (conf.db, conf.tbl), expression)
        else:
            conf.db = db

        conf.db = safeSQLIdentificatorNaming(conf.db)
        conf.tbl = safeSQLIdentificatorNaming(conf.tbl, True)

        columnsDict = conf.dbmsHandler.getColumns(onlyColNames=True)

        if columnsDict and conf.db in columnsDict and conf.tbl in columnsDict[conf.db]:
            columns = list(columnsDict[conf.db][conf.tbl].keys())
            columns.sort()
            columnsStr = ", ".join(column for column in columns)
            expression = expression.replace('*', columnsStr, 1)

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
    reverse = False

    if kb.dumpTable:
        if conf.limitStart and conf.limitStop and conf.limitStart > conf.limitStop:
            limitStop = conf.limitStart
            limitStart = conf.limitStop
            reverse = True
        else:
            if isinstance(conf.limitStop, int) and conf.limitStop > 0 and conf.limitStop < limitStop:
                limitStop = conf.limitStop

            if isinstance(conf.limitStart, int) and conf.limitStart > 0 and conf.limitStart <= limitStop:
                limitStart = conf.limitStart

    retVal = xrange(limitStart, limitStop + 1) if plusOne else xrange(limitStart - 1, limitStop)

    if reverse:
        retVal = xrange(retVal[-1], retVal[0] - 1, -1)

    return retVal

def parseUnionPage(page):
    """
    Returns resulting items from UNION query inside provided page content

    >>> parseUnionPage("%sfoo%s%sbar%s" % (kb.chars.start, kb.chars.stop, kb.chars.start, kb.chars.stop))
    ['foo', 'bar']
    """

    if page is None:
        return None

    if re.search(r"(?si)\A%s.*%s\Z" % (kb.chars.start, kb.chars.stop), page):
        if len(page) > LARGE_OUTPUT_THRESHOLD:
            warnMsg = "large output detected. This might take a while"
            logger.warn(warnMsg)

        data = BigArray()
        keys = set()

        for match in re.finditer(r"%s(.*?)%s" % (kb.chars.start, kb.chars.stop), page, re.DOTALL | re.IGNORECASE):
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
                entry = applyFunctionRecursively(entry, decodeDbmsHexValue)

            if kb.safeCharEncode:
                entry = applyFunctionRecursively(entry, safecharencode)

            data.append(entry[0] if len(entry) == 1 else entry)
    else:
        data = page

    if len(data) == 1 and isinstance(data[0], six.string_types):
        data = data[0]

    return data

def parseFilePaths(page):
    """
    Detects (possible) absolute system paths inside the provided page content

    >>> _ = "/var/www/html/index.php"; parseFilePaths("<html>Error occurred at line 207 of: %s<br>Please contact your administrator</html>" % _); _ in kb.absFilePaths
    True
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

    >>> pushValue(conf.hostname)
    >>> conf.hostname = "localhost"
    >>> getRemoteIP() == "127.0.0.1"
    True
    >>> conf.hostname = popValue()
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
    """
    Returns "magic" file type for given file path

    >>> getFileType(__file__)
    'text'
    >>> getFileType(sys.executable)
    'binary'
    """

    try:
        desc = magic.from_file(filePath) or magic.MAGIC_UNKNOWN_FILETYPE
    except:
        desc = magic.MAGIC_UNKNOWN_FILETYPE
    finally:
        desc = getText(desc)

    if desc == getText(magic.MAGIC_UNKNOWN_FILETYPE):
        content = openFile(filePath, "rb", encoding=None).read()

        try:
            content.decode()
        except:
            pass
        else:
            desc = "ascii"

    return "text" if any(_ in desc.lower() for _ in ("ascii", "text")) else "binary"

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

    # Binary
    elif charsetType == CHARSET_TYPE.BINARY:
        asciiTbl.extend((0, 1))
        asciiTbl.extend(xrange(47, 50))

    # Digits
    elif charsetType == CHARSET_TYPE.DIGITS:
        asciiTbl.extend((0, 9))
        asciiTbl.extend(xrange(47, 58))

    # Hexadecimal
    elif charsetType == CHARSET_TYPE.HEXADECIMAL:
        asciiTbl.extend((0, 1))
        asciiTbl.extend(xrange(47, 58))
        asciiTbl.extend(xrange(64, 71))
        asciiTbl.extend((87, 88))  # X
        asciiTbl.extend(xrange(96, 103))
        asciiTbl.extend((119, 120))  # x

    # Characters
    elif charsetType == CHARSET_TYPE.ALPHA:
        asciiTbl.extend((0, 1))
        asciiTbl.extend(xrange(64, 91))
        asciiTbl.extend(xrange(96, 123))

    # Characters and digits
    elif charsetType == CHARSET_TYPE.ALPHANUM:
        asciiTbl.extend((0, 1))
        asciiTbl.extend(xrange(47, 58))
        asciiTbl.extend(xrange(64, 91))
        asciiTbl.extend(xrange(96, 123))

    return asciiTbl

def directoryPath(filepath):
    """
    Returns directory path for a given filepath

    >>> directoryPath('/var/log/apache.log')
    '/var/log'
    >>> directoryPath('/var/log')
    '/var/log'
    """

    retVal = filepath

    if filepath and os.path.splitext(filepath)[-1]:
        retVal = ntpath.dirname(filepath) if isWindowsDriveLetterPath(filepath) else posixpath.dirname(filepath)

    return retVal

def normalizePath(filepath):
    """
    Returns normalized string representation of a given filepath

    >>> normalizePath('//var///log/apache.log')
    '/var/log/apache.log'
    """

    retVal = filepath

    if retVal:
        retVal = retVal.strip("\r\n")
        retVal = ntpath.normpath(retVal) if isWindowsDriveLetterPath(retVal) else re.sub(r"\A/{2,}", "/", posixpath.normpath(retVal))

    return retVal

def safeFilepathEncode(filepath):
    """
    Returns filepath in (ASCII) format acceptable for OS handling (e.g. reading)

    >>> 'sqlmap' in safeFilepathEncode(paths.SQLMAP_HOME_PATH)
    True
    """

    retVal = filepath

    if filepath and six.PY2 and isinstance(filepath, six.text_type):
        retVal = getBytes(filepath, sys.getfilesystemencoding() or UNICODE_ENCODING)

    return retVal


def safeExpandUser(filepath):
    """
    Patch for a Python Issue18171 (http://bugs.python.org/issue18171)

    >>> os.path.basename(__file__) in safeExpandUser(__file__)
    True
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
    'SELECT foo FROM bar LIMIT 1'
    >>> safeStringFormat("SELECT foo FROM %s WHERE name LIKE '%susan%' LIMIT %d", ('bar', '1'))
    "SELECT foo FROM bar WHERE name LIKE '%susan%' LIMIT 1"
    """

    if format_.count(PAYLOAD_DELIMITER) == 2:
        _ = format_.split(PAYLOAD_DELIMITER)
        _[1] = re.sub(r"(\A|[^A-Za-z0-9])(%d)([^A-Za-z0-9]|\Z)", r"\g<1>%s\g<3>", _[1])
        retVal = PAYLOAD_DELIMITER.join(_)
    else:
        retVal = re.sub(r"(\A|[^A-Za-z0-9])(%d)([^A-Za-z0-9]|\Z)", r"\g<1>%s\g<3>", format_)

    if isinstance(params, six.string_types):
        retVal = retVal.replace("%s", params, 1)
    elif not isListLike(params):
        retVal = retVal.replace("%s", getUnicode(params), 1)
    else:
        start, end = 0, len(retVal)
        match = re.search(r"%s(.+)%s" % (PAYLOAD_DELIMITER, PAYLOAD_DELIMITER), retVal)
        if match and PAYLOAD_DELIMITER not in match.group(1):
            start, end = match.start(), match.end()
        if retVal.count("%s", start, end) == len(params):
            for param in params:
                index = retVal.find("%s", start)
                if isinstance(param, six.string_types):
                    param = param.replace('%', PARAMETER_PERCENTAGE_MARKER)
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
                        warnMsg += "Please report by e-mail content \"%r | %r | %r\" to '%s'" % (format_, params, retVal, DEV_EMAIL_ADDRESS)
                        raise SqlmapValueException(warnMsg)
                    else:
                        try:
                            retVal = re.sub(r"(\A|[^A-Za-z0-9])(%s)([^A-Za-z0-9]|\Z)", r"\g<1>%s\g<3>" % params[count], retVal, 1)
                        except re.error:
                            retVal = retVal.replace(match.group(0), match.group(0) % params[count], 1)
                        count += 1
                else:
                    break

    retVal = getText(retVal).replace(PARAMETER_PERCENTAGE_MARKER, '%')

    return retVal

def getFilteredPageContent(page, onlyText=True, split=" "):
    """
    Returns filtered page content without script, style and/or comments
    or all HTML tags

    >>> getFilteredPageContent(u'<html><title>foobar</title><body>test</body></html>') == "foobar test"
    True
    """

    retVal = page

    # only if the page's charset has been successfully identified
    if isinstance(page, six.text_type):
        retVal = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>%s" % (r"|<[^>]+>|\t|\n|\r" if onlyText else ""), split, page)
        retVal = re.sub(r"%s{2,}" % split, split, retVal)
        retVal = htmlUnescape(retVal.strip().strip(split))

    return retVal

def getPageWordSet(page):
    """
    Returns word set used in page content

    >>> sorted(getPageWordSet(u'<html><title>foobar</title><body>test</body></html>')) == [u'foobar', u'test']
    True
    """

    retVal = set()

    # only if the page's charset has been successfully identified
    if isinstance(page, six.string_types):
        retVal = set(_.group(0) for _ in re.finditer(r"\w+", getFilteredPageContent(page)))

    return retVal

def showStaticWords(firstPage, secondPage, minLength=3):
    """
    Prints words appearing in two different response pages

    >>> showStaticWords("this is a test", "this is another test")
    ['this']
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
        commonWords = [_ for _ in commonWords if len(_) >= minLength]
        commonWords.sort(key=functools.cmp_to_key(lambda a, b: cmp(a.lower(), b.lower())))

        for word in commonWords:
            infoMsg += "'%s', " % word

        infoMsg = infoMsg.rstrip(", ")
    else:
        infoMsg += "None"

    logger.info(infoMsg)

    return commonWords

def isWindowsDriveLetterPath(filepath):
    """
    Returns True if given filepath starts with a Windows drive letter

    >>> isWindowsDriveLetterPath('C:\\boot.ini')
    True
    >>> isWindowsDriveLetterPath('/var/log/apache.log')
    False
    """

    return re.search(r"\A[\w]\:", filepath) is not None

def posixToNtSlashes(filepath):
    """
    Replaces all occurrences of Posix slashes in provided
    filepath with NT backslashes

    >>> posixToNtSlashes('C:/Windows')
    'C:\\\\Windows'
    """

    return filepath.replace('/', '\\') if filepath else filepath

def ntToPosixSlashes(filepath):
    """
    Replaces all occurrences of NT backslashes in provided
    filepath with Posix slashes

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

def isMultiThreadMode():
    """
    Checks if running in multi-thread(ing) mode

    >>> isMultiThreadMode()
    False
    >>> _ = lambda: time.sleep(0.1)
    >>> thread = threading.Thread(target=_)
    >>> thread.daemon = True
    >>> thread.start()
    >>> isMultiThreadMode()
    True
    """

    return threading.activeCount() > 1

@cachedmethod
def getConsoleWidth(default=80):
    """
    Returns console width

    >>> any((getConsoleWidth(), True))
    True
    """

    width = None

    if os.getenv("COLUMNS", "").isdigit():
        width = int(os.getenv("COLUMNS"))
    else:
        try:
            output = shellExec("stty size")
            match = re.search(r"\A\d+ (\d+)", output)

            if match:
                width = int(match.group(1))
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

def shellExec(cmd):
    """
    Executes arbitrary shell command

    >>> shellExec('echo 1').strip() == '1'
    True
    """

    retVal = ""

    try:
        retVal = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0] or ""
    except Exception as ex:
        retVal = getSafeExString(ex)
    finally:
        retVal = getText(retVal)

    return retVal

def clearConsoleLine(forceOutput=False):
    """
    Clears current console line
    """

    if IS_TTY:
        dataToStdout("\r%s\r" % (" " * (getConsoleWidth() - 1)), forceOutput)

    kb.prependFlag = False

def parseXmlFile(xmlFile, handler):
    """
    Parses XML file by a given handler
    """

    try:
        with contextlib.closing(io.StringIO(readCachedFileContent(xmlFile))) as stream:
            parse(stream, handler)
    except (SAXParseException, UnicodeError) as ex:
        errMsg = "something appears to be wrong with "
        errMsg += "the file '%s' ('%s'). Please make " % (xmlFile, getSafeExString(ex))
        errMsg += "sure that you haven't made any changes to it"
        raise SqlmapInstallationException(errMsg)

def getSQLSnippet(dbms, sfile, **variables):
    """
    Returns content of SQL snippet located inside 'procs/' directory

    >>> 'RECONFIGURE' in getSQLSnippet(DBMS.MSSQL, "activate_sp_oacreate")
    True
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
    retVal = re.sub(r";\s+", "; ", retVal).strip("\r\n")

    for _ in variables:
        retVal = re.sub(r"%%%s%%" % _, variables[_].replace('\\', r'\\'), retVal)

    for _ in re.findall(r"%RANDSTR\d+%", retVal, re.I):
        retVal = retVal.replace(_, randomStr())

    for _ in re.findall(r"%RANDINT\d+%", retVal, re.I):
        retVal = retVal.replace(_, randomInt())

    variables = re.findall(r"(?<!\bLIKE ')%(\w+)%", retVal, re.I)

    if variables:
        errMsg = "unresolved variable%s '%s' in SQL file '%s'" % ("s" if len(variables) > 1 else "", ", ".join(variables), sfile)
        logger.error(errMsg)

        msg = "do you want to provide the substitution values? [y/N] "

        if readInput(msg, default='N', boolean=True):
            for var in variables:
                msg = "insert value for variable '%s': " % var
                val = readInput(msg, default="")
                retVal = retVal.replace(r"%%%s%%" % var, val)

    return retVal

def readCachedFileContent(filename, mode="rb"):
    """
    Cached reading of file content (avoiding multiple same file reading)

    >>> "readCachedFileContent" in readCachedFileContent(__file__)
    True
    """

    if filename not in kb.cache.content:
        with kb.locks.cache:
            if filename not in kb.cache.content:
                checkFile(filename)
                try:
                    with openFile(filename, mode) as f:
                        kb.cache.content[filename] = f.read()
                except (IOError, OSError, MemoryError) as ex:
                    errMsg = "something went wrong while trying "
                    errMsg += "to read the content of file '%s' ('%s')" % (filename, getSafeExString(ex))
                    raise SqlmapSystemException(errMsg)

    return kb.cache.content[filename]

def average(values):
    """
    Computes the arithmetic mean of a list of numbers.

    >>> "%.1f" % average([0.9, 0.9, 0.9, 1.0, 0.8, 0.9])
    '0.9'
    """

    return (1.0 * sum(values) / len(values)) if values else None

@cachedmethod
def stdev(values):
    """
    Computes standard deviation of a list of numbers.

    # Reference: http://www.goldb.org/corestats.html

    >>> "%.3f" % stdev([0.9, 0.9, 0.9, 1.0, 0.8, 0.9])
    '0.063'
    """

    if not values or len(values) < 2:
        return None
    else:
        avg = average(values)
        _ = 1.0 * sum(pow((_ or 0) - avg, 2) for _ in values)
        return sqrt(_ / (len(values) - 1))

def calculateDeltaSeconds(start):
    """
    Returns elapsed time from start till now

    >>> calculateDeltaSeconds(0) > 1151721660
    True
    """

    return time.time() - start

def initCommonOutputs():
    """
    Initializes dictionary containing common output values used by "good samaritan" feature

    >>> initCommonOutputs(); "information_schema" in kb.commonOutputs["Databases"]
    True
    """

    kb.commonOutputs = {}
    key = None

    for line in openFile(paths.COMMON_OUTPUTS, 'r'):
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

def getFileItems(filename, commentPrefix='#', unicoded=True, lowercase=False, unique=False):
    """
    Returns newline delimited items contained inside file

    >>> "SELECT" in getFileItems(paths.SQL_KEYWORDS)
    True
    """

    retVal = list() if not unique else OrderedDict()

    if filename:
        filename = filename.strip('"\'')

    checkFile(filename)

    try:
        with openFile(filename, 'r', errors="ignore") if unicoded else open(filename, 'r') as f:
            for line in f:
                if commentPrefix:
                    if line.find(commentPrefix) != -1:
                        line = line[:line.find(commentPrefix)]

                line = line.strip()

                if line:
                    if lowercase:
                        line = line.lower()

                    if unique and line in retVal:
                        continue

                    if unique:
                        retVal[line] = True
                    else:
                        retVal.append(line)
    except (IOError, OSError, MemoryError) as ex:
        errMsg = "something went wrong while trying "
        errMsg += "to read the content of file '%s' ('%s')" % (filename, getSafeExString(ex))
        raise SqlmapSystemException(errMsg)

    return retVal if not unique else list(retVal.keys())

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
            if _unichr(ordChar) not in predictionSet:
                otherCharset.append(ordChar)
            else:
                commonCharset.append(ordChar)

        commonCharset.sort()

        return commonValue, commonPattern, commonCharset, originalCharset
    else:
        return None, None, None, originalCharset

def getPartRun(alias=True):
    """
    Goes through call stack and finds constructs matching
    conf.dbmsHandler.*. Returns it or its alias used in 'txt/common-outputs.txt'
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

def longestCommonPrefix(*sequences):
    """
    Returns longest common prefix occuring in given sequences

    # Reference: http://boredzo.org/blog/archives/2007-01-06/longest-common-prefix-in-python-2

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
    """
    Returns parts of sequence which start with the given initial string

    >>> commonFinderOnly("abcd", ["abcdefg", "foobar", "abcde"])
    'abcde'
    """

    return longestCommonPrefix(*[_ for _ in sequence if _.startswith(initial)])

def pushValue(value):
    """
    Push value to the stack (thread dependent)
    """

    exception = None
    success = False

    for i in xrange(PUSH_VALUE_EXCEPTION_RETRY_COUNT):
        try:
            getCurrentThreadData().valueStack.append(copy.deepcopy(value))
            success = True
            break
        except Exception as ex:
            exception = ex

    if not success:
        getCurrentThreadData().valueStack.append(None)

        if exception:
            raise exception

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
    Returns True if the last web request resulted in an erroneous HTTP code (like 500)
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

    if deviation and not conf.direct and not conf.disableStats:
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

                kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE if not readInput(msg, default='Y', boolean=True) else ADJUST_TIME_DELAY.YES
            if kb.adjustTimeDelay is ADJUST_TIME_DELAY.YES:
                adjustTimeDelay(threadData.lastQueryDuration, lowerStdLimit)

        return retVal
    else:
        delta = threadData.lastQueryDuration - conf.timeSec
        if Backend.getIdentifiedDbms() in (DBMS.MYSQL,):  # MySQL's SLEEP(X) lasts 0.05 seconds shorter on average
            delta += 0.05
        return delta >= 0

def adjustTimeDelay(lastQueryDuration, lowerStdLimit):
    """
    Provides tip for adjusting time delay in time-based data retrieval
    """

    candidate = (1 if not isHeavyQueryBased() else 2) + int(round(lowerStdLimit))

    kb.delayCandidates = [candidate] + kb.delayCandidates[:-1]

    if all((_ == candidate for _ in kb.delayCandidates)) and candidate < conf.timeSec:
        if lastQueryDuration / (1.0 * conf.timeSec / candidate) > MIN_VALID_DELAYED_RESPONSE:  # Note: to prevent problems with fast responses for heavy-queries like RANDOMBLOB
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

    >>> getText(extractErrorMessage(u'<html><title>Test</title>\\n<b>Warning</b>: oci_parse() [function.oci-parse]: ORA-01756: quoted string not properly terminated<br><p>Only a test page</p></html>') )
    'oci_parse() [function.oci-parse]: ORA-01756: quoted string not properly terminated'
    >>> extractErrorMessage('Warning: This is only a dummy foobar test') is None
    True
    """

    retVal = None

    if isinstance(page, six.string_types):
        if wasLastResponseDBMSError():
            page = re.sub(r"<[^>]+>", "", page)

        for regex in ERROR_PARSING_REGEXES:
            match = re.search(regex, page, re.IGNORECASE)

            if match:
                candidate = htmlUnescape(match.group("result")).replace("<br>", "\n").strip()
                if candidate and (1.0 * len(re.findall(r"[^A-Za-z,. ]", candidate)) / len(candidate) > MIN_ERROR_PARSING_NON_WRITING_RATIO):
                    retVal = candidate
                    break

        if not retVal and wasLastResponseDBMSError():
            match = re.search(r"[^\n]*SQL[^\n:]*:[^\n]*", page, re.IGNORECASE)

            if match:
                retVal = match.group(0)

    return retVal

def findLocalPort(ports):
    """
    Find the first opened localhost port from a given list of ports (e.g. for Tor port checks)
    """

    retVal = None

    for port in ports:
        try:
            try:
                s = socket._orig_socket(socket.AF_INET, socket.SOCK_STREAM)
            except AttributeError:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((LOCALHOST, port))
            retVal = port
            break
        except socket.error:
            pass
        finally:
            try:
                s.close()
            except socket.error:
                pass

    return retVal

def findMultipartPostBoundary(post):
    """
    Finds value for a boundary parameter in given multipart POST body

    >>> findMultipartPostBoundary("-----------------------------9051914041544843365972754266\\nContent-Disposition: form-data; name=text\\n\\ndefault")
    '9051914041544843365972754266'
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

def urldecode(value, encoding=None, unsafe="%%?&=;+%s" % CUSTOM_INJECTION_MARK_CHAR, convall=False, spaceplus=True):
    """
    URL decodes given value

    >>> urldecode('AND%201%3E%282%2B3%29%23', convall=True) == 'AND 1>(2+3)#'
    True
    >>> urldecode('AND%201%3E%282%2B3%29%23', convall=False) == 'AND 1>(2%2B3)#'
    True
    >>> urldecode(b'AND%201%3E%282%2B3%29%23', convall=False) == 'AND 1>(2%2B3)#'
    True
    """

    result = value

    if value:
        value = getUnicode(value)

        if convall:
            result = _urllib.parse.unquote_plus(value) if spaceplus else _urllib.parse.unquote(value)
        else:
            result = value
            charset = set(string.printable) - set(unsafe)

            def _(match):
                char = decodeHex(match.group(1), binary=False)
                return char if char in charset else match.group(0)

            if spaceplus:
                result = result.replace('+', ' ')  # plus sign has a special meaning in URL encoded data (hence the usage of _urllib.parse.unquote_plus in convall case)

            result = re.sub(r"%([0-9a-fA-F]{2})", _, result)

        result = getUnicode(result, encoding or UNICODE_ENCODING)

    return result

def urlencode(value, safe="%&=-_", convall=False, limit=False, spaceplus=False):
    """
    URL encodes given value

    >>> urlencode('AND 1>(2+3)#')
    'AND%201%3E%282%2B3%29%23'
    >>> urlencode("AND COUNT(SELECT name FROM users WHERE name LIKE '%DBA%')>0")
    'AND%20COUNT%28SELECT%20name%20FROM%20users%20WHERE%20name%20LIKE%20%27%25DBA%25%27%29%3E0'
    >>> urlencode("AND COUNT(SELECT name FROM users WHERE name LIKE '%_SYSTEM%')>0")
    'AND%20COUNT%28SELECT%20name%20FROM%20users%20WHERE%20name%20LIKE%20%27%25_SYSTEM%25%27%29%3E0'
    >>> urlencode("SELECT NAME FROM TABLE WHERE VALUE LIKE '%SOME%BEGIN%'")
    'SELECT%20NAME%20FROM%20TABLE%20WHERE%20VALUE%20LIKE%20%27%25SOME%25BEGIN%25%27'
    """

    if conf.get("direct"):
        return value

    count = 0
    result = None if value is None else ""

    if value:
        value = re.sub(r"\b[$\w]+=", lambda match: match.group(0).replace('$', DOLLAR_MARKER), value)

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
        if all('%' in _ for _ in (safe, value)) and not kb.tamperFunctions:
            value = re.sub(r"(?i)\bLIKE\s+'[^']+'", lambda match: match.group(0).replace('%', "%25"), value)
            value = re.sub(r"%(?![0-9a-fA-F]{2})", "%25", value)

        while True:
            result = _urllib.parse.quote(getBytes(value), safe)

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
            result = result.replace(_urllib.parse.quote(' '), '+')

        result = result.replace(DOLLAR_MARKER, '$')

    return result

def runningAsAdmin():
    """
    Returns True if the current process is run under admin privileges
    """

    isAdmin = None

    if PLATFORM in ("posix", "mac"):
        _ = os.geteuid()

        isAdmin = isinstance(_, (float, six.integer_types)) and _ == 0
    elif IS_WIN:
        import ctypes

        _ = ctypes.windll.shell32.IsUserAnAdmin()

        isAdmin = isinstance(_, (float, six.integer_types)) and _ == 1
    else:
        errMsg = "sqlmap is not able to check if you are running it "
        errMsg += "as an administrator account on this platform. "
        errMsg += "sqlmap will assume that you are an administrator "
        errMsg += "which is mandatory for the requested takeover attack "
        errMsg += "to work properly"
        logger.error(errMsg)

        isAdmin = True

    return isAdmin

def logHTTPTraffic(requestLogMsg, responseLogMsg, startTime=None, endTime=None):
    """
    Logs HTTP traffic to the output file
    """

    if conf.harFile:
        conf.httpCollector.collectRequest(requestLogMsg, responseLogMsg, startTime, endTime)

    if conf.trafficFile:
        with kb.locks.log:
            dataToTrafficFile("%s%s" % (requestLogMsg, os.linesep))
            dataToTrafficFile("%s%s" % (responseLogMsg, os.linesep))
            dataToTrafficFile("%s%s%s%s" % (os.linesep, 76 * '#', os.linesep, os.linesep))

def getPageTemplate(payload, place):  # Cross-referenced function
    raise NotImplementedError

@cachedmethod
def getPublicTypeMembers(type_, onlyValues=False):
    """
    Useful for getting members from types (e.g. in enums)

    >>> [_ for _ in getPublicTypeMembers(OS, True)]
    ['Linux', 'Windows']
    >>> [_ for _ in getPublicTypeMembers(PAYLOAD.TECHNIQUE, True)]
    [1, 2, 3, 4, 5, 6]
    """

    retVal = []

    for name, value in inspect.getmembers(type_):
        if not name.startswith("__"):
            if not onlyValues:
                retVal.append((name, value))
            else:
                retVal.append(value)

    return retVal

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

@cachedmethod
def extractRegexResult(regex, content, flags=0):
    """
    Returns 'result' group value from a possible match with regex on a given
    content

    >>> extractRegexResult(r'a(?P<result>[^g]+)g', 'abcdefg')
    'bcdef'
    """

    retVal = None

    if regex and content and "?P<result>" in regex:
        if isinstance(content, six.binary_type) and isinstance(regex, six.text_type):
            regex = getBytes(regex)

        match = re.search(regex, content, flags)

        if match:
            retVal = match.group("result")

    return retVal

def extractTextTagContent(page):
    """
    Returns list containing content from "textual" tags

    >>> extractTextTagContent('<html><head><title>Title</title></head><body><pre>foobar</pre><a href="#link">Link</a></body></html>')
    ['Title', 'foobar']
    """

    page = page or ""

    if REFLECTED_VALUE_MARKER in page:
        try:
            page = re.sub(r"(?i)[^\s>]*%s[^\s<]*" % REFLECTED_VALUE_MARKER, "", page)
        except MemoryError:
            page = page.replace(REFLECTED_VALUE_MARKER, "")

    return filterNone(_.group("result").strip() for _ in re.finditer(TEXT_TAG_REGEX, page))

def trimAlphaNum(value):
    """
    Trims alpha numeric characters from start and ending of a given value

    >>> trimAlphaNum('AND 1>(2+3)-- foobar')
    ' 1>(2+3)-- '
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
    >>> isNumPosStrValue('100000000000000000000')
    False
    """

    return ((hasattr(value, "isdigit") and value.isdigit() and int(value) > 0) or (isinstance(value, int) and value > 0)) and int(value) < MAX_INT

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

    >>> findDynamicContent("Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.", "Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. <script src='ads.js'></script>Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.")
    >>> kb.dynamicMarkings
    [('natum reque et per. ', 'Facer tritani repreh')]
    """

    if not firstPage or not secondPage:
        return

    infoMsg = "searching for dynamic content"
    singleTimeLogMessage(infoMsg)

    blocks = list(SequenceMatcher(None, firstPage, secondPage).get_matching_blocks())
    kb.dynamicMarkings = []

    # Removing too small matching blocks
    for block in blocks[:]:
        (_, _, length) = block

        if length <= 2 * DYNAMICITY_BOUNDARY_LENGTH:
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

            if prefix and suffix:
                prefix = prefix[-DYNAMICITY_BOUNDARY_LENGTH:]
                suffix = suffix[:DYNAMICITY_BOUNDARY_LENGTH]

                for _ in (firstPage, secondPage):
                    match = re.search(r"(?s)%s(.+)%s" % (re.escape(prefix), re.escape(suffix)), _)
                    if match:
                        infix = match.group(1)
                        if infix[0].isalnum():
                            prefix = trimAlphaNum(prefix)
                        if infix[-1].isalnum():
                            suffix = trimAlphaNum(suffix)
                        break

            kb.dynamicMarkings.append((prefix if prefix else None, suffix if suffix else None))

    if len(kb.dynamicMarkings) > 0:
        infoMsg = "dynamic content marked for removal (%d region%s)" % (len(kb.dynamicMarkings), 's' if len(kb.dynamicMarkings) > 1 else '')
        singleTimeLogMessage(infoMsg)

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
                page = re.sub(r"(?s)^.+%s" % re.escape(suffix), suffix.replace('\\', r'\\'), page)
            elif suffix is None:
                page = re.sub(r"(?s)%s.+$" % re.escape(prefix), prefix.replace('\\', r'\\'), page)
            else:
                page = re.sub(r"(?s)%s.+%s" % (re.escape(prefix), re.escape(suffix)), "%s%s" % (prefix.replace('\\', r'\\'), suffix.replace('\\', r'\\')), page)

    return page

def filterStringValue(value, charRegex, replacement=""):
    """
    Returns string value consisting only of chars satisfying supplied
    regular expression (note: it has to be in form [...])

    >>> filterStringValue('wzydeadbeef0123#', r'[0-9a-f]')
    'deadbeef0123'
    """

    retVal = value

    if value:
        retVal = re.sub(charRegex.replace("[", "[^") if "[^" not in charRegex else charRegex.replace("[^", "["), replacement, value)

    return retVal

def filterControlChars(value, replacement=' '):
    """
    Returns string value with control chars being supstituted with replacement character

    >>> filterControlChars('AND 1>(2+3)\\n--')
    'AND 1>(2+3) --'
    """

    return filterStringValue(value, PRINTABLE_CHAR_REGEX, replacement)

def filterNone(values):
    """
    Emulates filterNone([...]) functionality

    >>> filterNone([1, 2, "", None, 3])
    [1, 2, 3]
    """

    retVal = values

    if isinstance(values, _collections.Iterable):
        retVal = [_ for _ in values if _]

    return retVal

def isDBMSVersionAtLeast(minimum):
    """
    Checks if the recognized DBMS version is at least the version specified

    >>> pushValue(kb.dbmsVersion)
    >>> kb.dbmsVersion = "2"
    >>> isDBMSVersionAtLeast("1.3.4.1.4")
    True
    >>> isDBMSVersionAtLeast(2.1)
    False
    >>> isDBMSVersionAtLeast(">2")
    False
    >>> isDBMSVersionAtLeast(">=2.0")
    True
    >>> kb.dbmsVersion = "<2"
    >>> isDBMSVersionAtLeast("2")
    False
    >>> isDBMSVersionAtLeast("1.5")
    True
    >>> kb.dbmsVersion = "MySQL 5.4.3-log4"
    >>> isDBMSVersionAtLeast("5")
    True
    >>> kb.dbmsVersion = popValue()
    """

    retVal = None

    if not any(isNoneValue(_) for _ in (Backend.getVersion(), minimum)) and Backend.getVersion() != UNKNOWN_DBMS_VERSION:
        version = Backend.getVersion().replace(" ", "").rstrip('.')

        correction = 0.0
        if ">=" in version:
            pass
        elif '>' in version:
            correction = VERSION_COMPARISON_CORRECTION
        elif '<' in version:
            correction = -VERSION_COMPARISON_CORRECTION

        version = extractRegexResult(r"(?P<result>[0-9][0-9.]*)", version)

        if version:
            if '.' in version:
                parts = version.split('.', 1)
                parts[1] = filterStringValue(parts[1], '[0-9]')
                version = '.'.join(parts)

            try:
                version = float(filterStringValue(version, '[0-9.]')) + correction
            except ValueError:
                return None

            if isinstance(minimum, six.string_types):
                if '.' in minimum:
                    parts = minimum.split('.', 1)
                    parts[1] = filterStringValue(parts[1], '[0-9]')
                    minimum = '.'.join(parts)

                correction = 0.0
                if minimum.startswith(">="):
                    pass
                elif minimum.startswith(">"):
                    correction = VERSION_COMPARISON_CORRECTION

                minimum = float(filterStringValue(minimum, '[0-9.]')) + correction

            retVal = version >= minimum

    return retVal

def parseSqliteTableSchema(value):
    """
    Parses table column names and types from specified SQLite table schema

    >>> kb.data.cachedColumns = {}
    >>> parseSqliteTableSchema("CREATE TABLE users(\\n\\t\\tid INTEGER,\\n\\t\\tname TEXT\\n);")
    True
    >>> repr(kb.data.cachedColumns).count(',') == 1
    True
    """

    retVal = False

    if value:
        table = {}
        columns = {}

        for match in re.finditer(r"[(,]\s*[\"'`]?(\w+)[\"'`]?(?:\s+(INT|INTEGER|TINYINT|SMALLINT|MEDIUMINT|BIGINT|UNSIGNED BIG INT|INT2|INT8|INTEGER|CHARACTER|VARCHAR|VARYING CHARACTER|NCHAR|NATIVE CHARACTER|NVARCHAR|TEXT|CLOB|LONGTEXT|BLOB|NONE|REAL|DOUBLE|DOUBLE PRECISION|FLOAT|REAL|NUMERIC|DECIMAL|BOOLEAN|DATE|DATETIME|NUMERIC)\b)?", decodeStringEscape(value), re.I):
            retVal = True
            columns[match.group(1)] = match.group(2) or "TEXT"

        table[safeSQLIdentificatorNaming(conf.tbl, True)] = columns
        kb.data.cachedColumns[conf.db] = table

    return retVal

def getTechniqueData(technique=None):
    """
    Returns injection data for technique specified
    """

    return kb.injection.data.get(technique if technique is not None else getTechnique())

def isTechniqueAvailable(technique):
    """
    Returns True if there is injection data which sqlmap could use for technique specified

    >>> pushValue(kb.injection.data)
    >>> kb.injection.data[PAYLOAD.TECHNIQUE.ERROR] = [test for test in getSortedInjectionTests() if "error" in test["title"].lower()][0]
    >>> isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR)
    True
    >>> kb.injection.data = popValue()
    """

    if conf.technique and isinstance(conf.technique, list) and technique not in conf.technique:
        return False
    else:
        return getTechniqueData(technique) is not None

def isHeavyQueryBased(technique=None):
    """
    Returns True whether current (kb.)technique is heavy-query based

    >>> pushValue(kb.injection.data)
    >>> setTechnique(PAYLOAD.TECHNIQUE.STACKED)
    >>> kb.injection.data[getTechnique()] = [test for test in getSortedInjectionTests() if "heavy" in test["title"].lower()][0]
    >>> isHeavyQueryBased()
    True
    >>> kb.injection.data = popValue()
    """

    retVal = False

    technique = technique or getTechnique()

    if isTechniqueAvailable(technique):
        data = getTechniqueData(technique)
        if data and "heavy query" in data["title"].lower():
            retVal = True

    return retVal

def isStackingAvailable():
    """
    Returns True whether techniques using stacking are available

    >>> pushValue(kb.injection.data)
    >>> kb.injection.data[PAYLOAD.TECHNIQUE.STACKED] = [test for test in getSortedInjectionTests() if "stacked" in test["title"].lower()][0]
    >>> isStackingAvailable()
    True
    >>> kb.injection.data = popValue()
    """

    retVal = False

    if PAYLOAD.TECHNIQUE.STACKED in kb.injection.data:
        retVal = True
    else:
        for technique in getPublicTypeMembers(PAYLOAD.TECHNIQUE, True):
            data = getTechniqueData(technique)
            if data and "stacked" in data["title"].lower():
                retVal = True
                break

    return retVal

def isInferenceAvailable():
    """
    Returns True whether techniques using inference technique are available

    >>> pushValue(kb.injection.data)
    >>> kb.injection.data[PAYLOAD.TECHNIQUE.BOOLEAN] = getSortedInjectionTests()[0]
    >>> isInferenceAvailable()
    True
    >>> kb.injection.data = popValue()
    """

    return any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.BOOLEAN, PAYLOAD.TECHNIQUE.STACKED, PAYLOAD.TECHNIQUE.TIME))

def setOptimize():
    """
    Sets options turned on by switch '-o'
    """

    # conf.predictOutput = True
    conf.keepAlive = True
    conf.threads = 3 if conf.threads < 3 and cmdLineOptions.threads is None else conf.threads
    conf.nullConnection = not any((conf.data, conf.textOnly, conf.titles, conf.string, conf.notString, conf.regexp, conf.tor))

    if not conf.nullConnection:
        debugMsg = "turning off switch '--null-connection' used indirectly by switch '-o'"
        logger.debug(debugMsg)

def saveConfig(conf, filename):
    """
    Saves conf to configuration filename
    """

    config = UnicodeRawConfigParser()
    userOpts = {}

    for family in optDict:
        userOpts[family] = []

    for option, value in conf.items():
        for family, optionData in optDict.items():
            if option in optionData:
                userOpts[family].append((option, value, optionData[option]))

    for family, optionData in userOpts.items():
        config.add_section(family)

        optionData.sort()

        for option, value, datatype in optionData:
            if datatype and isListLike(datatype):
                datatype = datatype[0]

            if option in IGNORE_SAVE_OPTIONS:
                continue

            if value is None:
                if datatype == OPTION_TYPE.BOOLEAN:
                    value = "False"
                elif datatype in (OPTION_TYPE.INTEGER, OPTION_TYPE.FLOAT):
                    if option in defaults:
                        value = str(defaults[option])
                    else:
                        value = '0'
                elif datatype == OPTION_TYPE.STRING:
                    value = ""

            if isinstance(value, six.string_types):
                value = value.replace("\n", "\n ")

            config.set(family, option, value)

    with openFile(filename, "wb") as f:
        try:
            config.write(f)
        except IOError as ex:
            errMsg = "something went wrong while trying "
            errMsg += "to write to the configuration file '%s' ('%s')" % (filename, getSafeExString(ex))
            raise SqlmapSystemException(errMsg)

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
                    debugMsg = "resuming configuration option '%s' (%s)" % (key, ("'%s'" % value) if isinstance(value, six.string_types) else value)
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

    >>> arrayizeValue('1')
    ['1']
    """

    if isinstance(value, _collections.KeysView):
        value = [_ for _ in value]
    elif not isListLike(value):
        value = [value]

    return value

def unArrayizeValue(value):
    """
    Makes a value out of iterable if it is a list or tuple itself

    >>> unArrayizeValue(['1'])
    '1'
    >>> unArrayizeValue(['1', '2'])
    '1'
    >>> unArrayizeValue([['a', 'b'], 'c'])
    'a'
    >>> unArrayizeValue(_ for _ in xrange(10))
    0
    """

    if isListLike(value):
        if not value:
            value = None
        elif len(value) == 1 and not isListLike(value[0]):
            value = value[0]
        else:
            value = [_ for _ in flattenValue(value) if _ is not None]
            value = value[0] if len(value) > 0 else None
    elif inspect.isgenerator(value):
        value = unArrayizeValue([_ for _ in value])

    return value

def flattenValue(value):
    """
    Returns an iterator representing flat representation of a given value

    >>> [_ for _ in flattenValue([['1'], [['2'], '3']])]
    ['1', '2', '3']
    """

    for i in iter(value):
        if isListLike(i):
            for j in flattenValue(i):
                yield j
        else:
            yield i

def joinValue(value, delimiter=','):
    """
    Returns a value consisting of joined parts of a given value

    >>> joinValue(['1', '2'])
    '1,2'
    >>> joinValue('1')
    '1'
    """

    if isListLike(value):
        retVal = delimiter.join(value)
    else:
        retVal = value

    return retVal

def isListLike(value):
    """
    Returns True if the given value is a list-like instance

    >>> isListLike([1, 2, 3])
    True
    >>> isListLike('2')
    False
    """

    return isinstance(value, (list, tuple, set, OrderedSet, BigArray))

def getSortedInjectionTests():
    """
    Returns prioritized test list by eventually detected DBMS from error messages

    >>> pushValue(kb.forcedDbms)
    >>> kb.forcedDbms = DBMS.SQLITE
    >>> [test for test in getSortedInjectionTests() if hasattr(test, "details") and hasattr(test.details, "dbms")][0].details.dbms == kb.forcedDbms
    True
    >>> kb.forcedDbms = popValue()
    """

    retVal = copy.deepcopy(conf.tests)

    def priorityFunction(test):
        retVal = SORT_ORDER.FIRST

        if test.stype == PAYLOAD.TECHNIQUE.UNION:
            retVal = SORT_ORDER.LAST

        elif "details" in test and "dbms" in test.details:
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
    Returns list with items that have parts satisfying given regular expression

    >>> filterListValue(['users', 'admins', 'logs'], r'(users|admins)')
    ['users', 'admins']
    """

    if isinstance(value, list) and regex:
        retVal = [_ for _ in value if re.search(regex, _, re.I)]
    else:
        retVal = value

    return retVal

def showHttpErrorCodes():
    """
    Shows all HTTP error codes raised till now
    """

    if kb.httpErrorCodes:
        warnMsg = "HTTP error codes detected during run:\n"
        warnMsg += ", ".join("%d (%s) - %d times" % (code, _http_client.responses[code] if code in _http_client.responses else '?', count) for code, count in kb.httpErrorCodes.items())
        logger.warn(warnMsg)
        if any((str(_).startswith('4') or str(_).startswith('5')) and _ != _http_client.INTERNAL_SERVER_ERROR and _ != kb.originalCode for _ in kb.httpErrorCodes):
            msg = "too many 4xx and/or 5xx HTTP error codes "
            msg += "could mean that some kind of protection is involved (e.g. WAF)"
            logger.debug(msg)

def openFile(filename, mode='r', encoding=UNICODE_ENCODING, errors="reversible", buffering=1):  # "buffering=1" means line buffered (Reference: http://stackoverflow.com/a/3168436)
    """
    Returns file handle of a given filename

    >>> "openFile" in openFile(__file__).read()
    True
    >>> b"openFile" in openFile(__file__, "rb", None).read()
    True
    """

    # Reference: https://stackoverflow.com/a/37462452
    if 'b' in mode:
        buffering = 0

    if filename == STDIN_PIPE_DASH:
        if filename not in kb.cache.content:
            kb.cache.content[filename] = sys.stdin.read()

        return contextlib.closing(io.StringIO(readCachedFileContent(filename)))
    else:
        try:
            return codecs.open(filename, mode, encoding, errors, buffering)
        except IOError:
            errMsg = "there has been a file opening error for filename '%s'. " % filename
            errMsg += "Please check %s permissions on a file " % ("write" if mode and ('w' in mode or 'a' in mode or '+' in mode) else "read")
            errMsg += "and that it's not locked by another process"
            raise SqlmapSystemException(errMsg)

def decodeIntToUnicode(value):
    """
    Decodes inferenced integer value to an unicode character

    >>> decodeIntToUnicode(35) == '#'
    True
    >>> decodeIntToUnicode(64) == '@'
    True
    """
    retVal = value

    if isinstance(value, int):
        try:
            if value > 255:
                _ = "%x" % value

                if len(_) % 2 == 1:
                    _ = "0%s" % _

                raw = decodeHex(_)

                if Backend.isDbms(DBMS.MYSQL):
                    # Reference: https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_ord
                    # Note: https://github.com/sqlmapproject/sqlmap/issues/1531
                    retVal = getUnicode(raw, conf.encoding or UNICODE_ENCODING)
                elif Backend.isDbms(DBMS.MSSQL):
                    # Reference: https://docs.microsoft.com/en-us/sql/relational-databases/collations/collation-and-unicode-support?view=sql-server-2017 and https://stackoverflow.com/a/14488478
                    retVal = getUnicode(raw, "UTF-16-BE")
                elif Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.ORACLE, DBMS.SQLITE):     # Note: cases with Unicode code points (e.g. http://www.postgresqltutorial.com/postgresql-ascii/)
                    retVal = _unichr(value)
                else:
                    retVal = getUnicode(raw, conf.encoding)
            else:
                retVal = _unichr(value)
        except:
            retVal = INFERENCE_UNKNOWN_CHAR

    return retVal

def checkIntegrity():
    """
    Checks integrity of code files during the unhandled exceptions
    """

    if not paths:
        return

    logger.debug("running code integrity check")

    retVal = True

    baseTime = os.path.getmtime(paths.SQLMAP_SETTINGS_PATH) + 3600  # First hour free parking :)
    for root, _, filenames in os.walk(paths.SQLMAP_ROOT_PATH):
        for filename in filenames:
            if re.search(r"(\.py|\.xml|_)\Z", filename):
                filepath = os.path.join(root, filename)
                if os.path.getmtime(filepath) > baseTime:
                    logger.error("wrong modification time of '%s'" % filepath)
                    retVal = False

    return retVal

def getDaysFromLastUpdate():
    """
    Get total number of days from last update

    >>> getDaysFromLastUpdate() >= 0
    True
    """

    if not paths:
        return

    return int(time.time() - os.path.getmtime(paths.SQLMAP_SETTINGS_PATH)) // (3600 * 24)

def unhandledExceptionMessage():
    """
    Returns detailed message about occurred unhandled exception

    >>> all(_ in unhandledExceptionMessage() for _ in ("unhandled exception occurred", "Operating system", "Command line"))
    True
    """

    errMsg = "unhandled exception occurred in %s. It is recommended to retry your " % VERSION_STRING
    errMsg += "run with the latest development version from official GitHub "
    errMsg += "repository at '%s'. If the exception persists, please open a new issue " % GIT_PAGE
    errMsg += "at '%s' " % ISSUES_PAGE
    errMsg += "with the following text and any other information required to "
    errMsg += "reproduce the bug. Developers will try to reproduce the bug, fix it accordingly "
    errMsg += "and get back to you\n"
    errMsg += "Running version: %s\n" % VERSION_STRING[VERSION_STRING.find('/') + 1:]
    errMsg += "Python version: %s\n" % PYVERSION
    errMsg += "Operating system: %s\n" % platform.platform()
    errMsg += "Command line: %s\n" % re.sub(r".+?\bsqlmap\.py\b", "sqlmap.py", getUnicode(" ".join(sys.argv), encoding=getattr(sys.stdin, "encoding", None)))
    errMsg += "Technique: %s\n" % (enumValueToNameLookup(PAYLOAD.TECHNIQUE, getTechnique()) if getTechnique() is not None else ("DIRECT" if conf.get("direct") else None))
    errMsg += "Back-end DBMS:"

    if Backend.getDbms() is not None:
        errMsg += " %s (fingerprinted)" % Backend.getDbms()

    if Backend.getIdentifiedDbms() is not None and (Backend.getDbms() is None or Backend.getIdentifiedDbms() != Backend.getDbms()):
        errMsg += " %s (identified)" % Backend.getIdentifiedDbms()

    if not errMsg.endswith(')'):
        errMsg += " None"

    return errMsg

def getLatestRevision():
    """
    Retrieves latest revision from the offical repository
    """

    retVal = None
    req = _urllib.request.Request(url="https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/lib/core/settings.py", headers={HTTP_HEADER.USER_AGENT: fetchRandomAgent()})

    try:
        content = getUnicode(_urllib.request.urlopen(req).read())
        retVal = extractRegexResult(r"VERSION\s*=\s*[\"'](?P<result>[\d.]+)", content)
    except:
        pass

    return retVal

def fetchRandomAgent():
    """
    Returns random HTTP User-Agent header value

    >>> '(' in fetchRandomAgent()
    True
    """

    if not kb.userAgents:
        debugMsg = "loading random HTTP User-Agent header(s) from "
        debugMsg += "file '%s'" % paths.USER_AGENTS
        logger.debug(debugMsg)

        try:
            kb.userAgents = getFileItems(paths.USER_AGENTS)
        except IOError:
            errMsg = "unable to read HTTP User-Agent header "
            errMsg += "file '%s'" % paths.USER_AGENTS
            raise SqlmapSystemException(errMsg)

    return random.sample(kb.userAgents, 1)[0]

def createGithubIssue(errMsg, excMsg):
    """
    Automatically create a Github issue with unhandled exception information
    """

    try:
        issues = getFileItems(paths.GITHUB_HISTORY, unique=True)
    except:
        issues = []
    finally:
        issues = set(issues)

    _ = re.sub(r"'[^']+'", "''", excMsg)
    _ = re.sub(r"\s+line \d+", "", _)
    _ = re.sub(r'File ".+?/(\w+\.py)', r"\g<1>", _)
    _ = re.sub(r".+\Z", "", _)
    _ = re.sub(r"(Unicode[^:]*Error:).+", r"\g<1>", _)
    _ = re.sub(r"= _", "= ", _)

    key = hashlib.md5(getBytes(_)).hexdigest()[:8]

    if key in issues:
        return

    msg = "\ndo you want to automatically create a new (anonymized) issue "
    msg += "with the unhandled exception information at "
    msg += "the official Github repository? [y/N] "
    try:
        choice = readInput(msg, default='N', checkBatch=False, boolean=True)
    except:
        choice = None

    if choice:
        _excMsg = None
        errMsg = errMsg[errMsg.find("\n"):]

        req = _urllib.request.Request(url="https://api.github.com/search/issues?q=%s" % _urllib.parse.quote("repo:sqlmapproject/sqlmap Unhandled exception (#%s)" % key), headers={HTTP_HEADER.USER_AGENT: fetchRandomAgent()})

        try:
            content = _urllib.request.urlopen(req).read()
            _ = json.loads(content)
            duplicate = _["total_count"] > 0
            closed = duplicate and _["items"][0]["state"] == "closed"
            if duplicate:
                warnMsg = "issue seems to be already reported"
                if closed:
                    warnMsg += " and resolved. Please update to the latest "
                    warnMsg += "development version from official GitHub repository at '%s'" % GIT_PAGE
                logger.warn(warnMsg)
                return
        except:
            pass

        data = {"title": "Unhandled exception (#%s)" % key, "body": "```%s\n```\n```\n%s```" % (errMsg, excMsg)}
        req = _urllib.request.Request(url="https://api.github.com/repos/sqlmapproject/sqlmap/issues", data=getBytes(json.dumps(data)), headers={HTTP_HEADER.AUTHORIZATION: "token %s" % decodeBase64(GITHUB_REPORT_OAUTH_TOKEN, binary=False), HTTP_HEADER.USER_AGENT: fetchRandomAgent()})

        try:
            content = getText(_urllib.request.urlopen(req).read())
        except Exception as ex:
            content = None
            _excMsg = getSafeExString(ex)

        issueUrl = re.search(r"https://github.com/sqlmapproject/sqlmap/issues/\d+", content or "")
        if issueUrl:
            infoMsg = "created Github issue can been found at the address '%s'" % issueUrl.group(0)
            logger.info(infoMsg)

            try:
                with openFile(paths.GITHUB_HISTORY, "a+b") as f:
                    f.write("%s\n" % key)
            except:
                pass
        else:
            warnMsg = "something went wrong while creating a Github issue"
            if _excMsg:
                warnMsg += " ('%s')" % _excMsg
            if "Unauthorized" in warnMsg:
                warnMsg += ". Please update to the latest revision"
            logger.warn(warnMsg)

def maskSensitiveData(msg):
    """
    Masks sensitive data in the supplied message

    >>> maskSensitiveData('python sqlmap.py -u "http://www.test.com/vuln.php?id=1" --banner') == 'python sqlmap.py -u *********************************** --banner'
    True
    >>> maskSensitiveData('sqlmap.py -u test.com/index.go?id=index') == 'sqlmap.py -u **************************'
    True
    """

    retVal = getUnicode(msg)

    for item in filterNone(conf.get(_) for _ in SENSITIVE_OPTIONS):
        if isListLike(item):
            item = listToStrValue(item)

        regex = SENSITIVE_DATA_REGEX % re.sub(r"(\W)", r"\\\1", getUnicode(item))
        while extractRegexResult(regex, retVal):
            value = extractRegexResult(regex, retVal)
            retVal = retVal.replace(value, '*' * len(value))

    # Just in case (for problematic parameters regarding user encoding)
    for match in re.finditer(r"(?i)[ -]-(u|url|data|cookie|auth-\w+|proxy|host|referer|headers?|H)( |=)(.*?)(?= -?-[a-z]|\Z)", retVal):
        retVal = retVal.replace(match.group(3), '*' * len(match.group(3)))

    # Fail-safe substitutions
    retVal = re.sub(r"(?i)(Command line:.+)\b(https?://[^ ]+)", lambda match: "%s%s" % (match.group(1), '*' * len(match.group(2))), retVal)
    retVal = re.sub(r"(?i)(\b\w:[\\/]+Users[\\/]+|[\\/]+home[\\/]+)([^\\/]+)", lambda match: "%s%s" % (match.group(1), '*' * len(match.group(2))), retVal)

    if getpass.getuser():
        retVal = re.sub(r"(?i)\b%s\b" % re.escape(getpass.getuser()), '*' * len(getpass.getuser()), retVal)

    return retVal

def listToStrValue(value):
    """
    Flattens list to a string value

    >>> listToStrValue([1,2,3])
    '1, 2, 3'
    """

    if isinstance(value, (set, tuple, types.GeneratorType)):
        value = list(value)

    if isinstance(value, list):
        retVal = value.__str__().lstrip('[').rstrip(']')
    else:
        retVal = value

    return retVal

def intersect(containerA, containerB, lowerCase=False):
    """
    Returns intersection of the container-ized values

    >>> intersect([1, 2, 3], set([1,3]))
    [1, 3]
    """

    retVal = []

    if containerA and containerB:
        containerA = arrayizeValue(containerA)
        containerB = arrayizeValue(containerB)

        if lowerCase:
            containerA = [val.lower() if hasattr(val, "lower") else val for val in containerA]
            containerB = [val.lower() if hasattr(val, "lower") else val for val in containerB]

        retVal = [val for val in containerA if val in containerB]

    return retVal

def decodeStringEscape(value):
    """
    Decodes escaped string values (e.g. "\\t" -> "\t")
    """

    retVal = value

    if value and '\\' in value:
        charset = "\\%s" % string.whitespace.replace(" ", "")
        for _ in charset:
            retVal = retVal.replace(repr(_).strip("'"), _)

    return retVal

def encodeStringEscape(value):
    """
    Encodes escaped string values (e.g. "\t" -> "\\t")
    """

    retVal = value

    if value:
        charset = "\\%s" % string.whitespace.replace(" ", "")
        for _ in charset:
            retVal = retVal.replace(_, repr(_).strip("'"))

    return retVal

def removeReflectiveValues(content, payload, suppressWarning=False):
    """
    Neutralizes reflective values in a given content based on a payload
    (e.g. ..search.php?q=1 AND 1=2 --> "...searching for <b>1%20AND%201%3D2</b>..." --> "...searching for <b>__REFLECTED_VALUE__</b>...")
    """

    retVal = content

    try:
        if all((content, payload)) and isinstance(content, six.text_type) and kb.reflectiveMechanism and not kb.heuristicMode:
            def _(value):
                while 2 * REFLECTED_REPLACEMENT_REGEX in value:
                    value = value.replace(2 * REFLECTED_REPLACEMENT_REGEX, REFLECTED_REPLACEMENT_REGEX)
                return value

            payload = getUnicode(urldecode(payload.replace(PAYLOAD_DELIMITER, ""), convall=True))
            regex = _(filterStringValue(payload, r"[A-Za-z0-9]", encodeStringEscape(REFLECTED_REPLACEMENT_REGEX)))

            if regex != payload:
                if all(part.lower() in content.lower() for part in filterNone(regex.split(REFLECTED_REPLACEMENT_REGEX))[1:]):  # fast optimization check
                    parts = regex.split(REFLECTED_REPLACEMENT_REGEX)

                    # Note: naive approach
                    retVal = content.replace(payload, REFLECTED_VALUE_MARKER)
                    retVal = retVal.replace(re.sub(r"\A\w+", "", payload), REFLECTED_VALUE_MARKER)

                    if len(parts) > REFLECTED_MAX_REGEX_PARTS:  # preventing CPU hogs
                        regex = _("%s%s%s" % (REFLECTED_REPLACEMENT_REGEX.join(parts[:REFLECTED_MAX_REGEX_PARTS // 2]), REFLECTED_REPLACEMENT_REGEX, REFLECTED_REPLACEMENT_REGEX.join(parts[-REFLECTED_MAX_REGEX_PARTS // 2:])))

                    parts = filterNone(regex.split(REFLECTED_REPLACEMENT_REGEX))

                    if regex.startswith(REFLECTED_REPLACEMENT_REGEX):
                        regex = r"%s%s" % (REFLECTED_BORDER_REGEX, regex[len(REFLECTED_REPLACEMENT_REGEX):])
                    else:
                        regex = r"\b%s" % regex

                    if regex.endswith(REFLECTED_REPLACEMENT_REGEX):
                        regex = r"%s%s" % (regex[:-len(REFLECTED_REPLACEMENT_REGEX)], REFLECTED_BORDER_REGEX)
                    else:
                        regex = r"%s\b" % regex

                    _retVal = [retVal]

                    def _thread(regex):
                        try:
                            _retVal[0] = re.sub(r"(?i)%s" % regex, REFLECTED_VALUE_MARKER, _retVal[0])

                            if len(parts) > 2:
                                regex = REFLECTED_REPLACEMENT_REGEX.join(parts[1:])
                                _retVal[0] = re.sub(r"(?i)\b%s\b" % regex, REFLECTED_VALUE_MARKER, _retVal[0])
                        except KeyboardInterrupt:
                            raise
                        except:
                            pass

                    thread = threading.Thread(target=_thread, args=(regex,))
                    thread.daemon = True
                    thread.start()
                    thread.join(REFLECTED_REPLACEMENT_TIMEOUT)

                    if thread.is_alive():
                        kb.reflectiveMechanism = False
                        retVal = content
                        if not suppressWarning:
                            debugMsg = "turning off reflection removal mechanism (because of timeouts)"
                            logger.debug(debugMsg)
                    else:
                        retVal = _retVal[0]

                if retVal != content:
                    kb.reflectiveCounters[REFLECTIVE_COUNTER.HIT] += 1
                    if not suppressWarning:
                        warnMsg = "reflective value(s) found and filtering out"
                        singleTimeWarnMessage(warnMsg)

                    if re.search(r"(?i)FRAME[^>]+src=[^>]*%s" % REFLECTED_VALUE_MARKER, retVal):
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

def normalizeUnicode(value, charset=string.printable[:string.printable.find(' ') + 1]):
    """
    Does an ASCII normalization of unicode strings

    # Reference: http://www.peterbe.com/plog/unicode-to-ascii

    >>> normalizeUnicode(u'\\u0161u\\u0107uraj') == u'sucuraj'
    True
    >>> normalizeUnicode(getUnicode(decodeHex("666f6f00626172"))) == u'foobar'
    True
    """

    retVal = value

    if isinstance(value, six.text_type):
        retVal = unicodedata.normalize("NFKD", value)
        retVal = "".join(_ for _ in retVal if _ in charset)

    return retVal

def safeSQLIdentificatorNaming(name, isTable=False):
    """
    Returns a safe representation of SQL identificator name (internal data format)

    # Reference: http://stackoverflow.com/questions/954884/what-special-characters-are-allowed-in-t-sql-column-retVal

    >>> pushValue(kb.forcedDbms)
    >>> kb.forcedDbms = DBMS.MSSQL
    >>> getText(safeSQLIdentificatorNaming("begin"))
    '[begin]'
    >>> getText(safeSQLIdentificatorNaming("foobar"))
    'foobar'
    >>> kb.forceDbms = popValue()
    """

    retVal = name

    if isinstance(name, six.string_types):
        retVal = getUnicode(name)
        _ = isTable and Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE)

        if _:
            retVal = re.sub(r"(?i)\A\[?%s\]?\." % DEFAULT_MSSQL_SCHEMA, "%s." % DEFAULT_MSSQL_SCHEMA, retVal)

        # Note: SQL 92 has restrictions for identifiers starting with underscore (e.g. http://www.frontbase.com/documentation/FBUsers_4.pdf)
        if retVal.upper() in kb.keywords or (not isTable and (retVal or " ")[0] == '_') or (retVal or " ")[0].isdigit() or not re.match(r"\A[A-Za-z0-9_@%s\$]+\Z" % ('.' if _ else ""), retVal):  # MsSQL is the only DBMS where we automatically prepend schema to table name (dot is normal)
            if not conf.noEscape:
                retVal = unsafeSQLIdentificatorNaming(retVal)

                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.ACCESS, DBMS.CUBRID, DBMS.SQLITE):  # Note: in SQLite double-quotes are treated as string if column/identifier is non-existent (e.g. SELECT "foobar" FROM users)
                    retVal = "`%s`" % retVal
                elif Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.DB2, DBMS.HSQLDB, DBMS.H2, DBMS.INFORMIX, DBMS.MONETDB, DBMS.VERTICA, DBMS.MCKOI, DBMS.PRESTO, DBMS.CRATEDB, DBMS.CACHE, DBMS.EXTREMEDB, DBMS.FRONTBASE, DBMS.RAIMA, DBMS.VIRTUOSO):
                    retVal = "\"%s\"" % retVal
                elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.ALTIBASE, DBMS.MIMERSQL):
                    retVal = "\"%s\"" % retVal.upper()
                elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
                    if isTable:
                        parts = retVal.split('.', 1)
                        for i in xrange(len(parts)):
                            if parts[i] and (re.search(r"\A\d|[^\w]", parts[i], re.U) or parts[i].upper() in kb.keywords):
                                parts[i] = "[%s]" % parts[i]
                        retVal = '.'.join(parts)
                    else:
                        if re.search(r"\A\d|[^\w]", retVal, re.U) or retVal.upper() in kb.keywords:
                            retVal = "[%s]" % retVal

        if _ and DEFAULT_MSSQL_SCHEMA not in retVal and '.' not in re.sub(r"\[[^]]+\]", "", retVal):
            retVal = "%s.%s" % (DEFAULT_MSSQL_SCHEMA, retVal)

    return retVal

def unsafeSQLIdentificatorNaming(name):
    """
    Extracts identificator's name from its safe SQL representation

    >>> pushValue(kb.forcedDbms)
    >>> kb.forcedDbms = DBMS.MSSQL
    >>> getText(unsafeSQLIdentificatorNaming("[begin]"))
    'begin'
    >>> getText(unsafeSQLIdentificatorNaming("foobar"))
    'foobar'
    >>> kb.forceDbms = popValue()
    """

    retVal = name

    if isinstance(name, six.string_types):
        if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.ACCESS, DBMS.CUBRID, DBMS.SQLITE):
            retVal = name.replace("`", "")
        elif Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.DB2, DBMS.HSQLDB, DBMS.H2, DBMS.INFORMIX, DBMS.MONETDB, DBMS.VERTICA, DBMS.MCKOI, DBMS.PRESTO, DBMS.CRATEDB, DBMS.CACHE, DBMS.EXTREMEDB, DBMS.FRONTBASE, DBMS.RAIMA, DBMS.VIRTUOSO):
            retVal = name.replace("\"", "")
        elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.ALTIBASE, DBMS.MIMERSQL):
            retVal = name.replace("\"", "").upper()
        elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
            retVal = name.replace("[", "").replace("]", "")

        if Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
            retVal = re.sub(r"(?i)\A\[?%s\]?\." % DEFAULT_MSSQL_SCHEMA, "", retVal)

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

    if isinstance(value, six.string_types):
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

    return hasattr(value, "upper") and value.upper() == NULL

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
        name = mnemonic.split('=')[0].replace('-', "").strip()
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
                found = sorted(options.keys(), key=len)[0]
                warnMsg = "detected ambiguity (mnemonic '%s' can be resolved to any of: %s). " % (name, ", ".join("'%s'" % key for key in options))
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

    # Reference: http://tools.ietf.org/html/rfc4180

    >>> safeCSValue('foo, bar')
    '"foo, bar"'
    >>> safeCSValue('foobar')
    'foobar'
    """

    retVal = value

    if retVal and isinstance(retVal, six.string_types):
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
        retVal = [value for value in values if isinstance(value, (tuple, list, set)) and len(value) == 2]

    return retVal

def randomizeParameterValue(value):
    """
    Randomize a parameter value based on occurrences of alphanumeric characters

    >>> random.seed(0)
    >>> randomizeParameterValue('foobar')
    'fupgpy'
    >>> randomizeParameterValue('17')
    '36'
    """

    retVal = value

    value = re.sub(r"%[0-9a-fA-F]{2}", "", value)

    for match in re.finditer(r"[A-Z]+", value):
        while True:
            original = match.group()
            candidate = randomStr(len(match.group())).upper()
            if original != candidate:
                break

        retVal = retVal.replace(original, candidate)

    for match in re.finditer(r"[a-z]+", value):
        while True:
            original = match.group()
            candidate = randomStr(len(match.group())).lower()
            if original != candidate:
                break

        retVal = retVal.replace(original, candidate)

    for match in re.finditer(r"[0-9]+", value):
        while True:
            original = match.group()
            candidate = str(randomInt(len(match.group())))
            if original != candidate:
                break

        retVal = retVal.replace(original, candidate)

    if re.match(r"\A[^@]+@.+\.[a-z]+\Z", value):
        parts = retVal.split('.')
        parts[-1] = random.sample(RANDOMIZATION_TLDS, 1)[0]
        retVal = '.'.join(parts)

    if not retVal:
        retVal = randomStr(lowercase=True)

    return retVal

@cachedmethod
def asciifyUrl(url, forceQuote=False):
    """
    Attempts to make a unicode URL usable with ``urllib/urllib2``.

    More specifically, it attempts to convert the unicode object ``url``,
    which is meant to represent a IRI, to an unicode object that,
    containing only ASCII characters, is a valid URI. This involves:

        * IDNA/Puny-encoding the domain name.
        * UTF8-quoting the path and querystring parts.

    See also RFC 3987.

    # Reference: http://blog.elsdoerfer.name/2008/12/12/opening-iris-in-python/

    >>> asciifyUrl(u'http://www.\\u0161u\\u0107uraj.com')
    'http://www.xn--uuraj-gxa24d.com'
    """

    parts = _urllib.parse.urlsplit(url)
    if not all((parts.scheme, parts.netloc, parts.hostname)):
        # apparently not an url
        return getText(url)

    if all(char in string.printable for char in url):
        return getText(url)

    hostname = parts.hostname

    if isinstance(hostname, six.binary_type):
        hostname = getUnicode(hostname)

    # idna-encode domain
    try:
        hostname = hostname.encode("idna")
    except:
        hostname = hostname.encode("punycode")

    # UTF8-quote the other parts. We check each part individually if
    # if needs to be quoted - that should catch some additional user
    # errors, say for example an umlaut in the username even though
    # the path *is* already quoted.
    def quote(s, safe):
        s = s or ''
        # Triggers on non-ascii characters - another option would be:
        #     _urllib.parse.quote(s.replace('%', '')) != s.replace('%', '')
        # which would trigger on all %-characters, e.g. "&".
        if getUnicode(s).encode("ascii", "replace") != s or forceQuote:
            s = _urllib.parse.quote(getBytes(s), safe=safe)
        return s

    username = quote(parts.username, '')
    password = quote(parts.password, safe='')
    path = quote(parts.path, safe='/')
    query = quote(parts.query, safe="&=")

    # put everything back together
    netloc = getText(hostname)
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

    return getText(_urllib.parse.urlunsplit([parts.scheme, netloc, path, query, parts.fragment]) or url)

def isAdminFromPrivileges(privileges):
    """
    Inspects privileges to see if those are coming from an admin user
    """

    privileges = privileges or []

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
    retVal |= (Backend.isDbms(DBMS.FIREBIRD) and all(_ in privileges for _ in ("SELECT", "INSERT", "UPDATE", "DELETE", "REFERENCES", "EXECUTE")))

    return retVal

def findPageForms(content, url, raise_=False, addToTargets=False):
    """
    Parses given page content for possible forms (Note: still not implemented for Python3)

    >>> findPageForms('<html><form action="/input.php" method="POST"><input type="text" name="id" value="1"><input type="submit" value="Submit"></form></html>', 'http://www.site.com') == set([('http://www.site.com/input.php', 'POST', 'id=1', None, None)])
    True
    """

    class _(six.StringIO, object):
        def __init__(self, content, url):
            super(_, self).__init__(content)
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
    except ParseError:
        if re.search(r"(?i)<!DOCTYPE html|<html", content or "") and not re.search(r"(?i)\.js(\?|\Z)", url):
            dbgMsg = "badly formed HTML at the given URL ('%s'). Going to filter it" % url
            logger.debug(dbgMsg)
            filtered = _("".join(re.findall(FORM_SEARCH_REGEX, content)), url)

            if filtered and filtered != content:
                try:
                    forms = ParseResponse(filtered, backwards_compat=False)
                except:
                    errMsg = "no success"
                    if raise_:
                        raise SqlmapGenericException(errMsg)
                    else:
                        logger.debug(errMsg)
    except:
        pass

    for form in forms or []:
        try:
            for control in form.controls:
                if hasattr(control, "items") and not any((control.disabled, control.readonly)):
                    # if control has selectable items select first non-disabled
                    for item in control.items:
                        if not item.disabled:
                            if not item.selected:
                                item.selected = True
                            break

            if conf.crawlExclude and re.search(conf.crawlExclude, form.action or ""):
                dbgMsg = "skipping '%s'" % form.action
                logger.debug(dbgMsg)
                continue

            request = form.click()
        except (ValueError, TypeError) as ex:
            errMsg = "there has been a problem while "
            errMsg += "processing page forms ('%s')" % getSafeExString(ex)
            if raise_:
                raise SqlmapGenericException(errMsg)
            else:
                logger.debug(errMsg)
        else:
            url = urldecode(request.get_full_url(), kb.pageEncoding)
            method = request.get_method()
            data = request.data
            data = urldecode(data, kb.pageEncoding, spaceplus=False)

            if not data and method and method.upper() == HTTPMETHOD.POST:
                debugMsg = "invalid POST form with blank data detected"
                logger.debug(debugMsg)
                continue

            # flag to know if we are dealing with the same target host
            _ = checkSameHost(response.geturl(), url)

            if data:
                data = data.lstrip("&=").rstrip('&')

            if conf.scope and not re.search(conf.scope, url, re.I):
                continue
            elif data and not re.sub(r"(%s)=[^&]*&?" % '|'.join(IGNORE_PARAMETERS), "", data):
                continue
            elif not _:
                continue
            else:
                target = (url, method, data, conf.cookie, None)
                retVal.add(target)

    for match in re.finditer(r"\.post\(['\"]([^'\"]*)['\"],\s*\{([^}]*)\}", content):
        url = _urllib.parse.urljoin(url, htmlUnescape(match.group(1)))
        data = ""

        for name, value in re.findall(r"['\"]?(\w+)['\"]?\s*:\s*(['\"][^'\"]+)?", match.group(2)):
            data += "%s=%s%s" % (name, value, DEFAULT_GET_POST_DELIMITER)

        data = data.rstrip(DEFAULT_GET_POST_DELIMITER)
        retVal.add((url, HTTPMETHOD.POST, data, conf.cookie, None))

    for match in re.finditer(r"(?s)(\w+)\.open\(['\"]POST['\"],\s*['\"]([^'\"]+)['\"]\).*?\1\.send\(([^)]+)\)", content):
        url = _urllib.parse.urljoin(url, htmlUnescape(match.group(2)))
        data = match.group(3)

        data = re.sub(r"\s*\+\s*[^\s'\"]+|[^\s'\"]+\s*\+\s*", "", data)

        data = data.strip("['\"]")
        retVal.add((url, HTTPMETHOD.POST, data, conf.cookie, None))

    if not retVal and not conf.crawlDepth:
        errMsg = "there were no forms found at the given target URL"
        if raise_:
            raise SqlmapGenericException(errMsg)
        else:
            logger.debug(errMsg)

    if addToTargets and retVal:
        for target in retVal:
            kb.targets.add(target)

    return retVal

def checkSameHost(*urls):
    """
    Returns True if all provided urls share that same host

    >>> checkSameHost('http://www.target.com/page1.php?id=1', 'http://www.target.com/images/page2.php')
    True
    >>> checkSameHost('http://www.target.com/page1.php?id=1', 'http://www.target2.com/images/page2.php')
    False
    """

    if not urls:
        return None
    elif len(urls) == 1:
        return True
    else:
        def _(value):
            if value and not re.search(r"\A\w+://", value):
                value = "http://%s" % value
            return value

        return all(re.sub(r"(?i)\Awww\.", "", _urllib.parse.urlparse(_(url) or "").netloc.split(':')[0]) == re.sub(r"(?i)\Awww\.", "", _urllib.parse.urlparse(_(urls[0]) or "").netloc.split(':')[0]) for url in urls[1:])

def getHostHeader(url):
    """
    Returns proper Host header value for a given target URL

    >>> getHostHeader('http://www.target.com/vuln.php?id=1')
    'www.target.com'
    """

    retVal = url

    if url:
        retVal = _urllib.parse.urlparse(url).netloc

        if re.search(r"http(s)?://\[.+\]", url, re.I):
            retVal = extractRegexResult(r"http(s)?://\[(?P<result>.+)\]", url)
        elif any(retVal.endswith(':%d' % _) for _ in (80, 443)):
            retVal = retVal.split(':')[0]

    if retVal and retVal.count(':') > 1 and not any(_ in retVal for _ in ('[', ']')):
        retVal = "[%s]" % retVal

    return retVal

def checkOldOptions(args):
    """
    Checks for obsolete/deprecated options
    """

    for _ in args:
        _ = _.split('=')[0].strip()
        if _ in OBSOLETE_OPTIONS:
            errMsg = "switch/option '%s' is obsolete" % _
            if OBSOLETE_OPTIONS[_]:
                errMsg += " (hint: %s)" % OBSOLETE_OPTIONS[_]
            raise SqlmapSyntaxException(errMsg)
        elif _ in DEPRECATED_OPTIONS:
            warnMsg = "switch/option '%s' is deprecated" % _
            if DEPRECATED_OPTIONS[_]:
                warnMsg += " (hint: %s)" % DEPRECATED_OPTIONS[_]
            logger.warn(warnMsg)

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

            _reload_module(sys)
            sys.setdefaultencoding("cp1256")

def evaluateCode(code, variables=None):
    """
    Executes given python code given in a string form

    >>> _ = {}; evaluateCode("a = 1; b = 2; c = a", _); _["c"]
    1
    """

    try:
        exec(code, variables)
    except KeyboardInterrupt:
        raise
    except Exception as ex:
        errMsg = "an error occurred while evaluating provided code ('%s') " % getSafeExString(ex)
        raise SqlmapGenericException(errMsg)

def serializeObject(object_):
    """
    Serializes given object

    >>> type(serializeObject([1, 2, 3, ('a', 'b')])) == str
    True
    """

    return base64pickle(object_)

def unserializeObject(value):
    """
    Unserializes object from given serialized form

    >>> unserializeObject(serializeObject([1, 2, 3])) == [1, 2, 3]
    True
    >>> unserializeObject('gAJVBmZvb2JhcnEBLg==')
    'foobar'
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

    >>> resetCounter(PAYLOAD.TECHNIQUE.STACKED); incrementCounter(PAYLOAD.TECHNIQUE.STACKED); getCounter(PAYLOAD.TECHNIQUE.STACKED)
    1
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

def decodeDbmsHexValue(value, raw=False):
    """
    Returns value decoded from DBMS specific hexadecimal representation

    >>> decodeDbmsHexValue('3132332031') == u'123 1'
    True
    >>> decodeDbmsHexValue('313233203') == u'123 ?'
    True
    >>> decodeDbmsHexValue(['0x31', '0x32']) == [u'1', u'2']
    True
    >>> decodeDbmsHexValue('5.1.41') == u'5.1.41'
    True
    """

    retVal = value

    def _(value):
        retVal = value
        if value and isinstance(value, six.string_types):
            value = value.strip()

            if len(value) % 2 != 0:
                retVal = (decodeHex(value[:-1]) + b'?') if len(value) > 1 else value
                singleTimeWarnMessage("there was a problem decoding value '%s' from expected hexadecimal form" % value)
            else:
                retVal = decodeHex(value)

            if not raw:
                if not kb.binaryField:
                    if Backend.isDbms(DBMS.MSSQL) and value.startswith("0x"):
                        try:
                            retVal = retVal.decode("utf-16-le")
                        except UnicodeDecodeError:
                            pass

                    elif Backend.getIdentifiedDbms() in (DBMS.HSQLDB, DBMS.H2):
                        try:
                            retVal = retVal.decode("utf-16-be")
                        except UnicodeDecodeError:
                            pass

                if not isinstance(retVal, six.text_type):
                    retVal = getUnicode(retVal, conf.encoding or UNICODE_ENCODING)

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
    >>> extractExpectedValue('7\\xb9645', EXPECTED.INT) is None
    True
    """

    if expected:
        value = unArrayizeValue(value)

        if isNoneValue(value):
            value = None
        elif expected == EXPECTED.BOOL:
            if isinstance(value, int):
                value = bool(value)
            elif isinstance(value, six.string_types):
                value = value.strip().lower()
                if value in ("true", "false"):
                    value = value == "true"
                elif value in ('t', 'f'):
                    value = value == 't'
                elif value in ("1", "-1"):
                    value = True
                elif value == '0':
                    value = False
                else:
                    value = None
        elif expected == EXPECTED.INT:
            try:
                value = int(value)
            except:
                value = None

    return value

def hashDBWrite(key, value, serialize=False):
    """
    Helper function for writing session data to HashDB
    """

    if conf.hashDB:
        _ = '|'.join((str(_) if not isinstance(_, six.string_types) else _) for _ in (conf.hostname, conf.path.strip('/') if conf.path is not None else conf.port, key, HASHDB_MILESTONE_VALUE))
        conf.hashDB.write(_, value, serialize)

def hashDBRetrieve(key, unserialize=False, checkConf=False):
    """
    Helper function for restoring session data from HashDB
    """

    retVal = None

    if conf.hashDB:
        _ = '|'.join((str(_) if not isinstance(_, six.string_types) else _) for _ in (conf.hostname, conf.path.strip('/') if conf.path is not None else conf.port, key, HASHDB_MILESTONE_VALUE))
        retVal = conf.hashDB.retrieve(_, unserialize) if kb.resumeValues and not (checkConf and any((conf.flushSession, conf.freshQueries))) else None

        if not kb.inferenceMode and not kb.fileReadMode and isinstance(retVal, six.string_types) and any(_ in retVal for _ in (PARTIAL_VALUE_MARKER, PARTIAL_HEX_VALUE_MARKER)):
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
                lines = filterNone(line.strip() for line in content.split("\n") if not line.startswith('#'))
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
                if getattr(cookie, "expires", MAX_INT) < time.time():
                    warnMsg = "cookie '%s' has expired" % cookie
                    singleTimeWarnMessage(warnMsg)

            cookieJar.clear_expired_cookies()

            if not cookieJar._cookies:
                errMsg = "no valid cookies found"
                raise SqlmapGenericException(errMsg)

        except Exception as ex:
            errMsg = "there was a problem loading "
            errMsg += "cookies file ('%s')" % re.sub(r"(cookies) file '[^']+'", r"\g<1>", getSafeExString(ex))
            raise SqlmapGenericException(errMsg)

def decloakToTemp(filename):
    """
    Decloaks content of a given file to a temporary file with similar name and extension

    >>> _ = decloakToTemp(os.path.join(paths.SQLMAP_SHELL_PATH, "stagers", "stager.asp_"))
    >>> openFile(_, "rb", encoding=None).read().startswith(b'<%')
    True
    >>> os.remove(_)
    >>> _ = decloakToTemp(os.path.join(paths.SQLMAP_SHELL_PATH, "backdoors", "backdoor.asp_"))
    >>> openFile(_, "rb", encoding=None).read().startswith(b'<%')
    True
    >>> os.remove(_)
    >>> _ = decloakToTemp(os.path.join(paths.SQLMAP_UDF_PATH, "postgresql", "linux", "64", "11", "lib_postgresqludf_sys.so_"))
    >>> b'sys_eval' in openFile(_, "rb", encoding=None).read()
    True
    >>> os.remove(_)
    """

    content = decloak(filename)

    parts = os.path.split(filename[:-1])[-1].split('.')
    prefix, suffix = parts[0], '.' + parts[-1]
    handle, filename = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    os.close(handle)

    with openFile(filename, "w+b", encoding=None) as f:
        f.write(content)

    return filename

def prioritySortColumns(columns):
    """
    Sorts given column names by length in ascending order while those containing
    string 'id' go first

    >>> prioritySortColumns(['password', 'userid', 'name'])
    ['userid', 'name', 'password']
    """

    def _(column):
        return column and re.search(r"^id|id$", column, re.I) is not None

    return sorted(sorted(columns, key=len), key=functools.cmp_to_key(lambda x, y: -1 if _(x) and not _(y) else 1 if not _(x) and _(y) else 0))

def getRequestHeader(request, name):
    """
    Solving an issue with an urllib2 Request header case sensitivity

    # Reference: http://bugs.python.org/issue2275

    >>> _ = lambda _: _
    >>> _.headers = {"FOO": "BAR"}
    >>> _.header_items = lambda: _.headers.items()
    >>> getText(getRequestHeader(_, "foo"))
    'BAR'
    """

    retVal = None

    if request and request.headers and name:
        _ = name.upper()
        retVal = max(getBytes(value if _ == key.upper() else "") for key, value in request.header_items()) or None

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

    >>> _ = "SELECT (SELECT id FROM users WHERE 2>1) AS result FROM DUAL"; _[zeroDepthSearch(_, "FROM")[0]:]
    'FROM DUAL'
    >>> _ = "a(b; c),d;e"; _[zeroDepthSearch(_, "[;, ]")[0]:]
    ',d;e'
    """

    retVal = []

    depth = 0
    for index in xrange(len(expression)):
        if expression[index] == '(':
            depth += 1
        elif expression[index] == ')':
            depth -= 1
        elif depth == 0:
            if value.startswith('[') and value.endswith(']'):
                if re.search(value, expression[index:index + 1]):
                    retVal.append(index)
            elif expression[index:index + len(value)] == value:
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

    return [fields[x + 1:y] for (x, y) in _zip(commas, commas[1:])]

def pollProcess(process, suppress_errors=False):
    """
    Checks for process status (prints . if still running)
    """

    while process:
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

def parseRequestFile(reqFile, checkParams=True):
    """
    Parses WebScarab and Burp logs and adds results to the target URL list

    >>> handle, reqFile = tempfile.mkstemp(suffix=".req")
    >>> content = b"POST / HTTP/1.0\\nUser-agent: foobar\\nHost: www.example.com\\n\\nid=1\\n"
    >>> _ = os.write(handle, content)
    >>> os.close(handle)
    >>> next(parseRequestFile(reqFile)) == ('http://www.example.com:80/', 'POST', 'id=1', None, (('User-agent', 'foobar'), ('Host', 'www.example.com')))
    True
    """

    def _parseWebScarabLog(content):
        """
        Parses WebScarab logs (POST method not supported)
        """

        reqResList = content.split(WEBSCARAB_SPLITTER)

        for request in reqResList:
            url = extractRegexResult(r"URL: (?P<result>.+?)\n", request, re.I)
            method = extractRegexResult(r"METHOD: (?P<result>.+?)\n", request, re.I)
            cookie = extractRegexResult(r"COOKIE: (?P<result>.+?)\n", request, re.I)

            if not method or not url:
                logger.debug("not a valid WebScarab log data")
                continue

            if method.upper() == HTTPMETHOD.POST:
                warnMsg = "POST requests from WebScarab logs aren't supported "
                warnMsg += "as their body content is stored in separate files. "
                warnMsg += "Nevertheless you can use -r to load them individually."
                logger.warning(warnMsg)
                continue

            if not(conf.scope and not re.search(conf.scope, url, re.I)):
                yield (url, method, None, cookie, tuple())

    def _parseBurpLog(content):
        """
        Parses Burp logs
        """

        if not re.search(BURP_REQUEST_REGEX, content, re.I | re.S):
            if re.search(BURP_XML_HISTORY_REGEX, content, re.I | re.S):
                reqResList = []
                for match in re.finditer(BURP_XML_HISTORY_REGEX, content, re.I | re.S):
                    port, request = match.groups()
                    try:
                        request = decodeBase64(request, binary=False)
                    except (binascii.Error, TypeError):
                        continue
                    _ = re.search(r"%s:.+" % re.escape(HTTP_HEADER.HOST), request)
                    if _:
                        host = _.group(0).strip()
                        if not re.search(r":\d+\Z", host):
                            request = request.replace(host, "%s:%d" % (host, int(port)))
                    reqResList.append(request)
            else:
                reqResList = [content]
        else:
            reqResList = re.finditer(BURP_REQUEST_REGEX, content, re.I | re.S)

        for match in reqResList:
            request = match if isinstance(match, six.string_types) else match.group(1)
            request = re.sub(r"\A[^\w]+", "", request)
            schemePort = re.search(r"(http[\w]*)\:\/\/.*?\:([\d]+).+?={10,}", request, re.I | re.S)

            if schemePort:
                scheme = schemePort.group(1)
                port = schemePort.group(2)
                request = re.sub(r"\n=+\Z", "", request.split(schemePort.group(0))[-1].lstrip())
            else:
                scheme, port = None, None

            if "HTTP/" not in request:
                continue

            if re.search(r"^[\n]*%s.*?\.(%s)\sHTTP\/" % (HTTPMETHOD.GET, "|".join(CRAWL_EXCLUDE_EXTENSIONS)), request, re.I | re.M):
                if not re.search(r"^[\n]*%s[^\n]*\*[^\n]*\sHTTP\/" % HTTPMETHOD.GET, request, re.I | re.M):
                    continue

            getPostReq = False
            url = None
            host = None
            method = None
            data = None
            cookie = None
            params = False
            newline = None
            lines = request.split('\n')
            headers = []

            for index in xrange(len(lines)):
                line = lines[index]

                if not line.strip() and index == len(lines) - 1:
                    break

                newline = "\r\n" if line.endswith('\r') else '\n'
                line = line.strip('\r')
                match = re.search(r"\A([A-Z]+) (.+) HTTP/[\d.]+\Z", line) if not method else None

                if len(line.strip()) == 0 and method and method != HTTPMETHOD.GET and data is None:
                    data = ""
                    params = True

                elif match:
                    method = match.group(1)
                    url = match.group(2)

                    if any(_ in line for _ in ('?', '=', kb.customInjectionMark)):
                        params = True

                    getPostReq = True

                # POST parameters
                elif data is not None and params:
                    data += "%s%s" % (line, newline)

                # GET parameters
                elif "?" in line and "=" in line and ": " not in line:
                    params = True

                # Headers
                elif re.search(r"\A\S+:", line):
                    key, value = line.split(":", 1)
                    value = value.strip().replace("\r", "").replace("\n", "")

                    # Note: overriding values with --headers '...'
                    match = re.search(r"(?i)\b(%s): ([^\n]*)" % re.escape(key), conf.headers or "")
                    if match:
                        key, value = match.groups()

                    # Cookie and Host headers
                    if key.upper() == HTTP_HEADER.COOKIE.upper():
                        cookie = value
                    elif key.upper() == HTTP_HEADER.HOST.upper():
                        if '://' in value:
                            scheme, value = value.split('://')[:2]
                        splitValue = value.split(":")
                        host = splitValue[0]

                        if len(splitValue) > 1:
                            port = filterStringValue(splitValue[1], "[0-9]")

                    # Avoid to add a static content length header to
                    # headers and consider the following lines as
                    # POSTed data
                    if key.upper() == HTTP_HEADER.CONTENT_LENGTH.upper():
                        params = True

                    # Avoid proxy and connection type related headers
                    elif key not in (HTTP_HEADER.PROXY_CONNECTION, HTTP_HEADER.CONNECTION, HTTP_HEADER.IF_MODIFIED_SINCE, HTTP_HEADER.IF_NONE_MATCH):
                        headers.append((getUnicode(key), getUnicode(value)))

                    if kb.customInjectionMark in re.sub(PROBLEMATIC_CUSTOM_INJECTION_PATTERNS, "", value or ""):
                        params = True

            data = data.rstrip("\r\n") if data else data

            if getPostReq and (params or cookie or not checkParams):
                if not port and hasattr(scheme, "lower") and scheme.lower() == "https":
                    port = "443"
                elif not scheme and port == "443":
                    scheme = "https"

                if conf.forceSSL:
                    scheme = "https"
                    port = port or "443"

                if not host:
                    errMsg = "invalid format of a request file"
                    raise SqlmapSyntaxException(errMsg)

                if not url.startswith("http"):
                    url = "%s://%s:%s%s" % (scheme or "http", host, port or "80", url)
                    scheme = None
                    port = None

                if not(conf.scope and not re.search(conf.scope, url, re.I)):
                    yield (url, conf.method or method, data, cookie, tuple(headers))

    content = readCachedFileContent(reqFile)

    if conf.scope:
        logger.info("using regular expression '%s' for filtering targets" % conf.scope)

    for target in _parseBurpLog(content):
        yield target

    for target in _parseWebScarabLog(content):
        yield target

def getSafeExString(ex, encoding=None):
    """
    Safe way how to get the proper exception represtation as a string

    >>> getSafeExString(SqlmapBaseException('foobar')) == 'foobar'
    True
    >>> getSafeExString(OSError(0, 'foobar')) == 'OSError: foobar'
    True
    """

    retVal = None

    if getattr(ex, "message", None):
        retVal = ex.message
    elif getattr(ex, "msg", None):
        retVal = ex.msg
    elif getattr(ex, "args", None):
        for candidate in ex.args[::-1]:
            if isinstance(candidate, six.string_types):
                retVal = candidate
                break

    if retVal is None:
        retVal = str(ex)
    elif not isinstance(ex, SqlmapBaseException):
        retVal = "%s: %s" % (type(ex).__name__, retVal)

    return getUnicode(retVal or "", encoding=encoding).strip()

def safeVariableNaming(value):
    """
    Returns escaped safe-representation of a given variable name that can be used in Python evaluated code

    >>> safeVariableNaming("class.id") == "EVAL_636c6173732e6964"
    True
    """

    if value in keyword.kwlist or re.search(r"\A[^a-zA-Z]|[^\w]", value):
        value = "%s%s" % (EVALCODE_ENCODED_PREFIX, getUnicode(binascii.hexlify(getBytes(value))))

    return value

def unsafeVariableNaming(value):
    """
    Returns unescaped safe-representation of a given variable name

    >>> unsafeVariableNaming("EVAL_636c6173732e6964") == "class.id"
    True
    """

    if value.startswith(EVALCODE_ENCODED_PREFIX):
        value = decodeHex(value[len(EVALCODE_ENCODED_PREFIX):], binary=False)

    return value

def firstNotNone(*args):
    """
    Returns first not-None value from a given list of arguments

    >>> firstNotNone(None, None, 1, 2, 3)
    1
    """

    retVal = None

    for _ in args:
        if _ is not None:
            retVal = _
            break

    return retVal

def removePostHintPrefix(value):
    """
    Remove POST hint prefix from a given value (name)

    >>> removePostHintPrefix("JSON id")
    'id'
    >>> removePostHintPrefix("id")
    'id'
    """

    return re.sub(r"\A(%s) " % '|'.join(re.escape(__) for __ in getPublicTypeMembers(POST_HINT, onlyValues=True)), "", value)

def chunkSplitPostData(data):
    """
    Convert POST data to chunked transfer-encoded data (Note: splitting done by SQL keywords)

    >>> random.seed(0)
    >>> chunkSplitPostData("SELECT username,password FROM users")
    '5;4Xe90\\r\\nSELEC\\r\\n3;irWlc\\r\\nT u\\r\\n1;eT4zO\\r\\ns\\r\\n5;YB4hM\\r\\nernam\\r\\n9;2pUD8\\r\\ne,passwor\\r\\n3;mp07y\\r\\nd F\\r\\n5;8RKXi\\r\\nROM u\\r\\n4;MvMhO\\r\\nsers\\r\\n0\\r\\n\\r\\n'
    """

    length = len(data)
    retVal = ""
    index = 0

    while index < length:
        chunkSize = randomInt(1)

        if index + chunkSize >= length:
            chunkSize = length - index

        salt = randomStr(5, alphabet=string.ascii_letters + string.digits)

        while chunkSize:
            candidate = data[index:index + chunkSize]

            if re.search(r"\b%s\b" % '|'.join(HTTP_CHUNKED_SPLIT_KEYWORDS), candidate, re.I):
                chunkSize -= 1
            else:
                break

        index += chunkSize
        retVal += "%x;%s\r\n" % (chunkSize, salt)
        retVal += "%s\r\n" % candidate

    retVal += "0\r\n\r\n"

    return retVal
