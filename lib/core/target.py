#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import functools
import os
import re
import subprocess
import sys
import tempfile
import time

from lib.core.common import Backend
from lib.core.common import getSafeExString
from lib.core.common import hashDBRetrieve
from lib.core.common import intersect
from lib.core.common import isNumPosStrValue
from lib.core.common import normalizeUnicode
from lib.core.common import openFile
from lib.core.common import paramToDict
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import removePostHintPrefix
from lib.core.common import resetCookieJar
from lib.core.common import safeStringFormat
from lib.core.common import unArrayizeValue
from lib.core.common import urldecode
from lib.core.compat import xrange
from lib.core.convert import decodeBase64
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import mergedOptions
from lib.core.data import paths
from lib.core.datatype import InjectionDict
from lib.core.dicts import DBMS_DICT
from lib.core.dump import dumper
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.enums import PLACE
from lib.core.enums import POST_HINT
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapMissingPrivileges
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUserQuitException
from lib.core.option import _setAuthCred
from lib.core.option import _setDBMS
from lib.core.option import _setKnowledgeBaseAttributes
from lib.core.settings import ARRAY_LIKE_RECOGNITION_REGEX
from lib.core.settings import ASTERISK_MARKER
from lib.core.settings import CSRF_TOKEN_PARAMETER_INFIXES
from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import HOST_ALIASES
from lib.core.settings import INJECT_HERE_REGEX
from lib.core.settings import JSON_LIKE_RECOGNITION_REGEX
from lib.core.settings import JSON_RECOGNITION_REGEX
from lib.core.settings import MULTIPART_RECOGNITION_REGEX
from lib.core.settings import PROBLEMATIC_CUSTOM_INJECTION_PATTERNS
from lib.core.settings import REFERER_ALIASES
from lib.core.settings import RESTORE_MERGED_OPTIONS
from lib.core.settings import RESULTS_FILE_FORMAT
from lib.core.settings import SESSION_SQLITE_FILE
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import UNENCODED_ORIGINAL_VALUE
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.core.settings import URI_INJECTABLE_REGEX
from lib.core.settings import USER_AGENT_ALIASES
from lib.core.settings import XML_RECOGNITION_REGEX
from lib.core.threads import getCurrentThreadData
from lib.utils.hashdb import HashDB
from thirdparty import six
from thirdparty.odict import OrderedDict
from thirdparty.six.moves import urllib as _urllib

def _setRequestParams():
    """
    Check and set the parameters and perform checks on 'data' option for
    HTTP method POST.
    """

    if conf.direct:
        conf.parameters[None] = "direct connection"
        return

    hintNames = []
    testableParameters = False

    # Perform checks on GET parameters
    if conf.parameters.get(PLACE.GET):
        parameters = conf.parameters[PLACE.GET]
        paramDict = paramToDict(PLACE.GET, parameters)

        if paramDict:
            conf.paramDict[PLACE.GET] = paramDict
            testableParameters = True

    # Perform checks on POST parameters
    if conf.method == HTTPMETHOD.POST and conf.data is None:
        logger.warn("detected empty POST body")
        conf.data = ""

    if conf.data is not None:
        conf.method = conf.method or HTTPMETHOD.POST

        def process(match, repl):
            retVal = match.group(0)

            if not (conf.testParameter and match.group("name") not in (removePostHintPrefix(_) for _ in conf.testParameter)) and match.group("name") == match.group("name").strip('\\'):
                retVal = repl
                while True:
                    _ = re.search(r"\\g<([^>]+)>", retVal)
                    if _:
                        retVal = retVal.replace(_.group(0), match.group(int(_.group(1)) if _.group(1).isdigit() else _.group(1)))
                    else:
                        break
                if kb.customInjectionMark in retVal:
                    hintNames.append((retVal.split(kb.customInjectionMark)[0], match.group("name").strip('"\'') if kb.postHint == POST_HINT.JSON_LIKE else match.group("name")))

            return retVal

        if kb.processUserMarks is None and kb.customInjectionMark in conf.data:
            message = "custom injection marker ('%s') found in %s " % (kb.customInjectionMark, conf.method)
            message += "body. Do you want to process it? [Y/n/q] "
            choice = readInput(message, default='Y').upper()

            if choice == 'Q':
                raise SqlmapUserQuitException
            else:
                kb.processUserMarks = choice == 'Y'

                if kb.processUserMarks:
                    kb.testOnlyCustom = True

        if re.search(JSON_RECOGNITION_REGEX, conf.data):
            message = "JSON data found in %s body. " % conf.method
            message += "Do you want to process it? [Y/n/q] "
            choice = readInput(message, default='Y').upper()

            if choice == 'Q':
                raise SqlmapUserQuitException
            elif choice == 'Y':
                kb.postHint = POST_HINT.JSON
                if not (kb.processUserMarks and kb.customInjectionMark in conf.data):
                    conf.data = getattr(conf.data, UNENCODED_ORIGINAL_VALUE, conf.data)
                    conf.data = conf.data.replace(kb.customInjectionMark, ASTERISK_MARKER)
                    conf.data = re.sub(r'("(?P<name>[^"]+)"\s*:\s*".+?)"(?<!\\")', functools.partial(process, repl=r'\g<1>%s"' % kb.customInjectionMark), conf.data)
                    conf.data = re.sub(r'("(?P<name>[^"]+)"\s*:\s*)(-?\d[\d\.]*)\b', functools.partial(process, repl=r'\g<1>\g<3>%s' % kb.customInjectionMark), conf.data)
                    conf.data = re.sub(r'("(?P<name>[^"]+)"\s*:\s*)((true|false|null))\b', functools.partial(process, repl=r'\g<1>\g<3>%s' % kb.customInjectionMark), conf.data)
                    for match in re.finditer(r'(?P<name>[^"]+)"\s*:\s*\[([^\]]+)\]', conf.data):
                        if not (conf.testParameter and match.group("name") not in conf.testParameter):
                            _ = match.group(2)
                            if kb.customInjectionMark not in _:  # Note: only for unprocessed (simple) forms - i.e. non-associative arrays (e.g. [1,2,3])
                                _ = re.sub(r'("[^"]+)"', r'\g<1>%s"' % kb.customInjectionMark, _)
                                _ = re.sub(r'(\A|,|\s+)(-?\d[\d\.]*\b)', r'\g<0>%s' % kb.customInjectionMark, _)
                                conf.data = conf.data.replace(match.group(0), match.group(0).replace(match.group(2), _))

        elif re.search(JSON_LIKE_RECOGNITION_REGEX, conf.data):
            message = "JSON-like data found in %s body. " % conf.method
            message += "Do you want to process it? [Y/n/q] "
            choice = readInput(message, default='Y').upper()

            if choice == 'Q':
                raise SqlmapUserQuitException
            elif choice == 'Y':
                kb.postHint = POST_HINT.JSON_LIKE
                if not (kb.processUserMarks and kb.customInjectionMark in conf.data):
                    conf.data = getattr(conf.data, UNENCODED_ORIGINAL_VALUE, conf.data)
                    conf.data = conf.data.replace(kb.customInjectionMark, ASTERISK_MARKER)
                    if '"' in conf.data:
                        conf.data = re.sub(r'((?P<name>"[^"]+"|\w+)\s*:\s*"[^"]+)"', functools.partial(process, repl=r'\g<1>%s"' % kb.customInjectionMark), conf.data)
                        conf.data = re.sub(r'((?P<name>"[^"]+"|\w+)\s*:\s*)(-?\d[\d\.]*\b)', functools.partial(process, repl=r'\g<0>%s' % kb.customInjectionMark), conf.data)
                    else:
                        conf.data = re.sub(r"((?P<name>'[^']+'|\w+)\s*:\s*'[^']+)'", functools.partial(process, repl=r"\g<1>%s'" % kb.customInjectionMark), conf.data)
                        conf.data = re.sub(r"((?P<name>'[^']+'|\w+)\s*:\s*)(-?\d[\d\.]*\b)", functools.partial(process, repl=r"\g<0>%s" % kb.customInjectionMark), conf.data)

        elif re.search(ARRAY_LIKE_RECOGNITION_REGEX, conf.data):
            message = "Array-like data found in %s body. " % conf.method
            message += "Do you want to process it? [Y/n/q] "
            choice = readInput(message, default='Y').upper()

            if choice == 'Q':
                raise SqlmapUserQuitException
            elif choice == 'Y':
                kb.postHint = POST_HINT.ARRAY_LIKE
                if not (kb.processUserMarks and kb.customInjectionMark in conf.data):
                    conf.data = conf.data.replace(kb.customInjectionMark, ASTERISK_MARKER)
                    conf.data = re.sub(r"(=[^%s]+)" % DEFAULT_GET_POST_DELIMITER, r"\g<1>%s" % kb.customInjectionMark, conf.data)

        elif re.search(XML_RECOGNITION_REGEX, conf.data):
            message = "SOAP/XML data found in %s body. " % conf.method
            message += "Do you want to process it? [Y/n/q] "
            choice = readInput(message, default='Y').upper()

            if choice == 'Q':
                raise SqlmapUserQuitException
            elif choice == 'Y':
                kb.postHint = POST_HINT.SOAP if "soap" in conf.data.lower() else POST_HINT.XML
                if not (kb.processUserMarks and kb.customInjectionMark in conf.data):
                    conf.data = getattr(conf.data, UNENCODED_ORIGINAL_VALUE, conf.data)
                    conf.data = conf.data.replace(kb.customInjectionMark, ASTERISK_MARKER)
                    conf.data = re.sub(r"(<(?P<name>[^>]+)( [^<]*)?>)([^<]+)(</\2)", functools.partial(process, repl=r"\g<1>\g<4>%s\g<5>" % kb.customInjectionMark), conf.data)

        elif re.search(MULTIPART_RECOGNITION_REGEX, conf.data):
            message = "Multipart-like data found in %s body. " % conf.method
            message += "Do you want to process it? [Y/n/q] "
            choice = readInput(message, default='Y').upper()

            if choice == 'Q':
                raise SqlmapUserQuitException
            elif choice == 'Y':
                kb.postHint = POST_HINT.MULTIPART
                if not (kb.processUserMarks and kb.customInjectionMark in conf.data):
                    conf.data = getattr(conf.data, UNENCODED_ORIGINAL_VALUE, conf.data)
                    conf.data = conf.data.replace(kb.customInjectionMark, ASTERISK_MARKER)
                    conf.data = re.sub(r"(?si)((Content-Disposition[^\n]+?name\s*=\s*[\"']?(?P<name>[^\"'\r\n]+)[\"']?).+?)((%s)+--)" % ("\r\n" if "\r\n" in conf.data else '\n'), functools.partial(process, repl=r"\g<1>%s\g<4>" % kb.customInjectionMark), conf.data)

        if not kb.postHint:
            if kb.customInjectionMark in conf.data:  # later processed
                pass
            else:
                place = PLACE.POST

                conf.parameters[place] = conf.data
                paramDict = paramToDict(place, conf.data)

                if paramDict:
                    conf.paramDict[place] = paramDict
                    testableParameters = True
        else:
            if kb.customInjectionMark not in conf.data:  # in case that no usable parameter values has been found
                conf.parameters[PLACE.POST] = conf.data

    kb.processUserMarks = True if (kb.postHint and kb.customInjectionMark in (conf.data or "")) else kb.processUserMarks

    if re.search(URI_INJECTABLE_REGEX, conf.url, re.I) and not any(place in conf.parameters for place in (PLACE.GET, PLACE.POST)) and not kb.postHint and kb.customInjectionMark not in (conf.data or "") and conf.url.startswith("http"):
        warnMsg = "you've provided target URL without any GET "
        warnMsg += "parameters (e.g. 'http://www.site.com/article.php?id=1') "
        warnMsg += "and without providing any POST parameters "
        warnMsg += "through option '--data'"
        logger.warn(warnMsg)

        message = "do you want to try URI injections "
        message += "in the target URL itself? [Y/n/q] "
        choice = readInput(message, default='Y').upper()

        if choice == 'Q':
            raise SqlmapUserQuitException
        elif choice == 'Y':
            conf.url = "%s%s" % (conf.url, kb.customInjectionMark)
            kb.processUserMarks = True

    for place, value in ((PLACE.URI, conf.url), (PLACE.CUSTOM_POST, conf.data), (PLACE.CUSTOM_HEADER, str(conf.httpHeaders))):
        if place == PLACE.CUSTOM_HEADER and any((conf.forms, conf.crawlDepth)):
            continue

        _ = re.sub(PROBLEMATIC_CUSTOM_INJECTION_PATTERNS, "", value or "") if place == PLACE.CUSTOM_HEADER else value or ""
        if kb.customInjectionMark in _:
            if kb.processUserMarks is None:
                lut = {PLACE.URI: '-u', PLACE.CUSTOM_POST: '--data', PLACE.CUSTOM_HEADER: '--headers/--user-agent/--referer/--cookie'}
                message = "custom injection marker ('%s') found in option " % kb.customInjectionMark
                message += "'%s'. Do you want to process it? [Y/n/q] " % lut[place]
                choice = readInput(message, default='Y').upper()

                if choice == 'Q':
                    raise SqlmapUserQuitException
                else:
                    kb.processUserMarks = choice == 'Y'

                    if kb.processUserMarks:
                        kb.testOnlyCustom = True

                        if "=%s" % kb.customInjectionMark in _:
                            warnMsg = "it seems that you've provided empty parameter value(s) "
                            warnMsg += "for testing. Please, always use only valid parameter values "
                            warnMsg += "so sqlmap could be able to run properly"
                            logger.warn(warnMsg)

            if not kb.processUserMarks:
                if place == PLACE.URI:
                    query = _urllib.parse.urlsplit(value).query
                    if query:
                        parameters = conf.parameters[PLACE.GET] = query
                        paramDict = paramToDict(PLACE.GET, parameters)

                        if paramDict:
                            conf.url = conf.url.split('?')[0]
                            conf.paramDict[PLACE.GET] = paramDict
                            testableParameters = True
                elif place == PLACE.CUSTOM_POST:
                    conf.parameters[PLACE.POST] = conf.data
                    paramDict = paramToDict(PLACE.POST, conf.data)

                    if paramDict:
                        conf.paramDict[PLACE.POST] = paramDict
                        testableParameters = True

            else:
                conf.parameters[place] = value
                conf.paramDict[place] = OrderedDict()

                if place == PLACE.CUSTOM_HEADER:
                    for index in xrange(len(conf.httpHeaders)):
                        header, value = conf.httpHeaders[index]
                        if kb.customInjectionMark in re.sub(PROBLEMATIC_CUSTOM_INJECTION_PATTERNS, "", value):
                            parts = value.split(kb.customInjectionMark)
                            for i in xrange(len(parts) - 1):
                                conf.paramDict[place]["%s #%d%s" % (header, i + 1, kb.customInjectionMark)] = "%s,%s" % (header, "".join("%s%s" % (parts[j], kb.customInjectionMark if i == j else "") for j in xrange(len(parts))))
                            conf.httpHeaders[index] = (header, value.replace(kb.customInjectionMark, ""))
                else:
                    parts = value.split(kb.customInjectionMark)

                    for i in xrange(len(parts) - 1):
                        name = None
                        if kb.postHint:
                            for ending, _ in hintNames:
                                if parts[i].endswith(ending):
                                    name = "%s %s" % (kb.postHint, _)
                                    break
                        if name is None:
                            name = "%s#%s%s" % (("%s " % kb.postHint) if kb.postHint else "", i + 1, kb.customInjectionMark)
                        conf.paramDict[place][name] = "".join("%s%s" % (parts[j], kb.customInjectionMark if i == j else "") for j in xrange(len(parts)))

                    if place == PLACE.URI and PLACE.GET in conf.paramDict:
                        del conf.paramDict[PLACE.GET]
                    elif place == PLACE.CUSTOM_POST and PLACE.POST in conf.paramDict:
                        del conf.paramDict[PLACE.POST]

                testableParameters = True

    if kb.processUserMarks:
        for item in ("url", "data", "agent", "referer", "cookie"):
            if conf.get(item):
                conf[item] = conf[item].replace(kb.customInjectionMark, "")

    # Perform checks on Cookie parameters
    if conf.cookie:
        conf.parameters[PLACE.COOKIE] = conf.cookie
        paramDict = paramToDict(PLACE.COOKIE, conf.cookie)

        if paramDict:
            conf.paramDict[PLACE.COOKIE] = paramDict
            testableParameters = True

    # Perform checks on header values
    if conf.httpHeaders:
        for httpHeader, headerValue in list(conf.httpHeaders):
            # Url encoding of the header values should be avoided
            # Reference: http://stackoverflow.com/questions/5085904/is-ok-to-urlencode-the-value-in-headerlocation-value

            if httpHeader.upper() == HTTP_HEADER.USER_AGENT.upper():
                conf.parameters[PLACE.USER_AGENT] = urldecode(headerValue)

                condition = any((not conf.testParameter, intersect(conf.testParameter, USER_AGENT_ALIASES, True)))

                if condition:
                    conf.paramDict[PLACE.USER_AGENT] = {PLACE.USER_AGENT: headerValue}
                    testableParameters = True

            elif httpHeader.upper() == HTTP_HEADER.REFERER.upper():
                conf.parameters[PLACE.REFERER] = urldecode(headerValue)

                condition = any((not conf.testParameter, intersect(conf.testParameter, REFERER_ALIASES, True)))

                if condition:
                    conf.paramDict[PLACE.REFERER] = {PLACE.REFERER: headerValue}
                    testableParameters = True

            elif httpHeader.upper() == HTTP_HEADER.HOST.upper():
                conf.parameters[PLACE.HOST] = urldecode(headerValue)

                condition = any((not conf.testParameter, intersect(conf.testParameter, HOST_ALIASES, True)))

                if condition:
                    conf.paramDict[PLACE.HOST] = {PLACE.HOST: headerValue}
                    testableParameters = True

            else:
                condition = intersect(conf.testParameter, [httpHeader], True)

                if condition:
                    conf.parameters[PLACE.CUSTOM_HEADER] = str(conf.httpHeaders)
                    conf.paramDict[PLACE.CUSTOM_HEADER] = {httpHeader: "%s,%s%s" % (httpHeader, headerValue, kb.customInjectionMark)}
                    conf.httpHeaders = [(_[0], _[1].replace(kb.customInjectionMark, "")) for _ in conf.httpHeaders]
                    testableParameters = True

    if not conf.parameters:
        errMsg = "you did not provide any GET, POST and Cookie "
        errMsg += "parameter, neither an User-Agent, Referer or Host header value"
        raise SqlmapGenericException(errMsg)

    elif not testableParameters:
        errMsg = "all testable parameters you provided are not present "
        errMsg += "within the given request data"
        raise SqlmapGenericException(errMsg)

    if conf.csrfToken:
        if not any(re.search(conf.csrfToken, ' '.join(_), re.I) for _ in (conf.paramDict.get(PLACE.GET, {}), conf.paramDict.get(PLACE.POST, {}), conf.paramDict.get(PLACE.COOKIE, {}))) and not re.search(r"\b%s\b" % conf.csrfToken, conf.data or "") and conf.csrfToken not in set(_[0].lower() for _ in conf.httpHeaders) and conf.csrfToken not in conf.paramDict.get(PLACE.COOKIE, {}) and not all(re.search(conf.csrfToken, _, re.I) for _ in conf.paramDict.get(PLACE.URI, {}).values()):
            errMsg = "anti-CSRF token parameter '%s' not " % conf.csrfToken._original
            errMsg += "found in provided GET, POST, Cookie or header values"
            raise SqlmapGenericException(errMsg)
    else:
        for place in (PLACE.GET, PLACE.POST, PLACE.COOKIE):
            if conf.csrfToken:
                break

            for parameter in conf.paramDict.get(place, {}):
                if any(parameter.lower().count(_) for _ in CSRF_TOKEN_PARAMETER_INFIXES):
                    message = "%sparameter '%s' appears to hold anti-CSRF token. " % ("%s " % place if place != parameter else "", parameter)
                    message += "Do you want sqlmap to automatically update it in further requests? [y/N] "

                    if readInput(message, default='N', boolean=True):
                        class _(six.text_type):
                            pass
                        conf.csrfToken = _(re.escape(getUnicode(parameter)))
                        conf.csrfToken._original = getUnicode(parameter)
                        break

def _setHashDB():
    """
    Check and set the HashDB SQLite file for query resume functionality.
    """

    if not conf.hashDBFile:
        conf.hashDBFile = conf.sessionFile or os.path.join(conf.outputPath, SESSION_SQLITE_FILE)

    if conf.flushSession:
        if os.path.exists(conf.hashDBFile):
            if conf.hashDB:
                conf.hashDB.closeAll()

            try:
                os.remove(conf.hashDBFile)
                logger.info("flushing session file")
            except OSError as ex:
                errMsg = "unable to flush the session file ('%s')" % getSafeExString(ex)
                raise SqlmapFilePathException(errMsg)

    conf.hashDB = HashDB(conf.hashDBFile)

def _resumeHashDBValues():
    """
    Resume stored data values from HashDB
    """

    kb.absFilePaths = hashDBRetrieve(HASHDB_KEYS.KB_ABS_FILE_PATHS, True) or kb.absFilePaths
    kb.brute.tables = hashDBRetrieve(HASHDB_KEYS.KB_BRUTE_TABLES, True) or kb.brute.tables
    kb.brute.columns = hashDBRetrieve(HASHDB_KEYS.KB_BRUTE_COLUMNS, True) or kb.brute.columns
    kb.chars = hashDBRetrieve(HASHDB_KEYS.KB_CHARS, True) or kb.chars
    kb.dynamicMarkings = hashDBRetrieve(HASHDB_KEYS.KB_DYNAMIC_MARKINGS, True) or kb.dynamicMarkings
    kb.xpCmdshellAvailable = hashDBRetrieve(HASHDB_KEYS.KB_XP_CMDSHELL_AVAILABLE) or kb.xpCmdshellAvailable

    kb.errorChunkLength = hashDBRetrieve(HASHDB_KEYS.KB_ERROR_CHUNK_LENGTH)
    if isNumPosStrValue(kb.errorChunkLength):
        kb.errorChunkLength = int(kb.errorChunkLength)
    else:
        kb.errorChunkLength = None

    conf.tmpPath = conf.tmpPath or hashDBRetrieve(HASHDB_KEYS.CONF_TMP_PATH)

    for injection in hashDBRetrieve(HASHDB_KEYS.KB_INJECTIONS, True) or []:
        if isinstance(injection, InjectionDict) and injection.place in conf.paramDict and injection.parameter in conf.paramDict[injection.place]:
            if not conf.technique or intersect(conf.technique, injection.data.keys()):
                if intersect(conf.technique, injection.data.keys()):
                    injection.data = dict(_ for _ in injection.data.items() if _[0] in conf.technique)
                if injection not in kb.injections:
                    kb.injections.append(injection)
                    kb.vulnHosts.add(conf.hostname)

    _resumeDBMS()
    _resumeOS()

def _resumeDBMS():
    """
    Resume stored DBMS information from HashDB
    """

    value = hashDBRetrieve(HASHDB_KEYS.DBMS)

    if not value:
        if conf.offline:
            errMsg = "unable to continue in offline mode "
            errMsg += "because of lack of usable "
            errMsg += "session data"
            raise SqlmapNoneDataException(errMsg)
        else:
            return

    dbms = value.lower()
    dbmsVersion = [UNKNOWN_DBMS_VERSION]
    _ = "(%s)" % ('|'.join(SUPPORTED_DBMS))
    _ = re.search(r"\A%s (.*)" % _, dbms, re.I)

    if _:
        dbms = _.group(1).lower()
        dbmsVersion = [_.group(2)]

    if conf.dbms:
        check = True
        for aliases, _, _, _ in DBMS_DICT.values():
            if conf.dbms.lower() in aliases and dbms not in aliases:
                check = False
                break

        if not check:
            message = "you provided '%s' as a back-end DBMS, " % conf.dbms
            message += "but from a past scan information on the target URL "
            message += "sqlmap assumes the back-end DBMS is '%s'. " % dbms
            message += "Do you really want to force the back-end "
            message += "DBMS value? [y/N] "

            if not readInput(message, default='N', boolean=True):
                conf.dbms = None
                Backend.setDbms(dbms)
                Backend.setVersionList(dbmsVersion)
    else:
        infoMsg = "resuming back-end DBMS '%s' " % dbms
        logger.info(infoMsg)

        Backend.setDbms(dbms)
        Backend.setVersionList(dbmsVersion)

def _resumeOS():
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

            if not readInput(message, default='N', boolean=True):
                conf.os = os
        else:
            conf.os = os

        Backend.setOs(conf.os)

def _setResultsFile():
    """
    Create results file for storing results of running in a
    multiple target mode.
    """

    if not conf.multipleTargets:
        return

    if not conf.resultsFP:
        conf.resultsFile = conf.resultsFile or os.path.join(paths.SQLMAP_OUTPUT_PATH, time.strftime(RESULTS_FILE_FORMAT).lower())
        found = os.path.exists(conf.resultsFile)

        try:
            conf.resultsFP = openFile(conf.resultsFile, "a", UNICODE_ENCODING, buffering=0)
        except (OSError, IOError) as ex:
            try:
                warnMsg = "unable to create results file '%s' ('%s'). " % (conf.resultsFile, getUnicode(ex))
                handle, conf.resultsFile = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.RESULTS, suffix=".csv")
                os.close(handle)
                conf.resultsFP = openFile(conf.resultsFile, "w+", UNICODE_ENCODING, buffering=0)
                warnMsg += "Using temporary file '%s' instead" % conf.resultsFile
                logger.warn(warnMsg)
            except IOError as _:
                errMsg = "unable to write to the temporary directory ('%s'). " % _
                errMsg += "Please make sure that your disk is not full and "
                errMsg += "that you have sufficient write permissions to "
                errMsg += "create temporary files and/or directories"
                raise SqlmapSystemException(errMsg)

        if not found:
            conf.resultsFP.writelines("Target URL,Place,Parameter,Technique(s),Note(s)%s" % os.linesep)

        logger.info("using '%s' as the CSV results file in multiple targets mode" % conf.resultsFile)

def _createFilesDir():
    """
    Create the file directory.
    """

    if not any((conf.fileRead, conf.commonFiles)):
        return

    conf.filePath = paths.SQLMAP_FILES_PATH % conf.hostname

    if not os.path.isdir(conf.filePath):
        try:
            os.makedirs(conf.filePath)
        except OSError as ex:
            tempDir = tempfile.mkdtemp(prefix="sqlmapfiles")
            warnMsg = "unable to create files directory "
            warnMsg += "'%s' (%s). " % (conf.filePath, getUnicode(ex))
            warnMsg += "Using temporary directory '%s' instead" % getUnicode(tempDir)
            logger.warn(warnMsg)

            conf.filePath = tempDir

def _createDumpDir():
    """
    Create the dump directory.
    """

    if not conf.dumpTable and not conf.dumpAll and not conf.search:
        return

    conf.dumpPath = safeStringFormat(paths.SQLMAP_DUMP_PATH, conf.hostname)

    if not os.path.isdir(conf.dumpPath):
        try:
            os.makedirs(conf.dumpPath)
        except OSError as ex:
            tempDir = tempfile.mkdtemp(prefix="sqlmapdump")
            warnMsg = "unable to create dump directory "
            warnMsg += "'%s' (%s). " % (conf.dumpPath, getUnicode(ex))
            warnMsg += "Using temporary directory '%s' instead" % getUnicode(tempDir)
            logger.warn(warnMsg)

            conf.dumpPath = tempDir

def _configureDumper():
    conf.dumper = dumper
    conf.dumper.setOutputFile()

def _createTargetDirs():
    """
    Create the output directory.
    """

    conf.outputPath = os.path.join(getUnicode(paths.SQLMAP_OUTPUT_PATH), normalizeUnicode(getUnicode(conf.hostname)))

    try:
        if not os.path.isdir(conf.outputPath):
            os.makedirs(conf.outputPath)
    except (OSError, IOError, TypeError) as ex:
        tempDir = tempfile.mkdtemp(prefix="sqlmapoutput")
        warnMsg = "unable to create output directory "
        warnMsg += "'%s' (%s). " % (conf.outputPath, getUnicode(ex))
        warnMsg += "Using temporary directory '%s' instead" % getUnicode(tempDir)
        logger.warn(warnMsg)

        conf.outputPath = tempDir

    conf.outputPath = getUnicode(conf.outputPath)

    try:
        with openFile(os.path.join(conf.outputPath, "target.txt"), "w+") as f:
            f.write(getUnicode(kb.originalUrls.get(conf.url) or conf.url or conf.hostname))
            f.write(" (%s)" % (HTTPMETHOD.POST if conf.data else HTTPMETHOD.GET))
            f.write("  # %s" % getUnicode(subprocess.list2cmdline(sys.argv), encoding=sys.stdin.encoding))
            if conf.data:
                f.write("\n\n%s" % getUnicode(conf.data))
    except IOError as ex:
        if "denied" in getUnicode(ex):
            errMsg = "you don't have enough permissions "
        else:
            errMsg = "something went wrong while trying "
        errMsg += "to write to the output directory '%s' (%s)" % (paths.SQLMAP_OUTPUT_PATH, getSafeExString(ex))

        raise SqlmapMissingPrivileges(errMsg)
    except UnicodeError as ex:
        warnMsg = "something went wrong while saving target data ('%s')" % getSafeExString(ex)
        logger.warn(warnMsg)

    _createDumpDir()
    _createFilesDir()
    _configureDumper()

def _setAuxOptions():
    """
    Setup auxiliary (host-dependent) options
    """

    kb.aliasName = randomStr(seed=hash(conf.hostname or ""))

def _restoreMergedOptions():
    """
    Restore merged options (command line, configuration file and default values)
    that could be possibly changed during the testing of previous target.
    """

    for option in RESTORE_MERGED_OPTIONS:
        conf[option] = mergedOptions[option]

def initTargetEnv():
    """
    Initialize target environment.
    """

    if conf.multipleTargets:
        if conf.hashDB:
            conf.hashDB.close()

        if conf.cj:
            resetCookieJar(conf.cj)

        threadData = getCurrentThreadData()
        threadData.reset()

        conf.paramDict = {}
        conf.parameters = {}
        conf.hashDBFile = None

        _setKnowledgeBaseAttributes(False)
        _restoreMergedOptions()
        _setDBMS()

    if conf.data:
        class _(six.text_type):
            pass

        kb.postUrlEncode = True

        for key, value in conf.httpHeaders:
            if key.upper() == HTTP_HEADER.CONTENT_TYPE.upper():
                kb.postUrlEncode = "urlencoded" in value
                break

        if kb.postUrlEncode:
            original = conf.data
            conf.data = _(urldecode(conf.data))
            setattr(conf.data, UNENCODED_ORIGINAL_VALUE, original)
            kb.postSpaceToPlus = '+' in original

    if conf.data and unArrayizeValue(conf.base64Parameter) == HTTPMETHOD.POST:
        if '=' not in conf.data.strip('='):
            try:
                original = conf.data
                conf.data = _(decodeBase64(conf.data, binary=False))
                setattr(conf.data, UNENCODED_ORIGINAL_VALUE, original)
            except:
                pass

    match = re.search(INJECT_HERE_REGEX, "%s %s %s" % (conf.url, conf.data, conf.httpHeaders))
    kb.customInjectionMark = match.group(0) if match else CUSTOM_INJECTION_MARK_CHAR

def setupTargetEnv():
    _createTargetDirs()
    _setRequestParams()
    _setHashDB()
    _resumeHashDBValues()
    _setResultsFile()
    _setAuthCred()
    _setAuxOptions()
