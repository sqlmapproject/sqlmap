#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

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

import re
import time

from lib.core.common import calculateDeltaSeconds
from lib.core.common import dataToSessionFile
from lib.core.common import safeStringFormat
from lib.core.common import randomStr
from lib.core.common import replaceNewlineTabs
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.unescaper import unescaper
from lib.techniques.blind.inference import bisection

def queryOutputLength(expression, payload):
    """
    Returns the query output length.
    """

    lengthQuery         = queries[kb.dbms].length

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

        if kb.dbms in ( "MySQL", "PostgreSQL" ):
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

    dataToSessionFile("[%s][%s][%s][%s][" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], lengthExpr))

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

    if "sqlmapfile" in expression or "sqlmapoutput" in expression:
        return None

    condition = (
                  kb.resumedQueries and conf.url in kb.resumedQueries.keys()
                  and expression in kb.resumedQueries[conf.url].keys()
                )

    if not condition:
        return None

    resumedValue = kb.resumedQueries[conf.url][expression]

    if not resumedValue:
        return None

    resumedValue = resumedValue.replace("__NEWLINE__", "\n").replace("__TAB__", "\t")

    if resumedValue[-1] == "]":
        resumedValue = resumedValue[:-1]

        infoMsg  = "read from file '%s': " % conf.sessionFile
        logValue = re.findall("__START__(.*?)__STOP__", resumedValue, re.S)

        if logValue:
            logValue = ", ".join([value.replace("__DEL__", ", ") for value in logValue])
        else:
            logValue = resumedValue

        if "\n" in logValue:
            infoMsg += "%s..." % logValue.split("\n")[0]
        else:
            infoMsg += logValue

        logger.info(infoMsg)

        return resumedValue

    # If we called this function without providing a payload it means that
    # we have called it from lib/request/inject __goInband() function
    # in UNION query (inband) SQL injection so we return to the calling
    # function so that the query output will be retrieved taking advantage
    # of the inband SQL injection vulnerability.
    if not payload:
        return None

    if not kb.dbms:
        return None

    substringQuery = queries[kb.dbms].substring
    select = re.search("\ASELECT ", expression, re.I)

    _, length, regExpr = queryOutputLength(expression, payload)

    if not length:
        return None

    if len(resumedValue) == int(length):
        infoMsg  = "read from file '%s': " % conf.sessionFile
        infoMsg += "%s" % resumedValue.split("\n")[0]
        logger.info(infoMsg)

        dataToSessionFile("[%s][%s][%s][%s][%s]\n" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], expression, replaceNewlineTabs(resumedValue)))

        return resumedValue
    elif len(resumedValue) < int(length):
        infoMsg  = "resumed from file '%s': " % conf.sessionFile
        infoMsg += "%s..." % resumedValue.split("\n")[0]
        logger.info(infoMsg)

        dataToSessionFile("[%s][%s][%s][%s][%s" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], expression, replaceNewlineTabs(resumedValue)))

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
