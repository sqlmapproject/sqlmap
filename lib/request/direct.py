#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import time

from extra.safe2bin.safe2bin import safecharencode
from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import extractExpectedValue
from lib.core.common import getCurrentThreadData
from lib.core.common import getUnicode
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import isListLike
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.dicts import SQL_STATEMENTS
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.settings import UNICODE_ENCODING
from lib.utils.timeout import timeout

def direct(query, content=True):
    select = True
    query = agent.payloadDirect(query)
    query = agent.adjustLateValues(query)
    threadData = getCurrentThreadData()

    if Backend.isDbms(DBMS.ORACLE) and query.startswith("SELECT ") and " FROM " not in query:
        query = "%s FROM DUAL" % query

    for sqlTitle, sqlStatements in SQL_STATEMENTS.items():
        for sqlStatement in sqlStatements:
            if query.lower().startswith(sqlStatement) and sqlTitle != "SQL SELECT statement":
                select = False
                break

    if select and not query.upper().startswith("SELECT "):
        query = "SELECT %s" % query

    logger.log(CUSTOM_LOGGING.PAYLOAD, query)

    output = hashDBRetrieve(query, True, True)
    start = time.time()

    if not select and "EXEC " not in query:
        _ = timeout(func=conf.dbmsConnector.execute, args=(query,), duration=conf.timeout, default=None)
    elif not (output and "sqlmapoutput" not in query and "sqlmapfile" not in query):
        output = timeout(func=conf.dbmsConnector.select, args=(query,), duration=conf.timeout, default=None)
        hashDBWrite(query, output, True)
    elif output:
        infoMsg = "resumed: %s..." % getUnicode(output, UNICODE_ENCODING)[:20]
        logger.info(infoMsg)
    threadData.lastQueryDuration = calculateDeltaSeconds(start)

    if not output:
        return output
    elif content:
        if output and isListLike(output):
            if len(output[0]) == 1:
                output = [_[0] for _ in output]

        retVal = getUnicode(output, noneToNull=True)
        return safecharencode(retVal) if kb.safeCharEncode else retVal
    else:
        return extractExpectedValue(output, EXPECTED.BOOL)
