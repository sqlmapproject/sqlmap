#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import time

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import getCurrentThreadData
from lib.core.common import getUnicode
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.convert import base64unpickle
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.settings import SQL_STATEMENTS
from lib.core.settings import UNICODE_ENCODING
from lib.utils.timeout import timeout

def direct(query, content=True):
    select = True
    query = agent.payloadDirect(query)
    threadData = getCurrentThreadData()

    if Backend.isDbms(DBMS.ORACLE) and query.startswith("SELECT ") and " FROM " not in query:
        query = "%s FROM DUAL" % query

    for sqlTitle, sqlStatements in SQL_STATEMENTS.items():
        for sqlStatement in sqlStatements:
            if query.lower().startswith(sqlStatement) and sqlTitle != "SQL SELECT statement":
                select = False
                break

    if select and not query.upper().startswith("SELECT "):
        query = "SELECT " + query

    logger.log(9, query)

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
        if output and isinstance(output, (list, tuple)):
            if len(output[0]) == 1:
                if len(output) > 1:
                    output = map(lambda _: _[0], output)
                else:
                    output = output[0][0]

        return getUnicode(output, noneToNull=True)
    else:
        for line in output:
            if line[0] in (1, -1):
                return True
            else:
                return False
