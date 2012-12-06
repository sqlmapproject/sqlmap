#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.common import dataToStdout
from lib.core.common import getSQLSnippet
from lib.core.common import isTechniqueAvailable
from lib.core.convert import utf8decode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.dicts import SQL_STATEMENTS
from lib.core.enums import PAYLOAD
from lib.core.settings import PARAMETER_SPLITTING_REGEX
from lib.core.shell import autoCompletion
from lib.request import inject

class Custom:
    """
    This class defines custom enumeration functionalities for plugins.
    """

    def __init__(self):
        pass

    def sqlQuery(self, query):
        output = None
        sqlType = None
        query = query.rstrip(';')

        for sqlTitle, sqlStatements in SQL_STATEMENTS.items():
            for sqlStatement in sqlStatements:
                if query.lower().startswith(sqlStatement):
                    sqlType = sqlTitle
                    break

        if 'OPENROWSET' not in query.upper() and (not sqlType or 'SELECT' in sqlType):
            infoMsg = "fetching %s query output: '%s'" % (sqlType if sqlType is not None else "SQL", query)
            logger.info(infoMsg)

            output = inject.getValue(query, fromUser=True)

            return output
        elif not isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED) and not conf.direct:
                warnMsg = "execution of custom SQL queries is only "
                warnMsg += "available when stacked queries are supported"
                logger.warn(warnMsg)

                return None
        else:
            if sqlType:
                debugMsg = "executing %s query: '%s'" % (sqlType if sqlType is not None else "SQL", query)
            else:
                debugMsg = "executing unknown SQL type query: '%s'" % query
            logger.debug(debugMsg)

            inject.goStacked(query)

            debugMsg = "done"
            logger.debug(debugMsg)

            output = False

        return output

    def sqlShell(self):
        infoMsg = "calling %s shell. To quit type " % Backend.getIdentifiedDbms()
        infoMsg += "'x' or 'q' and press ENTER"
        logger.info(infoMsg)

        autoCompletion(sqlShell=True)

        while True:
            query = None

            try:
                query = raw_input("sql-shell> ")
                query = utf8decode(query)
            except KeyboardInterrupt:
                print
                errMsg = "user aborted"
                logger.error(errMsg)
            except EOFError:
                print
                errMsg = "exit"
                logger.error(errMsg)
                break

            if not query:
                continue

            if query.lower() in ("x", "q", "exit", "quit"):
                break

            output = self.sqlQuery(query)

            if output and output != "Quit":
                conf.dumper.query(query, output)

            elif not output:
                pass

            elif output != "Quit":
                dataToStdout("No output\n")

    def sqlFile(self):
        infoMsg = "executing SQL statements from given file(s)"
        logger.info(infoMsg)

        for sfile in re.split(PARAMETER_SPLITTING_REGEX, conf.sqlFile):
            sfile = sfile.strip()

            if not sfile:
                continue

            query = getSQLSnippet(Backend.getDbms(), sfile)

            infoMsg = "executing SQL statement%s from file '%s'" % ("s" if ";" in query else "", sfile)
            logger.info(infoMsg)

            conf.dumper.query(query, self.sqlQuery(query))
