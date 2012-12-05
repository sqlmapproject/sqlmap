#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from extra.safe2bin.safe2bin import safechardecode
from lib.core.bigarray import BigArray
from lib.core.common import Backend, isNoneValue, isNumPosStrValue, singleTimeWarnMessage, unArrayizeValue, \
    unsafeSQLIdentificatorNaming
from lib.core.data import conf, logger, queries
from lib.core.enums import CHARSET_TYPE, EXPECTED
from lib.core.exception import sqlmapConnectionException, sqlmapNoneDataException
from lib.core.settings import MAX_INT
from lib.core.unescaper import unescaper
from lib.request import inject

def pivotDumpTable(table, colList, count=None, blind=True):
    lengths = {}
    entries = {}

    dumpNode = queries[Backend.getIdentifiedDbms()].dump_table.blind

    validColumnList = False
    validPivotValue = False

    if count is None:
        query = dumpNode.count % table
        count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS) if blind else inject.getValue(query, blind=False, time=False, expected=EXPECTED.INT)

    if isinstance(count, basestring) and count.isdigit():
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

    colList = filter(None, sorted(colList, key=lambda x: len(x) if x else MAX_INT))

    for column in colList:
        infoMsg = "fetching number of distinct "
        infoMsg += "values for column '%s'" % column
        logger.info(infoMsg)

        query = dumpNode.count2 % (column, table)
        value = inject.getValue(query, blind=blind, union=not blind, error=not blind, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

        if isNumPosStrValue(value):
            validColumnList = True

            if value == count:
                infoMsg = "using column '%s' as a pivot " % column
                infoMsg += "for retrieving row data"
                logger.info(infoMsg)

                validPivotValue = True

                colList.remove(column)
                colList.insert(0, column)
                break

    if not validColumnList:
        errMsg = "all column name(s) provided are non-existent"
        raise sqlmapNoneDataException, errMsg

    if not validPivotValue:
        warnMsg = "no proper pivot column provided (with unique values)."
        warnMsg += " It won't be possible to retrieve all rows"
        logger.warn(warnMsg)

    pivotValue = " "
    breakRetrieval = False

    try:
        for i in xrange(count):
            if breakRetrieval:
                break

            for column in colList:
                def _(pivotValue):
                    if column == colList[0]:
                        query = dumpNode.query.replace("'%s'", "%s") % (column, table, column, unescaper.unescape(pivotValue, False))
                    else:
                        query = dumpNode.query2.replace("'%s'", "%s") % (column, table, colList[0], unescaper.unescape(pivotValue, False))

                    return unArrayizeValue(inject.getValue(query, blind=blind, time=blind, union=not blind, error=not blind))

                value = _(pivotValue)
                if column == colList[0]:
                    if isNoneValue(value):
                        for pivotValue in filter(None, ("  " if pivotValue == " " else None, "%s%s" % (pivotValue[0], unichr(ord(pivotValue[1]) + 1)) if len(pivotValue) > 1 else None, unichr(ord(pivotValue[0]) + 1))):
                            value = _(pivotValue)
                            if not isNoneValue(value):
                                break
                    if isNoneValue(value):
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

                lengths[column] = max(lengths[column], len(value) if value else 0)
                entries[column].append(value)

    except KeyboardInterrupt:
        warnMsg = "user aborted during enumeration. sqlmap "
        warnMsg += "will display partial output"
        logger.warn(warnMsg)

    except sqlmapConnectionException, e:
        errMsg = "connection exception detected. sqlmap "
        errMsg += "will display partial output"
        errMsg += "'%s'" % e
        logger.critical(errMsg)

    return entries, lengths
