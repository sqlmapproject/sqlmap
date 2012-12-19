#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import os
import threading

from xml.dom.minidom import getDOMImplementation

from lib.core.common import Backend
from lib.core.common import dataToDumpFile
from lib.core.common import dataToStdout
from lib.core.common import getUnicode
from lib.core.common import isListLike
from lib.core.common import normalizeUnicode
from lib.core.common import openFile
from lib.core.common import prioritySortColumns
from lib.core.common import safeCSValue
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.dicts import DUMP_REPLACEMENTS
from lib.core.enums import DBMS
from lib.core.enums import DUMP_FORMAT
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapValueException
from lib.core.replication import Replication
from lib.core.settings import HTML_DUMP_CSS_STYLE
from lib.core.settings import METADB_SUFFIX
from lib.core.settings import TRIM_STDOUT_DUMP_SIZE
from lib.core.settings import UNICODE_ENCODING

class Dump(object):
    """
    This class defines methods used to parse and output the results
    of SQL injection actions

    """

    def __init__(self):
        self._outputFile = None
        self._outputFP = None
        self._lock = threading.Lock()

    def _write(self, data, newline=True, console=True):
        text = "%s%s" % (data, "\n" if newline else " ")
        if console:
            dataToStdout(text)

        if kb.get("multiThreadMode"):
            self._lock.acquire()

        self._outputFP.write(text)

        if kb.get("multiThreadMode"):
            self._lock.release()

        kb.dataOutputFlag = True

    def setOutputFile(self):
        self._outputFile = "%s%slog" % (conf.outputPath, os.sep)
        try:
            self._outputFP = codecs.open(self._outputFile, "ab" if not conf.flushSession else "wb", UNICODE_ENCODING)
        except IOError, ex:
            errMsg = "error occurred while opening log file ('%s')" % ex
            raise SqlmapGenericException, errMsg

    def getOutputFile(self):
        return self._outputFile

    def singleString(self, data):
        self._write(data)

    def string(self, header, data, sort=True):
        kb.stickyLevel = None

        if isListLike(data):
            self.lister(header, data, sort)
        elif data is not None:
            _ = getUnicode(data)

            if _ and _[-1] == '\n':
                _ = _[:-1]

            if "\n" in _:
                self._write("%s:\n---\n%s\n---" % (header, _))
            else:
                self._write("%s:    %s" % (header, ("'%s'" % _) if isinstance(data, basestring) else _))
        else:
            self._write("%s:\tNone" % header)

    def lister(self, header, elements, sort=True):
        if elements:
            self._write("%s [%d]:" % (header, len(elements)))

        if sort:
            try:
                elements = set(elements)
                elements = list(elements)
                elements.sort(key=lambda x: x.lower() if isinstance(x, basestring) else x)
            except:
                pass

        for element in elements:
            if isinstance(element, basestring):
                self._write("[*] %s" % element)
            elif isListLike(element):
                self._write("[*] " + ", ".join(getUnicode(e) for e in element))

        if elements:
            self._write("")

    def banner(self,data):
        self.string("banner", data)

    def currentUser(self,data):
        self.string("current user", data)

    def currentDb(self,data):
        if Backend.isDbms(DBMS.MAXDB):
            self.string("current database (no practical usage on %s)" % Backend.getIdentifiedDbms(), data)
        elif Backend.isDbms(DBMS.ORACLE):
            self.string("current schema (equivalent to database on %s)" % Backend.getIdentifiedDbms(), data)
        else:
            self.string("current database", data)

    def hostname(self,data):
        self.string("hostname", data)

    def dba(self,data):
        self.string("current user is DBA", data)

    def users(self,users):
        self.lister("database management system users", users)

    def userSettings(self, header, userSettings, subHeader):
        self._areAdmins = set()

        if userSettings:
            self._write("%s:" % header)

        if isinstance(userSettings, (tuple, list, set)):
            self._areAdmins = userSettings[1]
            userSettings = userSettings[0]

        users = userSettings.keys()
        users.sort(key=lambda x: x.lower() if isinstance(x, basestring) else x)

        for user in users:
            settings = userSettings[user]

            if settings is None:
                stringSettings = ""
            else:
                stringSettings = " [%d]:" % len(settings)

            if user in self._areAdmins:
                self._write("[*] %s (administrator)%s" % (user, stringSettings))
            else:
                self._write("[*] %s%s" % (user, stringSettings))

            if settings:
                settings.sort()

                for setting in settings:
                    self._write("    %s: %s" % (subHeader, setting))

        self.singleString("")

    def dbs(self,dbs):
        self.lister("available databases", dbs)

    def dbTables(self, dbTables):
        if isinstance(dbTables, dict) and len(dbTables) > 0:
            maxlength = 0

            for tables in dbTables.values():
                for table in tables:
                    if table and isListLike(table):
                        table = table[0]

                    maxlength = max(maxlength, len(normalizeUnicode(table) or str(table)))

            lines = "-" * (int(maxlength) + 2)

            for db, tables in dbTables.items():
                tables.sort()

                self._write("Database: %s" % db if db else "Current database")

                if len(tables) == 1:
                    self._write("[1 table]")
                else:
                    self._write("[%d tables]" % len(tables))

                self._write("+%s+" % lines)

                for table in tables:
                    if table and isListLike(table):
                        table = table[0]

                    blank = " " * (maxlength - len(normalizeUnicode(table) or str(table)))
                    self._write("| %s%s |" % (table, blank))

                self._write("+%s+\n" % lines)
        elif dbTables is None or len(dbTables) == 0:
            self.singleString("No tables found")
        else:
            self.string("tables", dbTables)

    def dbTableColumns(self, tableColumns):
        if isinstance(tableColumns, dict) and len(tableColumns) > 0:
            for db, tables in tableColumns.items():
                if not db:
                    db = "All"

                for table, columns in tables.items():
                    maxlength1 = 0
                    maxlength2 = 0

                    colType = None

                    colList = columns.keys()
                    colList.sort(key=lambda x: x.lower() if isinstance(x, basestring) else x)

                    for column in colList:
                        colType = columns[column]

                        maxlength1 = max(maxlength1, len(column or ""))
                        maxlength2 = max(maxlength2, len(colType or ""))

                    maxlength1 = max(maxlength1, len("COLUMN"))
                    lines1 = "-" * (maxlength1 + 2)

                    if colType is not None:
                        maxlength2 = max(maxlength2, len("TYPE"))
                        lines2 = "-" * (maxlength2 + 2)

                    self._write("Database: %s\nTable: %s" % (db if db else "Current database", table))

                    if len(columns) == 1:
                        self._write("[1 column]")
                    else:
                        self._write("[%d columns]" % len(columns))

                    if colType is not None:
                        self._write("+%s+%s+" % (lines1, lines2))
                    else:
                        self._write("+%s+" % lines1)

                    blank1 = " " * (maxlength1 - len("COLUMN"))

                    if colType is not None:
                        blank2 = " " * (maxlength2 - len("TYPE"))

                    if colType is not None:
                        self._write("| Column%s | Type%s |" % (blank1, blank2))
                        self._write("+%s+%s+" % (lines1, lines2))
                    else:
                        self._write("| Column%s |" % blank1)
                        self._write("+%s+" % lines1)

                    for column in colList:
                        colType = columns[column]
                        blank1 = " " * (maxlength1 - len(column))

                        if colType is not None:
                            blank2 = " " * (maxlength2 - len(colType))
                            self._write("| %s%s | %s%s |" % (column, blank1, colType, blank2))
                        else:
                            self._write("| %s%s |" % (column, blank1))

                    if colType is not None:
                        self._write("+%s+%s+\n" % (lines1, lines2))
                    else:
                        self._write("+%s+\n" % lines1)

    def dbTablesCount(self, dbTables):
        if isinstance(dbTables, dict) and len(dbTables) > 0:
            maxlength1 = len("Table")
            maxlength2 = len("Entries")

            for ctables in dbTables.values():
                for tables in ctables.values():
                    for table in tables:
                        maxlength1 = max(maxlength1, len(normalizeUnicode(table) or str(table)))

            for db, counts in dbTables.items():
                self._write("Database: %s" % db if db else "Current database")

                lines1 = "-" * (maxlength1 + 2)
                blank1 = " " * (maxlength1 - len("Table"))
                lines2 = "-" * (maxlength2 + 2)
                blank2 = " " * (maxlength2 - len("Entries"))

                self._write("+%s+%s+" % (lines1, lines2))
                self._write("| Table%s | Entries%s |" % (blank1, blank2))
                self._write("+%s+%s+" % (lines1, lines2))

                sortedCounts = counts.keys()
                sortedCounts.sort(reverse=True)

                for count in sortedCounts:
                    tables = counts[count]

                    if count is None:
                        count = "Unknown"

                    tables.sort(key=lambda x: x.lower() if isinstance(x, basestring) else x)

                    for table in tables:
                        blank1 = " " * (maxlength1 - len(normalizeUnicode(table) or str(table)))
                        blank2 = " " * (maxlength2 - len(str(count)))
                        self._write("| %s%s | %d%s |" % (table, blank1, count, blank2))

                self._write("+%s+%s+\n" % (lines1, lines2))
        else:
            logger.error("unable to retrieve the number of entries for any table")

    def dbTableValues(self, tableValues):
        replication = None
        rtable = None
        documentNode, tableNode, bodyNode, headNode, rowNode = (0,) * 5
        dumpFP = None

        if tableValues is None:
            return

        db = tableValues["__infos__"]["db"]
        if not db:
            db = "All"
        table = tableValues["__infos__"]["table"]

        if conf.dumpFormat == DUMP_FORMAT.SQLITE:
            replication = Replication("%s%s%s.sqlite3" % (conf.dumpPath, os.sep, unsafeSQLIdentificatorNaming(db)))
        elif conf.dumpFormat in (DUMP_FORMAT.CSV, DUMP_FORMAT.HTML):
            dumpDbPath = "%s%s%s" % (conf.dumpPath, os.sep, unsafeSQLIdentificatorNaming(db))

            if not os.path.isdir(dumpDbPath):
                os.makedirs(dumpDbPath, 0755)

            dumpFileName = "%s%s%s.%s" % (dumpDbPath, os.sep, unsafeSQLIdentificatorNaming(table), conf.dumpFormat.lower())
            dumpFP = openFile(dumpFileName, "wb")

        count = int(tableValues["__infos__"]["count"])
        separator = str()
        field = 1
        fields = len(tableValues) - 1

        columns = prioritySortColumns(tableValues.keys())

        for column in columns:
            if column != "__infos__":
                info = tableValues[column]
                lines = "-" * (int(info["length"]) + 2)
                separator += "+%s" % lines

        separator += "+"
        self._write("Database: %s\nTable: %s" % (db if db else "Current database", table))

        if conf.dumpFormat == DUMP_FORMAT.SQLITE:
            cols = []

            for column in columns:
                if column != "__infos__":
                    colType = Replication.INTEGER

                    for value in tableValues[column]['values']:
                        try:
                            if not value or value == " ":  # NULL
                                continue

                            int(value)
                        except ValueError:
                            colType = None
                            break

                    if colType is None:
                        colType = Replication.REAL

                        for value in tableValues[column]['values']:
                            try:
                                if not value or value == " ":  # NULL
                                    continue

                                float(value)
                            except ValueError:
                                colType = None
                                break

                    cols.append((column, colType if colType else Replication.TEXT))

            rtable = replication.createTable(table, cols)
        elif conf.dumpFormat == DUMP_FORMAT.HTML:
            documentNode = getDOMImplementation().createDocument(None, "table", None)
            tableNode = documentNode.documentElement

        if count == 1:
            self._write("[1 entry]")
        else:
            self._write("[%d entries]" % count)

        self._write(separator)

        if conf.dumpFormat == DUMP_FORMAT.HTML:
            headNode = documentNode.createElement("thead")
            rowNode = documentNode.createElement("tr")
            tableNode.appendChild(headNode)
            headNode.appendChild(rowNode)
            bodyNode = documentNode.createElement("tbody")
            tableNode.appendChild(bodyNode)

        for column in columns:
            if column != "__infos__":
                info = tableValues[column]
                maxlength = int(info["length"])
                blank = " " * (maxlength - len(column))

                self._write("| %s%s" % (column, blank), newline=False)

                if conf.dumpFormat == DUMP_FORMAT.CSV:
                    if field == fields:
                        dataToDumpFile(dumpFP, "%s" % safeCSValue(column))
                    else:
                        dataToDumpFile(dumpFP, "%s%s" % (safeCSValue(column), conf.csvDel))
                elif conf.dumpFormat == DUMP_FORMAT.HTML:
                    entryNode = documentNode.createElement("td")
                    rowNode.appendChild(entryNode)
                    entryNode.appendChild(documentNode.createTextNode(column))

                field += 1

        self._write("|\n%s" % separator)

        if conf.dumpFormat == DUMP_FORMAT.CSV:
            dataToDumpFile(dumpFP, "\n")

        elif conf.dumpFormat == DUMP_FORMAT.SQLITE:
            rtable.beginTransaction()

        if count > TRIM_STDOUT_DUMP_SIZE:
            warnMsg = "console output will be trimmed to "
            warnMsg += "last %d rows due to " % TRIM_STDOUT_DUMP_SIZE
            warnMsg += "large table size"
            logger.warning(warnMsg)

        for i in xrange(count):
            console = (i >= count - TRIM_STDOUT_DUMP_SIZE)
            field = 1
            values = []

            if conf.dumpFormat == DUMP_FORMAT.HTML:
                rowNode = documentNode.createElement("tr")
                bodyNode.appendChild(rowNode)

            for column in columns:
                if column != "__infos__":
                    info = tableValues[column]

                    if len(info["values"]) <= i:
                        continue

                    if info["values"][i] is None:
                        value = u''
                    else:
                        value = getUnicode(info["values"][i])
                        value = DUMP_REPLACEMENTS.get(value, value)

                    values.append(value)
                    maxlength = int(info["length"])
                    blank = " " * (maxlength - len(value))
                    self._write("| %s%s" % (value, blank), newline=False, console=console)

                    if conf.dumpFormat == DUMP_FORMAT.CSV:
                        if field == fields:
                            dataToDumpFile(dumpFP, "%s" % safeCSValue(value))
                        else:
                            dataToDumpFile(dumpFP, "%s%s" % (safeCSValue(value), conf.csvDel))
                    elif conf.dumpFormat == DUMP_FORMAT.HTML:
                        entryNode = documentNode.createElement("td")
                        rowNode.appendChild(entryNode)
                        entryNode.appendChild(documentNode.createTextNode(value))

                    field += 1

            if conf.dumpFormat == DUMP_FORMAT.SQLITE:
                try:
                    rtable.insert(values)
                except SqlmapValueException:
                    pass
            elif conf.dumpFormat == DUMP_FORMAT.CSV:
                dataToDumpFile(dumpFP, "\n")

            self._write("|", console=console)

        self._write("%s\n" % separator)

        if conf.dumpFormat == DUMP_FORMAT.SQLITE:
            rtable.endTransaction()
            logger.info("table '%s.%s' dumped to sqlite3 database '%s'" % (db, table, replication.dbpath))

        elif conf.dumpFormat in (DUMP_FORMAT.CSV, DUMP_FORMAT.HTML):
            if conf.dumpFormat == DUMP_FORMAT.HTML:
                dataToDumpFile(dumpFP, "<!DOCTYPE html>\n<html>\n<head>\n")
                dataToDumpFile(dumpFP, "<meta http-equiv=\"Content-type\" content=\"text/html;charset=%s\">\n" % UNICODE_ENCODING)
                dataToDumpFile(dumpFP, "<title>%s</title>\n" % ("%s%s" % ("%s." % db if METADB_SUFFIX not in db else "", table)))
                dataToDumpFile(dumpFP, HTML_DUMP_CSS_STYLE)
                dataToDumpFile(dumpFP, "\n</head>\n")
                dataToDumpFile(dumpFP, tableNode.toxml())
                dataToDumpFile(dumpFP, "\n</html>")
            else:
                dataToDumpFile(dumpFP, "\n")
            dumpFP.close()
            logger.info("table '%s.%s' dumped to %s file '%s'" % (db, table, conf.dumpFormat, dumpFileName))

    def dbColumns(self, dbColumnsDict, colConsider, dbs):
        for column in dbColumnsDict.keys():
            if colConsider == "1":
                colConsiderStr = "s like '" + column + "' were"
            else:
                colConsiderStr = " '%s' was" % column

            msg = "Column%s found in the " % colConsiderStr
            msg += "following databases:"
            self._write(msg)

            _ = {}

            for db, tblData in dbs.items():
                for tbl, colData in tblData.items():
                    for col, dataType in colData.items():
                        if column.lower() in col.lower():
                            if db in _:
                                if tbl in _[db]:
                                    _[db][tbl][col] = dataType
                                else:
                                    _[db][tbl] = {col: dataType}
                            else:
                                _[db] = {}
                                _[db][tbl] = {col: dataType}

                            continue

            self.dbTableColumns(_)

    def query(self, query, queryRes):
        self.string(query, queryRes)

    def rFile(self, filePath, fileData):
        self.lister("files saved to", fileData, sort=False)

    def registerValue(self, registerData):
        self.string("Registry key value data", registerData, sort=False)

# object to manage how to print the retrieved queries output to
# standard output and sessions file
dumper = Dump()
