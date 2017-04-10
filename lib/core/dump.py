#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import cgi
import hashlib
import os
import re
import shutil
import tempfile
import threading

from lib.core.common import Backend
from lib.core.common import checkFile
from lib.core.common import dataToDumpFile
from lib.core.common import dataToStdout
from lib.core.common import getSafeExString
from lib.core.common import getUnicode
from lib.core.common import isListLike
from lib.core.common import normalizeUnicode
from lib.core.common import openFile
from lib.core.common import prioritySortColumns
from lib.core.common import randomInt
from lib.core.common import safeCSValue
from lib.core.common import unicodeencode
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.dicts import DUMP_REPLACEMENTS
from lib.core.enums import CONTENT_STATUS
from lib.core.enums import CONTENT_TYPE
from lib.core.enums import DBMS
from lib.core.enums import DUMP_FORMAT
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapValueException
from lib.core.exception import SqlmapSystemException
from lib.core.replication import Replication
from lib.core.settings import DUMP_FILE_BUFFER_SIZE
from lib.core.settings import HTML_DUMP_CSS_STYLE
from lib.core.settings import IS_WIN
from lib.core.settings import METADB_SUFFIX
from lib.core.settings import MIN_BINARY_DISK_DUMP_SIZE
from lib.core.settings import TRIM_STDOUT_DUMP_SIZE
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import WINDOWS_RESERVED_NAMES
from thirdparty.magic import magic

from extra.safe2bin.safe2bin import safechardecode

class Dump(object):
    """
    This class defines methods used to parse and output the results
    of SQL injection actions
    """

    def __init__(self):
        self._outputFile = None
        self._outputFP = None
        self._lock = threading.Lock()

    def _write(self, data, newline=True, console=True, content_type=None):
        if conf.api:
            dataToStdout(data, content_type=content_type, status=CONTENT_STATUS.COMPLETE)
            return

        text = "%s%s" % (data, "\n" if newline else " ")

        if console:
            dataToStdout(text)

        if kb.get("multiThreadMode"):
            self._lock.acquire()

        try:
            self._outputFP.write(text)
        except IOError, ex:
            errMsg = "error occurred while writing to log file ('%s')" % getSafeExString(ex)
            raise SqlmapGenericException(errMsg)

        if kb.get("multiThreadMode"):
            self._lock.release()

        kb.dataOutputFlag = True

    def flush(self):
        if self._outputFP:
            try:
                self._outputFP.flush()
            except IOError:
                pass

    def setOutputFile(self):
        self._outputFile = os.path.join(conf.outputPath, "log")
        try:
            self._outputFP = openFile(self._outputFile, "ab" if not conf.flushSession else "wb")
        except IOError, ex:
            errMsg = "error occurred while opening log file ('%s')" % getSafeExString(ex)
            raise SqlmapGenericException(errMsg)

    def getOutputFile(self):
        return self._outputFile

    def singleString(self, data, content_type=None):
        self._write(data, content_type=content_type)

    def string(self, header, data, content_type=None, sort=True):
        kb.stickyLevel = None

        if conf.api:
            self._write(data, content_type=content_type)
            return

        if isListLike(data):
            self.lister(header, data, content_type, sort)
        elif data is not None:
            _ = getUnicode(data)

            if _.endswith("\r\n"):
                _ = _[:-2]

            elif _.endswith("\n"):
                _ = _[:-1]

            if _.strip(' '):
                _ = _.strip(' ')

            if "\n" in _:
                self._write("%s:\n---\n%s\n---" % (header, _))
            else:
                self._write("%s:    %s" % (header, ("'%s'" % _) if isinstance(data, basestring) else _))
        else:
            self._write("%s:\tNone" % header)

    def lister(self, header, elements, content_type=None, sort=True):
        if elements and sort:
            try:
                elements = set(elements)
                elements = list(elements)
                elements.sort(key=lambda x: x.lower() if isinstance(x, basestring) else x)
            except:
                pass

        if conf.api:
            self._write(elements, content_type=content_type)
            return

        if elements:
            self._write("%s [%d]:" % (header, len(elements)))

        for element in elements:
            if isinstance(element, basestring):
                self._write("[*] %s" % element)
            elif isListLike(element):
                self._write("[*] " + ", ".join(getUnicode(e) for e in element))

        if elements:
            self._write("")

    def banner(self, data):
        self.string("banner", data, content_type=CONTENT_TYPE.BANNER)

    def currentUser(self, data):
        self.string("current user", data, content_type=CONTENT_TYPE.CURRENT_USER)

    def currentDb(self, data):
        if Backend.isDbms(DBMS.MAXDB):
            self.string("current database (no practical usage on %s)" % Backend.getIdentifiedDbms(), data, content_type=CONTENT_TYPE.CURRENT_DB)
        elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.PGSQL, DBMS.HSQLDB):
            self.string("current schema (equivalent to database on %s)" % Backend.getIdentifiedDbms(), data, content_type=CONTENT_TYPE.CURRENT_DB)
        else:
            self.string("current database", data, content_type=CONTENT_TYPE.CURRENT_DB)

    def hostname(self, data):
        self.string("hostname", data, content_type=CONTENT_TYPE.HOSTNAME)

    def dba(self, data):
        self.string("current user is DBA", data, content_type=CONTENT_TYPE.IS_DBA)

    def users(self, users):
        self.lister("database management system users", users, content_type=CONTENT_TYPE.USERS)

    def userSettings(self, header, userSettings, subHeader, content_type=None):
        self._areAdmins = set()

        if isinstance(userSettings, (tuple, list, set)):
            self._areAdmins = userSettings[1]
            userSettings = userSettings[0]

        users = userSettings.keys()
        users.sort(key=lambda x: x.lower() if isinstance(x, basestring) else x)

        if conf.api:
            self._write(userSettings, content_type=content_type)
            return

        if userSettings:
            self._write("%s:" % header)

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

        if userSettings:
            self.singleString("")

    def dbs(self, dbs):
        self.lister("available databases", dbs, content_type=CONTENT_TYPE.DBS)

    def dbTables(self, dbTables):
        if isinstance(dbTables, dict) and len(dbTables) > 0:
            if conf.api:
                self._write(dbTables, content_type=CONTENT_TYPE.TABLES)
                return

            maxlength = 0

            for tables in dbTables.values():
                for table in tables:
                    if table and isListLike(table):
                        table = table[0]

                    maxlength = max(maxlength, len(unsafeSQLIdentificatorNaming(normalizeUnicode(table) or unicode(table))))

            lines = "-" * (int(maxlength) + 2)

            for db, tables in dbTables.items():
                tables.sort()

                self._write("Database: %s" % unsafeSQLIdentificatorNaming(db) if db else "Current database")

                if len(tables) == 1:
                    self._write("[1 table]")
                else:
                    self._write("[%d tables]" % len(tables))

                self._write("+%s+" % lines)

                for table in tables:
                    if table and isListLike(table):
                        table = table[0]

                    table = unsafeSQLIdentificatorNaming(table)
                    blank = " " * (maxlength - len(normalizeUnicode(table) or unicode(table)))
                    self._write("| %s%s |" % (table, blank))

                self._write("+%s+\n" % lines)
        elif dbTables is None or len(dbTables) == 0:
            self.singleString("No tables found", content_type=CONTENT_TYPE.TABLES)
        else:
            self.string("tables", dbTables, content_type=CONTENT_TYPE.TABLES)

    def dbTableColumns(self, tableColumns, content_type=None):
        if isinstance(tableColumns, dict) and len(tableColumns) > 0:
            if conf.api:
                self._write(tableColumns, content_type=content_type)
                return

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

                        column = unsafeSQLIdentificatorNaming(column)
                        maxlength1 = max(maxlength1, len(column or ""))
                        maxlength2 = max(maxlength2, len(colType or ""))

                    maxlength1 = max(maxlength1, len("COLUMN"))
                    lines1 = "-" * (maxlength1 + 2)

                    if colType is not None:
                        maxlength2 = max(maxlength2, len("TYPE"))
                        lines2 = "-" * (maxlength2 + 2)

                    self._write("Database: %s\nTable: %s" % (unsafeSQLIdentificatorNaming(db) if db else "Current database", unsafeSQLIdentificatorNaming(table)))

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

                        column = unsafeSQLIdentificatorNaming(column)
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
            if conf.api:
                self._write(dbTables, content_type=CONTENT_TYPE.COUNT)
                return

            maxlength1 = len("Table")
            maxlength2 = len("Entries")

            for ctables in dbTables.values():
                for tables in ctables.values():
                    for table in tables:
                        maxlength1 = max(maxlength1, len(normalizeUnicode(table) or unicode(table)))

            for db, counts in dbTables.items():
                self._write("Database: %s" % unsafeSQLIdentificatorNaming(db) if db else "Current database")

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
                        blank1 = " " * (maxlength1 - len(normalizeUnicode(table) or unicode(table)))
                        blank2 = " " * (maxlength2 - len(str(count)))
                        self._write("| %s%s | %d%s |" % (table, blank1, count, blank2))

                self._write("+%s+%s+\n" % (lines1, lines2))
        else:
            logger.error("unable to retrieve the number of entries for any table")

    def dbTableValues(self, tableValues):
        replication = None
        rtable = None
        dumpFP = None
        appendToFile = False
        warnFile = False

        if tableValues is None:
            return

        db = tableValues["__infos__"]["db"]
        if not db:
            db = "All"
        table = tableValues["__infos__"]["table"]

        if conf.api:
            self._write(tableValues, content_type=CONTENT_TYPE.DUMP_TABLE)
            return

        dumpDbPath = os.path.join(conf.dumpPath, unsafeSQLIdentificatorNaming(db))

        if conf.dumpFormat == DUMP_FORMAT.SQLITE:
            replication = Replication(os.path.join(conf.dumpPath, "%s.sqlite3" % unsafeSQLIdentificatorNaming(db)))
        elif conf.dumpFormat in (DUMP_FORMAT.CSV, DUMP_FORMAT.HTML):
            if not os.path.isdir(dumpDbPath):
                try:
                    os.makedirs(dumpDbPath, 0755)
                except:
                    warnFile = True

                    _ = unicodeencode(re.sub(r"[^\w]", "_", unsafeSQLIdentificatorNaming(db)))
                    dumpDbPath = os.path.join(conf.dumpPath, "%s-%s" % (_, hashlib.md5(unicodeencode(db)).hexdigest()[:8]))

                    if not os.path.isdir(dumpDbPath):
                        try:
                            os.makedirs(dumpDbPath, 0755)
                        except Exception, ex:
                            try:
                                tempDir = tempfile.mkdtemp(prefix="sqlmapdb")
                            except IOError, _:
                                errMsg = "unable to write to the temporary directory ('%s'). " % _
                                errMsg += "Please make sure that your disk is not full and "
                                errMsg += "that you have sufficient write permissions to "
                                errMsg += "create temporary files and/or directories"
                                raise SqlmapSystemException(errMsg)

                            warnMsg = "unable to create dump directory "
                            warnMsg += "'%s' (%s). " % (dumpDbPath, getSafeExString(ex))
                            warnMsg += "Using temporary directory '%s' instead" % tempDir
                            logger.warn(warnMsg)

                            dumpDbPath = tempDir

            dumpFileName = os.path.join(dumpDbPath, "%s.%s" % (unsafeSQLIdentificatorNaming(table), conf.dumpFormat.lower()))
            if not checkFile(dumpFileName, False):
                try:
                    openFile(dumpFileName, "w+b").close()
                except SqlmapSystemException:
                    raise
                except:
                    warnFile = True

                    _ = re.sub(r"[^\w]", "_", normalizeUnicode(unsafeSQLIdentificatorNaming(table)))
                    if len(_) < len(table) or IS_WIN and table.upper() in WINDOWS_RESERVED_NAMES:
                        _ = unicodeencode(re.sub(r"[^\w]", "_", unsafeSQLIdentificatorNaming(table)))
                        dumpFileName = os.path.join(dumpDbPath, "%s-%s.%s" % (_, hashlib.md5(unicodeencode(table)).hexdigest()[:8], conf.dumpFormat.lower()))
                    else:
                        dumpFileName = os.path.join(dumpDbPath, "%s.%s" % (_, conf.dumpFormat.lower()))
            else:
                appendToFile = any((conf.limitStart, conf.limitStop))

                if not appendToFile:
                    count = 1
                    while True:
                        candidate = "%s.%d" % (dumpFileName, count)
                        if not checkFile(candidate, False):
                            try:
                                shutil.copyfile(dumpFileName, candidate)
                            except IOError:
                                pass
                            finally:
                                break
                        else:
                            count += 1

            dumpFP = openFile(dumpFileName, "wb" if not appendToFile else "ab", buffering=DUMP_FILE_BUFFER_SIZE)

        count = int(tableValues["__infos__"]["count"])
        separator = str()
        field = 1
        fields = len(tableValues) - 1

        columns = prioritySortColumns(tableValues.keys())

        if conf.col:
            cols = conf.col.split(',')
            columns = sorted(columns, key=lambda _: cols.index(_) if _ in cols else 0)

        for column in columns:
            if column != "__infos__":
                info = tableValues[column]
                lines = "-" * (int(info["length"]) + 2)
                separator += "+%s" % lines

        separator += "+"
        self._write("Database: %s\nTable: %s" % (unsafeSQLIdentificatorNaming(db) if db else "Current database", unsafeSQLIdentificatorNaming(table)))

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

                    cols.append((unsafeSQLIdentificatorNaming(column), colType if colType else Replication.TEXT))

            rtable = replication.createTable(table, cols)
        elif conf.dumpFormat == DUMP_FORMAT.HTML:
            dataToDumpFile(dumpFP, "<!DOCTYPE html>\n<html>\n<head>\n")
            dataToDumpFile(dumpFP, "<meta http-equiv=\"Content-type\" content=\"text/html;charset=%s\">\n" % UNICODE_ENCODING)
            dataToDumpFile(dumpFP, "<title>%s</title>\n" % ("%s%s" % ("%s." % db if METADB_SUFFIX not in db else "", table)))
            dataToDumpFile(dumpFP, HTML_DUMP_CSS_STYLE)
            dataToDumpFile(dumpFP, "\n</head>\n<body>\n<table>\n<thead>\n<tr>\n")

        if count == 1:
            self._write("[1 entry]")
        else:
            self._write("[%d entries]" % count)

        self._write(separator)

        for column in columns:
            if column != "__infos__":
                info = tableValues[column]

                column = unsafeSQLIdentificatorNaming(column)
                maxlength = int(info["length"])
                blank = " " * (maxlength - len(column))

                self._write("| %s%s" % (column, blank), newline=False)

                if not appendToFile:
                    if conf.dumpFormat == DUMP_FORMAT.CSV:
                        if field == fields:
                            dataToDumpFile(dumpFP, "%s" % safeCSValue(column))
                        else:
                            dataToDumpFile(dumpFP, "%s%s" % (safeCSValue(column), conf.csvDel))
                    elif conf.dumpFormat == DUMP_FORMAT.HTML:
                        dataToDumpFile(dumpFP, "<th>%s</th>" % cgi.escape(column).encode("ascii", "xmlcharrefreplace"))

                field += 1

        if conf.dumpFormat == DUMP_FORMAT.HTML:
            dataToDumpFile(dumpFP, "\n</tr>\n</thead>\n<tbody>\n")

        self._write("|\n%s" % separator)

        if conf.dumpFormat == DUMP_FORMAT.CSV:
            dataToDumpFile(dumpFP, "\n" if not appendToFile else "")

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
                dataToDumpFile(dumpFP, "<tr>")

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

                    if len(value) > MIN_BINARY_DISK_DUMP_SIZE and r'\x' in value:
                        try:
                            mimetype = magic.from_buffer(value, mime=True)
                            if any(mimetype.startswith(_) for _ in ("application", "image")):
                                if not os.path.isdir(dumpDbPath):
                                    os.makedirs(dumpDbPath, 0755)

                                _ = re.sub(r"[^\w]", "_", normalizeUnicode(unsafeSQLIdentificatorNaming(column)))
                                filepath = os.path.join(dumpDbPath, "%s-%d.bin" % (_, randomInt(8)))
                                warnMsg = "writing binary ('%s') content to file '%s' " % (mimetype, filepath)
                                logger.warn(warnMsg)

                                with open(filepath, "wb") as f:
                                    _ = safechardecode(value, True)
                                    f.write(_)
                        except magic.MagicException, err:
                            logger.debug(str(err))

                    if conf.dumpFormat == DUMP_FORMAT.CSV:
                        if field == fields:
                            dataToDumpFile(dumpFP, "%s" % safeCSValue(value))
                        else:
                            dataToDumpFile(dumpFP, "%s%s" % (safeCSValue(value), conf.csvDel))
                    elif conf.dumpFormat == DUMP_FORMAT.HTML:
                        dataToDumpFile(dumpFP, "<td>%s</td>" % cgi.escape(value).encode("ascii", "xmlcharrefreplace"))

                    field += 1

            if conf.dumpFormat == DUMP_FORMAT.SQLITE:
                try:
                    rtable.insert(values)
                except SqlmapValueException:
                    pass
            elif conf.dumpFormat == DUMP_FORMAT.CSV:
                dataToDumpFile(dumpFP, "\n")
            elif conf.dumpFormat == DUMP_FORMAT.HTML:
                dataToDumpFile(dumpFP, "</tr>\n")

            self._write("|", console=console)

        self._write("%s\n" % separator)

        if conf.dumpFormat == DUMP_FORMAT.SQLITE:
            rtable.endTransaction()
            logger.info("table '%s.%s' dumped to sqlite3 database '%s'" % (db, table, replication.dbpath))

        elif conf.dumpFormat in (DUMP_FORMAT.CSV, DUMP_FORMAT.HTML):
            if conf.dumpFormat == DUMP_FORMAT.HTML:
                dataToDumpFile(dumpFP, "</tbody>\n</table>\n</body>\n</html>")
            else:
                dataToDumpFile(dumpFP, "\n")
            dumpFP.close()

            msg = "table '%s.%s' dumped to %s file '%s'" % (db, table, conf.dumpFormat, dumpFileName)
            if not warnFile:
                logger.info(msg)
            else:
                logger.warn(msg)

    def dbColumns(self, dbColumnsDict, colConsider, dbs):
        if conf.api:
            self._write(dbColumnsDict, content_type=CONTENT_TYPE.COLUMNS)
            return

        for column in dbColumnsDict.keys():
            if colConsider == "1":
                colConsiderStr = "s LIKE '%s' were" % unsafeSQLIdentificatorNaming(column)
            else:
                colConsiderStr = " '%s' was" % unsafeSQLIdentificatorNaming(column)

            msg = "column%s found in the " % colConsiderStr
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
        self.string(query, queryRes, content_type=CONTENT_TYPE.SQL_QUERY)

    def rFile(self, fileData):
        self.lister("files saved to", fileData, sort=False, content_type=CONTENT_TYPE.FILE_READ)

    def registerValue(self, registerData):
        self.string("Registry key value data", registerData, content_type=CONTENT_TYPE.REG_READ, sort=False)

# object to manage how to print the retrieved queries output to
# standard output and sessions file
dumper = Dump()
