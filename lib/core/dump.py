#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import re
import os

from lib.core.common import dataToDumpFile
from lib.core.common import dataToStdout
from lib.core.common import getUnicode
from lib.core.common import openFile
from lib.core.common import restoreDumpMarkedChars
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.replication import Replication
from lib.core.settings import UNICODE_ENCODING

class Dump:
    """
    This class defines methods used to parse and output the results
    of SQL injection actions

    """

    def __init__(self):
        self.__outputFile = None
        self.__outputFP   = None

    def __write(self, data, n=True):
        text = "%s%s" % (data, "\n" if n else " ")
        dataToStdout(text)

        self.__outputFP.write(text)
        self.__outputFP.flush()

        conf.loggedToOut = True

    def __formatString(self, inpStr):
        return restoreDumpMarkedChars(getUnicode(inpStr))

    def setOutputFile(self):
        self.__outputFile = "%s%slog" % (conf.outputPath, os.sep)
        self.__outputFP = codecs.open(self.__outputFile, "ab", UNICODE_ENCODING)

    def getOutputFile(self):
        return self.__outputFile

    def string(self, header, data, sort=True):
        if isinstance(data, (list, tuple, set)):
            self.lister(header, data, sort)

            return

        data = getUnicode(data)

        if data:
            data = self.__formatString(data)

            if "\n" in data:
                self.__write("%s:\n---\n%s\n---\n" % (header, data))
            else:
                self.__write("%s:    '%s'\n" % (header, data))
        else:
            self.__write("%s:\tNone\n" % header)

    def lister(self, header, elements, sort=True):
        if elements:
            self.__write("%s [%d]:" % (header, len(elements)))

        if sort:
            try:
                elements = set(elements)
                elements = list(elements)
                elements.sort(key=lambda x: x.lower())
            except:
                pass

        for element in elements:
            if isinstance(element, basestring):
                self.__write("[*] %s" % element)
            elif isinstance(element, (list, tuple, set)):
                self.__write("[*] " + ", ".join(getUnicode(e) for e in element))

        if elements:
            self.__write("")

    def technic(self, header, data):
        self.string(header, data)

    def banner(self,data):
        self.string("banner", data)

    def currentUser(self,data):
        self.string("current user", data)

    def currentDb(self,data):
        self.string("current database", data)

    def dba(self,data):
        self.string("current user is DBA", data)

    def users(self,users):
        self.lister("database management system users", users)

    def userSettings(self, header, userSettings, subHeader):
        self.__areAdmins = set()

        if userSettings:
            self.__write("%s:" % header)

        if isinstance(userSettings, (tuple, list, set)):
            self.__areAdmins = userSettings[1]
            userSettings = userSettings[0]

        users = userSettings.keys()
        users.sort(key=lambda x: x.lower())

        for user in users:
            settings = userSettings[user]

            if settings is None:
                stringSettings = ""
            else:
                stringSettings = " [%d]:" % len(settings)

            if user in self.__areAdmins:
                self.__write("[*] %s (administrator)%s" % (user, stringSettings))
            else:
                self.__write("[*] %s%s" % (user, stringSettings))

            if settings:
                settings.sort()

                for setting in settings:
                    self.__write("    %s: %s" % (subHeader, setting))
        print

    def dbs(self,dbs):
        self.lister("available databases", dbs)

    def dbTables(self, dbTables):
        if isinstance(dbTables, dict) and len(dbTables) > 0:
            maxlength = 0

            for tables in dbTables.values():
                for table in tables:
                    if isinstance(table, (list, tuple, set)):
                        table = table[0]

                    maxlength = max(maxlength, len(str(table)))

            lines = "-" * (int(maxlength) + 2)

            for db, tables in dbTables.items():
                tables.sort()

                self.__write("Database: %s" % db)

                if len(tables) == 1:
                    self.__write("[1 table]")
                else:
                    self.__write("[%d tables]" % len(tables))

                self.__write("+%s+" % lines)

                for table in tables:
                    if isinstance(table, (list, tuple, set)):
                        table = table[0]

                    blank = " " * (maxlength - len(str(table)))
                    self.__write("| %s%s |" % (table, blank))

                self.__write("+%s+\n" % lines)
        else:
            self.string("tables", dbTables)

    def dbTableColumns(self, tableColumns):
        for db, tables in tableColumns.items():
            if not db:
                db = "All"

            for table, columns in tables.items():
                maxlength1 = 0
                maxlength2 = 0

                colType = None

                colList = columns.keys()
                colList.sort(key=lambda x: x.lower())

                for column in colList:
                    colType = columns[column]
                    maxlength1 = max(maxlength1, len(column))

                    if colType is not None:
                        maxlength2 = max(maxlength2, len(colType))

                maxlength1 = max(maxlength1, len("COLUMN"))
                lines1 = "-" * (int(maxlength1) + 2)

                if colType is not None:
                    maxlength2 = max(maxlength2, len("TYPE"))
                    lines2 = "-" * (int(maxlength2) + 2)

                self.__write("Database: %s\nTable: %s" % (db, table))

                if len(columns) == 1:
                    self.__write("[1 column]")
                else:
                    self.__write("[%d columns]" % len(columns))

                if colType is not None:
                    self.__write("+%s+%s+" % (lines1, lines2))
                else:
                    self.__write("+%s+" % lines1)

                blank1 = " " * (maxlength1 - len("COLUMN"))

                if colType is not None:
                    blank2 = " " * (maxlength2 - len("TYPE"))

                if colType is not None:
                    self.__write("| Column%s | Type%s |" % (blank1, blank2))
                    self.__write("+%s+%s+" % (lines1, lines2))
                else:
                    self.__write("| Column%s |" % blank1)
                    self.__write("+%s+" % lines1)

                for column in colList:
                    colType = columns[column]
                    blank1 = " " * (maxlength1 - len(column))

                    if colType is not None:
                        blank2 = " " * (maxlength2 - len(colType))
                        self.__write("| %s%s | %s%s |" % (column, blank1, colType, blank2))
                    else:
                        self.__write("| %s%s |" % (column, blank1))

                if colType is not None:
                    self.__write("+%s+%s+\n" % (lines1, lines2))
                else:
                    self.__write("+%s+\n" % lines1)

    def dbTableValues(self, tableValues):
        replication = None
        rtable      = None

        if tableValues is None:
            return

        db = tableValues["__infos__"]["db"]
        if not db:
            db = "All"
        table = tableValues["__infos__"]["table"]

        if conf.replicate:
            replication = Replication("%s%s%s.sqlite3" % (conf.dumpPath, os.sep, db))
        elif not conf.multipleTargets:
            dumpDbPath = "%s%s%s" % (conf.dumpPath, os.sep, db)

            if not os.path.isdir(dumpDbPath):
                os.makedirs(dumpDbPath, 0755)

            dumpFileName = "%s%s%s.csv" % (dumpDbPath, os.sep, table)
            dumpFP = openFile(dumpFileName, "wb")

        count       = int(tableValues["__infos__"]["count"])
        separator   = str()
        field       = 1
        fields      = len(tableValues) - 1

        columns = tableValues.keys()
        columns.sort(key=lambda x: x.lower())

        for column in columns:
            if column != "__infos__":
                info       = tableValues[column]
                lines      = "-" * (int(info["length"]) + 2)
                separator += "+%s" % lines

        separator += "+"
        self.__write("Database: %s\nTable: %s" % (db, table))

        if conf.replicate:
            cols = []

            for column in columns:
                if column != "__infos__":
                    colType = Replication.INTEGER

                    for value in tableValues[column]['values']:
                        try:
                            if re.search("^[\ *]*$", value): #NULL
                                continue

                            _ = int(value)
                        except ValueError:
                            colType = None
                            break

                    if colType is None:
                        colType = Replication.REAL

                        for value in tableValues[column]['values']:
                            try:
                                if re.search("^[\ *]*$", value): #NULL
                                    continue

                                _ = float(value)
                            except ValueError:
                                colType = None
                                break

                    cols.append((column, colType if colType else Replication.TEXT))

            rtable = replication.createTable(table, cols)

        if count == 1:
            self.__write("[1 entry]")
        else:
            self.__write("[%d entries]" % count)

        self.__write(separator)

        for column in columns:
            if column != "__infos__":
                info      = tableValues[column]
                maxlength = int(info["length"])
                blank     = " " * (maxlength - len(column))

                self.__write("| %s%s" % (column, blank), n=False)

                if not conf.replicate:
                    if not conf.multipleTargets and field == fields:
                        dataToDumpFile(dumpFP, "%s" % column)
                    elif not conf.multipleTargets:
                        dataToDumpFile(dumpFP, "%s," % column)

                field += 1

        self.__write("|\n%s" % separator)

        if not conf.multipleTargets and not conf.replicate:
            dataToDumpFile(dumpFP, "\n")

        for i in range(count):
            field = 1
            values = []

            for column in columns:
                if column != "__infos__":
                    info = tableValues[column]

                    if len(info["values"]) <= i:
                        continue

                    value = getUnicode(info["values"][i])

                    if re.search("^[\ *]*$", value):
                        value = "NULL"

                    values.append(value)
                    maxlength = int(info["length"])
                    blank = " " * (maxlength - len(value))
                    self.__write("| %s%s" % (value, blank), n=False)

                    if not conf.replicate:
                        if not conf.multipleTargets and field == fields:
                            dataToDumpFile(dumpFP, "\"%s\"" % value)
                        elif not conf.multipleTargets:
                            dataToDumpFile(dumpFP, "\"%s\"," % value)

                    field += 1

            if conf.replicate:
                rtable.insert(values)

            self.__write("|")

            if not conf.multipleTargets and not conf.replicate:
                dataToDumpFile(dumpFP, "\n")

        self.__write("%s\n" % separator)

        if conf.replicate:
            logger.info("Table '%s.%s' dumped to sqlite3 file '%s'" % (db, table, replication.dbpath))
        elif not conf.multipleTargets:
            dataToDumpFile(dumpFP, "\n")
            dumpFP.close()

            logger.info("Table '%s.%s' dumped to CSV file '%s'" % (db, table, dumpFileName))

    def dbColumns(self, dbColumns, colConsider, dbs):
        for column in dbColumns.keys():
            if colConsider == "1":
                colConsiderStr = "s like '" + column + "' were"
            else:
                colConsiderStr = " '%s' was" % column

            msg  = "Column%s found in the " % colConsiderStr
            msg += "following databases:"
            self.__write(msg)

            printDbs = {}

            for db, tblData in dbs.items():
                for tbl, colData in tblData.items():
                    for col, dataType in colData.items():
                        if column.lower() in col.lower():
                            if db in printDbs:
                                if tbl in printDbs[db]:
                                    printDbs[db][tbl][col] = dataType
                                else:
                                    printDbs[db][tbl] = { col: dataType }
                            else:
                                printDbs[db] = {}
                                printDbs[db][tbl] = { col: dataType }

                            continue

            self.dbTableColumns(printDbs)

    def query(self, query, queryRes):
        self.string(query, queryRes)

    def rFile(self,filePath,fileData):
        self.string("%s file saved to" % filePath,fileData,sort=False) 

    def registerValue(self,registerData):
        self.string("Registry key value data", registerData,sort=False)

# object to manage how to print the retrieved queries output to
# standard output and sessions file
dumper = Dump()
