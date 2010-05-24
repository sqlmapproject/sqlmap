#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

import codecs
import re
import os

from lib.core.common import dataToDumpFile
from lib.core.data import conf
from lib.core.data import logger

class Dump:
    """
    This class defines methods used to parse and output the results
    of SQL injection actions

    """

    def __init__(self):
        self.__outputFile = None
        self.__outputFP   = None
        
    def __write(self, data, n=True):
        if n:
            print data
            self.__outputFP.write("%s\n" % data)
        else:
            print data,
            self.__outputFP.write("%s " % data)

        self.__outputFP.flush()

        conf.loggedToOut = True
        
    def setOutputFile(self):
        self.__outputFile = "%s%slog" % (conf.outputPath, os.sep)
        self.__outputFP = codecs.open(self.__outputFile, "a", "utf-8")
        
    def string(self, header, data, sort=True):
        if isinstance(data, (list, tuple, set)):
            self.lister(header, data, sort)

            return

        data = str(data)

        if data:
            data = data.replace("__NEWLINE__", "\n").replace("__TAB__", "\t")
            data = data.replace("__START__", "").replace("__STOP__", "")
            data = data.replace("__DEL__", ", ")

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
            if isinstance(element, str):
                self.__write("[*] %s" % element)
            elif isinstance(element, (list, tuple, set)):
                self.__write("[*] " + ", ".join(str(e) for e in element))

        if elements:
            self.__write("")
            
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

            if user in self.__areAdmins:
                self.__write("[*] %s (administrator) [%d]:" % (user, len(settings)))
            else:
                self.__write("[*] %s [%d]:" % (user, len(settings)))

            settings.sort()

            for setting in settings:
                self.__write("    %s: %s" % (subHeader, setting))
        print

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

    def dbTables(self, dbTables):
        if not isinstance(dbTables, dict):
            self.string("tables", dbTables)

            return

        maxlength = 0

        for tables in dbTables.values():
            for table in tables:
                maxlength = max(maxlength, len(table))

        lines = "-" * (int(maxlength) + 2)

        for db, tables in dbTables.items():
            tables.sort(key=lambda x: x.lower())

            self.__write("Database: %s" % db)

            if len(tables) == 1:
                self.__write("[1 table]")
            else:
                self.__write("[%d tables]" % len(tables))

            self.__write("+%s+" % lines)

            for table in tables:
                blank = " " * (maxlength - len(table))
                self.__write("| %s%s |" % (table, blank))

            self.__write("+%s+\n" % lines)

    def dbTableColumns(self, tableColumns):
        for db, tables in tableColumns.items():
            if not db:
                db = "All"

            for table, columns in tables.items():
                maxlength1 = 0
                maxlength2 = 0

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
        if tableValues is None:
            return

        db = tableValues["__infos__"]["db"]
        if not db:
            db = "All"
        table = tableValues["__infos__"]["table"]

        if not conf.multipleTargets:
            dumpDbPath = "%s%s%s" % (conf.dumpPath, os.sep, db)

            if not os.path.isdir(dumpDbPath):
                os.makedirs(dumpDbPath, 0755)

            dumpFileName = "%s%s%s.csv" % (dumpDbPath, os.sep, table)
            dumpFP = codecs.open(dumpFileName, "w", "utf-8")

        count     = int(tableValues["__infos__"]["count"])
        separator = ""
        field     = 1
        fields    = len(tableValues) - 1

        columns = tableValues.keys()
        columns.sort(key=lambda x: x.lower())

        for column in columns:
            if column != "__infos__":
                info       = tableValues[column]
                lines      = "-" * (int(info["length"]) + 2)
                separator += "+%s" % lines

        separator += "+"
        self.__write("Database: %s\nTable: %s" % (db, table))

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

                if not conf.multipleTargets and field == fields:
                    dataToDumpFile(dumpFP, "%s" % column)
                elif not conf.multipleTargets:
                    dataToDumpFile(dumpFP, "%s," % column)

                field += 1

        self.__write("|\n%s" % separator)

        if not conf.multipleTargets:
            dataToDumpFile(dumpFP, "\n")

        for i in range(count):
            field = 1

            for column in columns:
                if column != "__infos__":
                    info = tableValues[column]

                    value = unicode(info["values"][i]) if type(info["values"][i]) != unicode else info["values"][i]

                    if re.search("^[\ *]*$", value):
                        value = "NULL"

                    maxlength = int(info["length"])
                    blank = " " * (maxlength - len(value))
                    self.__write("| %s%s" % (value, blank), n=False)

                    if not conf.multipleTargets and field == fields:
                        dataToDumpFile(dumpFP, "\"%s\"" % value)
                    elif not conf.multipleTargets:
                        dataToDumpFile(dumpFP, "\"%s\"," % value)

                    field += 1

            self.__write("|")

            if not conf.multipleTargets:
                dataToDumpFile(dumpFP, "\n")

        self.__write("%s\n" % separator)

        if not conf.multipleTargets:
            dataToDumpFile(dumpFP, "\n")
            dumpFP.close()

            logger.info("Table '%s.%s' dumped to CSV file '%s'" % (db, table, dumpFileName))

# object to manage how to print the retrieved queries output to
# standard output and sessions file
dumper = Dump()
