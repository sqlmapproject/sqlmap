#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import sqlite3

from extra.safe2bin.safe2bin import safechardecode
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapValueException

class Replication(object):
    """
    This class holds all methods/classes used for database
    replication purposes.
    """

    def __init__(self, dbpath):
        self.dbpath = dbpath
        self.connection = sqlite3.connect(dbpath)
        self.connection.isolation_level = None
        self.cursor = self.connection.cursor()

    class DataType:
        """
        Using this class we define auxiliary objects
        used for representing sqlite data types.
        """

        def __init__(self, name):
            self.name = name

        def __str__(self):
            return self.name

        def __repr__(self):
            return "<DataType: %s>" % self

    class Table:
        """
        This class defines methods used to manipulate table objects.
        """

        def __init__(self, parent, name, columns=None, create=True, typeless=False):
            self.parent = parent
            self.name = unsafeSQLIdentificatorNaming(name)
            self.columns = columns
            if create:
                self.execute('DROP TABLE IF EXISTS "%s"' % self.name)
                if not typeless:
                    self.execute('CREATE TABLE "%s" (%s)' % (self.name, ','.join('"%s" %s' % (unsafeSQLIdentificatorNaming(colname), coltype) for colname, coltype in self.columns)))
                else:
                    self.execute('CREATE TABLE "%s" (%s)' % (self.name, ','.join('"%s"' % unsafeSQLIdentificatorNaming(colname) for colname in self.columns)))

        def insert(self, values):
            """
            This function is used for inserting row(s) into current table.
            """

            if len(values) == len(self.columns):
                self.execute('INSERT INTO "%s" VALUES (%s)' % (self.name, ','.join(['?'] * len(values))), safechardecode(values))
            else:
                errMsg = "wrong number of columns used in replicating insert"
                raise SqlmapValueException(errMsg)

        def execute(self, sql, parameters=[]):
            try:
                self.parent.cursor.execute(sql, parameters)
            except sqlite3.OperationalError, ex:
                errMsg = "problem occurred ('%s') while accessing sqlite database " % ex
                errMsg += "located at '%s'. Please make sure that " % self.parent.dbpath
                errMsg += "it's not used by some other program"
                raise SqlmapGenericException(errMsg)

        def beginTransaction(self):
            """
            Great speed improvement can be gained by using explicit transactions around multiple inserts.
            Reference: http://stackoverflow.com/questions/4719836/python-and-sqlite3-adding-thousands-of-rows
            """
            self.execute('BEGIN TRANSACTION')

        def endTransaction(self):
            self.execute('END TRANSACTION')

        def select(self, condition=None):
            """
            This function is used for selecting row(s) from current table.
            """
            _ = 'SELECT * FROM %s' % self.name
            if condition:
                _ += 'WHERE %s' % condition
            return self.execute(_)

    def createTable(self, tblname, columns=None, typeless=False):
        """
        This function creates Table instance with current connection settings.
        """
        return Replication.Table(parent=self, name=tblname, columns=columns, typeless=typeless)

    def __del__(self):
        self.cursor.close()
        self.connection.close()

    # sqlite data types
    NULL = DataType('NULL')
    INTEGER = DataType('INTEGER')
    REAL = DataType('REAL')
    TEXT = DataType('TEXT')
    BLOB = DataType('BLOB')
