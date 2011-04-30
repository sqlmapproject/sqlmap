#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.convert import safechardecode
from lib.core.exception import sqlmapMissingDependence
from lib.core.exception import sqlmapValueException

class Replication:
    """
    This class holds all methods/classes used for database
    replication purposes.
    """

    def __init__(self, dbpath):
        try:
            import sqlite3
        except ImportError, _:
            errMsg = "missing module 'sqlite3' needed by --replicate switch"
            raise sqlmapMissingDependence, errMsg

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
            self.name = name
            self.columns = columns
            if create:
                self.parent.cursor.execute('DROP TABLE IF EXISTS %s' % self.name)
                if not typeless:
                    self.parent.cursor.execute('CREATE TABLE %s (%s)' % (self.name, ','.join('%s %s' % (colname, coltype) for colname, coltype in self.columns)))
                else:
                    self.parent.cursor.execute('CREATE TABLE %s (%s)' % (self.name, ','.join(colname for colname in self.columns)))

        def insert(self, values):
            """
            This function is used for inserting row(s) into current table.
            """

            if len(values) == len(self.columns):
                self.parent.cursor.execute('INSERT INTO %s VALUES (%s)' % (self.name, ','.join(['?']*len(values))), safechardecode(values))
            else:
                errMsg = "wrong number of columns used in replicating insert"
                raise sqlmapValueException, errMsg

        def beginTransaction(self):
            """
            Great speed improvement can be gained by using explicit transactions around multiple inserts.
            Reference: http://stackoverflow.com/questions/4719836/python-and-sqlite3-adding-thousands-of-rows
            """
            self.parent.cursor.execute('BEGIN TRANSACTION')

        def endTransaction(self):
            self.parent.cursor.execute('END TRANSACTION')

        def select(self, condition=None):
            """
            This function is used for selecting row(s) from current table.
            """
            stmt = 'SELECT * FROM %s' % self.name
            if condition:
                stmt += 'WHERE %s' % condition
            return self.parent.cursor.execute(stmt)

    def createTable(self, tblname, columns=None, typeless=False):
        """
        This function creates Table instance with current connection settings.
        """
        return Replication.Table(parent=self, name=tblname, columns=columns, typeless=typeless)

    def dropTable(self, tblname):
        """
        This function drops table with given name using current connection.
        """
        self.cursor.execute('DROP TABLE IF EXISTS %s' % tblname)

    def __del__(self):
        self.cursor.close()
        self.connection.close()

    # sqlite data types
    NULL = DataType('NULL')
    INTEGER = DataType('INTEGER')
    REAL = DataType('REAL')
    TEXT = DataType('TEXT')
    BLOB = DataType('BLOB')
