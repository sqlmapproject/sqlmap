#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (C) 2010  Miroslav Stampar, Bernardo Damele A. G.
email(s): miroslav.stampar@gmail.com, bernardo.damele@gmail.com

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
"""

import sqlite3

class Replication:
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
            self.name = name
            self.columns = columns
            if create:
                self.parent.cursor.execute('DROP TABLE IF EXISTS %s' % self.name)
                if not typeless:
                    self.parent.cursor.execute('CREATE TABLE %s (%s)' % (self.name, ','.join('%s %s' % (colname, coltype) for colname, coltype in self.columns)))
                else:
                    self.parent.cursor.execute('CREATE TABLE %s (%s)' % (self.name, ','.join(colname for colname in self.columns)))
            
        def insert(self, rows):
            """
            This function is used for inserting row(s) into current table.
            """
            self.parent.cursor.executemany('INSERT INTO %s VALUES (?,?,?,?,?)' % self.name, rows)

        def select(self, condition=None):
            """
            This function is used for selecting row(s) from current table.
            """        
            stmt = 'SELECT * FROM %s' % self.name
            if condition:
                stmt += 'WHERE %s' % condition
            return self.parent.cursor.execute(stmt)

    # sqlite data types
    NULL    = DataType('NULL')
    INTEGER = DataType('INTEGER')
    REAL    = DataType('REAL')
    TEXT    = DataType('TEXT')
    BLOB    = DataType('BLOB')
    
    def createTable(self, tblname, columns=None):
        """
        This function creates Table instance with current connection settings.
        """
        return Table(self, tblname, columns)
    
    def dropTable(self, tblname):
        """
        This function drops table with given name using current connection.
        """
        self.cursor.execute('DROP TABLE IF EXISTS %s' % tblname)
            
    def __del__(self):
        self.cursor.close()
        self.connection.close()
        