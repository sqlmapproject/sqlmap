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
    def __init__(self, dbpath):
        self.dbpath = dbpath
        self.connection = sqlite3.connect(dbpath)
        self.connection.isolation_level = None
        self.cursor = self.connection.cursor()
        
    class DataType:
        def __init__(self, name):
            self.name = name

        def __str__(self):
            return self.name

        def __repr__(self):
            return "<DataType: %s>" % self
       
    class Table:
        def __init__(self, parent, name, columns, typeless=False):
            self.parent = parent
            self.name = name
            self.columns = columns
            if not typeless:
                self.parent.cursor.execute('CREATE TABLE %s (%s)' % (name, ','.join('%s %s' % (colname, coltype) for colname, coltype in columns)))
            else:
                self.parent.cursor.execute('CREATE TABLE %s (%s)' % (name, ','.join(colname for colname in columns)))
            
        def insert(self, rows):
            self.parent.cursor.executemany('INSERT INTO %s VALUES (?,?,?,?,?)' % self.name, rows)


    NULL = DataType('NULL')
    INTEGER = DataType('INTEGER')
    REAL = DataType('REAL')
    TEXT = DataType('TEXT')
    BLOB = DataType('BLOB')
    
    def createTable(self, name, columns):
        return Table(self, name, columns)
    
    def __del__(self):
        self.cursor.close()
        self.connection.close()
        