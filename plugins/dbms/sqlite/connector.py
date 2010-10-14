#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

try:
    import sqlite3
except ImportError, _:
    pass

from lib.core.convert import utf8encode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException

from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://pysqlite.googlecode.com/
    User guide: http://docs.python.org/release/2.5/lib/module-sqlite3.html
    API: http://docs.python.org/library/sqlite3.html
    Debian package: python-pysqlite2
    License: MIT

    Possible connectors: http://wiki.python.org/moin/SQLite
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        self.initConnection()
        self.checkFileDb()

        try:
            self.connector = sqlite3.connect(database=self.db, check_same_thread=False, timeout=conf.timeout)
        except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
            raise sqlmapConnectionException, msg[0]

        self.setCursor()
        self.connected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except sqlite3.OperationalError, msg:
            logger.log(8, msg[0])
            return None

    def execute(self, query):
        try:
            import pdb
            pdb.set_trace()
            self.cursor.execute(utf8encode(query))
        except sqlite3.OperationalError, msg:
            logger.log(8, msg[0])
        except sqlite3.DatabaseError, msg:
            raise sqlmapConnectionException, msg[0]

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
