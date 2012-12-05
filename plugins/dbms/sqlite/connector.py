#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

try:
    import sqlite3
except ImportError:
    pass

import logging

from lib.core.convert import utf8encode
from lib.core.data import conf, logger
from lib.core.exception import sqlmapConnectionException, sqlmapMissingDependence
from plugins.generic.connector import Connector as GenericConnector


class Connector(GenericConnector):
    """
    Homepage: http://pysqlite.googlecode.com/
    User guide: http://docs.python.org/release/2.5/lib/module-sqlite3.html
    API: http://docs.python.org/library/sqlite3.html
    Debian package: python-pysqlite2 (SQLite 2), python-pysqlite3 (SQLite 3)
    License: MIT

    Possible connectors: http://wiki.python.org/moin/SQLite
    """

    def __init__(self):
        GenericConnector.__init__(self)
        self.__sqlite = sqlite3

    def connect(self):
        self.initConnection()
        self.checkFileDb()

        try:
            self.connector = self.__sqlite.connect(database=self.db, check_same_thread=False, timeout=conf.timeout)

            cursor = self.connector.cursor()
            cursor.execute("SELECT * FROM sqlite_master")
            cursor.close()

        except (self.__sqlite.DatabaseError, self.__sqlite.OperationalError), msg:
            warnMsg = "unable to connect using SQLite 3 library, trying with SQLite 2"
            logger.warn(warnMsg)

            try:
                try:
                    import sqlite
                except ImportError, _:
                    errMsg = "sqlmap requires 'python-sqlite2' third-party library "
                    errMsg += "in order to directly connect to the database '%s'" % self.db
                    raise sqlmapMissingDependence, errMsg

                self.__sqlite = sqlite
                self.connector = self.__sqlite.connect(database=self.db, check_same_thread=False, timeout=conf.timeout)
            except (self.__sqlite.DatabaseError, self.__sqlite.OperationalError), msg:
                raise sqlmapConnectionException, msg[0]

        self.setCursor()
        self.connected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except self.__sqlite.OperationalError, msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg[0])
            return None

    def execute(self, query):
        try:
            self.cursor.execute(utf8encode(query))
        except self.__sqlite.OperationalError, msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg[0])
        except self.__sqlite.DatabaseError, msg:
            raise sqlmapConnectionException, msg[0]

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
