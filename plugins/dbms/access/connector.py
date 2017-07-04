#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

try:
    import pyodbc
except ImportError:
    pass

import logging

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.settings import IS_WIN
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://pyodbc.googlecode.com/
    User guide: http://code.google.com/p/pyodbc/wiki/GettingStarted
    API: http://code.google.com/p/pyodbc/w/list
    Debian package: python-pyodbc
    License: MIT
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        if not IS_WIN:
            errMsg = "currently, direct connection to Microsoft Access database(s) "
            errMsg += "is restricted to Windows platforms"
            raise SqlmapUnsupportedFeatureException(errMsg)

        self.initConnection()
        self.checkFileDb()

        try:
            self.connector = pyodbc.connect('Driver={Microsoft Access Driver (*.mdb)};Dbq=%s;Uid=Admin;Pwd=;' % self.db)
        except (pyodbc.Error, pyodbc.OperationalError), msg:
            raise SqlmapConnectionException(msg[1])

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except pyodbc.ProgrammingError, msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg[1])
            return None

    def execute(self, query):
        try:
            self.cursor.execute(query)
        except (pyodbc.OperationalError, pyodbc.ProgrammingError), msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg[1])
        except pyodbc.Error, msg:
            raise SqlmapConnectionException(msg[1])

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
