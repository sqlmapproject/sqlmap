#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

try:
    import pyodbc
except:
    pass

import logging

from lib.core.common import getSafeExString
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.settings import IS_WIN
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: https://github.com/mkleehammer/pyodbc
    User guide: https://github.com/mkleehammer/pyodbc/wiki
    Debian package: python-pyodbc
    License: MIT
    """

    def connect(self):
        if not IS_WIN:
            errMsg = "currently, direct connection to Microsoft Access database(s) "
            errMsg += "is restricted to Windows platforms"
            raise SqlmapUnsupportedFeatureException(errMsg)

        self.initConnection()
        self.checkFileDb()

        try:
            self.connector = pyodbc.connect('Driver={Microsoft Access Driver (*.mdb)};Dbq=%s;Uid=Admin;Pwd=;' % self.db)
        except (pyodbc.Error, pyodbc.OperationalError) as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except pyodbc.ProgrammingError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
            return None

    def execute(self, query):
        try:
            self.cursor.execute(query)
        except (pyodbc.OperationalError, pyodbc.ProgrammingError) as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
        except pyodbc.Error as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
