#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

try:
    import _mssql
    import pymssql
except:
    pass

import logging

from lib.core.convert import utf8encode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://www.pymssql.org/en/stable/
    User guide: http://www.pymssql.org/en/stable/pymssql_examples.html
    API: http://www.pymssql.org/en/stable/ref/pymssql.html
    Debian package: python-pymssql
    License: LGPL

    Possible connectors: http://wiki.python.org/moin/SQL%20Server

    Important note: pymssql library on your system MUST be version 1.0.2
    to work, get it from http://sourceforge.net/projects/pymssql/files/pymssql/1.0.2/
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        self.initConnection()

        try:
            self.connector = pymssql.connect(host="%s:%d" % (self.hostname, self.port), user=self.user, password=self.password, database=self.db, login_timeout=conf.timeout, timeout=conf.timeout)
        except (pymssql2.Error, _mssql.MssqlDatabaseException), msg:
            raise SqlmapConnectionException(msg)
        except ValueError:
            raise SqlmapConnectionException

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except (pymssql.Error, _mssql.MssqlDatabaseException), msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % str(msg).replace("\n", " "))
            return None

    def execute(self, query):
        retVal = False

        try:
            self.cursor.execute(utf8encode(query))
            retVal = True
        except (pymssql.OperationalError, pymssql.ProgrammingError), msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % str(msg).replace("\n", " "))
        except pymssql.InternalError, msg:
            raise SqlmapConnectionException(msg)

        return retVal

    def select(self, query):
        retVal = None

        if self.execute(query):
            retVal = self.fetchall()

            try:
                self.connector.commit()
            except pymssql.OperationalError:
                pass

        return retVal
