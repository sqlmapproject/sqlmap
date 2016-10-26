#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

try:
    import pymysql
except ImportError:
    pass

import logging
import struct

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://code.google.com/p/pymysql/
    User guide: http://code.google.com/p/pymysql/
    API: http://code.google.com/p/pymysql/
    Debian package: <none>
    License: MIT

    Possible connectors: http://wiki.python.org/moin/MySQL
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        self.initConnection()

        try:
            self.connector = pymysql.connect(host=self.hostname, user=self.user, passwd=self.password, db=self.db, port=self.port, connect_timeout=conf.timeout, use_unicode=True)
        except (pymysql.OperationalError, pymysql.InternalError, struct.error), msg:
            raise SqlmapConnectionException(msg[1])

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except pymysql.ProgrammingError, msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg[1])
            return None

    def execute(self, query):
        retVal = False

        try:
            self.cursor.execute(query)
            retVal = True
        except (pymysql.OperationalError, pymysql.ProgrammingError), msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg[1])
        except pymysql.InternalError, msg:
            raise SqlmapConnectionException(msg[1])

        self.connector.commit()

        return retVal

    def select(self, query):
        retVal = None

        if self.execute(query):
            retVal = self.fetchall()

        return retVal
