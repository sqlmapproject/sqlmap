#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

try:
    import pymysql
except ImportError, _:
    pass

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException

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
        except pymysql.OperationalError, msg:
            raise sqlmapConnectionException, msg[1]

        self.setCursor()
        self.connected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except pymysql.ProgrammingError, msg:
            logger.warn(msg[1])
            return None

    def execute(self, query):
        try:
            self.cursor.execute(query)
        except (pymysql.OperationalError, pymysql.ProgrammingError), msg:
            logger.warn(msg[1])
        except pymysql.InternalError, msg:
            raise sqlmapConnectionException, msg[1]

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
