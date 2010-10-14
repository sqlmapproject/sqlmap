#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file doc/COPYING for copying permission.
"""

try:
    import MySQLdb
except ImportError, _:
    pass

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException

from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://mysql-python.sourceforge.net/
    User guide: http://mysql-python.sourceforge.net/MySQLdb.html
    API: http://mysql-python.sourceforge.net/MySQLdb-1.2.2/
    Debian package: python-mysqldb
    License: GPL

    Possible connectors: http://wiki.python.org/moin/MySQL
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        self.initConnection()

        try:
            self.connector = MySQLdb.connect(host=self.hostname, user=self.user, passwd=self.password, db=self.db, port=self.port, connect_timeout=conf.timeout, use_unicode=True)
        except MySQLdb.OperationalError, msg:
            raise sqlmapConnectionException, msg[1]

        self.setCursor()
        self.connected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except MySQLdb.ProgrammingError, msg:
            logger.log(8, msg[1])
            return None

    def execute(self, query):
        try:
            self.cursor.execute(query)
        except (MySQLdb.OperationalError, MySQLdb.ProgrammingError), msg:
            logger.log(8, msg[1])
        except MySQLdb.InternalError, msg:
            raise sqlmapConnectionException, msg[1]

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
