#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file doc/COPYING for copying permission.
"""

try:
    import kinterbasdb
except ImportError, _:
    pass

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException

from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://kinterbasdb.sourceforge.net/
    User guide: http://kinterbasdb.sourceforge.net/dist_docs/usage.html
    Debian package: python-kinterbasdb
    License: BSD
    """

    def __init__(self):
        GenericConnector.__init__(self)

    # sample usage:
    # ./sqlmap.py -d "firebird://sysdba:testpass@/opt/firebird/testdb.fdb"
    # ./sqlmap.py -d "firebird://sysdba:testpass@127.0.0.1:3050//opt/firebird/testdb.fdb"
    def connect(self):
        self.initConnection()

        if not self.hostname:
            self.checkFileDb()

        try:
            self.connector = kinterbasdb.connect(host=self.hostname.encode(conf.dataEncoding), database=self.db.encode(conf.dataEncoding), \
                user=self.user.encode(conf.dataEncoding), password=self.password.encode(conf.dataEncoding), charset="UTF8") #http://www.daniweb.com/forums/thread248499.html
        except kinterbasdb.OperationalError, msg:
            raise sqlmapConnectionException, msg[1]
        self.setCursor()
        self.connected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except kinterbasdb.OperationalError, msg:
            logger.log(8, msg[1])
            return None

    def execute(self, query):
        try:
            self.cursor.execute(query)
        except kinterbasdb.OperationalError, msg:
            logger.log(8, msg[1])
        except kinterbasdb.Error, msg:
            raise sqlmapConnectionException, msg[1]

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
