#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

try:
    import kinterbasdb
except:
    pass

import logging

from lib.core.common import getSafeExString
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from lib.core.settings import UNICODE_ENCODING
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://kinterbasdb.sourceforge.net/
    User guide: http://kinterbasdb.sourceforge.net/dist_docs/usage.html
    Debian package: python-kinterbasdb
    License: BSD
    """

    # sample usage:
    # ./sqlmap.py -d "firebird://sysdba:testpass@/opt/firebird/testdb.fdb"
    # ./sqlmap.py -d "firebird://sysdba:testpass@127.0.0.1:3050//opt/firebird/testdb.fdb"
    def connect(self):
        self.initConnection()

        if not self.hostname:
            self.checkFileDb()

        try:
            # Reference: http://www.daniweb.com/forums/thread248499.html
            self.connector = kinterbasdb.connect(host=self.hostname.encode(UNICODE_ENCODING), database=self.db.encode(UNICODE_ENCODING), user=self.user.encode(UNICODE_ENCODING), password=self.password.encode(UNICODE_ENCODING), charset="UTF8")
        except kinterbasdb.OperationalError as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except kinterbasdb.OperationalError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
            return None

    def execute(self, query):
        try:
            self.cursor.execute(query)
        except kinterbasdb.OperationalError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
        except kinterbasdb.Error as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
