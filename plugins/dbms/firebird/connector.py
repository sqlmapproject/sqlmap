#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

try:
    import firebirdsql
except:
    pass

import logging

from lib.core.common import getSafeExString
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: https://github.com/nakagami/pyfirebirdsql
    User guide: https://pyfirebirdsql.readthedocs.io/
    Debian package: python3-firebirdsql
    License: BSD

    Note: ported from the (Python 2-only, unmaintained) kinterbasdb driver to firebirdsql
    """

    # sample usage:
    # ./sqlmap.py -d "firebird://sysdba:testpass@/opt/firebird/testdb.fdb"
    # ./sqlmap.py -d "firebird://sysdba:testpass@127.0.0.1:3050//opt/firebird/testdb.fdb"
    def connect(self):
        self.initConnection()

        if not self.hostname:
            self.checkFileDb()

        try:
            self.connector = firebirdsql.connect(host=self.hostname, database=self.db, port=self.port or 3050, user=self.user, password=self.password, charset="UTF8")
        except firebirdsql.OperationalError as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except firebirdsql.OperationalError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
            return None

    def execute(self, query, commit=True):
        try:
            self.cursor.execute(query)
        except firebirdsql.OperationalError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
        except firebirdsql.Error as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        # commit non-SELECT (DML) here; select() commits only AFTER fetchall() because a Firebird COMMIT closes
        # open cursors (discarding an unfetched result set)
        if commit:
            self.connector.commit()

    def select(self, query):
        self.execute(query, commit=False)
        retVal = self.fetchall()
        self.connector.commit()
        return retVal
