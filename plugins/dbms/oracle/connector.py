#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

try:
    import oracledb
except ImportError:
    pass

import logging
import os

from lib.core.common import getSafeExString
from lib.core.convert import getText
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

os.environ["NLS_LANG"] = ".AL32UTF8"

class Connector(GenericConnector):
    """
    Homepage: https://oracle.github.io/python-oracledb/
    User: https://python-oracledb.readthedocs.io/en/latest/
    License: https://github.com/oracle/python-oracledb/blob/main/LICENSE.txt
    """

    def connect(self):
        self.initConnection()

        # Fetch CLOB/BLOB values directly as str/bytes instead of oracledb.LOB objects; otherwise a LOB cell
        # reached the renderer as the repr '<oracledb.LOB object at 0x...>' (BLOB bytes are then hex-encoded
        # by direct()'s binary handling).
        try:
            oracledb.defaults.fetch_lobs = False
        except AttributeError:
            pass

        self.user = getText(self.user)
        self.password = getText(self.password)

        try:
            dsn = oracledb.makedsn(self.hostname, self.port, service_name=self.db)
            self.connector = oracledb.connect(user=self.user, password=self.password, dsn=dsn, mode=oracledb.AUTH_MODE_SYSDBA)
            logger.info("successfully connected as SYSDBA")
        except oracledb.DatabaseError:
            # Try again without SYSDBA
            try:
                self.connector = oracledb.connect(user=self.user, password=self.password, dsn=dsn)
            except oracledb.DatabaseError as ex:
                raise SqlmapConnectionException(ex)

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except oracledb.InterfaceError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) '%s'" % getSafeExString(ex))
            return None

    def execute(self, query):
        retVal = False

        try:
            self.cursor.execute(getText(query))
            retVal = True
        except oracledb.DatabaseError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) '%s'" % getSafeExString(ex))

        self.connector.commit()
        return retVal

    def select(self, query):
        retVal = None

        if self.execute(query):
            retVal = self.fetchall()

        return retVal
