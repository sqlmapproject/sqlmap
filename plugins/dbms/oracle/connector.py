#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

try:
    import cx_Oracle
except ImportError, _:
    pass

import logging
import os

from lib.core.convert import utf8encode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

os.environ["NLS_LANG"] = ".AL32UTF8"

class Connector(GenericConnector):
    """
    Homepage: http://cx-oracle.sourceforge.net/
    User guide: http://cx-oracle.sourceforge.net/README.txt
    API: http://cx-oracle.sourceforge.net/html/index.html
    License: http://cx-oracle.sourceforge.net/LICENSE.txt
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        self.initConnection()
        self.__dsn = cx_Oracle.makedsn(self.hostname, self.port, self.db)
        self.__dsn = utf8encode(self.__dsn)
        self.user = utf8encode(self.user)
        self.password = utf8encode(self.password)

        try:
            self.connector = cx_Oracle.connect(dsn=self.__dsn, user=self.user, password=self.password,
                mode=cx_Oracle.SYSDBA)
            logger.info("successfully connected as SYSDBA")
        except (cx_Oracle.OperationalError, cx_Oracle.DatabaseError), _:
            try:
                self.connector = cx_Oracle.connect(dsn=self.__dsn, user=self.user, password=self.password)
            except (cx_Oracle.OperationalError, cx_Oracle.DatabaseError), msg:
                raise sqlmapConnectionException, msg

        self.setCursor()
        self.connected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except cx_Oracle.InterfaceError, msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg)
            return None

    def execute(self, query):
        retVal = False

        try:
            self.cursor.execute(utf8encode(query))
            retVal = True
        except (cx_Oracle.DatabaseError), msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg)
        except cx_Oracle.InternalError, msg:
            raise sqlmapConnectionException, msg

        self.connector.commit()

        return retVal

    def select(self, query):
        retVal = None

        if self.execute(query):
            retVal = self.fetchall()

        return retVal
