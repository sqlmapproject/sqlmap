#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

try:
    import cx_Oracle
except:
    pass

import logging
import os
import re

from lib.core.common import getSafeExString
from lib.core.convert import getText
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

os.environ["NLS_LANG"] = ".AL32UTF8"

class Connector(GenericConnector):
    """
    Homepage: https://oracle.github.io/python-cx_Oracle/
    User https://cx-oracle.readthedocs.io/en/latest/
    API: https://wiki.python.org/moin/DatabaseProgramming
    License: https://cx-oracle.readthedocs.io/en/latest/license.html#license
    """

    def connect(self):
        self.initConnection()
        self.__dsn = cx_Oracle.makedsn(self.hostname, self.port, self.db)
        self.__dsn = getText(self.__dsn)
        self.user = getText(self.user)
        self.password = getText(self.password)

        try:
            self.connector = cx_Oracle.connect(dsn=self.__dsn, user=self.user, password=self.password, mode=cx_Oracle.SYSDBA)
            logger.info("successfully connected as SYSDBA")
        except (cx_Oracle.OperationalError, cx_Oracle.DatabaseError, cx_Oracle.InterfaceError) as ex:
            if "Oracle Client library" in getSafeExString(ex):
                msg = re.sub(r"DPI-\d+:\s+", "", getSafeExString(ex))
                msg = re.sub(r': ("[^"]+")', r" (\g<1>)", msg)
                msg = re.sub(r". See (http[^ ]+)", r'. See "\g<1>"', msg)
                raise SqlmapConnectionException(msg)

            try:
                self.connector = cx_Oracle.connect(dsn=self.__dsn, user=self.user, password=self.password)
            except (cx_Oracle.OperationalError, cx_Oracle.DatabaseError, cx_Oracle.InterfaceError) as ex:
                raise SqlmapConnectionException(ex)

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except cx_Oracle.InterfaceError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) '%s'" % getSafeExString(ex))
            return None

    def execute(self, query):
        retVal = False

        try:
            self.cursor.execute(getText(query))
            retVal = True
        except cx_Oracle.DatabaseError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) '%s'" % getSafeExString(ex))

        self.connector.commit()

        return retVal

    def select(self, query):
        retVal = None

        if self.execute(query):
            retVal = self.fetchall()

        return retVal
