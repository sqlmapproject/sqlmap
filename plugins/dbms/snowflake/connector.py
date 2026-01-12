#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

try:
    import snowflake.connector
except:
    pass

import logging

from lib.core.common import getSafeExString
from lib.core.convert import getText
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: https://www.snowflake.com/
    User guide: https://docs.snowflake.com/en/developer-guide/python-connector/python-connector
    API: https://docs.snowflake.com/en/developer-guide/python-connector/python-connector-api
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        self.initConnection()

        try:
            self.connector = snowflake.connector.connect(
                user=self.user,
                password=self.password,
                account=self.account,
                warehouse=self.warehouse,
                database=self.db,
                schema=self.schema
            )
            cursor = self.connector.cursor()
            cursor.execute("SELECT CURRENT_VERSION()")
            cursor.close()

        except Exception as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except Exception as ex:
            logger.log(logging.WARNING if conf.dbmsHandler else logging.DEBUG, "(remote) '%s'" % getSafeExString(ex))
            return None

    def execute(self, query):
        try:
            self.cursor.execute(getText(query))
        except Exception as ex:
            logger.log(logging.WARNING if conf.dbmsHandler else logging.DEBUG, "(remote) '%s'" % getSafeExString(ex))
            return None

    def select(self, query):
        self.execute(query)
        return self.fetchall()
