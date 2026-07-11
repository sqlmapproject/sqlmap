#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

try:
    import clickhouse_connect
    import clickhouse_connect.dbapi
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
    Homepage: https://github.com/ClickHouse/clickhouse-connect
    User guide: https://clickhouse.com/docs/integrations/python
    License: Apache 2.0
    """

    def connect(self):
        self.initConnection()

        try:
            self.connector = clickhouse_connect.dbapi.connect(host=self.hostname, port=self.port, username=self.user, password=self.password, database=self.db)
        except clickhouse_connect.dbapi.Error as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except clickhouse_connect.dbapi.Error as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
            return None

    def execute(self, query):
        try:
            self.cursor.execute(query)
        except clickhouse_connect.dbapi.Error as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))

    def select(self, query):
        self.execute(query)
        return self.fetchall()
