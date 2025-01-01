#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

try:
    import drda
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
    Homepage: https://github.com/nakagami/pydrda/
    User guide: https://github.com/nakagami/pydrda/blob/master/README.rst
    API: https://www.python.org/dev/peps/pep-0249/
    License: MIT
    """

    def connect(self):
        self.initConnection()

        try:
            self.connector = drda.connect(host=self.hostname, database=self.db, port=self.port)
        except drda.OperationalError as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except drda.ProgrammingError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
            return None

    def execute(self, query):
        try:
            self.cursor.execute(query)
        except (drda.OperationalError, drda.ProgrammingError) as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
        except drda.InternalError as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        try:
            self.connector.commit()
        except drda.OperationalError:
            pass

    def select(self, query):
        self.execute(query)
        return self.fetchall()
