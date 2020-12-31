#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

try:
    import prestodb
except:
    pass

import logging
import struct

from lib.core.common import getSafeExString
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: https://github.com/prestodb/presto-python-client
    User guide: https://github.com/prestodb/presto-python-client/blob/master/README.md
    API: https://www.python.org/dev/peps/pep-0249/
    PyPI package: presto-python-client
    License: Apache License 2.0
    """

    def connect(self):
        self.initConnection()

        try:
            self.connector = prestodb.dbapi.connect(host=self.hostname, user=self.user, catalog=self.db, port=self.port, request_timeout=conf.timeout)
        except (prestodb.exceptions.OperationalError, prestodb.exceptions.InternalError, prestodb.exceptions.ProgrammingError, struct.error) as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except prestodb.exceptions.ProgrammingError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
            return None

    def execute(self, query):
        retVal = False

        try:
            self.cursor.execute(query)
            retVal = True
        except (prestodb.exceptions.OperationalError, prestodb.exceptions.ProgrammingError) as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
        except prestodb.exceptions.InternalError as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.connector.commit()

        return retVal

    def select(self, query):
        retVal = None

        if self.execute(query):
            retVal = self.fetchall()

        return retVal
