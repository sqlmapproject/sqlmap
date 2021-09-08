#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

try:
    import ibm_db_dbi
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
    Homepage: https://github.com/ibmdb/python-ibmdb
    User guide: https://github.com/ibmdb/python-ibmdb/wiki/README
    API: https://www.python.org/dev/peps/pep-0249/
    License: Apache License 2.0
    """

    def connect(self):
        self.initConnection()

        try:
            database = "DATABASE=%s;HOSTNAME=%s;PORT=%s;PROTOCOL=TCPIP;" % (self.db, self.hostname, self.port)
            self.connector = ibm_db_dbi.connect(database, self.user, self.password)
        except ibm_db_dbi.OperationalError as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except ibm_db_dbi.ProgrammingError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
            return None

    def execute(self, query):
        try:
            self.cursor.execute(query)
        except (ibm_db_dbi.OperationalError, ibm_db_dbi.ProgrammingError) as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
        except ibm_db_dbi.InternalError as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
