#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

try:
    import ibm_db_dbi
except:
    pass

import logging

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://code.google.com/p/ibm-db/
    User guide: http://code.google.com/p/ibm-db/wiki/README
    API: http://www.python.org/dev/peps/pep-0249/
    License: Apache License 2.0
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        self.initConnection()

        try:
            database = "DRIVER={IBM DB2 ODBC DRIVER};DATABASE=%s;HOSTNAME=%s;PORT=%s;PROTOCOL=TCPIP;" % (self.db, self.hostname, self.port)
            self.connector = ibm_db_dbi.connect(database, self.user, self.password)
        except ibm_db_dbi.OperationalError, msg:
            raise SqlmapConnectionException(msg)


        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except ibm_db_dbi.ProgrammingError, msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg[1])
            return None

    def execute(self, query):
        try:
            self.cursor.execute(query)
        except (ibm_db_dbi.OperationalError, ibm_db_dbi.ProgrammingError), msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg[1])
        except ibm_db_dbi.InternalError, msg:
            raise SqlmapConnectionException(msg[1])

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
