#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapUndefinedMethod

class Connector:
    """
    This class defines generic dbms protocol functionalities for plugins.
    """

    def __init__(self):
        self.connector = None
        self.cursor = None

    def initConnection(self):
        self.user = conf.dbmsUser
        self.password = conf.dbmsPass if conf.dbmsPass is not None else ""
        self.hostname = conf.hostname
        self.port = conf.port
        self.db = conf.dbmsDb

    def printConnected(self):
        infoMsg = "connection to %s server %s" % (conf.dbms, self.hostname)
        infoMsg += ":%d established" % self.port
        logger.info(infoMsg)

    def closed(self):
        infoMsg = "connection to %s server %s" % (conf.dbms, self.hostname)
        infoMsg += ":%d closed" % self.port
        logger.info(infoMsg)

        self.connector = None
        self.cursor = None

    def initCursor(self):
        self.cursor = self.connector.cursor()

    def close(self):
        try:
            if self.cursor:
                self.cursor.close()
            if self.connector:
                self.connector.close()
        except Exception, msg:
            logger.debug(msg)
        finally:
            self.closed()

    def checkFileDb(self):
        if not os.path.exists(self.db):
            errMsg = "the provided database file '%s' does not exist" % self.db
            raise SqlmapFilePathException(errMsg)

    def connect(self):
        errMsg = "'connect' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def fetchall(self):
        errMsg = "'fetchall' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def execute(self, query):
        errMsg = "'execute' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def select(self, query):
        errMsg = "'select' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)
