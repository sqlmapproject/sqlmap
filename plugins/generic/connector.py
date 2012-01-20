#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapFilePathException
from lib.core.exception import sqlmapUndefinedMethod

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

    def connected(self):
        infoMsg = "connection to %s server %s" % (conf.dbms, self.hostname)
        infoMsg += ":%d established" % self.port
        logger.info(infoMsg)

    def closed(self):
        infoMsg = "connection to %s server %s" % (conf.dbms, self.hostname)
        infoMsg += ":%d closed" % self.port
        logger.info(infoMsg)

        self.connector = None
        self.cursor = None

    def setCursor(self):
        self.cursor = self.connector.cursor()

    def getCursor(self):
        return self.cursor

    def close(self):
        try:
            self.cursor.close()
            self.connector.close()
        except Exception, msg:
            logger.debug(msg)
        finally:
            self.closed()

    def checkFileDb(self):
        if not os.path.exists(self.db):
            errMsg = "the provided database file '%s' does not exist" % self.db
            raise sqlmapFilePathException, errMsg

    def connect(self):
        errMsg = "'connect' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def fetchall(self):
        errMsg = "'fetchall' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def execute(self, query):
        errMsg = "'execute' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def select(self, query):
        errMsg = "'select' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg
