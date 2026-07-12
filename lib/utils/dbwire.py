#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import importlib
import logging

import extra.dbwire

from lib.core.common import getSafeExString
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Adapter exposing sqlmap's connector interface over a dependency-free 'extra/dbwire' pure-python
    wire-protocol client. Used for '-d' when neither a native driver nor SQLAlchemy is available.
    """

    def __init__(self, module):
        GenericConnector.__init__(self)
        self._driver = importlib.import_module("extra.dbwire.%s" % module)

    def connect(self):
        self.initConnection()

        try:
            self.connector = self._driver.connect(host=self.hostname, port=self.port, user=self.user, password=self.password, database=self.db, connect_timeout=conf.timeout)
        except extra.dbwire.Error as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except extra.dbwire.Error as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
            return None

    def execute(self, query):
        try:
            self.cursor.execute(query)
        except extra.dbwire.Error as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
