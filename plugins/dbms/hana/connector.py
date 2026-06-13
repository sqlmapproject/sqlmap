#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

try:
    from hdbcli import dbapi
except ImportError:
    pass

from lib.core.common import getSafeExString
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: https://pypi.org/project/hdbcli/
    User guide: https://help.sap.com/docs/SAP_HANA_PLATFORM/f1b440ded6144a54ada97ff95dac7adf/4fe9978ebac44f35b9369ef5a4a6d73e.html
    API: https://help.sap.com/docs/SAP_HANA_CLIENT/f1b440ded6144a54ada97ff95dac7adf/39eb663beaab4f7b94850834e6cb6280.html
    Debian package: not available
    License: SAP Developer License
    """

    def connect(self):
        self.initConnection()

        try:
            self.connector = dbapi.connect(address=self.hostname, port=self.port, user=self.user, password=self.password, databaseName=self.db)
        except Exception as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except dbapi.Error as ex:
            logger.warning(getSafeExString(ex))
            return None

    def execute(self, query):
        retVal = False

        try:
            self.cursor.execute(query)
            retVal = True
        except dbapi.Error as ex:
            logger.warning(("(remote) '%s'" % getSafeExString(ex)).strip())

        self.connector.commit()

        return retVal

    def select(self, query):
        retVal = None

        if self.execute(query):
            retVal = self.fetchall()

        return retVal
