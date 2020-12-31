#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

try:
    import psycopg2
    import psycopg2.extensions
    psycopg2.extensions.register_type(psycopg2.extensions.UNICODE)
    psycopg2.extensions.register_type(psycopg2.extensions.UNICODEARRAY)
except:
    pass

from lib.core.common import getSafeExString
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://initd.org/psycopg/
    User guide: http://initd.org/psycopg/docs/
    API: http://initd.org/psycopg/docs/genindex.html
    Debian package: python-psycopg2
    License: GPL

    Possible connectors: http://wiki.python.org/moin/PostgreSQL
    """

    def connect(self):
        self.initConnection()

        try:
            self.connector = psycopg2.connect(host=self.hostname, user=self.user, password=self.password, database=self.db, port=self.port)
        except psycopg2.OperationalError as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.connector.set_client_encoding('UNICODE')

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except psycopg2.ProgrammingError as ex:
            logger.warn(getSafeExString(ex))
            return None

    def execute(self, query):
        retVal = False

        try:
            self.cursor.execute(query)
            retVal = True
        except (psycopg2.OperationalError, psycopg2.ProgrammingError) as ex:
            logger.warn(("(remote) '%s'" % getSafeExString(ex)).strip())
        except psycopg2.InternalError as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.connector.commit()

        return retVal

    def select(self, query):
        retVal = None

        if self.execute(query):
            retVal = self.fetchall()

        return retVal
