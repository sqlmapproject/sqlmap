#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

try:
    import psycopg2
except ImportError, _:
    pass

from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException

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

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        self.initConnection()

        try:
            self.connector = psycopg2.connect(host=self.hostname, user=self.user, password=self.password, database=self.db, port=self.port)
        except psycopg2.OperationalError, msg:
            raise sqlmapConnectionException, msg

        self.setCursor()
        self.connected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except psycopg2.ProgrammingError, msg:
            logger.log(8, msg)
            return None

    def execute(self, query):
        logger.debug(query)

        try:
            self.cursor.execute(query)
        except (psycopg2.OperationalError, psycopg2.ProgrammingError), msg:
            logger.log(8, msg)
        except psycopg2.InternalError, msg:
            raise sqlmapConnectionException, msg

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
