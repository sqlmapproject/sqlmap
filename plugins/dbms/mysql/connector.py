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
    import MySQLdb
except ImportError, _:
    pass

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException

from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://mysql-python.sourceforge.net/
    User guide: http://mysql-python.sourceforge.net/MySQLdb.html
    API: http://mysql-python.sourceforge.net/MySQLdb-1.2.2/
    Debian package: python-mysqldb
    License: GPL

    Possible connectors: http://wiki.python.org/moin/MySQL
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self, reuse=True):
        if reuse and self.connector:
            return

        self.initConnection()

        try:
            self.connector = MySQLdb.connect(host=self.hostname, user=self.user, passwd=self.password, db=self.db, port=self.port, connect_timeout=conf.timeout)
        except MySQLdb.OperationalError, msg:
            raise sqlmapConnectionException, msg[1]

        self.setCursor()
        self.connected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except MySQLdb.ProgrammingError, msg:
            logger.log(8, msg[1])
            return None

    def execute(self, query):
        logger.debug(query)

        try:
            self.cursor.execute(query)
        except (MySQLdb.OperationalError, MySQLdb.ProgrammingError), msg:
            logger.log(8, msg[1])
        except MySQLdb.InternalError, msg:
            raise sqlmapConnectionException, msg[1]

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()

    def setCursor(self):
        self.cursor = self.connector.cursor()

    def close(self):
        self.cursor.close()
        self.connector.close()
        self.closed()
