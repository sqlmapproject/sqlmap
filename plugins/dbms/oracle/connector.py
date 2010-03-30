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
    import cx_Oracle
except ImportError, _:
    pass

from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException

from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://cx-oracle.sourceforge.net/
    User guide: http://cx-oracle.sourceforge.net/README.txt
    API: http://cx-oracle.sourceforge.net/html/index.html
    Debian package: -
    License: http://cx-oracle.sourceforge.net/LICENSE.txt

    Possible connectors: -
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self, reuse=True):
        if reuse and self.connector:
            return

        self.initConnection()
        self.__dsn = cx_Oracle.makedsn(self.hostname, self.port, self.db)

        try:
            self.connector = cx_Oracle.connect(dsn=self.__dsn, user=self.user, password=self.password, mode=cx_Oracle.SYSDBA)
            logger.info("successfully connected as SYSDBA")
        except (cx_Oracle.OperationalError, cx_Oracle.DatabaseError), _:
            try:
                self.connector = cx_Oracle.connect(dsn=self.__dsn, user=self.user, password=self.password)
            except (cx_Oracle.OperationalError, cx_Oracle.DatabaseError), msg:
                raise sqlmapConnectionException, msg

        self.setCursor()
        self.connected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except cx_Oracle.InterfaceError, msg:
            logger.log(8, msg)
            return None

    def execute(self, query):
        logger.debug(query)

        try:
            self.cursor.execute(query)
        except (cx_Oracle.DatabaseError), msg:
            logger.log(8, msg)
        except cx_Oracle.InternalError, msg:
            raise sqlmapConnectionException, msg

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
