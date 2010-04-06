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
    import sqlite3
except ImportError, _:
    pass

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException
from lib.utils.timeout import timeout

from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://pysqlite.googlecode.com/
    User guide: http://docs.python.org/release/2.5/lib/module-sqlite3.html
    API: http://docs.python.org/library/sqlite3.html
    Debian package: python-pysqlite2
    License: MIT

    Possible connectors: http://wiki.python.org/moin/SQLite
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        self.initConnection()
        self.checkFileDb()

        try:
            self.connector = sqlite3.connect(database=self.db, timeout=conf.timeout)
        except sqlite3.OperationalError, msg:
            raise sqlmapConnectionException, msg[0]

        self.setCursor()
        self.connected()

    def fetchall(self):
        retVal = timeout(func=self.cursor.fetchall, duration=conf.timeout, default=None)
        if self.exceptionMsg:
            logger.log(8, self.exceptionMsg[0])
        return retVal

    def execute(self, query):
        logger.debug(query)

        try:
            self.cursor.execute(query)
        except sqlite3.OperationalError, msg:
            logger.log(8, msg[0])
        except sqlite3.DatabaseError, msg:
            raise sqlmapConnectionException, msg[0]

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
