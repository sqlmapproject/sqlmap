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
    import kinterbasdb
except ImportError, _:
    pass

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException

from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://kinterbasdb.sourceforge.net/
    User guide: http://kinterbasdb.sourceforge.net/dist_docs/usage.html
    License: BSD
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        self.initConnection()

        try:
            self.connector = kinterbasdb.connect(database=self.db, user=self.user, password=self.password, timeout={'period': conf.timeout})
        except kinterbasdb.OperationalError, msg:
            raise sqlmapConnectionException, msg[1]

        self.setCursor()
        self.connected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except kinterbasdb.OperationalError, msg:
            logger.log(8, msg[1])
            return None

    def execute(self, query):
        logger.debug(query)

        try:
            self.cursor.execute(query)
        except kinterbasdb.OperationalError, msg:
            logger.log(8, msg[1])
        except kinterbasdb.Error, msg:
            raise sqlmapConnectionException, msg[1]

        self.connector.commit()

    def select(self, query):
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def setCursor(self):
        self.cursor = self.connector.cursor()

    def close(self):
        self.cursor.close()
        self.connector.close()
