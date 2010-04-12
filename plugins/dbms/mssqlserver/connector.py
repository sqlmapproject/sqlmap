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
    import _mssql
    import pymssql
except ImportError, _:
    pass

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException

from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://pymssql.sourceforge.net/
    User guide: http://pymssql.sourceforge.net/examples_pymssql.php
    API: http://pymssql.sourceforge.net/ref_pymssql.php
    Debian package: python-pymssql
    License: LGPL

    Possible connectors: http://wiki.python.org/moin/SQL%20Server

    Important note: pymssql library on your system MUST be version 1.0.2
    to work, get it from http://sourceforge.net/projects/pymssql/files/pymssql/1.0.2/
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        self.initConnection()

        try:
            self.connector = pymssql.connect(host="%s:%d" % (self.hostname, self.port), user=self.user, password=self.password, database=self.db, login_timeout=conf.timeout, timeout=conf.timeout)
        except pymssql.OperationalError, msg:
            raise sqlmapConnectionException, msg

        self.setCursor()
        self.connected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except (pymssql.ProgrammingError, pymssql.OperationalError, _mssql.MssqlDatabaseException), msg:
            logger.log(8, msg)
            return None

    def execute(self, query):
        try:
            self.cursor.execute(query)
        except (pymssql.OperationalError, pymssql.ProgrammingError), msg:
            logger.log(8, msg)
        except pymssql.InternalError, msg:
            raise sqlmapConnectionException, msg

    def select(self, query):
        self.execute(query)
        value = self.fetchall()

        try:
            self.connector.commit()
        except pymssql.OperationalError:
            pass

        return value
