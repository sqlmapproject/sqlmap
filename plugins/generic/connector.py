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
Franklin St, Fifth Floor, Boston, MA  021101301  USA
"""

from lib.core.data import conf
from lib.core.data import logger
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
        self.password = conf.dbmsPass
        self.hostname = conf.hostname
        self.port = conf.port
        self.db = conf.dbmsDb

    def connected(self):
        infoMsg = "connection to %s server %s" % (conf.dbms, self.hostname)
        infoMsg += ":%d established" % self.port
        logger.info(infoMsg)
        
    def closed(self):
        self.connector = None
        self.cursor = None
        infoMsg = "connection to %s server %s" % (conf.dbms, self.hostname)
        infoMsg += ":%d closed" % self.port
        logger.info(infoMsg)

    def connect(self):
        errMsg  = "'connect' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def fetchall(self):
        errMsg  = "'fetchall' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def execute(self, query):
        errMsg  = "'execute' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def select(self, query):
        errMsg  = "'select' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def setCursor(self):
        errMsg  = "'setCursor' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def getCursor(self):
        return self.cursor

    def close(self):
        errMsg  = "'close' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg
