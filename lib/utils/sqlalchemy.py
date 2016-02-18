#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import imp
import logging
import os
import sys
import warnings

_sqlalchemy = None
try:
    f, pathname, desc = imp.find_module("sqlalchemy", sys.path[1:])
    _ = imp.load_module("sqlalchemy", f, pathname, desc)
    if hasattr(_, "dialects"):
        _sqlalchemy = _
        warnings.simplefilter(action="ignore", category=_sqlalchemy.exc.SAWarning)
except ImportError:
    pass

try:
    import MySQLdb  # used by SQLAlchemy in case of MySQL
    warnings.filterwarnings("error", category=MySQLdb.Warning)
except ImportError:
    pass

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapFilePathException
from plugins.generic.connector import Connector as GenericConnector

class SQLAlchemy(GenericConnector):
    def __init__(self, dialect=None):
        GenericConnector.__init__(self)
        self.dialect = dialect

    def connect(self):
        if _sqlalchemy:
            self.initConnection()

            try:
                if not self.port and self.db:
                    if not os.path.exists(self.db):
                        raise SqlmapFilePathException, "the provided database file '%s' does not exist" % self.db

                    _ = conf.direct.split("//", 1)
                    conf.direct = "%s////%s" % (_[0], os.path.abspath(self.db))

                if self.dialect:
                    conf.direct = conf.direct.replace(conf.dbms, self.dialect, 1)

                engine = _sqlalchemy.create_engine(conf.direct, connect_args={'check_same_thread':False} if self.dialect == "sqlite" else {})
                self.connector = engine.connect()
            except SqlmapFilePathException:
                raise
            except Exception, msg:
                raise SqlmapConnectionException("SQLAlchemy connection issue ('%s')" % msg[0])

            self.printConnected()

    def fetchall(self):
        try:
            retVal = []
            for row in self.cursor.fetchall():
                retVal.append(tuple(row))
            return retVal
        except _sqlalchemy.exc.ProgrammingError, msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg.message if hasattr(msg, "message") else msg)
            return None

    def execute(self, query):
        try:
            self.cursor = self.connector.execute(query)
        except (_sqlalchemy.exc.OperationalError, _sqlalchemy.exc.ProgrammingError), msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg.message if hasattr(msg, "message") else msg)
        except _sqlalchemy.exc.InternalError, msg:
            raise SqlmapConnectionException(msg[1])

    def select(self, query):
        self.execute(query)
        return self.fetchall()
