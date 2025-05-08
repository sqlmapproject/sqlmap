#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import importlib
import logging
import os
import re
import sys
import traceback
import warnings

_path = list(sys.path)
_sqlalchemy = None
try:
    sys.path = sys.path[1:]
    module = importlib.import_module("sqlalchemy")
    if hasattr(module, "dialects"):
        _sqlalchemy = module
        warnings.simplefilter(action="ignore", category=_sqlalchemy.exc.SAWarning)
except:
    pass
finally:
    sys.path = _path

try:
    import MySQLdb  # used by SQLAlchemy in case of MySQL
    warnings.filterwarnings("error", category=MySQLdb.Warning)
except (ImportError, AttributeError):
    pass

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapMissingDependence
from plugins.generic.connector import Connector as GenericConnector
from thirdparty import six
from thirdparty.six.moves import urllib as _urllib

def getSafeExString(ex, encoding=None):  # Cross-referenced function
    raise NotImplementedError

class SQLAlchemy(GenericConnector):
    def __init__(self, dialect=None):
        GenericConnector.__init__(self)

        self.dialect = dialect
        self.address = conf.direct

        if conf.dbmsUser:
            self.address = self.address.replace("'%s':" % conf.dbmsUser, "%s:" % _urllib.parse.quote(conf.dbmsUser))
            self.address = self.address.replace("%s:" % conf.dbmsUser, "%s:" % _urllib.parse.quote(conf.dbmsUser))

        if conf.dbmsPass:
            self.address = self.address.replace(":'%s'@" % conf.dbmsPass, ":%s@" % _urllib.parse.quote(conf.dbmsPass))
            self.address = self.address.replace(":%s@" % conf.dbmsPass, ":%s@" % _urllib.parse.quote(conf.dbmsPass))

        if self.dialect:
            self.address = re.sub(r"\A.+://", "%s://" % self.dialect, self.address)

    def connect(self):
        if _sqlalchemy:
            self.initConnection()

            try:
                if not self.port and self.db:
                    if not os.path.exists(self.db):
                        raise SqlmapFilePathException("the provided database file '%s' does not exist" % self.db)

                    _ = self.address.split("//", 1)
                    self.address = "%s////%s" % (_[0], os.path.abspath(self.db))

                if self.dialect == "sqlite":
                    engine = _sqlalchemy.create_engine(self.address, connect_args={"check_same_thread": False})
                elif self.dialect == "oracle":
                    engine = _sqlalchemy.create_engine(self.address)
                else:
                    engine = _sqlalchemy.create_engine(self.address, connect_args={})

                self.connector = engine.connect()
            except (TypeError, ValueError):
                if "_get_server_version_info" in traceback.format_exc():
                    try:
                        import pymssql
                        if int(pymssql.__version__[0]) < 2:
                            raise SqlmapConnectionException("SQLAlchemy connection issue (obsolete version of pymssql ('%s') is causing problems)" % pymssql.__version__)
                    except ImportError:
                        pass
                elif "invalid literal for int() with base 10: '0b" in traceback.format_exc():
                    raise SqlmapConnectionException("SQLAlchemy connection issue ('https://bitbucket.org/zzzeek/sqlalchemy/issues/3975')")
                else:
                    pass
            except SqlmapFilePathException:
                raise
            except Exception as ex:
                raise SqlmapConnectionException("SQLAlchemy connection issue ('%s')" % getSafeExString(ex))

            self.printConnected()
        else:
            raise SqlmapMissingDependence("SQLAlchemy not available (e.g. 'pip%s install SQLAlchemy')" % ('3' if six.PY3 else ""))

    def fetchall(self):
        try:
            retVal = []
            for row in self.cursor.fetchall():
                retVal.append(tuple(row))
            return retVal
        except _sqlalchemy.exc.ProgrammingError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
            return None

    def execute(self, query):
        retVal = False

        # Reference: https://stackoverflow.com/a/69491015
        if hasattr(_sqlalchemy, "text"):
            query = _sqlalchemy.text(query)

        try:
            self.cursor = self.connector.execute(query)
            retVal = True
        except (_sqlalchemy.exc.OperationalError, _sqlalchemy.exc.ProgrammingError) as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % getSafeExString(ex))
        except _sqlalchemy.exc.InternalError as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        return retVal

    def select(self, query):
        retVal = None

        if self.execute(query):
            retVal = self.fetchall()

        return retVal
