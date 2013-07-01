#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

try:
    import jaydebeapi
    import jpype
except ImportError, msg:
    pass

import logging

from lib.core.common import checkFile
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: https://pypi.python.org/pypi/JayDeBeApi/ & http://jpype.sourceforge.net/
    User guide: https://pypi.python.org/pypi/JayDeBeApi/#usage & http://jpype.sourceforge.net/doc/user-guide/userguide.html
    API: -
    Debian package: -
    License: LGPL & Apache License 2.0
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        self.initConnection()
        try:
            msg = "what's the location of 'hsqldb.jar'? "
            jar = readInput(msg)
            checkFile(jar)
            args = "-Djava.class.path=%s" % jar
            jvm_path = jpype.getDefaultJVMPath()
            jpype.startJVM(jvm_path, args)
        except Exception, msg:
            raise SqlmapConnectionException(msg[0])

        try:
            driver = 'org.hsqldb.jdbc.JDBCDriver'
            connection_string = 'jdbc:hsqldb:mem:.' #'jdbc:hsqldb:hsql://%s/%s' % (self.hostname, self.db)
            self.connector = jaydebeapi.connect(driver,
                                        connection_string,
                                        str(self.user),
                                        str(self.password))
        except Exception, msg:
            raise SqlmapConnectionException(msg[0])

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except Exception, msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg[1])
            return None

    def execute(self, query):
        retVal = False

        try:
            self.cursor.execute(query)
            retVal = True
        except Exception, msg: #todo fix with specific error
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg[1])

        self.connector.commit()

        return retVal

    def select(self, query):
        retVal = None

        upper_query = query.upper()

        if query and not (upper_query.startswith("SELECT ") or upper_query.startswith("VALUES ")):
            query = "VALUES %s" % query

        if query and upper_query.startswith("SELECT ") and " FROM " not in upper_query:
            query = "%s FROM (VALUES(0))" % query

        self.cursor.execute(query)
        retVal = self.cursor.fetchall()

        return retVal
