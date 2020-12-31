#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

try:
    import jaydebeapi
    import jpype
except:
    pass

import logging

from lib.core.common import checkFile
from lib.core.common import getSafeExString
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

    def connect(self):
        self.initConnection()
        try:
            msg = "please enter the location of 'cachejdbc.jar'? "
            jar = readInput(msg)
            checkFile(jar)
            args = "-Djava.class.path=%s" % jar
            jvm_path = jpype.getDefaultJVMPath()
            jpype.startJVM(jvm_path, args)
        except Exception as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        try:
            driver = 'com.intersys.jdbc.CacheDriver'
            connection_string = 'jdbc:Cache://%s:%d/%s' % (self.hostname, self.port, self.db)
            self.connector = jaydebeapi.connect(driver, connection_string, str(self.user), str(self.password))
        except Exception as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except Exception as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) '%s'" % getSafeExString(ex))
            return None

    def execute(self, query):
        retVal = False

        try:
            self.cursor.execute(query)
            retVal = True
        except Exception as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) '%s'" % getSafeExString(ex))

        self.connector.commit()

        return retVal

    def select(self, query):
        self.execute(query)
        return self.fetchall()
