#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.exception import sqlmapMissingDependence
from lib.core.settings import DBMS_DICT
from lib.core.settings import IS_WIN

def checkDependencies():
    missing_libraries = set()

    for dbmsName, data in DBMS_DICT.items():
        if data[1] is None:
            continue

        try:
            if dbmsName in (DBMS.MSSQL, DBMS.SYBASE):
                import _mssql
                import pymssql

                if not hasattr(pymssql, "__version__") or pymssql.__version__ < "1.0.2":
                    errMsg = "'%s' third-party library must be " % data[1]
                    errMsg += "version >= 1.0.2 to work properly. "
                    errMsg += "Download from %s" % data[2]
                    logger.error(errMsg)
            elif dbmsName == DBMS.MYSQL:
                import MySQLdb
            elif dbmsName == DBMS.PGSQL:
                import psycopg2
            elif dbmsName == DBMS.ORACLE:
                import cx_Oracle
            elif dbmsName == DBMS.SQLITE:
                import sqlite3
            elif dbmsName == DBMS.ACCESS:
                import pyodbc
            elif dbmsName == DBMS.FIREBIRD:
                import kinterbasdb
        except ImportError, _:
            errMsg = "sqlmap requires '%s' third-party library " % data[1]
            errMsg += "in order to directly connect to the database "
            errMsg += "%s. Download from %s" % (dbmsName, data[2])
            logger.error(errMsg)
            missing_libraries.add(data[1])

            continue

        debugMsg = "'%s' third-party library is found" % data[1]
        logger.debug(debugMsg)

    try:
        import impacket
        debugMsg = "'python-impacket' third-party library is found"
        logger.debug(debugMsg)
    except ImportError, _:
        errMsg = "sqlmap requires 'python-impacket' third-party library for "
        errMsg += "out-of-band takeover feature. Download from "
        errMsg += "http://code.google.com/p/impacket/"
        logger.error(errMsg)
        missing_libraries.add('python-impacket')

    try:
        import ntlm
        debugMsg = "'python-ntlm' third-party library is found"
        logger.debug(debugMsg)
    except ImportError, _:
        errMsg = "sqlmap requires 'python-ntlm' third-party library for "
        errMsg += "if you plan to attack a web application behind NTLM "
        errMsg += "authentication. Download from http://code.google.com/p/python-ntlm/"
        logger.error(errMsg)
        missing_libraries.add('python-ntlm')

    try:
        import pysvn
        debugMsg = "'python-svn' third-party library is found"
        logger.debug(debugMsg)
    except ImportError, _:
        errMsg = "sqlmap requires 'python-svn' third-party library for "
        errMsg += "if you want to use the sqlmap update functionality. "
        errMsg += "Download from http://pysvn.tigris.org/"
        logger.error(errMsg)
        missing_libraries.add('python-svn')

    if IS_WIN:
        try:
            import pyreadline
            debugMsg = "'python-pyreadline' third-party library is found"
            logger.debug(debugMsg)
        except ImportError, _:
            errMsg = "sqlmap requires 'pyreadline' third-party library to "
            errMsg += "be able to take advantage of the sqlmap TAB "
            errMsg += "completion and history support features in the SQL "
            errMsg += "shell and OS shell. Download from "
            errMsg += "http://ipython.scipy.org/moin/PyReadline/Intro"
            logger.error(errMsg)
            missing_libraries.add('python-pyreadline')

    if len(missing_libraries) == 0:
        infoMsg = "all dependencies are installed"
