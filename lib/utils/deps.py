#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.data import logger
from lib.core.enums import DBMS
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
                    warnMsg = "'%s' third-party library must be " % data[1]
                    warnMsg += "version >= 1.0.2 to work properly. "
                    warnMsg += "Download from %s" % data[2]
                    logger.warn(warnMsg)
            elif dbmsName == DBMS.MYSQL:
                import pymysql
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
            warnMsg = "sqlmap requires '%s' third-party library " % data[1]
            warnMsg += "in order to directly connect to the database "
            warnMsg += "%s. Download from %s" % (dbmsName, data[2])
            logger.warn(warnMsg)
            missing_libraries.add(data[1])

            continue

        debugMsg = "'%s' third-party library is found" % data[1]
        logger.debug(debugMsg)

    try:
        import impacket
        debugMsg = "'python-impacket' third-party library is found"
        logger.debug(debugMsg)
    except ImportError, _:
        warnMsg = "sqlmap requires 'python-impacket' third-party library for "
        warnMsg += "out-of-band takeover feature. Download from "
        warnMsg += "http://code.google.com/p/impacket/"
        logger.warn(warnMsg)
        missing_libraries.add('python-impacket')

    try:
        import ntlm
        debugMsg = "'python-ntlm' third-party library is found"
        logger.debug(debugMsg)
    except ImportError, _:
        warnMsg = "sqlmap requires 'python-ntlm' third-party library for "
        warnMsg += "if you plan to attack a web application behind NTLM "
        warnMsg += "authentication. Download from http://code.google.com/p/python-ntlm/"
        logger.warn(warnMsg)
        missing_libraries.add('python-ntlm')

    if IS_WIN:
        try:
            import pyreadline
            debugMsg = "'python-pyreadline' third-party library is found"
            logger.debug(debugMsg)
        except ImportError, _:
            warnMsg = "sqlmap requires 'pyreadline' third-party library to "
            warnMsg += "be able to take advantage of the sqlmap TAB "
            warnMsg += "completion and history support features in the SQL "
            warnMsg += "shell and OS shell. Download from "
            warnMsg += "http://ipython.scipy.org/moin/PyReadline/Intro"
            logger.warn(warnMsg)
            missing_libraries.add('python-pyreadline')

    if len(missing_libraries) == 0:
        infoMsg = "all dependencies are installed"
