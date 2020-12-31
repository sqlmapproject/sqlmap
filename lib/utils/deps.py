#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.dicts import DBMS_DICT
from lib.core.enums import DBMS
from lib.core.settings import IS_WIN

def checkDependencies():
    missing_libraries = set()

    for dbmsName, data in DBMS_DICT.items():
        if data[1] is None:
            continue

        try:
            if dbmsName in (DBMS.MSSQL, DBMS.SYBASE):
                __import__("_mssql")

                pymssql = __import__("pymssql")
                if not hasattr(pymssql, "__version__") or pymssql.__version__ < "1.0.2":
                    warnMsg = "'%s' third-party library must be " % data[1]
                    warnMsg += "version >= 1.0.2 to work properly. "
                    warnMsg += "Download from '%s'" % data[2]
                    logger.warn(warnMsg)
            elif dbmsName == DBMS.MYSQL:
                __import__("pymysql")
            elif dbmsName in (DBMS.PGSQL, DBMS.CRATEDB):
                __import__("psycopg2")
            elif dbmsName == DBMS.ORACLE:
                __import__("cx_Oracle")
            elif dbmsName == DBMS.SQLITE:
                __import__("sqlite3")
            elif dbmsName == DBMS.ACCESS:
                __import__("pyodbc")
            elif dbmsName == DBMS.FIREBIRD:
                __import__("kinterbasdb")
            elif dbmsName == DBMS.DB2:
                __import__("ibm_db_dbi")
            elif dbmsName in (DBMS.HSQLDB, DBMS.CACHE):
                __import__("jaydebeapi")
                __import__("jpype")
            elif dbmsName == DBMS.INFORMIX:
                __import__("ibm_db_dbi")
            elif dbmsName == DBMS.MONETDB:
                __import__("pymonetdb")
            elif dbmsName == DBMS.DERBY:
                __import__("drda")
            elif dbmsName == DBMS.VERTICA:
                __import__("vertica_python")
            elif dbmsName == DBMS.PRESTO:
                __import__("prestodb")
            elif dbmsName == DBMS.MIMERSQL:
                __import__("mimerpy")
            elif dbmsName == DBMS.CUBRID:
                __import__("CUBRIDdb")
        except:
            warnMsg = "sqlmap requires '%s' third-party library " % data[1]
            warnMsg += "in order to directly connect to the DBMS "
            warnMsg += "'%s'. Download from '%s'" % (dbmsName, data[2])
            logger.warn(warnMsg)
            missing_libraries.add(data[1])

            continue

        debugMsg = "'%s' third-party library is found" % data[1]
        logger.debug(debugMsg)

    try:
        __import__("impacket")
        debugMsg = "'python-impacket' third-party library is found"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmap requires 'python-impacket' third-party library for "
        warnMsg += "out-of-band takeover feature. Download from "
        warnMsg += "'https://github.com/coresecurity/impacket'"
        logger.warn(warnMsg)
        missing_libraries.add('python-impacket')

    try:
        __import__("ntlm")
        debugMsg = "'python-ntlm' third-party library is found"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmap requires 'python-ntlm' third-party library "
        warnMsg += "if you plan to attack a web application behind NTLM "
        warnMsg += "authentication. Download from 'https://github.com/mullender/python-ntlm'"
        logger.warn(warnMsg)
        missing_libraries.add('python-ntlm')

    try:
        __import__("websocket._abnf")
        debugMsg = "'websocket-client' library is found"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmap requires 'websocket-client' third-party library "
        warnMsg += "if you plan to attack a web application using WebSocket. "
        warnMsg += "Download from 'https://pypi.python.org/pypi/websocket-client/'"
        logger.warn(warnMsg)
        missing_libraries.add('websocket-client')

    try:
        __import__("tkinter")
        debugMsg = "'tkinter' library is found"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmap requires 'tkinter' library "
        warnMsg += "if you plan to run a GUI"
        logger.warn(warnMsg)
        missing_libraries.add('tkinter')

    try:
        __import__("tkinter.ttk")
        debugMsg = "'tkinter.ttk' library is found"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmap requires 'tkinter.ttk' library "
        warnMsg += "if you plan to run a GUI"
        logger.warn(warnMsg)
        missing_libraries.add('tkinter.ttk')

    if IS_WIN:
        try:
            __import__("pyreadline")
            debugMsg = "'python-pyreadline' third-party library is found"
            logger.debug(debugMsg)
        except ImportError:
            warnMsg = "sqlmap requires 'pyreadline' third-party library to "
            warnMsg += "be able to take advantage of the sqlmap TAB "
            warnMsg += "completion and history support features in the SQL "
            warnMsg += "shell and OS shell. Download from "
            warnMsg += "'https://pypi.org/project/pyreadline/'"
            logger.warn(warnMsg)
            missing_libraries.add('python-pyreadline')

    if len(missing_libraries) == 0:
        infoMsg = "all dependencies are installed"
        logger.info(infoMsg)
