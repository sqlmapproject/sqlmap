#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.controller.handler import setHandler
from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import CONTENT_TYPE
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.core.settings import SUPPORTED_DBMS
from lib.utils.brute import columnExists
from lib.utils.brute import fileExists
from lib.utils.brute import tableExists

def action():
    """
    This function exploit the SQL injection on the affected
    URL parameter and extract requested data from the
    back-end database management system or operating system
    if possible
    """

    # First of all we have to identify the back-end database management
    # system to be able to go ahead with the injection
    setHandler()

    if not Backend.getDbms() or not conf.dbmsHandler:
        htmlParsed = Format.getErrorParsedDBMSes()

        errMsg = "sqlmap was not able to fingerprint the "
        errMsg += "back-end database management system"

        if htmlParsed:
            errMsg += ", but from the HTML error page it was "
            errMsg += "possible to determinate that the "
            errMsg += "back-end DBMS is %s" % htmlParsed

        if htmlParsed and htmlParsed.lower() in SUPPORTED_DBMS:
            errMsg += ". Do not specify the back-end DBMS manually, "
            errMsg += "sqlmap will fingerprint the DBMS for you"
        elif kb.nullConnection:
            errMsg += ". You can try to rerun without using optimization "
            errMsg += "switch '%s'" % ("-o" if conf.optimize else "--null-connection")

        raise SqlmapUnsupportedDBMSException(errMsg)

    conf.dumper.singleString(conf.dbmsHandler.getFingerprint())

    kb.fingerprinted = True

    # Enumeration options
    if conf.getBanner:
        conf.dumper.banner(conf.dbmsHandler.getBanner())

    if conf.getCurrentUser:
        conf.dumper.currentUser(conf.dbmsHandler.getCurrentUser())

    if conf.getCurrentDb:
        conf.dumper.currentDb(conf.dbmsHandler.getCurrentDb())

    if conf.getHostname:
        conf.dumper.hostname(conf.dbmsHandler.getHostname())

    if conf.isDba:
        conf.dumper.dba(conf.dbmsHandler.isDba())

    if conf.getUsers:
        conf.dumper.users(conf.dbmsHandler.getUsers())

    if conf.getStatements:
        conf.dumper.statements(conf.dbmsHandler.getStatements())

    if conf.getPasswordHashes:
        try:
            conf.dumper.userSettings("database management system users password hashes", conf.dbmsHandler.getPasswordHashes(), "password hash", CONTENT_TYPE.PASSWORDS)
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getPrivileges:
        try:
            conf.dumper.userSettings("database management system users privileges", conf.dbmsHandler.getPrivileges(), "privilege", CONTENT_TYPE.PRIVILEGES)
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getRoles:
        try:
            conf.dumper.userSettings("database management system users roles", conf.dbmsHandler.getRoles(), "role", CONTENT_TYPE.ROLES)
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getDbs:
        try:
            conf.dumper.dbs(conf.dbmsHandler.getDbs())
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getTables:
        try:
            conf.dumper.dbTables(conf.dbmsHandler.getTables())
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.commonTables:
        try:
            conf.dumper.dbTables(tableExists(paths.COMMON_TABLES))
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getSchema:
        try:
            conf.dumper.dbTableColumns(conf.dbmsHandler.getSchema(), CONTENT_TYPE.SCHEMA)
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getColumns:
        try:
            conf.dumper.dbTableColumns(conf.dbmsHandler.getColumns(), CONTENT_TYPE.COLUMNS)
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getCount:
        try:
            conf.dumper.dbTablesCount(conf.dbmsHandler.getCount())
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.commonColumns:
        try:
            conf.dumper.dbTableColumns(columnExists(paths.COMMON_COLUMNS))
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.dumpTable:
        try:
            conf.dbmsHandler.dumpTable()
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.dumpAll:
        try:
            conf.dbmsHandler.dumpAll()
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.search:
        try:
            conf.dbmsHandler.search()
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.sqlQuery:
        for query in conf.sqlQuery.strip(';').split(';'):
            query = query.strip()
            if query:
                conf.dumper.sqlQuery(query, conf.dbmsHandler.sqlQuery(query))

    if conf.sqlShell:
        conf.dbmsHandler.sqlShell()

    if conf.sqlFile:
        conf.dbmsHandler.sqlFile()

    # User-defined function options
    if conf.udfInject:
        conf.dbmsHandler.udfInjectCustom()

    # File system options
    if conf.fileRead:
        conf.dumper.rFile(conf.dbmsHandler.readFile(conf.fileRead))

    if conf.fileWrite:
        conf.dbmsHandler.writeFile(conf.fileWrite, conf.fileDest, conf.fileWriteType)

    if conf.commonFiles:
        try:
            conf.dumper.rFile(fileExists(paths.COMMON_FILES))
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    # Operating system options
    if conf.osCmd:
        conf.dbmsHandler.osCmd()

    if conf.osShell:
        conf.dbmsHandler.osShell()

    if conf.osPwn:
        conf.dbmsHandler.osPwn()

    if conf.osSmb:
        conf.dbmsHandler.osSmb()

    if conf.osBof:
        conf.dbmsHandler.osBof()

    # Windows registry options
    if conf.regRead:
        conf.dumper.registerValue(conf.dbmsHandler.regRead())

    if conf.regAdd:
        conf.dbmsHandler.regAdd()

    if conf.regDel:
        conf.dbmsHandler.regDel()

    # Miscellaneous options
    if conf.cleanup:
        conf.dbmsHandler.cleanup()

    if conf.direct:
        conf.dbmsConnector.close()
