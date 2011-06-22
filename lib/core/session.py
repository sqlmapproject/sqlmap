#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import dataToSessionFile
from lib.core.common import getFilteredPageContent
from lib.core.common import intersect
from lib.core.common import readInput
from lib.core.convert import base64pickle
from lib.core.convert import base64unpickle
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import injectionDict
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.settings import METADB_SUFFIX
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import UNKNOWN_DBMS_VERSION

def safeFormatString(value):
    retVal = value
    if retVal:
        retVal = retVal.replace("[", "__LEFT_SQUARE_BRACKET__").replace("]", "__RIGHT_SQUARE_BRACKET__")
    return retVal

def unSafeFormatString(value):
    retVal = value
    if retVal:
        retVal = retVal.replace("__LEFT_SQUARE_BRACKET__", "[").replace("__RIGHT_SQUARE_BRACKET__", "]")
    return retVal

def setInjection(inj):
    """
    Save information retrieved about injection place and parameter in the
    session file.
    """

    condition = ( not kb.resumedQueries
                  or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("Injection data"))
                  or ( kb.resumedQueries[conf.url].has_key("Injection data")
                  and intersect(base64unpickle(kb.resumedQueries[conf.url]["Injection data"][:-1]).data.keys(),\
                    inj.data.keys()) != inj.data.keys()
                ) )

    if condition:
        dataToSessionFile("[%s][%s][%s][Injection data][%s]\n" % (conf.url, inj.place, safeFormatString(conf.parameters[inj.place]), base64pickle(inj)))

def setDynamicMarkings(markings):
    """
    Save information retrieved about dynamic markings to the
    session file.
    """

    condition = (
                  ( not kb.resumedQueries
                  or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("Dynamic markings")
                  ) )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][Dynamic markings][%s]\n" % (conf.url, None, None, base64pickle(markings)))

def setDbms(dbms):
    """
    @param dbms: database management system to be set into the knowledge
    base as fingerprint.
    @type dbms: C{str}
    """
    condition = (
                  not kb.resumedQueries
                  or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("DBMS") )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][DBMS][%s]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]), safeFormatString(dbms)))

    firstRegExp = "(%s)" % ("|".join([alias for alias in SUPPORTED_DBMS]))
    dbmsRegExp = re.search("^%s" % firstRegExp, dbms, re.I)

    if dbmsRegExp:
        dbms = dbmsRegExp.group(1)

    Backend.setDbms(dbms)

    logger.info("the back-end DBMS is %s" % Backend.getDbms())

def setOs():
    """
    Example of kb.bannerFp dictionary:

    {
      'sp': set(['Service Pack 4']),
      'dbmsVersion': '8.00.194',
      'dbmsServicePack': '0',
      'distrib': set(['2000']),
      'dbmsRelease': '2000',
      'type': set(['Windows'])
    }
    """

    infoMsg = ""
    condition = (
                  not kb.resumedQueries
                  or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("OS") )
                )

    if not kb.bannerFp:
        return

    if "type" in kb.bannerFp:
        Backend.setOs(Format.humanize(kb.bannerFp["type"]))
        infoMsg = "the back-end DBMS operating system is %s" % Backend.getOs()

    if "distrib" in kb.bannerFp:
        kb.osVersion = Format.humanize(kb.bannerFp["distrib"])
        infoMsg += " %s" % kb.osVersion

    if "sp" in kb.bannerFp:
        kb.osSP = int(Format.humanize(kb.bannerFp["sp"]).replace("Service Pack ", ""))

    elif "sp" not in kb.bannerFp and Backend.isOs(OS.WINDOWS):
        kb.osSP = 0

    if Backend.getOs() and kb.osVersion and kb.osSP:
        infoMsg += " Service Pack %d" % kb.osSP

    if infoMsg:
        logger.info(infoMsg)

    if condition:
        dataToSessionFile("[%s][%s][%s][OS][%s]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]), Backend.getOs()))

def setRemoteTempPath():
    condition = (
                  not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("Remote temp path") )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][Remote temp path][%s]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]), safeFormatString(conf.tmpPath)))

def setXpCmdshellAvailability(available):
    condition = (
                  not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("xp_cmdshell availability") )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][xp_cmdshell availability][%s]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]), str(available).lower()))

def resumeConfKb(expression, url, value):
    if expression == "Injection data" and url == conf.url:
        injection = base64unpickle(value[:-1])

        infoMsg = "resuming injection data from session file"
        logger.info(infoMsg)

        if injection.place in conf.paramDict and \
           injection.parameter in conf.paramDict[injection.place]:

            if not conf.tech or intersect(conf.tech, injection.data.keys()):
                if intersect(conf.tech, injection.data.keys()):
                    injection.data = dict(filter(lambda (key, item): key in conf.tech, injection.data.items()))

                if injection not in kb.injections:
                    kb.injections.append(injection)
        else:
            warnMsg = "there is an injection in %s parameter '%s' " % (injection.place, injection.parameter)
            warnMsg += "but you did not provided it this time"
            logger.warn(warnMsg)

    elif expression == "Dynamic markings" and url == conf.url:
        kb.dynamicMarkings = base64unpickle(value[:-1])
        infoMsg = "resuming dynamic markings from session file"
        logger.info(infoMsg)

    elif expression == "DBMS" and url == conf.url:
        dbms = unSafeFormatString(value[:-1])
        dbms = dbms.lower()
        dbmsVersion = [UNKNOWN_DBMS_VERSION]

        infoMsg = "resuming back-end DBMS '%s' " % dbms
        infoMsg += "from session file"
        logger.info(infoMsg)

        firstRegExp = "(%s)" % ("|".join([alias for alias in SUPPORTED_DBMS]))
        dbmsRegExp = re.search("%s ([\d\.]+)" % firstRegExp, dbms)

        if dbmsRegExp:
            dbms = dbmsRegExp.group(1)
            dbmsVersion = [ dbmsRegExp.group(2) ]

        if conf.dbms and conf.dbms.lower() != dbms:
            message = "you provided '%s' as back-end DBMS, " % conf.dbms
            message += "but from a past scan information on the target URL "
            message += "sqlmap assumes the back-end DBMS is %s. " % dbms
            message += "Do you really want to force the back-end "
            message += "DBMS value? [y/N] "
            test = readInput(message, default="N")

            if not test or test[0] in ("n", "N"):
                conf.dbms = None
                Backend.setDbms(dbms)
                Backend.setVersionList(dbmsVersion)
        else:
            Backend.setDbms(dbms)
            Backend.setVersionList(dbmsVersion)

    elif expression == "OS" and url == conf.url:
        os = unSafeFormatString(value[:-1])

        if os and os != 'None':
            infoMsg = "resuming back-end DBMS operating system '%s' " % os
            infoMsg += "from session file"
            logger.info(infoMsg)

            if conf.os and conf.os.lower() != os.lower():
                message = "you provided '%s' as back-end DBMS operating " % conf.os
                message += "system, but from a past scan information on the "
                message += "target URL sqlmap assumes the back-end DBMS "
                message += "operating system is %s. " % os
                message += "Do you really want to force the back-end DBMS "
                message += "OS value? [y/N] "
                test = readInput(message, default="N")

                if not test or test[0] in ("n", "N"):
                    conf.os = os
            else:
                conf.os = os

            Backend.setOs(conf.os)

    elif expression == "Remote temp path" and url == conf.url and conf.tmpPath is None:
        conf.tmpPath = unSafeFormatString(value[:-1])

        infoMsg = "resuming remote absolute path of temporary "
        infoMsg += "files directory '%s' from session file" % conf.tmpPath
        logger.info(infoMsg)

    elif expression == "TABLE_EXISTS" and url == conf.url:
        table = unSafeFormatString(value[:-1])
        split = '..' if Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE) else '.'

        if split in table:
            db, table = table.split(split)
        else:
            db = "%s%s" % (Backend.getIdentifiedDbms(), METADB_SUFFIX)

        infoMsg = "resuming brute forced table name "
        infoMsg += "'%s' from session file" % table
        logger.info(infoMsg)

        kb.brute.tables.append((db, table))

    elif expression == "COLUMN_EXISTS" and url == conf.url:
        table, column = unSafeFormatString(value[:-1]).split('|')
        colName, colType = column.split(' ')
        split = '..' if Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE) else '.'

        if split in table:
            db, table = table.split(split)
        else:
            db = "%s%s" % (Backend.getIdentifiedDbms(), METADB_SUFFIX)

        infoMsg = "resuming brute forced column name "
        infoMsg += "'%s' for table '%s' from session file" % (colName, table)
        logger.info(infoMsg)

        kb.brute.columns.append((db, table, colName, colType))

    elif expression == "xp_cmdshell availability" and url == conf.url:
        kb.xpCmdshellAvailable = True if unSafeFormatString(value[:-1]).lower() == "true" else False
        infoMsg = "resuming xp_cmdshell availability"
        logger.info(infoMsg)
