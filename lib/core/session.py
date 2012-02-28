#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import dataToSessionFile
from lib.core.common import intersect
from lib.core.common import readInput
from lib.core.common import singleTimeWarnMessage
from lib.core.convert import base64pickle
from lib.core.convert import base64unpickle
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import OS
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

def resumeConfKb(expression, url, value):
    if expression == "Dynamic markings" and url == conf.url:
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

    elif conf.freshQueries:
        pass

    elif expression == "xp_cmdshell availability" and url == conf.url:
        kb.xpCmdshellAvailable = True if unSafeFormatString(value[:-1]).lower() == "true" else False
        infoMsg = "resuming xp_cmdshell availability"
        logger.info(infoMsg)
