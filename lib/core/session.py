#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.common import dataToSessionFile
from lib.core.common import formatFingerprintString
from lib.core.common import readInput
from lib.core.convert import base64pickle
from lib.core.convert import base64unpickle
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import injectionDict
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.settings import MSSQL_ALIASES
from lib.core.settings import MYSQL_ALIASES
from lib.core.settings import PGSQL_ALIASES
from lib.core.settings import ORACLE_ALIASES

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

def setString():
    """
    Save string to match in session file.
    """

    condition = (
                  not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("String") )
                )

    if condition:
        dataToSessionFile("[%s][None][None][String][%s]\n" % (conf.url, safeFormatString(conf.string)))

def setRegexp():
    """
    Save regular expression to match in session file.
    """

    condition = (
                  not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("Regular expression") )
                )

    if condition:
        dataToSessionFile("[%s][None][None][Regular expression][%s]\n" % (conf.url, safeFormatString(conf.regexp)))

def setMatchRatio():
    condition = (
                  isinstance(conf.matchRatio, (int, float))
                  and ( not kb.resumedQueries
                  or ( kb.resumedQueries.has_key(conf.url) and not
                  kb.resumedQueries[conf.url].has_key("Match ratio") ) )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][Match ratio][%s]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]), conf.matchRatio))

def setInjection(inj):
    """
    Save information retrieved about injection place and parameter in the
    session file.
    """

    condition = (
                  ( not kb.resumedQueries
                  or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("Injection data")
                  ) )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][Injection data][%s]\n" % (conf.url, inj.place, safeFormatString(conf.parameters[inj.place]), base64pickle(inj)))

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

    firstRegExp = "(%s|%s|%s|%s)" % ("|".join([alias for alias in MSSQL_ALIASES]),
                                     "|".join([alias for alias in MYSQL_ALIASES]),
                                     "|".join([alias for alias in PGSQL_ALIASES]),
                                     "|".join([alias for alias in ORACLE_ALIASES]))
    dbmsRegExp = re.search("^%s" % firstRegExp, dbms, re.I)

    if dbmsRegExp:
        dbms = dbmsRegExp.group(1)

    kb.dbms = dbms

    logger.info("the back-end DBMS is %s" % kb.dbms)

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

    infoMsg   = ""
    condition = (
                  not kb.resumedQueries
                  or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("OS") )
                )

    if not kb.bannerFp:
        return

    if "type" in kb.bannerFp:
        kb.os   = formatFingerprintString(kb.bannerFp["type"])
        infoMsg = "the back-end DBMS operating system is %s" % kb.os

    if "distrib" in kb.bannerFp:
        kb.osVersion = formatFingerprintString(kb.bannerFp["distrib"])
        infoMsg     += " %s" % kb.osVersion

    if "sp" in kb.bannerFp:
        kb.osSP = int(formatFingerprintString(kb.bannerFp["sp"]).replace("Service Pack ", ""))

    elif "sp" not in kb.bannerFp and kb.os == "Windows":
        kb.osSP = 0

    if kb.os and kb.osVersion and kb.osSP:
        infoMsg += " Service Pack %d" % kb.osSP

    if infoMsg:
        logger.info(infoMsg)

    if condition:
        dataToSessionFile("[%s][%s][%s][OS][%s]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]), safeFormatString(kb.os)))

def setBooleanBased(place, parameter, payload):
    condition = (
                  not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("Boolean-based blind injection") )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][Boolean-based blind injection][%s]\n" % (conf.url, place, safeFormatString(conf.parameters[place]), payload))

def setStacked(place, parameter, payload):
    condition = (
                  not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("Stacked queries") )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][Stacked queries][%s]\n" % (conf.url, place, safeFormatString(conf.parameters[place]), payload))

def setError(place, parameter, payload):
    condition = (
                  not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("Error-based injection") )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][Error-based injection][%s]\n" % (conf.url, place, safeFormatString(conf.parameters[place]), payload))

def setTimeBased(place, parameter, payload):
    condition = (
                  not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("Time-based blind injection") )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][Time-based blind injection][%s]\n" % (conf.url, place, safeFormatString(conf.parameters[place]), payload))

def setUnion(comment=None, count=None, position=None, negative=False, falseCond=False, char=None, payload=None):
    """
    @param comment: union comment to save in session file
    @type comment: C{str}

    @param count: union count to save in session file
    @type count: C{str}

    @param position: union position to save in session file
    @type position: C{str}
    """

    if comment:
        condition = (
                      not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                      not kb.resumedQueries[conf.url].has_key("Union comment") )
                    )

        if condition:
            dataToSessionFile("[%s][%s][%s][Union comment][%s]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]), safeFormatString(comment)))

        kb.unionComment = comment

    if count:
        condition = (
                      not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                      not kb.resumedQueries[conf.url].has_key("Union count") )
                    )

        if condition:
            dataToSessionFile("[%s][%s][%s][Union count][%d]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]), count))

        kb.unionCount = count

    if position is not None:
        condition = (
                      not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                      not kb.resumedQueries[conf.url].has_key("Union position") )
                    )

        if condition:
            dataToSessionFile("[%s][%s][%s][Union position][%s]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]), position))

        kb.unionPosition = position

    if negative:
        condition = (
                      not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                      ( not kb.resumedQueries[conf.url].has_key("Union negative")
                      ) )
                    )

        if condition:
            dataToSessionFile("[%s][%s][%s][Union negative][Yes]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place])))

        kb.unionNegative = True

    if falseCond:
        condition = (
                      not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                      ( not kb.resumedQueries[conf.url].has_key("Union false condition")
                      ) )
                    )

        if condition:
            dataToSessionFile("[%s][%s][%s][Union false condition][Yes]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place])))

        kb.unionFalseCond = True

    if char:
        condition = (
                      not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                      ( not kb.resumedQueries[conf.url].has_key("Union char")
                      ) )
                    )

        if condition:
            dataToSessionFile("[%s][%s][%s][Union char][%s]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]), char))

    if payload:
        condition = (
                      not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                      ( not kb.resumedQueries[conf.url].has_key("Union payload")
                      ) )
                    )

        if condition:
            dataToSessionFile("[%s][%s][%s][Union payload][%s]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]), payload))

        kb.unionTest = payload

def setRemoteTempPath():
    condition = (
                  not kb.resumedQueries or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("Remote temp path") )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][Remote temp path][%s]\n" % (conf.url, kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]), safeFormatString(conf.tmpPath)))

def resumeConfKb(expression, url, value):
    if expression == "String" and url == conf.url:
        string = unSafeFormatString(value[:-1])

        logMsg = "resuming string match '%s' from session file" % string
        logger.info(logMsg)

        if string and ( not conf.string or string != conf.string ):
            if not conf.string:
                message = "you did not provide any string to match. "
            else:
                message  = "The string you provided does not match "
                message += "the resumed string. "

            message += "Do you want to use the resumed string "
            message += "to be matched in page when the query "
            message += "is valid? [Y/n] "
            test = readInput(message, default="Y")

            if not test or test[0] in ("y", "Y"):
                conf.string = string

    elif expression == "Regular expression" and url == conf.url:
        regexp = unSafeFormatString(value[:-1])

        logMsg = "resuming regular expression match '%s' from session file" % regexp
        logger.info(logMsg)

        if regexp and ( not conf.regexp or regexp != conf.regexp ):
            if not conf.regexp:
                message  = "you did not provide any regular expression "
                message += "to match. "
            else:
                message  = "The regular expression you provided does not "
                message += "match the resumed regular expression. "

            message += "Do you want to use the resumed regular expression "
            message += "to be matched in page when the query "
            message += "is valid? [Y/n] "
            test = readInput(message, default="Y")

            if not test or test[0] in ("y", "Y"):
                conf.regexp = regexp

    elif expression == "Match ratio" and url == conf.url and conf.matchRatio is None:
        matchRatio = value[:-1]

        logMsg = "resuming match ratio '%s' from session file" % matchRatio
        logger.info(logMsg)

        try:
            conf.matchRatio = round(float(matchRatio), 3)
        except ValueError:
            pass

    elif expression == "Injection data" and url == conf.url:
        injection = base64unpickle(value[:-1])
        kb.injections.append(injection)

        logMsg = "resuming injection data"
        logger.info(logMsg)

    elif expression == "Boolean-based blind injection" and url == conf.url:
        kb.booleanTest = unSafeFormatString(value[:-1])

        logMsg = "resuming boolean-based blind injection "
        logMsg += "'%s' from session file" % kb.booleanTest
        logger.info(logMsg)

    elif expression == "Error-based injection" and url == conf.url:
        kb.errorTest = unSafeFormatString(value[:-1])

        logMsg = "resuming error-based injection "
        logMsg += "'%s' from session file" % kb.errorTest
        logger.info(logMsg)

    elif expression == "Stacked queries" and url == conf.url:
        kb.stackedTest = unSafeFormatString(value[:-1])

        logMsg = "resuming stacked queries syntax "
        logMsg += "'%s' from session file" % kb.stackedTest
        logger.info(logMsg)

    elif expression == "Time-based blind injection" and url == conf.url:
        kb.timeTest = unSafeFormatString(value[:-1])

        logMsg = "resuming time-based blind injection "
        logMsg += "'%s' from session file" % kb.timeTest
        logger.info(logMsg)

    elif expression == "DBMS" and url == conf.url:
        dbms        = unSafeFormatString(value[:-1])
        dbms        = dbms.lower()
        dbmsVersion = None

        logMsg = "resuming back-end DBMS '%s' " % dbms
        logMsg += "from session file"
        logger.info(logMsg)

        firstRegExp = "(%s|%s|%s|%s)" % ("|".join([alias for alias in MSSQL_ALIASES]),
                                         "|".join([alias for alias in MYSQL_ALIASES]),
                                         "|".join([alias for alias in PGSQL_ALIASES]),
                                         "|".join([alias for alias in ORACLE_ALIASES]))
        dbmsRegExp = re.search("%s ([\d\.]+)" % firstRegExp, dbms)

        if dbmsRegExp:
            dbms        = dbmsRegExp.group(1)
            dbmsVersion = [ dbmsRegExp.group(2) ]

        if conf.dbms and conf.dbms.lower() != dbms:
            message  = "you provided '%s' as back-end DBMS, " % conf.dbms
            message += "but from a past scan information on the target URL "
            message += "sqlmap assumes the back-end DBMS is %s. " % dbms
            message += "Do you really want to force the back-end "
            message += "DBMS value? [y/N] "
            test = readInput(message, default="N")

            if not test or test[0] in ("n", "N"):
                kb.dbms = dbms
                kb.dbmsVersion = dbmsVersion
        else:
            kb.dbms = dbms
            kb.dbmsVersion = dbmsVersion

    elif expression == "OS" and url == conf.url:
        os = unSafeFormatString(value[:-1])

        logMsg = "resuming back-end DBMS operating system '%s' " % os
        logMsg += "from session file"
        logger.info(logMsg)

        if conf.os and conf.os.lower() != os.lower():
            message  = "you provided '%s' as back-end DBMS operating " % conf.os
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

    elif expression == "Union comment" and url == conf.url:
        kb.unionComment = unSafeFormatString(value[:-1])

        logMsg = "resuming union comment "
        logMsg += "'%s' from session file" % kb.unionComment
        logger.info(logMsg)

    elif expression == "Union count" and url == conf.url:
        kb.unionCount = int(value[:-1])

        logMsg = "resuming union count "
        logMsg += "%s from session file" % kb.unionCount
        logger.info(logMsg)

    elif expression == "Union position" and url == conf.url:
        kb.unionPosition = int(value[:-1])

        logMsg = "resuming union position "
        logMsg += "%s from session file" % kb.unionPosition
        logger.info(logMsg)

    elif expression == "Union negative" and url == conf.url:
        kb.unionNegative = True if value[:-1] == "Yes" else False

        logMsg = "resuming union negative from session file"
        logger.info(logMsg)

    elif expression == "Union false condition" and url == conf.url:
        kb.unionFalseCond = True if value[:-1] == "Yes" else False

        logMsg = "resuming union false condition from session file"
        logger.info(logMsg)

    elif expression == "Union char" and url == conf.url:
        conf.uChar = value[:-1]

        logMsg = "resuming union char %s from session file" % conf.uChar
        logger.info(logMsg)

    elif expression == "Union payload" and url == conf.url:
        kb.unionTest = value[:-1]

        logMsg = "resuming union payload "
        logMsg += "%s from session file" % kb.unionTest
        logger.info(logMsg)

    elif expression == "Remote temp path" and url == conf.url:
        conf.tmpPath = unSafeFormatString(value[:-1])

        logMsg = "resuming remote absolute path of temporary "
        logMsg += "files directory '%s' from session file" % conf.tmpPath
        logger.info(logMsg)
