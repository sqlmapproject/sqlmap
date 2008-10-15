#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2008 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""



import re

from lib.core.common import dataToSessionFile
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.settings import MSSQL_ALIASES
from lib.core.settings import MYSQL_ALIASES

def setString():
    """
    Save string to match in session file.
    """

    condition = (
                  conf.sessionFile and ( not kb.resumedQueries
                  or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("String") ) )
                )

    if condition:
        dataToSessionFile("[%s][None][None][String][%s]\n" % (conf.url, conf.string))


def setInjection():
    """
    Save information retrieved about injection place and parameter in the
    session file.
    """

    if kb.injPlace == "User-Agent":
        kb.injParameter = conf.agent

    condition = (
                  kb.injPlace and kb.injParameter and
                  conf.sessionFile and ( not kb.resumedQueries
                  or ( kb.resumedQueries.has_key(conf.url) and
                  ( not kb.resumedQueries[conf.url].has_key("Injection point") 
                  or not kb.resumedQueries[conf.url].has_key("Injection parameter")
                  or not kb.resumedQueries[conf.url].has_key("Injection type")
                  ) ) )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][Injection point][%s]\n" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], kb.injPlace))
        dataToSessionFile("[%s][%s][%s][Injection parameter][%s]\n" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], kb.injParameter))
        dataToSessionFile("[%s][%s][%s][Injection type][%s]\n" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], kb.injType))


def setParenthesis(parenthesisCount):
    """
    @param parenthesisCount: number of parenthesis to be set into the
    knowledge base as fingerprint.
    @type parenthesisCount: C{int}
    """

    condition = (
                  conf.sessionFile and ( not kb.resumedQueries
                  or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("Parenthesis") ) )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][Parenthesis][%s]\n" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], parenthesisCount))

    kb.parenthesis = parenthesisCount


def setDbms(dbms):
    """
    @param dbms: database management system to be set into the knowledge
    base as fingerprint.
    @type dbms: C{str}
    """

    condition = (
                  conf.sessionFile and ( not kb.resumedQueries
                  or ( kb.resumedQueries.has_key(conf.url) and
                  not kb.resumedQueries[conf.url].has_key("DBMS") ) )
                )

    if condition:
        dataToSessionFile("[%s][%s][%s][DBMS][%s]\n" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], dbms))

    firstRegExp = "(%s|%s)" % ("|".join([alias for alias in MSSQL_ALIASES]),
                               "|".join([alias for alias in MYSQL_ALIASES]))
    dbmsRegExp = re.search("^%s" % firstRegExp, dbms, re.I)

    if dbmsRegExp:
        dbms = dbmsRegExp.group(1)

    kb.dbms = dbms


def setUnion(comment=None, count=None, position=None):
    """
    @param comment: union comment to save in session file
    @type comment: C{str}

    @param count: union count to save in session file
    @type count: C{str}

    @param position: union position to save in session file
    @type position: C{str}
    """

    if comment and count:
        condition = (
                      conf.sessionFile and ( not kb.resumedQueries
                      or ( kb.resumedQueries.has_key(conf.url) and
                      ( not kb.resumedQueries[conf.url].has_key("Union comment") 
                      or not kb.resumedQueries[conf.url].has_key("Union count")
                      ) ) )
                    )

        if condition:
            dataToSessionFile("[%s][%s][%s][Union comment][%s]\n" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], comment))
            dataToSessionFile("[%s][%s][%s][Union count][%s]\n" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], count))

        kb.unionComment = comment
        kb.unionCount = count

    elif position:
        condition = (
                      conf.sessionFile and ( not kb.resumedQueries
                      or ( kb.resumedQueries.has_key(conf.url) and
                      ( not kb.resumedQueries[conf.url].has_key("Union position")
                      ) ) )
                    )

        if condition:
            dataToSessionFile("[%s][%s][%s][Union position][%s]\n" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], position))

        kb.unionPosition = position


def resumeConfKb(expression, url, value):
    if expression == "String" and url == conf.url:
        string = value[:-1]

        logMsg  = "resuming string match '%s' from session file" % string
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

    elif expression == "Injection point" and url == conf.url:
        injPlace = value[:-1]

        logMsg  = "resuming injection point '%s' from session file" % injPlace
        logger.info(logMsg)

        if not conf.paramDict.has_key(injPlace):
            warnMsg  = "none of the parameters you provided "
            warnMsg += "matches the resumable injection point. "
            warnMsg += "sqlmap is going to reidentify the "
            warnMsg += "injectable point"
            logger.warn(warnMsg)
        else:
            kb.injPlace = injPlace

    elif expression == "Injection parameter" and url == conf.url:
        injParameter = value[:-1]

        logMsg  = "resuming injection parameter '%s' from session file" % injParameter
        logger.info(logMsg)

        condition = (
                      not conf.paramDict.has_key(kb.injPlace) or
                      not conf.paramDict[kb.injPlace].has_key(injParameter)
                    )

        if condition:
            warnMsg  = "none of the parameters you provided "
            warnMsg += "matches the resumable injection parameter. "
            warnMsg += "sqlmap is going to reidentify the "
            warnMsg += "injectable point"
            logger.warn(warnMsg)
        else:
            kb.injParameter = injParameter

    elif expression == "Injection type" and url == conf.url:
        kb.injType = value[:-1]

        logMsg  = "resuming injection type '%s' from session file" % kb.injType
        logger.info(logMsg)

    elif expression == "Parenthesis" and url == conf.url:
        kb.parenthesis = int(value[:-1])

        logMsg  = "resuming %d number of " % kb.parenthesis
        logMsg += "parenthesis from session file"
        logger.info(logMsg)

    elif expression == "DBMS" and url == conf.url:
        dbms = value[:-1]

        logMsg  = "resuming back-end DBMS '%s' " % dbms
        logMsg += "from session file"
        logger.info(logMsg)

        dbms = dbms.lower()
        firstRegExp = "(%s|%s)" % ("|".join([alias for alias in MSSQL_ALIASES]),
                                   "|".join([alias for alias in MYSQL_ALIASES]))
        dbmsRegExp = re.search("%s ([\d\.]+)" % firstRegExp, dbms)

        if dbmsRegExp:
            dbms = dbmsRegExp.group(1)
            kb.dbmsVersion = [dbmsRegExp.group(2)]

        if conf.dbms and conf.dbms.lower() != dbms:
            message  = "you provided '%s' as back-end DBMS, " % conf.dbms
            message += "but from a past scan information on the target URL "
            message += "sqlmap assumes the back-end DBMS is %s. " % dbms
            message += "Do you really want to force the back-end "
            message += "DBMS value? [y/N] "
            test = readInput(message, default="N")

            if not test or test[0] in ("n", "N"):
                conf.dbms = dbms
        else:
            conf.dbms = dbms

    elif expression == "Union comment" and url == conf.url:
        kb.unionComment = value[:-1]

        logMsg  = "resuming union comment "
        logMsg += "'%s' from session file" % kb.unionComment
        logger.info(logMsg)

    elif expression == "Union count" and url == conf.url:
        kb.unionCount = int(value[:-1])

        logMsg  = "resuming union count "
        logMsg += "%s from session file" % kb.unionCount
        logger.info(logMsg)

    elif expression == "Union position" and url == conf.url:
        kb.unionPosition = int(value[:-1])

        logMsg  = "resuming union position "
        logMsg += "%s from session file" % kb.unionPosition
        logger.info(logMsg)
