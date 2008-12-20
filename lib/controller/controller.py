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



from lib.controller.action import action
from lib.controller.checks import checkSqlInjection
from lib.controller.checks import checkDynParam
from lib.controller.checks import checkStability
from lib.controller.checks import checkString
from lib.controller.checks import checkRegexp
from lib.controller.checks import checkConnection
from lib.core.common import paramToDict
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapNotVulnerableException
from lib.core.session import setInjection
from lib.core.target import createTargetDirs
from lib.core.target import initTargetEnv
from lib.utils.parenthesis import checkForParenthesis


def __selectInjection(injData):
    """
    Selection function for injection place, parameters and type.
    """

    message  = "there were multiple injection points, please select the "
    message += "one to use to go ahead:\n"

    for i in xrange(0, len(injData)):
        injPlace     = injData[i][0]
        injParameter = injData[i][1]
        injType      = injData[i][2]

        message += "[%d] place: %s, parameter: " % (i, injPlace)
        message += "%s, type: %s" % (injParameter, injType)

        if i == 0:
            message += " (default)"

        message += "\n"

    message += "[q] Quit\nChoice: "
    select   = readInput(message, default="0")

    if not select:
        index = 0

    elif select.isdigit() and int(select) < len(injData) and int(select) >= 0:
        index = int(select)

    elif select[0] in ( "Q", "q" ):
        return "Quit"

    else:
        warnMsg = "Invalid choice, retry"
        logger.warn(warnMsg)
        __selectInjection(injData)

    return injData[index]


def start():
    """
    This function calls a function that performs checks on both URL
    stability and all GET, POST, Cookie and User-Agent parameters to
    check if they are dynamic and SQL injection affected
    """

    if conf.url:
        kb.targetUrls.add(( conf.url, conf.method, conf.data, conf.cookie ))

    if conf.configFile and not kb.targetUrls:
        errMsg  = "you did not edit the configuration file properly, set "
        errMsg += "the target url, list of targets or google dork"
        logger.error(errMsg)

    if kb.targetUrls and len(kb.targetUrls) > 1:
        infoMsg = "sqlmap got a total of %d targets" % len(kb.targetUrls)
        logger.info(infoMsg)

    hostCount               = 0
    receivedCookies         = []
    cookieStr               = ""
    setCookieAsInjectable   = True

    for targetUrl, targetMethod, targetData, targetCookie in kb.targetUrls:
        conf.url    = targetUrl
        conf.method = targetMethod
        conf.data   = targetData
        conf.cookie = targetCookie
        injData     = []

        if conf.multipleTargets:
            hostCount += 1
            message = "url %d:\n%s %s" % (hostCount, conf.method or "GET", targetUrl)

            if conf.cookie:
                message += "\nCookie: %s" % conf.cookie

            if conf.data:
                message += "\nPOST data: %s" % conf.data

            message += "\ndo you want to test this url? [Y/n/q] "
            test = readInput(message, default="Y")

            if not test:
                pass
            elif test[0] in ("n", "N"):
                continue
            elif test[0] in ("q", "Q"):
                break

            logMsg = "testing url %s" % targetUrl
            logger.info(logMsg)

        initTargetEnv()

        if not checkConnection() or not checkString() or not checkRegexp():
            continue

        for _, cookie in enumerate(conf.cj):
            cookie = str(cookie)
            index  = cookie.index(" for ")

            cookieStr += "%s;" % cookie[8:index]

        if cookieStr:
            cookieStr = cookieStr[:-1]

            if "Cookie" in conf.parameters:
                message  = "you provided an HTTP Cookie header value. "
                message += "The target url provided its own Cookie within "
                message += "the HTTP Set-Cookie header. Do you want to "
                message += "continue using the HTTP Cookie values that "
                message += "you provided? [Y/n] "
                test = readInput(message, default="Y")

                if not test or test[0] in ("y", "Y"):
                    setCookieAsInjectable = False

            if setCookieAsInjectable:
                conf.httpHeaders.append(("Cookie", cookieStr))
                conf.parameters["Cookie"] = cookieStr.replace("%", "%%")
                __paramDict = paramToDict("Cookie", cookieStr)

                if __paramDict:
                    conf.paramDict["Cookie"] = __paramDict
                    __testableParameters = True

        if not kb.injPlace or not kb.injParameter or not kb.injType:
            if not conf.string and not conf.regexp and not conf.eRegexp:
                # NOTE: this is not needed anymore, leaving only to display
                # a warning message to the user in case the page is not stable
                checkStability()

            for place in conf.parameters.keys():
                if not conf.paramDict.has_key(place):
                    continue

                paramDict = conf.paramDict[place]

                for parameter, value in paramDict.items():
                    if not checkDynParam(place, parameter, value):
                        warnMsg = "%s parameter '%s' is not dynamic" % (place, parameter)
                        logger.warn(warnMsg)
                    else:
                        logMsg = "%s parameter '%s' is dynamic" % (place, parameter)
                        logger.info(logMsg)

                        for parenthesis in range(0, 4):
                            logMsg  = "testing sql injection on %s " % place
                            logMsg += "parameter '%s' with " % parameter
                            logMsg += "%d parenthesis" % parenthesis
                            logger.info(logMsg)

                            injType = checkSqlInjection(place, parameter, value, parenthesis)

                            if injType:
                                injData.append((place, parameter, injType))

                                break
                            else:
                                infoMsg  = "%s parameter '%s' is not " % (place, parameter)
                                infoMsg += "injectable with %d parenthesis" % parenthesis
                                logger.info(infoMsg)

                        if not injData:
                            warnMsg  = "%s parameter '%s' is not " % (place, parameter)
                            warnMsg += "injectable"
                            logger.warn(warnMsg)

        if not kb.injPlace or not kb.injParameter or not kb.injType:
            if len(injData) == 1:
                injDataSelected = injData[0]

            elif len(injData) > 1:
                injDataSelected = __selectInjection(injData)

            elif conf.multipleTargets:
                continue

            else:
                return

            if injDataSelected == "Quit":
                return

            else:
                kb.injPlace, kb.injParameter, kb.injType = injDataSelected
                setInjection()

        if not conf.multipleTargets and ( not kb.injPlace or not kb.injParameter or not kb.injType ):
            raise sqlmapNotVulnerableException, "all parameters are not injectable"
        elif kb.injPlace and kb.injParameter and kb.injType:
            condition = False

            if conf.multipleTargets:
                message = "do you want to exploit this SQL injection? [Y/n] "
                exploit = readInput(message, default="Y")

                if not exploit or exploit[0] in ("y", "Y"):
                    condition = True
            else:
                condition = True

            if condition:
                checkForParenthesis()
                createTargetDirs()
                action()

    if conf.loggedToOut:
        logger.info("Fetched data logged to text files under '%s'" % conf.outputPath)
