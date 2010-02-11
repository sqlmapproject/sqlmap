#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

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

from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.dump import dumper
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

        message   = "do you want to retrieve the command standard "
        message  += "output? [Y/n] "
        getOutput = readInput(message, default="Y")

        if not getOutput or getOutput in ("y", "Y"):
            output = self.evalCmd(cmd)

            if output:
                dumper.string("command standard output", output)
            else:
                print "No output"
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
