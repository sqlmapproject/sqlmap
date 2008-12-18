#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2008 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

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



from lib.controller.handler import setHandler
from lib.core.common import getHtmlErrorFp
from lib.core.data import conf
from lib.core.data import kb
from lib.core.dump import dumper
from lib.core.exception import sqlmapUnsupportedDBMSException
from lib.core.settings import SUPPORTED_DBMS
from lib.techniques.blind.timebased import timeTest
from lib.techniques.inband.union.test import unionTest
from lib.techniques.outband.stacked import stackedTest


def action():
    """
    This function exploit the SQL injection on the affected
    url parameter and extract requested data from the
    back-end database management system or operating system
    if possible
    """

    # First of all we have to identify the back-end database management
    # system to be able to go ahead with the injection
    conf.dbmsHandler = setHandler()

    if not conf.dbmsHandler:
        htmlParsed = getHtmlErrorFp()

        errMsg  = "sqlmap was not able to fingerprint the "
        errMsg += "back-end database management system"

        if htmlParsed:
            errMsg += ", but from the HTML error page it was "
            errMsg += "possible to determinate that the "
            errMsg += "back-end DBMS is %s" % htmlParsed

        if htmlParsed and htmlParsed.lower() in SUPPORTED_DBMS:
            errMsg += ". Do not specify the back-end DBMS manually, "
            errMsg += "sqlmap will fingerprint the DBMS for you"
        else:
            errMsg += ". Support for this DBMS will be implemented if "
            errMsg += "you ask, just drop us an email"

        raise sqlmapUnsupportedDBMSException, errMsg

    print "%s\n" % conf.dbmsHandler.getFingerprint()

    # Techniques options
    if conf.stackedTest:
        dumper.string("stacked queries support", stackedTest())

    if conf.timeTest:
        dumper.string("time based blind sql injection payload", timeTest())

    if conf.unionTest:
        dumper.string("valid union", unionTest())

    # Enumeration options
    if conf.getBanner:
        dumper.string("banner", conf.dbmsHandler.getBanner())

    if conf.getCurrentUser:
        dumper.string("current user", conf.dbmsHandler.getCurrentUser())

    if conf.getCurrentDb:
        dumper.string("current database", conf.dbmsHandler.getCurrentDb())

    if conf.isDba:
        dumper.string("current user is DBA", conf.dbmsHandler.isDba())

    if conf.getUsers:
        dumper.lister("database management system users", conf.dbmsHandler.getUsers())

    if conf.getPasswordHashes:
        dumper.userSettings("database management system users password hashes",
                            conf.dbmsHandler.getPasswordHashes(), "password hash")

    if conf.getPrivileges:
        dumper.userSettings("database management system users privileges",
                            conf.dbmsHandler.getPrivileges(), "privilege")

    if conf.getDbs:
        dumper.lister("available databases", conf.dbmsHandler.getDbs())

    if conf.getTables:
        dumper.dbTables(conf.dbmsHandler.getTables())

    if conf.getColumns:
        dumper.dbTableColumns(conf.dbmsHandler.getColumns())

    if conf.dumpTable:
        dumper.dbTableValues(conf.dbmsHandler.dumpTable())

    if conf.dumpAll:
        conf.dbmsHandler.dumpAll()

    if conf.query:
        dumper.string(conf.query, conf.dbmsHandler.sqlQuery(conf.query))

    if conf.sqlShell:
        conf.dbmsHandler.sqlShell()

    # File system options
    if conf.rFile:
        dumper.string(conf.rFile, conf.dbmsHandler.readFile(conf.rFile))

    if conf.wFile:
        dumper.string(conf.wFile, conf.dbmsHandler.writeFile(conf.wFile))

    # Takeover options
    if conf.osShell:
        conf.dbmsHandler.osShell()
