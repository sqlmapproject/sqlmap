#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import PGSQL_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.postgresql.enumeration import Enumeration
from plugins.dbms.postgresql.filesystem import Filesystem
from plugins.dbms.postgresql.fingerprint import Fingerprint
from plugins.dbms.postgresql.syntax import Syntax
from plugins.dbms.postgresql.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class PostgreSQLMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines PostgreSQL methods
    """

    def __init__(self):
        self.excludeDbsList = PGSQL_SYSTEM_DBS
        self.sysUdfs        = {
                                # UDF name:     UDF parameters' input data-type and return data-type
                                "sys_exec":     { "input":  [ "text" ], "return": "int4" },
                                "sys_eval":     { "input":  [ "text" ], "return": "text" },
                                "sys_bineval":  { "input":  [ "text" ], "return": "int4" },
                                "sys_fileread": { "input":  [ "text" ], "return": "text" }
                              }

        Syntax.__init__(self)
        Fingerprint.__init__(self)
        Enumeration.__init__(self)
        Filesystem.__init__(self)
        Miscellaneous.__init__(self)
        Takeover.__init__(self)

        unescaper[DBMS.PGSQL] = PostgreSQLMap.unescape
        unescaper.setUnescape(PostgreSQLMap.unescape)
