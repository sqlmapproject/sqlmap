#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
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
        self.sysUdfs = {
            # UDF name: UDF parameters' input data-type and return data-type
            "sys_exec": {"input": ["text"], "return": "int4"},
            "sys_eval": {"input": ["text"], "return": "text"},
            "sys_bineval": {"input": ["text"], "return": "int4"},
            "sys_fileread": {"input": ["text"], "return": "text"}
        }

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.PGSQL] = Syntax.escape
