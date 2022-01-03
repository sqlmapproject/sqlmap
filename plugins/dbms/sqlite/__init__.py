#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import SQLITE_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.sqlite.enumeration import Enumeration
from plugins.dbms.sqlite.filesystem import Filesystem
from plugins.dbms.sqlite.fingerprint import Fingerprint
from plugins.dbms.sqlite.syntax import Syntax
from plugins.dbms.sqlite.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class SQLiteMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines SQLite methods
    """

    def __init__(self):
        self.excludeDbsList = SQLITE_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.SQLITE] = Syntax.escape
