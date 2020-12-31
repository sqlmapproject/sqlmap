#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import DB2_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.db2.enumeration import Enumeration
from plugins.dbms.db2.filesystem import Filesystem
from plugins.dbms.db2.fingerprint import Fingerprint
from plugins.dbms.db2.syntax import Syntax
from plugins.dbms.db2.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class DB2Map(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines DB2 methods
    """

    def __init__(self):
        self.excludeDbsList = DB2_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.DB2] = Syntax.escape
