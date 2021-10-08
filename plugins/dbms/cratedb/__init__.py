#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import CRATEDB_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.cratedb.enumeration import Enumeration
from plugins.dbms.cratedb.filesystem import Filesystem
from plugins.dbms.cratedb.fingerprint import Fingerprint
from plugins.dbms.cratedb.syntax import Syntax
from plugins.dbms.cratedb.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class CrateDBMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines CrateDB methods
    """

    def __init__(self):
        self.excludeDbsList = CRATEDB_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.CRATEDB] = Syntax.escape
