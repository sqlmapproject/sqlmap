#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import MAXDB_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.maxdb.enumeration import Enumeration
from plugins.dbms.maxdb.filesystem import Filesystem
from plugins.dbms.maxdb.fingerprint import Fingerprint
from plugins.dbms.maxdb.syntax import Syntax
from plugins.dbms.maxdb.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class MaxDBMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines SAP MaxDB methods
    """

    def __init__(self):
        self.excludeDbsList = MAXDB_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.MAXDB] = Syntax.escape
