#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import HSQLDB_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.hsqldb.enumeration import Enumeration
from plugins.dbms.hsqldb.filesystem import Filesystem
from plugins.dbms.hsqldb.fingerprint import Fingerprint
from plugins.dbms.hsqldb.syntax import Syntax
from plugins.dbms.hsqldb.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class HSQLDBMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines HSQLDB methods
    """

    def __init__(self):
        self.excludeDbsList = HSQLDB_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.HSQLDB] = Syntax.escape
