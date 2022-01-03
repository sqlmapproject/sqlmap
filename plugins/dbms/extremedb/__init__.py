#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import EXTREMEDB_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.extremedb.enumeration import Enumeration
from plugins.dbms.extremedb.filesystem import Filesystem
from plugins.dbms.extremedb.fingerprint import Fingerprint
from plugins.dbms.extremedb.syntax import Syntax
from plugins.dbms.extremedb.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class ExtremeDBMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines eXtremeDB methods
    """

    def __init__(self):
        self.excludeDbsList = EXTREMEDB_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.EXTREMEDB] = Syntax.escape
