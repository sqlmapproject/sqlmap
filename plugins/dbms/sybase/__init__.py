#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import SYBASE_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.sybase.enumeration import Enumeration
from plugins.dbms.sybase.filesystem import Filesystem
from plugins.dbms.sybase.fingerprint import Fingerprint
from plugins.dbms.sybase.syntax import Syntax
from plugins.dbms.sybase.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class SybaseMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Sybase methods
    """

    def __init__(self):
        self.excludeDbsList = SYBASE_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.SYBASE] = Syntax.escape
