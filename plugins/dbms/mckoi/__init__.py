#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import MCKOI_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.mckoi.enumeration import Enumeration
from plugins.dbms.mckoi.filesystem import Filesystem
from plugins.dbms.mckoi.fingerprint import Fingerprint
from plugins.dbms.mckoi.syntax import Syntax
from plugins.dbms.mckoi.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class MckoiMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Mckoi methods
    """

    def __init__(self):
        self.excludeDbsList = MCKOI_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.MCKOI] = Syntax.escape
