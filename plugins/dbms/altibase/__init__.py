#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import ALTIBASE_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.altibase.enumeration import Enumeration
from plugins.dbms.altibase.filesystem import Filesystem
from plugins.dbms.altibase.fingerprint import Fingerprint
from plugins.dbms.altibase.syntax import Syntax
from plugins.dbms.altibase.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class AltibaseMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Altibase methods
    """

    def __init__(self):
        self.excludeDbsList = ALTIBASE_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.ALTIBASE] = Syntax.escape
