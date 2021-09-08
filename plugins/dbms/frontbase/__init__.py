#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import FRONTBASE_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.frontbase.enumeration import Enumeration
from plugins.dbms.frontbase.filesystem import Filesystem
from plugins.dbms.frontbase.fingerprint import Fingerprint
from plugins.dbms.frontbase.syntax import Syntax
from plugins.dbms.frontbase.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class FrontBaseMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines FrontBase methods
    """

    def __init__(self):
        self.excludeDbsList = FRONTBASE_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.FRONTBASE] = Syntax.escape
