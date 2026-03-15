#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import SPANNER_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.spanner.enumeration import Enumeration
from plugins.dbms.spanner.filesystem import Filesystem
from plugins.dbms.spanner.fingerprint import Fingerprint
from plugins.dbms.spanner.syntax import Syntax
from plugins.dbms.spanner.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class SpannerMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Spanner methods
    """

    def __init__(self):
        self.excludeDbsList = SPANNER_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.SPANNER] = Syntax.escape
