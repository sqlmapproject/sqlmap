#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import VIRTUOSO_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.virtuoso.enumeration import Enumeration
from plugins.dbms.virtuoso.filesystem import Filesystem
from plugins.dbms.virtuoso.fingerprint import Fingerprint
from plugins.dbms.virtuoso.syntax import Syntax
from plugins.dbms.virtuoso.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class VirtuosoMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Virtuoso methods
    """

    def __init__(self):
        self.excludeDbsList = VIRTUOSO_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.VIRTUOSO] = Syntax.escape
