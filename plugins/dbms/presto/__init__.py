#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import PRESTO_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.presto.enumeration import Enumeration
from plugins.dbms.presto.filesystem import Filesystem
from plugins.dbms.presto.fingerprint import Fingerprint
from plugins.dbms.presto.syntax import Syntax
from plugins.dbms.presto.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class PrestoMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Presto methods
    """

    def __init__(self):
        self.excludeDbsList = PRESTO_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.PRESTO] = Syntax.escape
