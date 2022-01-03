#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import MIMERSQL_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.mimersql.enumeration import Enumeration
from plugins.dbms.mimersql.filesystem import Filesystem
from plugins.dbms.mimersql.fingerprint import Fingerprint
from plugins.dbms.mimersql.syntax import Syntax
from plugins.dbms.mimersql.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class MimerSQLMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines MimerSQL methods
    """

    def __init__(self):
        self.excludeDbsList = MIMERSQL_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.MIMERSQL] = Syntax.escape
