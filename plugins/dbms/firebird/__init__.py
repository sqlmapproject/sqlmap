#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import FIREBIRD_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.firebird.enumeration import Enumeration
from plugins.dbms.firebird.filesystem import Filesystem
from plugins.dbms.firebird.fingerprint import Fingerprint
from plugins.dbms.firebird.syntax import Syntax
from plugins.dbms.firebird.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class FirebirdMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Firebird methods
    """

    def __init__(self):
        self.excludeDbsList = FIREBIRD_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.FIREBIRD] = Syntax.escape
