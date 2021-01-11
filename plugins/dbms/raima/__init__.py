#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import RAIMA_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.raima.enumeration import Enumeration
from plugins.dbms.raima.filesystem import Filesystem
from plugins.dbms.raima.fingerprint import Fingerprint
from plugins.dbms.raima.syntax import Syntax
from plugins.dbms.raima.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class RaimaMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Raima methods
    """

    def __init__(self):
        self.excludeDbsList = RAIMA_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.RAIMA] = Syntax.escape
