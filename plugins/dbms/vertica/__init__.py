#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import VERTICA_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.vertica.enumeration import Enumeration
from plugins.dbms.vertica.filesystem import Filesystem
from plugins.dbms.vertica.fingerprint import Fingerprint
from plugins.dbms.vertica.syntax import Syntax
from plugins.dbms.vertica.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class VerticaMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Vertica methods
    """

    def __init__(self):
        self.excludeDbsList = VERTICA_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.VERTICA] = Syntax.escape
