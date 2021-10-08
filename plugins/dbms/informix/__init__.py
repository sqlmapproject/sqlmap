#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import INFORMIX_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.informix.enumeration import Enumeration
from plugins.dbms.informix.filesystem import Filesystem
from plugins.dbms.informix.fingerprint import Fingerprint
from plugins.dbms.informix.syntax import Syntax
from plugins.dbms.informix.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class InformixMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Informix methods
    """

    def __init__(self):
        self.excludeDbsList = INFORMIX_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.INFORMIX] = Syntax.escape
