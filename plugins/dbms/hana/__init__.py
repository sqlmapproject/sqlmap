#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import HANA_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.hana.enumeration import Enumeration
from plugins.dbms.hana.filesystem import Filesystem
from plugins.dbms.hana.fingerprint import Fingerprint
from plugins.dbms.hana.syntax import Syntax
from plugins.dbms.hana.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class HANAMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines SAP HANA methods
    """

    def __init__(self):
        self.excludeDbsList = HANA_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.HANA] = Syntax.escape
