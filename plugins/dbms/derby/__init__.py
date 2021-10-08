#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import DERBY_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.derby.enumeration import Enumeration
from plugins.dbms.derby.filesystem import Filesystem
from plugins.dbms.derby.fingerprint import Fingerprint
from plugins.dbms.derby.syntax import Syntax
from plugins.dbms.derby.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class DerbyMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Apache Derby methods
    """

    def __init__(self):
        self.excludeDbsList = DERBY_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.DERBY] = Syntax.escape
