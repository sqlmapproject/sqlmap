#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import DB2_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.db2.enumeration import Enumeration
from plugins.dbms.db2.filesystem import Filesystem
from plugins.dbms.db2.fingerprint import Fingerprint
from plugins.dbms.db2.syntax import Syntax
from plugins.dbms.db2.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class DB2Map(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines DB2 methods
    """

    def __init__(self):
        self.excludeDbsList = DB2_SYSTEM_DBS

        Syntax.__init__(self)
        Fingerprint.__init__(self)
        Enumeration.__init__(self)
        Filesystem.__init__(self)
        Miscellaneous.__init__(self)
        Takeover.__init__(self)

    unescaper[DBMS.DB2] = Syntax.escape
