#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file doc/COPYING for copying permission.
"""

from lib.core.settings import SQLITE_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.sqlite.enumeration import Enumeration
from plugins.dbms.sqlite.filesystem import Filesystem
from plugins.dbms.sqlite.fingerprint import Fingerprint
from plugins.dbms.sqlite.syntax import Syntax
from plugins.dbms.sqlite.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class SQLiteMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines SQLite methods
    """

    def __init__(self):
        self.excludeDbsList = SQLITE_SYSTEM_DBS

        Syntax.__init__(self)
        Fingerprint.__init__(self)
        Enumeration.__init__(self)
        Filesystem.__init__(self)
        Miscellaneous.__init__(self)
        Takeover.__init__(self)

        unescaper.setUnescape(SQLiteMap.unescape)
