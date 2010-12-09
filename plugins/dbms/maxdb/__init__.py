#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import MAXDB_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.maxdb.enumeration import Enumeration
from plugins.dbms.maxdb.filesystem import Filesystem
from plugins.dbms.maxdb.fingerprint import Fingerprint
from plugins.dbms.maxdb.syntax import Syntax
from plugins.dbms.maxdb.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class MaxDBMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines SAP MaxDB methods
    """

    def __init__(self):
        self.excludeDbsList = MAXDB_SYSTEM_DBS

        Syntax.__init__(self)
        Fingerprint.__init__(self)
        Enumeration.__init__(self)
        Filesystem.__init__(self)
        Miscellaneous.__init__(self)
        Takeover.__init__(self)

        unescaper[DBMS.MAXDB] = MaxDBMap.unescape
        unescaper.setUnescape(MaxDBMap.unescape)
