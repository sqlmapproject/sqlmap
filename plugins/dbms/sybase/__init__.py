#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file doc/COPYING for copying permission.
"""

from lib.core.settings import SYBASE_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.sybase.enumeration import Enumeration
from plugins.dbms.sybase.filesystem import Filesystem
from plugins.dbms.sybase.fingerprint import Fingerprint
from plugins.dbms.sybase.syntax import Syntax
from plugins.dbms.sybase.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class SybaseMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Sybase methods
    """

    def __init__(self):
        self.excludeDbsList = SYBASE_SYSTEM_DBS

        Syntax.__init__(self)
        Fingerprint.__init__(self)
        Enumeration.__init__(self)
        Filesystem.__init__(self)
        Miscellaneous.__init__(self)
        Takeover.__init__(self)

        unescaper.setUnescape(SybaseMap.unescape)
