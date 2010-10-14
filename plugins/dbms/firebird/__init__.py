#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file doc/COPYING for copying permission.
"""

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

        Syntax.__init__(self)
        Fingerprint.__init__(self)
        Enumeration.__init__(self)
        Filesystem.__init__(self)
        Miscellaneous.__init__(self)
        Takeover.__init__(self)

        unescaper.setUnescape(FirebirdMap.unescape)
