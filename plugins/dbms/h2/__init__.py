#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import H2_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.h2.enumeration import Enumeration
from plugins.dbms.h2.filesystem import Filesystem
from plugins.dbms.h2.fingerprint import Fingerprint
from plugins.dbms.h2.syntax import Syntax
from plugins.dbms.h2.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class H2Map(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines H2 methods
    """

    def __init__(self):
        self.excludeDbsList = H2_SYSTEM_DBS

        Syntax.__init__(self)
        Fingerprint.__init__(self)
        Enumeration.__init__(self)
        Filesystem.__init__(self)
        Miscellaneous.__init__(self)
        Takeover.__init__(self)

    unescaper[DBMS.H2] = Syntax.escape
