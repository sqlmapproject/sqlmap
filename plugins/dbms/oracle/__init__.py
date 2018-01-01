#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import ORACLE_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.oracle.enumeration import Enumeration
from plugins.dbms.oracle.filesystem import Filesystem
from plugins.dbms.oracle.fingerprint import Fingerprint
from plugins.dbms.oracle.syntax import Syntax
from plugins.dbms.oracle.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class OracleMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Oracle methods
    """

    def __init__(self):
        self.excludeDbsList = ORACLE_SYSTEM_DBS

        Syntax.__init__(self)
        Fingerprint.__init__(self)
        Enumeration.__init__(self)
        Filesystem.__init__(self)
        Miscellaneous.__init__(self)
        Takeover.__init__(self)

    unescaper[DBMS.ORACLE] = Syntax.escape
