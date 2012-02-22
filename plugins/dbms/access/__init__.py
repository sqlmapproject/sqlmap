#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import ACCESS_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.access.enumeration import Enumeration
from plugins.dbms.access.filesystem import Filesystem
from plugins.dbms.access.fingerprint import Fingerprint
from plugins.dbms.access.syntax import Syntax
from plugins.dbms.access.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class AccessMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Microsoft Access methods
    """

    def __init__(self):
        self.excludeDbsList = ACCESS_SYSTEM_DBS

        Syntax.__init__(self)
        Fingerprint.__init__(self)
        Enumeration.__init__(self)
        Filesystem.__init__(self)
        Miscellaneous.__init__(self)
        Takeover.__init__(self)

    unescaper[DBMS.ACCESS] = Syntax.unescape
