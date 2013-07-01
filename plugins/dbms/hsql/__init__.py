#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import HSQL_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.hsql.enumeration import Enumeration
from plugins.dbms.hsql.filesystem import Filesystem
from plugins.dbms.hsql.fingerprint import Fingerprint
from plugins.dbms.hsql.syntax import Syntax
from plugins.dbms.hsql.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class HSQLMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines MySQL methods
    """

    def __init__(self):
        self.excludeDbsList = HSQL_SYSTEM_DBS
        self.sysUdfs = {
                         # UDF name:    UDF return data-type
                         "sys_exec":    { "return": "int" },
                         "sys_eval":    { "return": "string" },
                         "sys_bineval": { "return": "int" }
                       }

        Syntax.__init__(self)
        Fingerprint.__init__(self)
        Enumeration.__init__(self)
        Filesystem.__init__(self)
        Miscellaneous.__init__(self)
        Takeover.__init__(self)

    unescaper[DBMS.HSQL] = Syntax.escape
