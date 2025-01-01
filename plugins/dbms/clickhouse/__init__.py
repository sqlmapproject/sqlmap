#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import CLICKHOUSE_SYSTEM_DBS
from lib.core.unescaper import unescaper

from plugins.dbms.clickhouse.enumeration import Enumeration
from plugins.dbms.clickhouse.filesystem import Filesystem
from plugins.dbms.clickhouse.fingerprint import Fingerprint
from plugins.dbms.clickhouse.syntax import Syntax
from plugins.dbms.clickhouse.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class ClickHouseMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines ClickHouse methods
    """

    def __init__(self):
        self.excludeDbsList = CLICKHOUSE_SYSTEM_DBS

        for cls in self.__class__.__bases__:
            cls.__init__(self)

    unescaper[DBMS.CLICKHOUSE] = Syntax.escape
