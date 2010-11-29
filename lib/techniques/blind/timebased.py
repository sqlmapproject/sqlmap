#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import time

from lib.core.agent import agent
from lib.core.common import calculateDeltaSeconds
from lib.core.common import getDelayQuery
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.request import inject
from lib.request.connect import Connect as Request

def timeUse(query):
    start      = time.time()
    _, _       = inject.goStacked(query)
    duration   = calculateDeltaSeconds(start)

    return duration
