#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import randomInt
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.settings import FROM_DUMMY_TABLE
from lib.techniques.dns.use import dnsUse


def dnsTest(payload):
    logger.info("testing for data retrieval through DNS channel")

    randInt = randomInt()
    kb.dnsTest = dnsUse(payload, "SELECT %d%s" % (randInt, FROM_DUMMY_TABLE.get(Backend.getIdentifiedDbms(), ""))) == str(randInt)

    if not kb.dnsTest:
        errMsg = "data retrieval through DNS channel failed. Turning off DNS exfiltration support"
        logger.error(errMsg)

        conf.dName = None
    else:
        infoMsg = "data retrieval through DNS channel was successful"
        logger.info(infoMsg)
