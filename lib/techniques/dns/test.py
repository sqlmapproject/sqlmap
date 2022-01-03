#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import randomInt
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.dicts import FROM_DUMMY_TABLE
from lib.core.exception import SqlmapNotVulnerableException
from lib.techniques.dns.use import dnsUse

def dnsTest(payload):
    logger.info("testing for data retrieval through DNS channel")

    randInt = randomInt()
    kb.dnsTest = dnsUse(payload, "SELECT %d%s" % (randInt, FROM_DUMMY_TABLE.get(Backend.getIdentifiedDbms(), ""))) == str(randInt)

    if not kb.dnsTest:
        errMsg = "data retrieval through DNS channel failed"
        if not conf.forceDns:
            conf.dnsDomain = None
            errMsg += ". Turning off DNS exfiltration support"
            logger.error(errMsg)
        else:
            raise SqlmapNotVulnerableException(errMsg)
    else:
        infoMsg = "data retrieval through DNS channel was successful"
        logger.info(infoMsg)
