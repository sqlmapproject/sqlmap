#!/usr/bin/env python

"""
Copyright (c) 2006-2015 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os,sys
from lib.core.enums import PRIORITY
from lib.core.data import logger
from lib.core.common import singleTimeWarnMessage

__priority__ = PRIORITY.LOWEST

def dependencies():
    singleTimeWarnMessage("For use Bypassip Tamper, Unix system is required, and root privileges\n Set --delay time for uniq IP by request")
    if sys.platform == 'win32':
		    logger.error("Bypass IP Tamper only work in Unix systems")
		    raise SystemExit
	  singleTimeWarnMessage("Initiating Tor..")
    os.system("service tor restart")

def tamper(payload, **kwargs):
    """    
	Use a different IP address for each request
    """
    logger.debug("Changing Public IP...")
    os.system("pkill -sighup tor")
    return payload if payload else payload
