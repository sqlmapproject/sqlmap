#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from plugins.generic.enumeration import Enumeration as GenericEnumeration
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.common import Backend
from lib.core.common import unArrayizeValue
from lib.request import inject
from lib.parse.banner import bannerParser

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)

    def getBanner(self):
        if not conf.getBanner:
            return

        if kb.data.banner is None:
            infoMsg = "fetching banner"
            logger.info(infoMsg)

            query = queries[Backend.getIdentifiedDbms()].banner.query
            kb.data.banner = unArrayizeValue(inject.getValue(query, safeCharEncode=True))

        return kb.data.banner
