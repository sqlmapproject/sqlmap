#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def __init__(self):
        GenericTakeover.__init__(self)

    def osCmd(self):
        errMsg = "Not implemented in HSQL"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osShell(self):
        errMsg = "Not implemented in HSQL"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osPwn(self):
        errMsg = "Not implemented in HSQL"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osSmb(self):
        errMsg = "Not implemented in HSQL"
        raise SqlmapUnsupportedFeatureException(errMsg)
