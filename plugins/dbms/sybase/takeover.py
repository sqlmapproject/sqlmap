#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def __init__(self):
        GenericTakeover.__init__(self)

    def osCmd(self):
        errMsg = "on Sybase it is not possible to execute commands"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osShell(self):
        errMsg = "on Sybase it is not possible to execute commands"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osPwn(self):
        errMsg = "on Sybase it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osSmb(self):
        errMsg = "on Sybase it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise SqlmapUnsupportedFeatureException(errMsg)
