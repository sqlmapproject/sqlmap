#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def osCmd(self):
        errMsg = "on Cubrid it is not possible to execute commands"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osShell(self):
        errMsg = "on Cubrid it is not possible to execute commands"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osPwn(self):
        errMsg = "on Cubrid it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osSmb(self):
        errMsg = "on Cubrid it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise SqlmapUnsupportedFeatureException(errMsg)
