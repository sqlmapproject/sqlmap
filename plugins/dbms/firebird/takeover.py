#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.exception import sqlmapUnsupportedFeatureException

from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def __init__(self):
        GenericTakeover.__init__(self)

    def osCmd(self):
        errMsg = "on Firebird it is not possible to execute commands"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osShell(self):
        errMsg = "on Firebird it is not possible to execute commands"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osPwn(self):
        errMsg = "on Firebird it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osSmb(self):
        errMsg = "on Firebird it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise sqlmapUnsupportedFeatureException, errMsg
