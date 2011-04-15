#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.exception import sqlmapUnsupportedFeatureException

from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def __init__(self):
        GenericTakeover.__init__(self)

    def osCmd(self):
        errMsg  = "Operating system command execution functionality not "
        errMsg += "yet implemented for Oracle"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osShell(self):
        errMsg  = "Operating system shell functionality not yet "
        errMsg += "implemented for Oracle"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osPwn(self):
        errMsg  = "Operating system out-of-band control functionality "
        errMsg += "not yet implemented for Oracle"
        raise sqlmapUnsupportedFeatureException, errMsg

    def osSmb(self):
        errMsg  = "One click operating system out-of-band control "
        errMsg += "functionality not yet implemented for Oracle"
        raise sqlmapUnsupportedFeatureException, errMsg
