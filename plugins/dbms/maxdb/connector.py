#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        errMsg = "on SAP MaxDB it is not possible to establish a "
        errMsg += "direct connection"
        raise SqlmapUnsupportedFeatureException, errMsg
