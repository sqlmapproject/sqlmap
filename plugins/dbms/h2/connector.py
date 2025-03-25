#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    def connect(self):
        errMsg = "on H2 it is not (currently) possible to establish a "
        errMsg += "direct connection"
        raise SqlmapUnsupportedFeatureException(errMsg)
