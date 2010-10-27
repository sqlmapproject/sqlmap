#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.exception import sqlmapUnsupportedFeatureException

from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        errMsg  = "on SAP MaxDB it is not possible to establish a "
        errMsg += "direct connection"
        raise sqlmapUnsupportedFeatureException, errMsg
