#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

try:
    import ibm_db
except ImportError, _:
    pass

from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapUnsupportedFeatureException

from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://code.google.com/p/ibm-db/
    User guide: http://code.google.com/p/ibm-db/wiki/ibm_db_README
    API: http://code.google.com/p/ibm-db/wiki/APIs
    Debian package: <none>
    License: Apache
    """

    def __init__(self):
        GenericConnector.__init__(self)
