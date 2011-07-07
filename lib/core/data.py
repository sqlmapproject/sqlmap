#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.datatype import advancedDict
from lib.core.settings import LOGGER

# sqlmap paths
paths = advancedDict()

# object to store original command line options
cmdLineOptions = advancedDict()

# object to share within function and classes command
# line options and settings
conf = advancedDict()

# object to share within function and classes results
kb = advancedDict()

# object with each database management system specific queries
queries = {}

# logger
logger = LOGGER
