#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import PLACE
from lib.core.exception import sqlmapNoneDataException
from lib.request import inject
#from lib.techniques.inband.union.use import unionUse

from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def __init__(self):
        GenericFilesystem.__init__(self)
