#!/usr/bin/env python2

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def __init__(self):
        GenericFilesystem.__init__(self)
