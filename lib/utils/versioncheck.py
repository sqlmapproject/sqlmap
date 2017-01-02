#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import sys

PYVERSION = sys.version.split()[0]

if PYVERSION >= "3" or PYVERSION < "2.6":
    exit("[CRITICAL] incompatible Python version detected ('%s'). For successfully running sqlmap you'll have to use version 2.6.x or 2.7.x (visit 'http://www.python.org/download/')" % PYVERSION)

extensions = ("gzip", "ssl", "sqlite3", "zlib")
try:
    for _ in extensions:
        __import__(_)
except ImportError:
    errMsg = "missing one or more core extensions (%s) " % (", ".join("'%s'" % _ for _ in extensions))
    errMsg += "most probably because current version of Python has been "
    errMsg += "built without appropriate dev packages (e.g. 'libsqlite3-dev')"
    exit(errMsg)