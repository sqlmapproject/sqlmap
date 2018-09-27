#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import sys
import time

PYVERSION = sys.version.split()[0]

if PYVERSION >= "3" or PYVERSION < "2.6":
    exit("[%s] [CRITICAL] incompatible Python version detected ('%s'). To successfully run sqlmap you'll have to use version 2.6.x or 2.7.x (visit 'https://www.python.org/downloads/')" % (time.strftime("%X"), PYVERSION))

errors = []
extensions = ("bz2", "gzip", "pyexpat", "ssl", "sqlite3", "zlib")
for _ in extensions:
    try:
        __import__(_)
    except ImportError:
        errors.append(_)

if errors:
    errMsg = "missing one or more core extensions (%s) " % (", ".join("'%s'" % _ for _ in errors))
    errMsg += "most likely because current version of Python has been "
    errMsg += "built without appropriate dev packages"
    exit(errMsg)
