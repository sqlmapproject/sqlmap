#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import sys

PYVERSION = sys.version.split()[0]

if PYVERSION >= "3" or PYVERSION < "2.6":
    exit("[CRITICAL] wrong Python version detected ('%s'). For successfully running sqlmap you have to use 2.6 <= Python < 3.0" % PYVERSION)
else:
    from _sqlmap import main
    main()
