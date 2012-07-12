#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import sys

PYVERSION = sys.version.split()[0]

if PYVERSION >= "3" or PYVERSION < "2.6":
    exit("[CRITICAL] incompatible Python version detected ('%s'). For successfully running sqlmap you'll have to use version 2.6 or 2.7 (visit \"http://www.python.org/download/\")" % PYVERSION)
elif __name__ == "__main__":
    from _sqlmap import main
    from lib.controller.controller import start  # needed for proper working of --profile switch
    main()
