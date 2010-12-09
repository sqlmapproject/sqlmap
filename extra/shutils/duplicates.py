#!/usr/bin/env python

"""
$Id: fingerprint.py 2463 2010-11-30 22:40:25Z inquisb $

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

# Removes duplicate entries in wordlist like files

import sys

if len(sys.argv) > 0:

    items = list()
    f = open(sys.argv[1], 'r')

    for item in f.readlines():
        item = item.strip()
        try:
            str.encode(item)
            if item in items:
                if item:
                    print item
            else:
                items.append(item)

            if not item:
                items.append('')
        except:
            pass
    f.close()

    f = open(sys.argv[1], 'w+')
    f.writelines("\n".join(items))
    f.close()
