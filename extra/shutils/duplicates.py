#!/usr/bin/env python

# Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
# See the file 'doc/COPYING' for copying permission

# Removes duplicate entries in wordlist like files

import sys

if len(sys.argv) > 0:
    items = list()

    with open(sys.argv[1], 'r') as f:
        for item in f.readlines():
            item = item.strip()
            try:
                str.encode(item)
                if item in items:
                    if item:
                        print item
                else:
                    items.append(item)
            except:
                pass

    with open(sys.argv[1], 'w+') as f:
        f.writelines("\n".join(items))
