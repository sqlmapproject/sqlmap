#!/usr/bin/env python

# Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
# See the file 'LICENSE' for copying permission

# Removes duplicate entries in wordlist like files

from __future__ import print_function

import sys

if __name__ == "__main__":
    if len(sys.argv) > 1:
        items = list()

        with open(sys.argv[1], 'r') as f:
            for item in f:
                item = item.strip()
                try:
                    str.encode(item)
                    if item in items:
                        if item:
                            print(item)
                    else:
                        items.append(item)
                except:
                    pass

        with open(sys.argv[1], 'w+') as f:
            f.writelines("\n".join(items))
