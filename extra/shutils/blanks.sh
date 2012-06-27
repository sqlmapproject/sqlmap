#!/bin/bash

# Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
# See the file 'doc/COPYING' for copying permission

# Removes trailing spaces from blank lines inside project files
find ../../. -type f -iname '*.py' -exec sed -i 's/^[ \t]*$//' {} \;
