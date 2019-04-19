#!/bin/bash

# Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
# See the file 'LICENSE' for copying permission

# Removes trailing spaces from blank lines inside project files
find . -type f -iname '*.py' -exec sed -i 's/^[ \t]*$//' {} \;
