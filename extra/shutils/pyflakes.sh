#!/bin/bash

# Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
# See the file 'doc/COPYING' for copying permission

# Runs pyflakes on all python files
find . -wholename "./thirdparty" -prune -o -type f -iname "*.py" -exec pyflakes '{}' \;
