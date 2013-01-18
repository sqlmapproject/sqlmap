#!/bin/bash

# Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
# See the file 'doc/COPYING' for copying permission

# Runs pyflakes on all python files (prerequisite: apt-get install pyflakes)
find . -wholename "./thirdparty" -prune -o -type f -iname "*.py" -exec pyflakes '{}' \;
