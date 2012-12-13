#!/bin/bash

# Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
# See the file 'doc/COPYING' for copying permission

# Runs pep8 on all python files (prerequisite: apt-get install pep8)
find . -wholename "./thirdparty" -prune -o -type f -iname "*.py" -exec pep8 '{}' \;
