#!/bin/bash

# Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
# See the file 'LICENSE' for copying permission

# Runs pep8 on all python files (prerequisite: apt-get install pep8)
find . -wholename "./thirdparty" -prune -o -type f -iname "*.py" -exec pep8 '{}' \;
