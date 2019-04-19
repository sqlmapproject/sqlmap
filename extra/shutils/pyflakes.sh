#!/bin/bash

# Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
# See the file 'LICENSE' for copying permission

# Runs pyflakes on all python files (prerequisite: apt-get install pyflakes)
find . -wholename "./thirdparty" -prune -o -type f -iname "*.py" -exec pyflakes '{}' \; | grep -v "redefines '_'"
