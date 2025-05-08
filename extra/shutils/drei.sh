#!/bin/bash

# Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
# See the file 'LICENSE' for copying permission

# Stress test against Python3

export SQLMAP_DREI=1
#for i in $(find . -iname "*.py" | grep -v __init__); do python3 -c 'import '`echo $i | cut -d '.' -f 2 | cut -d '/' -f 2- | sed 's/\//./g'`''; done
for i in $(find . -iname "*.py" | grep -v __init__); do PYTHONWARNINGS=all python3 -m compileall $i | sed 's/Compiling/Checking/g'; done
unset SQLMAP_DREI
source `dirname "$0"`"/junk.sh"

# for i in $(find . -iname "*.py" | grep -v __init__); do timeout 10 pylint --py3k $i; done 2>&1 | grep -v -E 'absolute_import|No config file'
