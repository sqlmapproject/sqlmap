#!/bin/bash

# Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
# See the file 'LICENSE' for copying permission

# Stress test against Python3(.14)

for i in $(find . -iname "*.py" | grep -v __init__); do PYTHONWARNINGS=all python3.14 -m compileall $i | sed 's/Compiling/Checking/g'; done
source `dirname "$0"`"/junk.sh"
