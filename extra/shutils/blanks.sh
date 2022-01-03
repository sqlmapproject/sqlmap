#!/bin/bash

# Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
# See the file 'LICENSE' for copying permission

# Removes trailing spaces from blank lines inside project files
find . -type f -iname '*.py' -exec sed -i 's/^[ \t]*$//' {} \;
