#!/bin/bash

# Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
# See the file 'LICENSE' for copying permission

# Runs py2diatra on all python files (prerequisite: pip install pydiatra)
find . -wholename "./thirdparty" -prune -o -type f -iname "*.py" -exec py2diatra '{}' \; | grep -v bare-except
