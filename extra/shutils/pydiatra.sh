#!/bin/bash

# Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
# See the file 'LICENSE' for copying permission

# Runs py3diatra on all python files (prerequisite: pip install pydiatra)
find . -wholename "./thirdparty" -prune -o -type f -iname "*.py" -exec py3diatra '{}' \; | grep -v bare-except
