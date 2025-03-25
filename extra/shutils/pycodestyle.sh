#!/bin/bash

# Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
# See the file 'LICENSE' for copying permission

# Runs pycodestyle on all python files (prerequisite: pip install pycodestyle)
find . -wholename "./thirdparty" -prune -o -type f -iname "*.py" -exec pycodestyle --ignore=E501,E302,E305,E722,E402 '{}' \;
