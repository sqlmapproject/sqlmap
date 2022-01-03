#!/bin/bash

# Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
# See the file 'LICENSE' for copying permission

find . -wholename "./thirdparty" -prune -o -type f -iname "*.py" -exec pylint --rcfile=./.pylintrc '{}' \;
