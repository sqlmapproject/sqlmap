#!/bin/bash

# Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
# See the file 'LICENSE' for copying permission

find . -wholename "./thirdparty" -prune -o -type f -iname "*.py" -exec pylint --rcfile=./.pylintrc '{}' \;
