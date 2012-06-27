#!/bin/bash

# Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
# See the file 'doc/COPYING' for copying permission

# Adds SVN property 'Id' to project files
find ../../. -type f -iname "*.py" -exec sed -i s/\$Id.*$/\$Id\$/g '{}' \;
find ../../. -type f -iname "*.py" -exec svn propset svn:keywords "Id" '{}' \;
