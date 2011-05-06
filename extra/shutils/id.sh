#!/bin/bash

# $Id$

# Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
# See the file 'doc/COPYING' for copying permission

# Adds SVN property 'Id' to project files
find ../../. -type f -iname "*.py" -exec sed -i s/\$Id.*$/\$Id\$/g '{}' \;
find ../../. -type f -iname "*.py" -exec svn propset svn:keywords "Id" '{}' \;
