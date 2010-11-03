#!/bin/bash

# $Id$

# Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
# See the file 'doc/COPYING' for copying permission

# Adds SVN property 'Id' to project files
find ../../. -type f -name "*.py" -exec svn propset svn:keywords "Id" '{}' \;