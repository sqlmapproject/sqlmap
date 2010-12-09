#!/bin/bash

# $Id$

# Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
# See the file 'doc/COPYING' for copying permission

# Lists all duplicate entries inside a file
cat $1 | uniq -d