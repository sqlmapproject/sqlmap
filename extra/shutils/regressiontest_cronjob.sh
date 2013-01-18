#!/usr/bin/env bash

# Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
# See the file 'doc/COPYING' for copying permission

SQLMAP_HOME="/opt/sqlmap"
REGRESSION_SCRIPT="${SQLMAP_HOME}/extra/shutils"

cd $SQLMAP_HOME
git pull
rm -f output 2>/dev/null

cd $REGRESSION_SCRIPT
python regressiontest.py
