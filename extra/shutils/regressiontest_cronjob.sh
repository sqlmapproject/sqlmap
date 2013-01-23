#!/usr/bin/env bash

# Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
# See the file 'doc/COPYING' for copying permission

SQLMAP_HOME="/opt/sqlmap"
REGRESSION_SCRIPT="${SQLMAP_HOME}/extra/shutils"

FROM="regressiontest@sqlmap.org"
TO="bernardo.damele@gmail.com, miroslav.stampar@gmail.com"
SUBJECT="Automated regression test failed on $(date)"

cd $SQLMAP_HOME
git pull
rm -f output 2>/dev/null

cd $REGRESSION_SCRIPT
echo "Regression test started at $(date)" 1>/tmp/regressiontest.log 2>&1
python regressiontest.py 1>>/tmp/regressiontest.log 2>&1

if [ $? -ne 0 ]
then
    echo "Regression test finished at $(date)" 1>>/tmp/regressiontest.log 2>&1
    cat /tmp/regressiontest.log | mailx -s "${SUBJECT}" -aFrom:${FROM} ${TO}
else
    echo "Regression test finished at $(date)" 1>>/tmp/regressiontest.log 2>&1
fi
