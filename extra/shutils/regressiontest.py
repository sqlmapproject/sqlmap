#!/usr/bin/env python

# Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
# See the file 'doc/COPYING' for copying permission

# Removes duplicate entries in wordlist like files
import codecs
import os
import re
import smtplib
import subprocess
import time

from email.mime.text import MIMEText

TIME = time.strftime("%H:%M:%S %d-%m-%Y", time.gmtime())

SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 25
SMTP_TIMEOUT = 30
FROM = "regressiontest@sqlmap.org"
TO = "dev@sqlmap.org"
SUBJECT = "Regression test results on on %s" % TIME
CONTENT = ""
TEST_COUNTS = []

command_line = "cd ../../ ; rm -f $REGRESSION_FILE ; python sqlmap.py --live-test --run-case 'Invalid logic'"
proc = subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
proc.wait()
stdout, stderr = proc.communicate()
failed_tests = re.findall("running live test case: (.+?) \((\d+)\/\d+\)[\r]*\n(.+?)test failed (.*?)at parsing item: (.+) \- scan folder is (\/.+)[\r]*\n", stdout, re.I | re.M)

for failed_test in failed_tests:
    title = failed_test[0]
    test_count = failed_test[1]
    error = True if "the test did not identify the SQL injection" in failed_test[2] else False
    traceback = failed_test[2] or None
    parse = failed_test[3]
    output_folder = failed_test[4]

    TEST_COUNTS.append(test_count)

    console_output_fd = codecs.open(os.path.join(output_folder, "console_output"), "rb", "utf8")
    console_output = console_output_fd.read()
    console_output_fd.close()

    if error is False:
        log_fd = codecs.open(os.path.join(output_folder, "debiandev", "log"), "rb", "utf8")
        log = log_fd.read()
        log_fd.close()

    if traceback:
        traceback_fd = codecs.open(os.path.join(output_folder, "traceback"), "rb", "utf8")
        traceback = traceback_fd.read()
        traceback_fd.close()

    CONTENT += "Failed test case '%s' at parsing: %s:\n\n" % (title, parse)

    if error is False:
        CONTENT += "### LOG FILE:\n\n"
        CONTENT += "%s\n" % log
    else:
        CONTENT += "### CONSOLE OUTPUT\n\n"
        CONTENT += "%s\n" % str(console_output)

    if traceback:
        CONTENT += "### TRACEBACK:\n"
        CONTENT += "%s\n" % str(traceback)

    CONTENT += "\n#######################################\n\n"

if CONTENT:
    SUBJECT += " (%s)" % ", ".join("#%d" % count for count in TEST_COUNTS)
    msg = MIMEText(CONTENT)
    msg["Subject"] = SUBJECT
    msg["From"] = FROM
    msg["To"] = TO

    s = smtplib.SMTP(host=SMTP_SERVER, port=SMTP_PORT, timeout=SMTP_TIMEOUT)
    #s.set_debuglevel(1)
    s.sendmail(FROM, TO, msg.as_string())
    s.quit()
