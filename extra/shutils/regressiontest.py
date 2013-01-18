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

TIME = time.strftime("%H:%M:%S", time.gmtime())
DATE = time.strftime("%d-%m-%Y", time.gmtime())

SMTP_SERVER = "10.129.121.194"
SMTP_PORT = 25
SMTP_TIMEOUT = 30
FROM = "regressiontest@sqlmap.org"
TO = "bernardo.damele@gmail.com"
SUBJECT = "Regression test results - started at %s on %s" % (TIME, DATE)
CONTENT = ""

command_line = "cd ../../ ; rm -f $REGRESSION_FILE ; python sqlmap.py --live-test --run-case 'Invalid logic'"
proc = subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
proc.wait()
stdout, stderr = proc.communicate()
failed_tests = re.findall("running live test case: (.+?) \(\d+\/\d+\)[\r]*\n.+test failed (.*?)at parsing item: (.+) \- scan folder is (\/.+)[\r]*\n", stdout, re.I | re.M)

for failed_test in failed_tests:
    title = failed_test[0]
    traceback = failed_test[1] or None
    parse = failed_test[2]
    output_folder = failed_test[3]

    console_output_fd = codecs.open(os.path.join(output_folder, "console_output"), "rb", "utf8")
    console_output = console_output_fd.read()
    console_output_fd.close()

    log_fd = codecs.open(os.path.join(output_folder, "debiandev", "log"), "rb", "utf8")
    log = log_fd.read()
    log_fd.close()

    if traceback:
        traceback_fd = codecs.open(os.path.join(output_folder, "traceback"), "rb", "utf8")
        traceback = traceback_fd.read()
        traceback_fd.close()

    CONTENT += "Failed test case '%s' at parsing: %s:\n\n" % (title, parse)
    CONTENT += "### LOG FILE:\n\n"
    CONTENT += "%s\n" % log
    CONTENT += "### CONSOLE OUTPUT\n\n"
    CONTENT += "%s\n" % str(console_output)

    if traceback:
        CONTENT += "### TRACEBACK:\n"
        CONTENT += "%s\n" % str(traceback)

    CONTENT += "\n#######################################\n\n"

if CONTENT:
    msg = MIMEText(CONTENT)
    msg["Subject"] = SUBJECT
    msg["From"] = FROM
    msg["To"] = TO

    s = smtplib.SMTP(host=SMTP_SERVER, port=SMTP_PORT, timeout=SMTP_TIMEOUT)
    #s.set_debuglevel(1)
    s.sendmail(FROM, TO, msg)
    s.quit()
