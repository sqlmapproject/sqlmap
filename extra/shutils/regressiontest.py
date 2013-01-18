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
from email.mime.multipart import MIMEMultipart

TIME = time.strftime("%H:%M:%S %d-%m-%Y", time.gmtime())

SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 25
SMTP_TIMEOUT = 30
FROM = "regressiontest@sqlmap.org"
#TO = "dev@sqlmap.org"
TO = "bernardo.damele@gmail.com"
SUBJECT = "Regression test results on %s" % TIME
CONTENT = ""
TEST_COUNTS = []
ATTACHMENTS = {}

command_line = "cd ../../ ; rm -f $REGRESSION_FILE ; python sqlmap.py --live-test --run-case 'Invalid'"
proc = subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
proc.wait()
stdout, stderr = proc.communicate()
failed_tests = re.findall("running live test case: (.+?) \((\d+)\/\d+\)[\r]*\n.+test failed (at parsing item \"(.+)\" )?\- scan folder: (\/.+) \- traceback: (.*?)( - SQL injection not detected)?[\r]*\n", stdout, re.M)

for failed_test in failed_tests:
    title = failed_test[0]
    test_count = int(failed_test[1])
    parse = failed_test[3] if failed_test[3] else None
    output_folder = failed_test[4]
    traceback = False if failed_test[5] == "False" else bool(failed_test[5])
    detected = False if failed_test[6] else True

    TEST_COUNTS.append(test_count)

    console_output_fd = codecs.open(os.path.join(output_folder, "console_output"), "rb", "utf8")
    console_output = console_output_fd.read()
    console_output_fd.close()

    ATTACHMENTS[test_count] = str(console_output)

    log_fd = codecs.open(os.path.join(output_folder, "debiandev", "log"), "rb", "utf8")
    log = log_fd.read()
    log_fd.close()

    if traceback:
        traceback_fd = codecs.open(os.path.join(output_folder, "traceback"), "rb", "utf8")
        traceback = traceback_fd.read()
        traceback_fd.close()

    CONTENT += "Failed test case '%s'" % title

    if parse:
        CONTENT += " at parsing: %s:\n\n" % parse
        CONTENT += "### Log file:\n\n"
        CONTENT += "%s\n" % log
    elif not detected:
        CONTENT += " - SQL injection not detected\n\n"

    if traceback:
        CONTENT += "### Traceback:\n\n"
        CONTENT += "%s\n" % str(traceback)

    CONTENT += "#######################################################################\n\n"

if CONTENT:
    SUBJECT += " (%s)" % ", ".join("#%d" % count for count in TEST_COUNTS)
    CONTENT += "\n\nRegression test finished at %s" % time.strftime("%H:%M:%S %d-%m-%Y", time.gmtime())

    msg = MIMEMultipart()
    msg["Subject"] = SUBJECT
    msg["From"] = FROM
    msg["To"] = TO

    msg.attach(MIMEText(CONTENT))

    for test_count, attachment in ATTACHMENTS.items():
        attachment = MIMEText(attachment)
        attachment.add_header('Content-Disposition', 'attachment', filename="test_case_%d_console_output.txt" % test_count)
        msg.attach(attachment)

    s = smtplib.SMTP(host=SMTP_SERVER, port=SMTP_PORT, timeout=SMTP_TIMEOUT)
    #s.set_debuglevel(1)
    s.sendmail(FROM, TO, msg.as_string())
    s.quit()
