#!/usr/bin/env python

# Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
# See the file 'doc/COPYING' for copying permission

import codecs
import os
import re
import smtplib
import subprocess
import sys
import time

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

sys.path.append("../../")

from lib.core.revision import getRevisionNumber

TIME = time.strftime("%H:%M:%S %d-%m-%Y", time.gmtime())
SQLMAP_HOME = "/opt/sqlmap"
REVISION = getRevisionNumber()

SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 25
SMTP_TIMEOUT = 30
FROM = "regressiontest@sqlmap.org"
#TO = "dev@sqlmap.org"
TO = ["bernardo.damele@gmail.com", "miroslav.stampar@gmail.com"]
SUBJECT = "Regression test on %s using revision %s" % (TIME, REVISION)

def prepare_email(content):
    global FROM
    global TO
    global SUBJECT

    msg = MIMEMultipart()
    msg["Subject"] = SUBJECT
    msg["From"] = FROM
    msg["To"] = TO if isinstance(TO, basestring) else ",".join(TO)

    msg.attach(MIMEText(content))

    return msg

def send_email(msg):
    global SMTP_SERVER
    global SMTP_PORT
    global SMTP_TIMEOUT

    try:
        s = smtplib.SMTP(host=SMTP_SERVER, port=SMTP_PORT, timeout=SMTP_TIMEOUT)
        s.sendmail(FROM, TO, msg.as_string())
        s.quit()
    # Catch all for SMTP exceptions
    except smtplib.SMTPException, e:
        print "Failure to send email: %s" % str(e)

def main():
    global SUBJECT

    content = ""
    test_counts = []
    attachments = {}

    command_line = "cd %s && python sqlmap.py --live-test" % SQLMAP_HOME
    proc = subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    proc.wait()
    stdout, stderr = proc.communicate()

    if stderr:
        msg = prepare_email("Execution of regression test failed with error:\n\n%s" % stderr)
        send_email(msg)
        sys.exit(1)

    failed_tests = re.findall("running live test case: (.+?) \((\d+)\/\d+\)[\r]*\n.+test failed (at parsing item \"(.+)\" )?\- scan folder: (\/.+) \- traceback: (.*?)( - SQL injection not detected)?[\r]*\n", stdout, re.M)

    for failed_test in failed_tests:
        title = failed_test[0]
        test_count = int(failed_test[1])
        parse = failed_test[3] if failed_test[3] else None
        output_folder = failed_test[4]
        traceback = False if failed_test[5] == "False" else bool(failed_test[5])
        detected = False if failed_test[6] else True

        test_counts.append(test_count)

        console_output_file = os.path.join(output_folder, "console_output")
        log_file = os.path.join(output_folder, "debiandev", "log")
        traceback_file = os.path.join(output_folder, "traceback")

        if os.path.exists(console_output_file):
            console_output_fd = codecs.open(console_output_file, "rb", "utf8")
            console_output = console_output_fd.read()
            console_output_fd.close()
            attachments[test_count] = str(console_output)

        if os.path.exists(log_file):
            log_fd = codecs.open(log_file, "rb", "utf8")
            log = log_fd.read()
            log_fd.close()

        if os.path.exists(traceback_file):
            traceback_fd = codecs.open(traceback_file, "rb", "utf8")
            traceback = traceback_fd.read()
            traceback_fd.close()

        content += "Failed test case '%s' (#%d)" % (title, test_count)

        if parse:
            content += " at parsing: %s:\n\n" % parse
            content += "### Log file:\n\n"
            content += "%s\n\n" % log
        elif not detected:
            content += " - SQL injection not detected\n\n"
        else:
            content += "\n\n"

        if traceback:
            content += "### Traceback:\n\n"
            content += "%s\n\n" % str(traceback)

        content += "#######################################################################\n\n"

    if content:
        content += "Regression test finished at %s" % time.strftime("%H:%M:%S %d-%m-%Y", time.gmtime())
        SUBJECT += " (%s)" % ", ".join("#%d" % count for count in test_counts)

        msg = prepare_email(content)

        for test_count, attachment in attachments.items():
            attachment = MIMEText(attachment)
            attachment.add_header("Content-Disposition", "attachment", filename="test_case_%d_console_output.txt" % test_count)
            msg.attach(attachment)

        send_email(msg)

if __name__ == "__main__":
    main()
