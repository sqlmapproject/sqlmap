#!/usr/bin/env python

# Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
# See the file 'doc/COPYING' for copying permission

import codecs
import inspect
import os
import re
import smtplib
import subprocess
import sys
import time
import traceback

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

sys.path.append(os.path.normpath("%s/../../" % os.path.dirname(inspect.getfile(inspect.currentframe()))))

from lib.core.revision import getRevisionNumber

START_TIME = time.strftime("%H:%M:%S %d-%m-%Y", time.gmtime())
SQLMAP_HOME = "/opt/sqlmap"
REVISION = getRevisionNumber()

SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 25
SMTP_TIMEOUT = 30
FROM = "regressiontest@sqlmap.org"
#TO = "dev@sqlmap.org"
TO = ["bernardo.damele@gmail.com", "miroslav.stampar@gmail.com"]
SUBJECT = "regression test started on %s using revision %s" % (START_TIME, REVISION)

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

def failure_email(msg):
    msg = prepare_email(msg)
    send_email(msg)
    sys.exit(1)

def main():
    global SUBJECT

    content = ""
    test_counts = []
    attachments = {}

    updateproc = subprocess.Popen("cd /opt/sqlmap/ ; python /opt/sqlmap/sqlmap.py --update", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = updateproc.communicate()

    if stderr:
        failure_email("Update of sqlmap failed with error:\n\n%s" % stderr)

    regressionproc = subprocess.Popen("python /opt/sqlmap/sqlmap.py --live-test", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=False)
    stdout, stderr = regressionproc.communicate()

    if stderr:
        failure_email("Execution of regression test failed with error:\n\n%s" % stderr)

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

    end_string = "Regression test finished at %s" % time.strftime("%H:%M:%S %d-%m-%Y", time.gmtime())

    if content:
        content += end_string
        SUBJECT = "Failed %s (%s)" % (SUBJECT, ", ".join("#%d" % count for count in test_counts))

        msg = prepare_email(content)

        for test_count, attachment in attachments.items():
            attachment = MIMEText(attachment)
            attachment.add_header("Content-Disposition", "attachment", filename="test_case_%d_console_output.txt" % test_count)
            msg.attach(attachment)

        send_email(msg)
    else:
        SUBJECT = "Successful %s" % SUBJECT
        msg = prepare_email("All test cases were successful\n\n%s" % end_string)
        send_email(msg)

if __name__ == "__main__":
    log_fd = open("/tmp/sqlmapregressiontest.log", "wb")
    log_fd.write("Regression test started at %s\n" % START_TIME)

    try:
        main()
    except Exception, e:
        log_fd.write("An exception has occurred:\n%s" % str(traceback.format_exc()))

    log_fd.write("Regression test finished at %s\n\n" % time.strftime("%H:%M:%S %d-%m-%Y", time.gmtime()))
    log_fd.close()
