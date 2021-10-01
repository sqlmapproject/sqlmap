#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import doctest
import logging
import os
import random
import re
import socket
import sqlite3
import sys
import tempfile
import threading
import time

from extra.vulnserver import vulnserver
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import shellExec
from lib.core.compat import round
from lib.core.compat import xrange
from lib.core.convert import encodeBase64
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.patch import unisonRandom
from lib.core.settings import MAX_CONSECUTIVE_CONNECTION_ERRORS
from lib.core.settings import IS_WIN

def vulnTest():
    """
    Runs the testing against 'vulnserver'
    """

    TESTS = (
        ("-h", ("to see full list of options run with '-hh'",)),
        ("--dependencies --deprecations", ("sqlmap requires", "third-party library", "~DeprecationWarning:")),
        ("-u <url> --data=\"reflect=1\" --flush-session --wizard --disable-coloring", ("Please choose:", "back-end DBMS: SQLite", "current user is DBA: True", "banner: '3.")),
        ("-u <url> --data=\"code=1\" --code=200 --technique=B --banner --no-cast --flush-session", ("back-end DBMS: SQLite", "banner: '3.", "~COALESCE(CAST(")),
        (u"-c <config> --flush-session --output-dir=\"<tmpdir>\" --smart --roles --statements --hostname --privileges --sql-query=\"SELECT '\u0161u\u0107uraj'\" --technique=U", (u": '\u0161u\u0107uraj'", "on SQLite it is not possible", "as the output directory")),
        (u"-u <url> --flush-session --sql-query=\"SELECT '\u0161u\u0107uraj'\" --technique=B --no-escape --string=luther --unstable", (u": '\u0161u\u0107uraj'",)),
        ("-m <multiple> --flush-session --technique=B --banner", ("/3] URL:", "back-end DBMS: SQLite", "banner: '3.")),
        ("--dummy", ("all tested parameters do not appear to be injectable", "does not seem to be injectable", "there is not at least one", "~might be injectable")),
        ("-u \"<url>&id2=1\" -p id2 -v 5 --flush-session --level=5 --text-only --test-filter=\"AND boolean-based blind - WHERE or HAVING clause (MySQL comment)\"", ("~1AND",)),
        ("--list-tampers", ("between", "MySQL", "xforwardedfor")),
        ("-r <request> --flush-session -v 5 --test-skip=\"heavy\" --save=<config>", ("CloudFlare", "web application technology: Express", "possible DBMS: 'SQLite'", "User-agent: foobar", "~Type: time-based blind", "saved command line options to the configuration file")),
        ("-c <config>", ("CloudFlare", "possible DBMS: 'SQLite'", "User-agent: foobar", "~Type: time-based blind")),
        ("-l <log> --flush-session --keep-alive --skip-waf -vvvvv --technique=U --union-from=users --banner --parse-errors", ("banner: '3.", "ORDER BY term out of range", "~xp_cmdshell", "Connection: keep-alive")),
        ("-l <log> --offline --banner -v 5", ("banner: '3.", "~[TRAFFIC OUT]")),
        ("-u <base> --flush-session --data=\"id=1&_=Eewef6oh\" --chunked --randomize=_ --random-agent --banner", ("fetched random HTTP User-Agent header value", "Parameter: id (POST)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "banner: '3.")),
        ("-u <base64> -p id --base64=id --data=\"base64=true\" --flush-session --banner --technique=B", ("banner: '3.",)),
        ("-u <base64> -p id --base64=id --data=\"base64=true\" --flush-session --tables --technique=U", (" users ",)),
        ("-u <url> --flush-session --banner --technique=B --disable-precon --not-string \"no results\"", ("banner: '3.",)),
        ("-u <url> --flush-session --encoding=gbk --banner --technique=B --first=1 --last=2", ("banner: '3.'",)),
        ("-u <url> --flush-session --encoding=ascii --forms --crawl=2 --threads=2 --banner", ("total of 2 targets", "might be injectable", "Type: UNION query", "banner: '3.")),
        ("-u <base> --flush-session --data=\"{\\\"id\\\": 1}\" --banner", ("might be injectable", "3 columns", "Payload: {\"id\"", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "banner: '3.")),
        ("-u <base> --flush-session -H \"Foo: Bar\" -H \"Sna: Fu\" --data=\"<root><param name=\\\"id\\\" value=\\\"1*\\\"/></root>\" --union-char=1 --mobile --answers=\"smartphone=3\" --banner --smart -v 5", ("might be injectable", "Payload: <root><param name=\"id\" value=\"1", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "banner: '3.", "Nexus", "Sna: Fu", "Foo: Bar")),
        ("-u <base> --flush-session --method=PUT --data=\"a=1;id=1;b=2\" --param-del=\";\" --skip-static --har=<tmpfile> --dump -T users --start=1 --stop=2", ("might be injectable", "Parameter: id (PUT)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "2 entries")),
        ("-u <url> --flush-session -H \"id: 1*\" --tables -t <tmpfile>", ("might be injectable", "Parameter: id #1* ((custom) HEADER)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", " users ")),
        ("-u <url> --flush-session --banner --invalid-logical --technique=B --predict-output --test-filter=\"OR boolean\" --tamper=space2dash", ("banner: '3.", " LIKE ")),
        ("-u <url> --flush-session --cookie=\"PHPSESSID=d41d8cd98f00b204e9800998ecf8427e; id=1*; id2=2\" --tables --union-cols=3", ("might be injectable", "Cookie #1* ((custom) HEADER)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", " users ")),
        ("-u <url> --flush-session --null-connection --technique=B --tamper=between,randomcase --banner --count -T users", ("NULL connection is supported with HEAD method", "banner: '3.", "users | 5")),
        ("-u <url> --flush-session --parse-errors --test-filter=\"subquery\" --eval=\"import hashlib; id2=2; id3=hashlib.md5(id.encode()).hexdigest()\" --referer=\"localhost\"", ("might be injectable", ": syntax error", "back-end DBMS: SQLite", "WHERE or HAVING clause (subquery")),
        ("-u <url> --banner --schema --dump -T users --binary-fields=surname --where \"id>3\"", ("banner: '3.", "INTEGER", "TEXT", "id", "name", "surname", "2 entries", "6E616D6569736E756C6C")),
        ("-u <url> --technique=U --fresh-queries --force-partial --dump -T users --dump-format=HTML --answers=\"crack=n\" -v 3", ("performed 6 queries", "nameisnull", "~using default dictionary", "dumped to HTML file")),
        ("-u <url> --flush-session --all", ("5 entries", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "luther", "blisset", "fluffy", "179ad45c6ce2cb97cf1029e212046e81", "NULL", "nameisnull", "testpass")),
        ("-u <url> -z \"tec=B\" --hex --fresh-queries --threads=4 --sql-query=\"SELECT * FROM users\"", ("SELECT * FROM users [5]", "nameisnull")),
        ("-u \"<url>&echo=foobar*\" --flush-session", ("might be vulnerable to cross-site scripting",)),
        ("-u \"<url>&query=*\" --flush-session --technique=Q --banner", ("Title: SQLite inline queries", "banner: '3.")),
        ("-d \"<direct>\" --flush-session --dump -T users --dump-format=SQLITE --binary-fields=name --where \"id=3\"", ("7775", "179ad45c6ce2cb97cf1029e212046e81 (testpass)", "dumped to SQLITE database")),
        ("-d \"<direct>\" --flush-session --banner --schema --sql-query=\"UPDATE users SET name='foobar' WHERE id=5; SELECT * FROM users; SELECT 987654321\"", ("banner: '3.", "INTEGER", "TEXT", "id", "name", "surname", "5, foobar, nameisnull", "'987654321'",)),
        ("--purge -v 3", ("~ERROR", "~CRITICAL", "deleting the whole directory tree")),
    )

    retVal = True
    count = 0

    while True:
        address, port = "127.0.0.1", random.randint(10000, 65535)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if s.connect_ex((address, port)):
                break
            else:
                time.sleep(1)
        finally:
            s.close()

    def _thread():
        vulnserver.init(quiet=True)
        vulnserver.run(address=address, port=port)

    thread = threading.Thread(target=_thread)
    thread.daemon = True
    thread.start()

    success = False
    for i in xrange(MAX_CONSECUTIVE_CONNECTION_ERRORS):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((address, port))
            s.send(b"GET / HTTP/1.0\r\n\r\n")
            if b"vulnserver" in s.recv(4096):
                success = True
                break
        except:
            time.sleep(1)
        finally:
            s.close()

    if not success:
        logger.error("problem occurred in vulnserver instantiation (address: 'http://%s:%s', alive: %s)" % (address, port, vulnserver._alive))
        return False
    else:
        logger.info("vulnserver running at 'http://%s:%s'..." % (address, port))

    handle, config = tempfile.mkstemp(suffix=".conf")
    os.close(handle)

    handle, database = tempfile.mkstemp(suffix=".sqlite")
    os.close(handle)

    with sqlite3.connect(database) as conn:
        c = conn.cursor()
        c.executescript(vulnserver.SCHEMA)

    handle, request = tempfile.mkstemp(suffix=".req")
    os.close(handle)

    handle, log = tempfile.mkstemp(suffix=".log")
    os.close(handle)

    handle, multiple = tempfile.mkstemp(suffix=".lst")
    os.close(handle)

    content = "POST / HTTP/1.0\nUser-agent: foobar\nHost: %s:%s\n\nid=1\n" % (address, port)
    with open(request, "w+") as f:
        f.write(content)
        f.flush()

    content = '<port>%d</port><request base64="true"><![CDATA[%s]]></request>' % (port, encodeBase64(content, binary=False))
    with open(log, "w+") as f:
        f.write(content)
        f.flush()

    base = "http://%s:%d/" % (address, port)
    url = "%s?id=1" % base
    direct = "sqlite3://%s" % database
    tmpdir = tempfile.mkdtemp()

    content = open(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sqlmap.conf"))).read().replace("url =", "url = %s" % url)
    with open(config, "w+") as f:
        f.write(content)
        f.flush()

    content = "%s?%s=%d\n%s?%s=%d\n%s&%s=1" % (base, randomStr(), randomInt(), base, randomStr(), randomInt(), url, randomStr())
    with open(multiple, "w+") as f:
        f.write(content)
        f.flush()

    for options, checks in TESTS:
        status = '%d/%d (%d%%) ' % (count, len(TESTS), round(100.0 * count / len(TESTS)))
        dataToStdout("\r[%s] [INFO] complete: %s" % (time.strftime("%X"), status))

        if IS_WIN and "uraj" in options:
            options = options.replace(u"\u0161u\u0107uraj", "sucuraj")
            checks = [check.replace(u"\u0161u\u0107uraj", "sucuraj") for check in checks]

        for tag, value in (("<url>", url), ("<base>", base), ("<direct>", direct), ("<tmpdir>", tmpdir), ("<request>", request), ("<log>", log), ("<multiple>", multiple), ("<config>", config), ("<base64>", url.replace("id=1", "id=MZ=%3d"))):
            options = options.replace(tag, value)

        cmd = "%s \"%s\" %s --batch --non-interactive --debug --time-sec=1" % (sys.executable if ' ' not in sys.executable else '"%s"' % sys.executable, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sqlmap.py")), options)

        if "<tmpfile>" in cmd:
            handle, tmp = tempfile.mkstemp()
            os.close(handle)
            cmd = cmd.replace("<tmpfile>", tmp)

        output = shellExec(cmd)

        if not all((check in output if not check.startswith('~') else check[1:] not in output) for check in checks) or "unhandled exception" in output:
            dataToStdout("---\n\n$ %s\n" % cmd)
            dataToStdout("%s---\n" % output, coloring=False)
            retVal = False

        count += 1

    clearConsoleLine()
    if retVal:
        logger.info("vuln test final result: PASSED")
    else:
        logger.error("vuln test final result: FAILED")

    return retVal

def smokeTest():
    """
    Runs the basic smoke testing of a program
    """

    unisonRandom()

    content = open(paths.ERRORS_XML, "r").read()
    for regex in re.findall(r'<error regexp="(.+?)"/>', content):
        try:
            re.compile(regex)
        except re.error:
            errMsg = "smoke test failed at compiling '%s'" % regex
            logger.error(errMsg)
            return False

    retVal = True
    count, length = 0, 0

    for root, _, files in os.walk(paths.SQLMAP_ROOT_PATH):
        if any(_ in root for _ in ("thirdparty", "extra", "interbase")):
            continue

        for filename in files:
            if os.path.splitext(filename)[1].lower() == ".py" and filename != "__init__.py":
                length += 1

    for root, _, files in os.walk(paths.SQLMAP_ROOT_PATH):
        if any(_ in root for _ in ("thirdparty", "extra", "interbase")):
            continue

        for filename in files:
            if os.path.splitext(filename)[1].lower() == ".py" and filename not in ("__init__.py", "gui.py"):
                path = os.path.join(root, os.path.splitext(filename)[0])
                path = path.replace(paths.SQLMAP_ROOT_PATH, '.')
                path = path.replace(os.sep, '.').lstrip('.')
                try:
                    __import__(path)
                    module = sys.modules[path]
                except Exception as ex:
                    retVal = False
                    dataToStdout("\r")
                    errMsg = "smoke test failed at importing module '%s' (%s):\n%s" % (path, os.path.join(root, filename), ex)
                    logger.error(errMsg)
                else:
                    logger.setLevel(logging.CRITICAL)
                    kb.smokeMode = True

                    (failure_count, _) = doctest.testmod(module)

                    kb.smokeMode = False
                    logger.setLevel(logging.INFO)

                    if failure_count > 0:
                        retVal = False

                count += 1
                status = '%d/%d (%d%%) ' % (count, length, round(100.0 * count / length))
                dataToStdout("\r[%s] [INFO] complete: %s" % (time.strftime("%X"), status))

    def _(node):
        for __ in dir(node):
            if not __.startswith('_'):
                candidate = getattr(node, __)
                if isinstance(candidate, str):
                    if '\\' in candidate:
                        try:
                            re.compile(candidate)
                        except:
                            errMsg = "smoke test failed at compiling '%s'" % candidate
                            logger.error(errMsg)
                            raise
                else:
                    _(candidate)

    for dbms in queries:
        try:
            _(queries[dbms])
        except:
            retVal = False

    clearConsoleLine()
    if retVal:
        logger.info("smoke test final result: PASSED")
    else:
        logger.error("smoke test final result: FAILED")

    return retVal
