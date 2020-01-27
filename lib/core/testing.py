#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

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
from lib.core.common import clearColors
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

_rand = 0

def vulnTest():
    """
    Runs the testing against 'vulnserver'
    """

    TESTS = (
        ("-h", ("to see full list of options run with '-hh'",)),
        ("-u <url> --flush-session --wizard --check-internet", ("Please choose:", "back-end DBMS: SQLite", "current user is DBA: True", "banner: '3.", "~no connection detected")),
        (u"-c <config> --flush-session --sql-query=\"SELECT '\u0161u\u0107uraj'\" --technique=U", (u": '\u0161u\u0107uraj'",)),
        (u"-u <url> --flush-session --sql-query=\"SELECT '\u0161u\u0107uraj'\" --technique=B --no-escape --string=luther --unstable", (u": '\u0161u\u0107uraj'",)),
        ("--dummy", ("all tested parameters do not appear to be injectable", "does not seem to be injectable", "there is not at least one", "~might be injectable")),
        ("--list-tampers", ("between", "MySQL", "xforwardedfor")),
        ("-r <request> --flush-session -v 5", ("CloudFlare", "possible DBMS: 'SQLite'", "User-agent: foobar")),
        ("-l <log> --flush-session --keep-alive --skip-waf -v 5 --technique=U --union-from=users --banner --parse-errors", ("banner: '3.", "ORDER BY term out of range", "~xp_cmdshell", "Connection: keep-alive")),
        ("-l <log> --offline --banner -v 5", ("banner: '3.", "~[TRAFFIC OUT]")),
        ("-u <url> --flush-session --encoding=ascii --forms --crawl=2 --threads=2 --banner", ("total of 2 targets", "might be injectable", "Type: UNION query", "banner: '3.")),
        ("-u <url> --flush-session --data='{\"id\": 1}' --banner", ("might be injectable", "3 columns", "Payload: {\"id\"", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "banner: '3.")),
        ("-u <url> --flush-session -H 'Foo: Bar' -H 'Sna: Fu' --data='<root><param name=\"id\" value=\"1*\"/></root>' --union-char=1 --mobile --answers='smartphone=3' --banner --smart -v 5", ("might be injectable", "Payload: <root><param name=\"id\" value=\"1", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "banner: '3.", "Nexus", "Sna: Fu", "Foo: Bar")),
        ("-u <url> --flush-session --method=PUT --data='a=1&b=2&c=3&id=1' --skip-static --dump -T users --start=1 --stop=2", ("might be injectable", "Parameter: id (PUT)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "2 entries")),
        ("-u <url> --flush-session -H 'id: 1*' --tables", ("might be injectable", "Parameter: id #1* ((custom) HEADER)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", " users ")),
        ("-u <url> --flush-session --banner --invalid-logical --technique=B --predict-output --test-filter='OR boolean' --tamper=space2dash", ("banner: '3.", " LIKE ")),
        ("-u <url> --flush-session --cookie=\"PHPSESSID=d41d8cd98f00b204e9800998ecf8427e; id=1*; id2=2\" --tables --union-cols=3", ("might be injectable", "Cookie #1* ((custom) HEADER)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", " users ")),
        ("-u <url> --flush-session --null-connection --technique=B --tamper=between,randomcase --banner", ("NULL connection is supported with HEAD method", "banner: '3.")),
        ("-u <url> --flush-session --parse-errors --test-filter=\"subquery\" --eval=\"import hashlib; id2=2; id3=hashlib.md5(id.encode()).hexdigest()\" --referer=\"localhost\"", ("might be injectable", ": syntax error", "back-end DBMS: SQLite", "WHERE or HAVING clause (subquery")),
        ("-u <url> --banner --schema --dump -T users --binary-fields=surname --where \"id>3\"", ("banner: '3.", "INTEGER", "TEXT", "id", "name", "surname", "2 entries", "6E616D6569736E756C6C")),
        ("-u <url> --technique=U --fresh-queries --force-partial --dump -T users --dump-format=HTML --answers=\"crack=n\" -v 3", ("performed 6 queries", "nameisnull", "~using default dictionary", "dumped to HTML file")),
        ("-u <url> --flush-session --all", ("5 entries", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "luther", "blisset", "fluffy", "179ad45c6ce2cb97cf1029e212046e81", "NULL", "nameisnull", "testpass")),
        ("-u <url> -z \"tec=B\" --hex --fresh-queries --threads=4 --sql-query=\"SELECT * FROM users\"", ("SELECT * FROM users [5]", "nameisnull")),
        ("-u '<url>&echo=foobar*' --flush-session", ("might be vulnerable to cross-site scripting",)),
        ("-u '<url>&query=*' --flush-session --technique=Q --banner", ("Title: SQLite inline queries", "banner: '3.")),
        ("-d <direct> --flush-session --dump -T users --dump-format=SQLITE --binary-fields=name --where \"id=3\"", ("7775", "179ad45c6ce2cb97cf1029e212046e81 (testpass)", "dumped to SQLITE database")),
        ("-d <direct> --flush-session --banner --schema --sql-query=\"UPDATE users SET name='foobar' WHERE id=5; SELECT * FROM users; SELECT 987654321\"", ("banner: '3.", "INTEGER", "TEXT", "id", "name", "surname", "5, foobar, nameisnull", "[*] 987654321",)),
        ("--purge -v 3", ("~ERROR", "~CRITICAL", "deleting the whole directory tree")),
    )

    retVal = True
    count = 0
    address, port = "127.0.0.10", random.randint(1025, 65535)

    def _thread():
        vulnserver.init(quiet=True)
        vulnserver.run(address=address, port=port)

    thread = threading.Thread(target=_thread)
    thread.daemon = True
    thread.start()

    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((address, port))
            break
        except:
            time.sleep(1)

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

    content = "POST / HTTP/1.0\nUser-agent: foobar\nHost: %s:%s\n\nid=1\n" % (address, port)

    open(request, "w+").write(content)
    open(log, "w+").write('<port>%d</port><request base64="true"><![CDATA[%s]]></request>' % (port, encodeBase64(content, binary=False)))

    url = "http://%s:%d/?id=1" % (address, port)
    direct = "sqlite3://%s" % database

    content = open(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sqlmap.conf"))).read().replace("url =", "url = %s" % url)
    open(config, "w+").write(content)

    for options, checks in TESTS:
        status = '%d/%d (%d%%) ' % (count, len(TESTS), round(100.0 * count / len(TESTS)))
        dataToStdout("\r[%s] [INFO] complete: %s" % (time.strftime("%X"), status))

        cmd = "%s %s %s --batch" % (sys.executable, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sqlmap.py")), options.replace("<url>", url).replace("<direct>", direct).replace("<request>", request).replace("<log>", log).replace("<config>", config))
        output = shellExec(cmd)

        if not all((check in output if not check.startswith('~') else check[1:] not in output) for check in checks):
            dataToStdout("---\n\n$ %s\n" % cmd)
            dataToStdout("%s---\n" % clearColors(output))
            retVal = False

        count += 1

    clearConsoleLine()
    if retVal:
        logger.info("vuln test final result: PASSED")
    else:
        logger.error("vuln test final result: FAILED")

    return retVal

def fuzzTest():
    count = 0
    address, port = "127.0.0.10", random.randint(1025, 65535)

    def _thread():
        vulnserver.init(quiet=True)
        vulnserver.run(address=address, port=port)

    thread = threading.Thread(target=_thread)
    thread.daemon = True
    thread.start()

    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((address, port))
            break
        except:
            time.sleep(1)

    handle, config = tempfile.mkstemp(suffix=".conf")
    os.close(handle)

    url = "http://%s:%d/?id=1" % (address, port)

    content = open(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sqlmap.conf"))).read().replace("url =", "url = %s" % url)
    open(config, "w+").write(content)

    while True:
        lines = content.split("\n")

        for i in xrange(20):
            j = random.randint(0, len(lines) - 1)

            if any(_ in lines[j] for _ in ("googleDork",)):
                continue

            if lines[j].strip().endswith('='):
                lines[j] += random.sample(("True", "False", randomStr(), str(randomInt())), 1)[0]

            k = random.randint(0, len(lines) - 1)
            if '=' in lines[k]:
                lines[k] += chr(random.randint(0, 255))

        open(config, "w+").write("\n".join(lines))

        cmd = "%s %s -c %s --non-interactive --answers='Github=n' --flush-session --technique=%s --banner" % (sys.executable, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sqlmap.py")), config, random.sample("BEUQ", 1)[0])
        output = shellExec(cmd)

        if "Traceback" in output:
            dataToStdout("---\n\n$ %s\n" % cmd)
            dataToStdout("%s---\n" % clearColors(output))

            handle, config = tempfile.mkstemp(prefix="sqlmapcrash", suffix=".conf")
            os.close(handle)
            open(config, "w+").write("\n".join(lines))
        else:
            dataToStdout("\r%d\r" % count)

        count += 1

def dirtyPatchRandom():
    """
    Unifying random generated data across different Python versions
    """

    def _lcg():
        global _rand
        a = 1140671485
        c = 128201163
        m = 2 ** 24
        _rand = (a * _rand + c) % m
        return _rand

    def _randint(a, b):
        _ = a + (_lcg() % (b - a + 1))
        return _

    def _choice(seq):
        return seq[_randint(0, len(seq) - 1)]

    def _sample(population, k):
        return [_choice(population) for _ in xrange(k)]

    def _seed(seed):
        global _rand
        _rand = seed

    random.choice = _choice
    random.randint = _randint
    random.sample = _sample
    random.seed = _seed

def smokeTest():
    """
    Runs the basic smoke testing of a program
    """

    dirtyPatchRandom()

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
        if any(_ in root for _ in ("thirdparty", "extra")):
            continue

        for filename in files:
            if os.path.splitext(filename)[1].lower() == ".py" and filename != "__init__.py":
                length += 1

    for root, _, files in os.walk(paths.SQLMAP_ROOT_PATH):
        if any(_ in root for _ in ("thirdparty", "extra")):
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
