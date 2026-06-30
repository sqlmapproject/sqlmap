#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import doctest
import json
import logging
import os
import random
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

from extra.vulnserver import vulnserver
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import getSafeExString
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import shellExec
from lib.core.compat import round
from lib.core.compat import xrange
from lib.core.convert import encodeBase64
from lib.core.convert import getBytes
from lib.core.convert import getText
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.patch import unisonRandom
from lib.core.settings import IS_WIN
from lib.core.settings import RESTAPI_VERSION

def vulnTest():
    """
    Runs the testing against 'vulnserver'
    """

    TESTS = (
        ("-h", ("to see full list of options run with '-hh'",)),
        ("--dependencies", ("sqlmap requires", "third-party library")),
        ("-u <url> --data=\"reflect=1\" --flush-session --wizard --disable-coloring", ("Please choose:", "back-end DBMS: SQLite", "current user is DBA: True", "banner: '3.")),
        ("-u <url> --data=\"code=1\" --code=200 --technique=B --banner --no-cast --flush-session", ("back-end DBMS: SQLite", "banner: '3.", "~COALESCE(CAST(")),
        (u"-c <config> --flush-session --output-dir=\"<tmpdir>\" --smart --roles --statements --hostname --privileges --sql-query=\"SELECT '\u0161u\u0107uraj'\" --technique=U", (u": '\u0161u\u0107uraj'", "on SQLite it is not possible", "as the output directory")),
        (u"-u <url> --flush-session --sql-query=\"SELECT '\u0161u\u0107uraj'\" --titles --technique=B --no-escape --string=luther --unstable", (u": '\u0161u\u0107uraj'", "~with --string",)),
        ("-m <multiple> --flush-session --technique=B --banner", ("/3] URL:", "back-end DBMS: SQLite", "banner: '3.")),
        ("--dummy", ("all tested parameters do not appear to be injectable", "does not seem to be injectable", "there is not at least one", "~might be injectable")),
        ("-u \"<url>&id2=1\" -p id2 -v 5 --flush-session --level=5 --text-only --test-filter=\"AND boolean-based blind - WHERE or HAVING clause (MySQL comment)\"", ("~1AND",)),
        ("--list-tampers", ("between", "MySQL", "xforwardedfor")),
        ("-u \"<url>&json=1\" -p id --flush-session --technique=B --banner", ("Type: boolean-based blind", "banner: '3.")),   # JSON-response detection via the structure-aware oracle (no --string hint)
        ("-u <url> --data=\"security_level=1\" -p id --flush-session --technique=B --banner", ("random (non-scanner) User-Agent and browser-like headers to bypass the WAF/IPS", "Type: boolean-based blind", "banner: '3.")),   # automatic WAF-bypass: request-fingerprint dimension (a non-scanner User-Agent, applied up-front, restores detection)
        ("-u <url> --data=\"security_level=2\" -p id --flush-session --technique=B --banner", ("bypassed the WAF/IPS by using tamper script", "reproduced manually with switch '--random-agent' and tamper script", "Type: boolean-based blind", "banner: '3.")),   # automatic WAF-bypass: SQL-tamper dimension (structural substitution) on top of the non-scanner User-Agent
        ("-u <url> --data=\"security_level=3\" -p id --flush-session --technique=B", ("bypassed the WAF/IPS by using tamper script", "Type: boolean-based blind")),   # automatic WAF-bypass: SQL-tamper dimension at a stricter signature threshold
        ("-u <url> --data=\"security_level=4\" -p id --flush-session --technique=B --banner", ("random (non-scanner) User-Agent and browser-like headers to bypass the WAF/IPS", "Type: boolean-based blind", "banner: '3.")),   # automatic WAF-bypass against a libinjection-class WAF: tampers cannot help, only the non-scanner User-Agent does
        ("-u <url> --data=\"security_level=5\" -p id --flush-session --technique=B", ("unable to automatically bypass the WAF/IPS", "does not seem to be injectable")),   # automatic WAF-bypass honest bail: a libinjection-class WAF that no User-Agent or tamper can defeat
        ("-u <url> -p id --flush-session --proof", ("sqlmap proved exploitation of the following injection point", "Parameter: id (GET)", "Technique: boolean-based blind", "TRUE (5/5)", "repeatably", "Retrieved: back-end DBMS banner '3.")),   # --proof: report-grade proof in the injection-point style - forces the boolean technique (so a multi-technique point still proves), and actively reads a value out as the strongest proof
        ("-r <request> --flush-session -v 5 --test-skip=\"heavy\" --save=<config>", ("CloudFlare", "web application technology: Express", "possible DBMS: 'SQLite'", "User-Agent: foobar", "~Type: time-based blind", "saved command line options to the configuration file")),
        ("-c <config>", ("CloudFlare", "possible DBMS: 'SQLite'", "User-Agent: foobar", "~Type: time-based blind")),
        ("-l <log> --flush-session --skip-waf -vvvvv --technique=U --union-from=users --banner --parse-errors", ("banner: '3.", "ORDER BY term out of range", "~xp_cmdshell", "Connection: keep-alive")),
        ("-l <log> --offline --banner -v 5", ("banner: '3.", "~[TRAFFIC OUT]")),
        ("-u <base> --flush-session --data=\"id=1&_=Eewef6oh\" --chunked --randomize=_ --random-agent --banner", ("fetched random HTTP User-Agent header value", "Parameter: id (POST)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "banner: '3.")),
        ("-u <base64> -p id --base64=id --data=\"base64=true\" --flush-session --banner --technique=B", ("banner: '3.",)),
        ("-u <base64> -p id --base64=id --data=\"base64=true\" --flush-session --tables --technique=U", (" users ",)),
        ("-u <url> --flush-session --banner --technique=B --disable-precon --not-string \"no results\"", ("banner: '3.",)),
        ("-u <url> --flush-session --encoding=gbk --banner --technique=B --first=1 --last=2", ("banner: '3.'",)),
        ("-u <url> --flush-session --encoding=ascii --forms --crawl=2 --threads=2 --banner", ("total of 2 targets", "might be injectable", "Type: UNION query", "banner: '3.")),
        ("-u <base> --flush-session --technique=BU --data=\"{\\\"id\\\": 1}\" --banner", ("might be injectable", "3 columns", "Payload: {\"id\"", "Type: boolean-based blind", "Type: UNION query", "banner: '3.")),
        ("-u <base> --flush-session -H \"Foo: Bar\" -H \"Sna: Fu\" --data=\"<root><param name=\\\"id\\\" value=\\\"1*\\\"/></root>\" --union-char=1 --mobile --answers=\"smartphone=3\" --banner --smart -v 5", ("might be injectable", "Payload: <root><param name=\"id\" value=\"1", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "banner: '3.", "Nexus", "Sna: Fu", "Foo: Bar")),
        ("-u <base> --flush-session --technique=BU --method=PUT --data=\"a=1;id=1;b=2\" --param-del=\";\" --skip-static --har=<tmpfile> --dump -T users --start=1 --stop=2", ("might be injectable", "Parameter: id (PUT)", "Type: boolean-based blind", "Type: UNION query", "2 entries")),
        ("-u <url> --flush-session -H \"id: 1*\" --tables -t <tmpfile>", ("might be injectable", "Parameter: id #1* ((custom) HEADER)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", " users ")),
        ("-u <url> --flush-session --banner --invalid-logical --technique=B --predict-output --titles --test-filter=\"OR boolean\" --tamper=space2dash", ("banner: '3.", " LIKE ")),
        ("-u <url> --flush-session --cookie=\"PHPSESSID=d41d8cd98f00b204e9800998ecf8427e; id=1*; id2=2\" --tables --union-cols=3", ("might be injectable", "Cookie #1* ((custom) HEADER)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", " users ")),
        ("-u <url> --flush-session --null-connection --technique=B --tamper=between,randomcase --banner --count -T users", ("NULL connection is supported with HEAD method", "banner: '3.", "users | 30")),
        ("-u <base> --data=\"aWQ9MQ==\" --flush-session --base64=POST -v 6", ("aWQ9MTtXQUlURk9SIERFTEFZICcwOjA",)),
        ("-u <url> --flush-session --parse-errors --test-filter=\"subquery\" --eval=\"import hashlib; id2=2; id3=hashlib.md5(id.encode()).hexdigest()\" --referer=\"localhost\"", ("might be injectable", ": syntax error", "back-end DBMS: SQLite", "WHERE or HAVING clause (subquery")),
        ("-u <url> --banner --schema --dump -T users --binary-fields=surname --where \"id>3\"", ("banner: '3.", "INTEGER", "TEXT", "id", "name", "surname", "27 entries", "6E616D6569736E756C6C")),
        ("-u <url> --technique=U --fresh-queries --force-partial --dump -T users --dump-format=HTML --answers=\"crack=n\" -v 3", ("performed 31 queries", "nameisnull", "~using default dictionary", "dumped to HTML file")),
        ("-u <url> --flush-session --technique=BU --all", ("30 entries", "Type: boolean-based blind", "Type: UNION query", "luther", "blisset", "fluffy", "179ad45c6ce2cb97cf1029e212046e81", "NULL", "nameisnull", "testpass")),
        ("-u <url> --flush-session --technique=B --keyset --dump -T users", ("using keyset (seek) pagination", "30 entries", "luther", "nameisnull")),   # keyset/seek dump via the SQLite rowid cursor
        ("-u <url> -z \"tec=B\" --hex --fresh-queries --threads=4 --sql-query=\"SELECT * FROM users\"", ("SELECT * FROM users [30]", "nameisnull")),
        ("-u \"<url>&echo=foobar*\" --flush-session", ("might be vulnerable to cross-site scripting",)),
        ("-u \"<base>nosql?name=luther&password=x\" -p password --nosql --flush-session", ("is vulnerable to NoSQL injection", "back-end: 'MongoDB'", "NoSQL: GET parameter 'password'", "s3cr3t")),   # NoSQL (MongoDB) operator-injection detection + blind regexp extraction
        ("-u \"<base>graphql\" --graphql --flush-session --disable-hashing", ("found GraphQL endpoint", "introspection returned", "skipping 2 mutation slot", "GraphQL boolean-based blind", "in-band data exposure", "back-end DBMS: 'SQLite'", "banner: '3.", "GraphQL database tables", "fetched 30 entries from table 'creds'", "db3a16990a0008a3b04707fdef6584a0", "GraphQL scan complete")),   # GraphQL: endpoint detection + introspection + mutation-skip + boolean-blind/in-band + back-end fingerprint + batched blind dump of an injection-only table (SQLite-backed)
        ("-u \"<base>ldap/search?q=x\" --ldap --flush-session --disable-hashing", ("is vulnerable to LDAP injection", "Title: LDAP in-band data exposure", "LDAP: GET parameter 'q' in-band entries", "in-band data exposure", "LDAP scan complete")),   # LDAP: error-based detection (unbalanced paren) + boolean oracle + directory attribute extraction via blind substring probing
        ("-u \"<base>xpath/search?q=x\" --xpath --flush-session --disable-hashing", ("is vulnerable to XPath injection", "Title: XPath boolean-based blind", "XPath: GET parameter 'q' XML tree", "extracted", "XPath scan complete")),   # XPath: error-based detection + boolean oracle + blind XML tree-walking via starts-with character extraction
        ("-u \"<base>ssti/search?q=x\" --ssti --flush-session --disable-hashing", ("is vulnerable to SSTI", "Title: SSTI Jinja2 injection", "back-end template engine: 'Jinja2'", "in-band arithmetic proof confirmed", "SSTI scan complete")),   # SSTI: Jinja2 detection via arithmetic control-pair + boolean oracle + distinguishing probe
        ("-u \"<url>&query=*\" --flush-session --technique=Q --banner", ("Title: SQLite inline queries", "banner: '3.")),
        ("-d \"<direct>\" --flush-session --dump -T creds --dump-format=SQLITE --binary-fields=password_hash --where \"user_id=5\"", ("3137396164343563366365326362393763663130323965323132303436653831", "dumped to SQLITE database")),
        ("-d \"<direct>\" --flush-session --banner --schema --sql-query=\"UPDATE users SET name='foobar' WHERE id=4; SELECT * FROM users; SELECT 987654321\"", ("banner: '3.", "INTEGER", "TEXT", "id", "name", "surname", "4,foobar,nameisnull", "'987654321'",)),
        ("-u <base>csrf --data=\"id=1&csrf_token=1\" --banner --answers=\"update=y\" --flush-session", ("back-end DBMS: SQLite", "banner: '3.")),
        ("--purge -v 3", ("~ERROR", "~CRITICAL", "deleting the whole directory tree")),
    )

    # The vulnserver's XPath endpoint renders with lxml and its SSTI endpoint with jinja2; where those
    # optional third-party engines are not importable (e.g. PyPy 2.7, which has no lxml wheel), skip
    # just those entries instead of failing the whole run - the rest of the suite is unaffected.
    try:
        __import__("lxml")
    except ImportError:
        TESTS = tuple(_ for _ in TESTS if "--xpath" not in _[0])
        logger.warning("skipping the XPath vuln-test entry ('lxml' not available)")
    try:
        __import__("jinja2")
    except ImportError:
        TESTS = tuple(_ for _ in TESTS if "--ssti" not in _[0])
        logger.warning("skipping the SSTI vuln-test entry ('jinja2' not available)")

    # --test-filter / --test-skip narrow a (slow) full run to just the entries touching a change:
    # the needle is matched case-insensitively against each entry's command line and its expected
    # checks (e.g. '--vuln-test --test-filter=ssti' runs only the SSTI entry).
    def _entryMatches(entry, needle):
        needle = needle.lower()
        return needle in entry[0].lower() or any(needle in getText(_).lower() for _ in entry[1])

    if conf.get("testFilter"):
        TESTS = tuple(_ for _ in TESTS if _entryMatches(_, conf.testFilter))
        logger.info("'--test-filter' selected %d vuln-test entr%s" % (len(TESTS), "y" if len(TESTS) == 1 else "ies"))
    if conf.get("testSkip"):
        TESTS = tuple(_ for _ in TESTS if not _entryMatches(_, conf.testSkip))
        logger.info("'--test-skip' left %d vuln-test entr%s" % (len(TESTS), "y" if len(TESTS) == 1 else "ies"))

    retVal = True
    count = 0
    cleanups = []

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

    vulnserver._alive = True

    thread = threading.Thread(target=_thread)
    thread.daemon = True
    thread.start()

    while vulnserver._alive:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((address, port))
            s.sendall(b"GET / HTTP/1.1\r\n\r\n")
            result = b""
            while True:
                current = s.recv(1024)
                if not current:
                    break
                else:
                    result += current
            if b"vulnserver" in result:
                break
        except:
            pass
        finally:
            s.close()
        time.sleep(1)

    if not vulnserver._alive:
        logger.error("problem occurred in vulnserver instantiation (address: 'http://%s:%s')" % (address, port))
        return False
    else:
        logger.info("vulnserver running at 'http://%s:%s'..." % (address, port))

    handle, config = tempfile.mkstemp(suffix=".conf")
    os.close(handle)
    cleanups.append(config)

    handle, database = tempfile.mkstemp(suffix=".sqlite")
    os.close(handle)
    cleanups.append(database)

    with sqlite3.connect(database) as conn:
        c = conn.cursor()
        c.executescript(vulnserver.SCHEMA)

    handle, request = tempfile.mkstemp(suffix=".req")
    os.close(handle)
    cleanups.append(request)

    handle, log = tempfile.mkstemp(suffix=".log")
    os.close(handle)
    cleanups.append(log)

    handle, multiple = tempfile.mkstemp(suffix=".lst")
    os.close(handle)
    cleanups.append(multiple)

    content = "POST / HTTP/1.0\nUser-Agent: foobar\nHost: %s:%s\n\nid=1\n" % (address, port)
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

    with open(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sqlmap.conf"))) as f:
        content = f.read().replace("url =", "url = %s" % url)

    with open(config, "w+") as f:
        f.write(content)
        f.flush()

    content = "%s?%s=%d\n%s?%s=%d\n%s&%s=1" % (base, randomStr(), randomInt(), base, randomStr(), randomInt(), url, randomStr())
    with open(multiple, "w+") as f:
        f.write(content)
        f.flush()

    for options, checks in TESTS:
        status = '%d/%d (%d%%) ' % (count, len(TESTS), round(100.0 * count / len(TESTS)))
        dataToStdout("\r[%s] [INFO] completed: %s" % (time.strftime("%X"), status))

        if IS_WIN and "uraj" in options:
            options = options.replace(u"\u0161u\u0107uraj", "sucuraj")
            checks = [check.replace(u"\u0161u\u0107uraj", "sucuraj") for check in checks]

        for tag, value in (("<url>", url), ("<base>", base), ("<direct>", direct), ("<tmpdir>", tmpdir), ("<request>", request), ("<log>", log), ("<multiple>", multiple), ("<config>", config), ("<base64>", url.replace("id=1", "id=MZ=%3d"))):
            options = options.replace(tag, value)

        cmd = "%s \"%s\" %s --batch --non-interactive --debug --time-sec=1" % (sys.executable if ' ' not in sys.executable else '"%s"' % sys.executable, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sqlmap.py")), options)

        if "<tmpfile>" in cmd:
            handle, tmp = tempfile.mkstemp()
            os.close(handle)
            cleanups.append(tmp)
            cmd = cmd.replace("<tmpfile>", tmp)

        os.environ["SQLMAP_UNSAFE_EVAL"] = '1'

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

    for filename in cleanups:
        try:
            os.remove(filename)
        except:
            pass

    try:
        shutil.rmtree(tmpdir)
    except:
        pass

    return retVal

def apiTest():
    """
    Runs a basic live test of the REST API: launches the server in a separate process
    ('sqlmapapi.py -s') and drives the control-plane endpoints with an HTTP client - a real
    server + client round-trip, without launching an actual scan. A separate process (rather
    than an in-process thread) isolates the single-threaded server from the client's GIL and
    from sqlmap's global HTTP machinery, which otherwise makes the round-trip flaky.
    """

    retVal = True

    # pick a free port the same way vulnTest() does
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

    username, password = "test", "test"
    apipath = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sqlmapapi.py"))

    try:
        devnull = subprocess.DEVNULL
    except AttributeError:
        devnull = open(os.devnull, "wb")

    process = subprocess.Popen([sys.executable, apipath, "-s", "-H", address, "-p", str(port), "--username", username, "--password", password], stdout=devnull, stderr=devnull)

    base = "http://%s:%d" % (address, port)

    def _call(path, data=None, authorize=True):
        # NOTE: a raw socket is used deliberately instead of urllib/http.client. The host sqlmap
        # process installs a global keep-alive opener and patches http.client, which makes a
        # library client flaky against the single-threaded server; a hand-rolled HTTP/1.0 request
        # (Connection: close, read to EOF) is hermetic and immune to all of that.
        method = "POST" if data is not None else "GET"
        lines = ["%s %s HTTP/1.0" % (method, path), "Host: %s:%d" % (address, port)]
        if authorize:
            lines.append("Authorization: Basic %s" % encodeBase64("%s:%s" % (username, password), binary=False))
        body = getBytes(json.dumps(data)) if data is not None else b""
        if data is not None:
            lines.append("Content-Type: application/json")
            lines.append("Content-Length: %d" % len(body))
        lines.append("Connection: close")
        request = getBytes("\r\n".join(lines) + "\r\n\r\n") + body

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        try:
            s.connect((address, port))
            s.sendall(request)
            raw = b""
            while True:
                chunk = s.recv(8192)
                if not chunk:
                    break
                raw += chunk
        except Exception as ex:
            logger.debug("API test: request to '%s' failed (%s)" % (path, getSafeExString(ex)))
            return None, None
        finally:
            s.close()

        head, _, payload = raw.partition(b"\r\n\r\n")
        try:
            code = int(head.split(b"\r\n")[0].split(b" ")[1])
        except (IndexError, ValueError):
            return None, None
        try:
            return code, json.loads(getText(payload))
        except ValueError:
            return code, None

    try:
        # wait for the server process to come up (or die trying)
        for _ in xrange(200):
            if process.poll() is not None:
                logger.error("API test: server process exited prematurely (address: '%s')" % base)
                return False
            code, data = _call("/version")
            if code == 200 and data and data.get("success"):
                break
            time.sleep(0.1)
        else:
            logger.error("API test: server did not come up (address: '%s')" % base)
            return False

        logger.info("REST API server running at '%s'..." % base)

        results = []

        def _check(name, condition):
            results.append((name, bool(condition)))
            if not condition:
                logger.error("API test: check '%s' FAILED" % name)

        # GET /version - success envelope + MAJOR-only integer api_version
        code, data = _call("/version")
        _check("version", code == 200 and data and data.get("success") is True and data.get("api_version") == int(RESTAPI_VERSION.split(".")[0]) and data.get("version"))

        # the auth hook must reject an unauthenticated request
        code, _ = _call("/version", authorize=False)
        _check("auth-401", code == 401)

        # GET /task/new - mint a task
        code, data = _call("/task/new")
        taskid = data.get("taskid") if data else None
        _check("task-new", code == 200 and data and data.get("success") and taskid)

        # POST /option/<taskid>/set then read it back via /get and /list (JSON round-trip + IPC)
        code, data = _call("/option/%s/set" % taskid, {"flushSession": True})
        _check("option-set", code == 200 and data and data.get("success"))

        code, data = _call("/option/%s/get" % taskid, ["flushSession"])
        _check("option-get", data and data.get("success") and (data.get("options") or {}).get("flushSession") is True)

        code, data = _call("/option/%s/list" % taskid)
        _check("option-list", data and data.get("success") and isinstance(data.get("options"), dict))

        # GET /admin/list - the IP-bound listing (our client is the task's creator) must see it
        code, data = _call("/admin/list")
        _check("admin-list", data and data.get("success") and taskid in (data.get("tasks") or {}))

        # a bogus task ID must produce a failure envelope (not a crash)
        code, data = _call("/option/%s/list" % "nonexistent")
        _check("invalid-task", data is not None and data.get("success") is False)

        # GET /task/<taskid>/delete - tear the task down
        code, data = _call("/task/%s/delete" % taskid)
        _check("task-delete", data and data.get("success"))

        if all(ok for _, ok in results):
            logger.info("API test final result: PASSED")
        else:
            retVal = False
            logger.error("API test final result: FAILED (%s)" % ", ".join(name for name, ok in results if not ok))
    finally:
        try:
            process.terminate()
            process.wait()
        except Exception:
            pass

    return retVal

def smokeTest():
    """
    Runs the basic smoke testing of a program
    """

    unisonRandom()

    with open(paths.ERRORS_XML, "r") as f:
        content = f.read()

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
        if any(_ in root for _ in ("thirdparty", "extra", "interbase", "tests")):
            continue

        for filename in files:
            if os.path.splitext(filename)[1].lower() == ".py" and filename != "__init__.py":
                length += 1

    for root, _, files in os.walk(paths.SQLMAP_ROOT_PATH):
        if any(_ in root for _ in ("thirdparty", "extra", "interbase", "tests")):
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
                dataToStdout("\r[%s] [INFO] completed: %s" % (time.strftime("%X"), status))

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
