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

def vulnTest(tests=None, label="vuln"):
    """
    Runs the testing against 'vulnserver' (default suite, or a caller-supplied one e.g. FP_TESTS)
    """

    TESTS = tests if tests is not None else (
        ("-h", ("to see full list of options run with '-hh'",)),
        ("--dependencies", ("sqlmap requires", "third-party library")),
        ("-u <url> --data=\"reflect=1\" --flush-session --wizard --disable-coloring", ("Please choose:", "back-end DBMS: SQLite", "current user is DBA: True", "banner: '3.")),
        ("-u <url> --data=\"code=1\" --code=200 --technique=B --banner --no-cast --flush-session", ("back-end DBMS: SQLite", "banner: '3.", "~COALESCE(CAST(")),
        ("-u <url> --flush-session --technique=B --banner", ("Type: boolean-based blind", "banner: '3.")),   # session resume (1/2): detect + STORE the injection into the (serialized) session
        ("-u <url> --technique=B --banner", ("sqlmap resumed the following injection point(s) from stored session", "Type: boolean-based blind", "banner: '3.")),   # session resume (2/2): NO --flush-session, so the injection must round-trip back OUT of the serialized session and still work (guards session serialization/deserialization end-to-end)
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
        ("-u <url> -p id --flush-session --technique=B --proof", ("sqlmap proved exploitation of the following injection point", "Parameter: id (GET)", "Technique: boolean-based blind", "TRUE (5/5)", "repeatably", "Retrieved: back-end DBMS banner '3.")),   # --proof: report-grade proof in the injection-point style - forces the boolean technique (so a multi-technique point still proves), and actively reads a value out as the strongest proof
        ("-r <request> --flush-session -v 5 --test-skip=\"heavy\" --save=<config>", ("CloudFlare", "web application technology: Express", "possible DBMS: 'SQLite'", "User-Agent: foobar", "~Type: time-based blind", "saved command line options to the configuration file")),
        ("-c <config>", ("CloudFlare", "possible DBMS: 'SQLite'", "User-Agent: foobar", "~Type: time-based blind")),
        ("-l <log> --flush-session --skip-waf -vvvvv --technique=U --union-from=users --banner --parse-errors", ("banner: '3.", "ORDER BY term out of range", "~xp_cmdshell", "Connection: keep-alive")),
        ("-l <log> --offline --banner -v 5", ("banner: '3.", "~[TRAFFIC OUT]")),
        ("-u <base> --flush-session --data=\"id=1&_=Eewef6oh\" --chunked --randomize=_ --random-agent --banner", ("fetched random HTTP User-Agent header value", "Parameter: id (POST)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "banner: '3.")),
        ("-u <base64> -p id --base64=id --data=\"base64=true\" --flush-session --banner --technique=B", ("banner: '3.",)),
        ("-u <base64> -p id --base64=id --data=\"base64=true\" --flush-session --tables --technique=U", (" users ",)),
        ("-u <url> --flush-session --banner --technique=B --disable-precon --not-string \"no results\"", ("banner: '3.",)),
        ("-u <url> --flush-session --encoding=gbk --banner --technique=B --first=1 --last=2", ("banner: '3.'",)),
        ("-u <url> --flush-session --technique=BU --encoding=ascii --forms --crawl=2 --threads=2 --banner", ("total of 2 targets", "might be injectable", "Type: UNION query", "banner: '3.")),
        ("-u <base> --flush-session --technique=BU --data=\"{\\\"id\\\": 1}\" --banner", ("might be injectable", "3 columns", "Payload: {\"id\"", "Type: boolean-based blind", "Type: UNION query", "banner: '3.")),
        ("-u <base> --flush-session -H \"Foo: Bar\" -H \"Sna: Fu\" --data=\"<root><param name=\\\"id\\\" value=\\\"1*\\\"/></root>\" --union-char=1 --mobile --answers=\"smartphone=3\" --banner --smart -v 5", ("might be injectable", "Payload: <root><param name=\"id\" value=\"1", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "banner: '3.", "Nexus", "Sna: Fu", "Foo: Bar")),
        ("-u <base> --flush-session --technique=BU --method=PUT --data=\"a=1;id=1;b=2\" --param-del=\";\" --skip-static --har=<tmpfile> --dump -T users --start=1 --stop=2", ("might be injectable", "Parameter: id (PUT)", "Type: boolean-based blind", "Type: UNION query", "2 entries")),
        ("-u <url> --flush-session -H \"id: 1*\" --tables -t <tmpfile>", ("might be injectable", "Parameter: id #1* ((custom) HEADER)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", " users ")),
        ("-u <url> --flush-session --banner --invalid-logical --technique=B --titles --test-filter=\"OR boolean\" --tamper=space2dash", ("banner: '3.", " LIKE ")),
        ("-u <url> --flush-session --cookie=\"PHPSESSID=d41d8cd98f00b204e9800998ecf8427e; id=1*; id2=2\" --tables --union-cols=3", ("might be injectable", "Cookie #1* ((custom) HEADER)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", " users ")),
        ("-u <url> --flush-session --null-connection --technique=B --tamper=between,randomcase --banner --count -T users", ("NULL connection is supported with HEAD method", "banner: '3.", "users | 30")),
        ("-u <base> --data=\"aWQ9MQ==\" --flush-session --base64=POST -v 6", ("aWQ9MTtXQUlURk9SIERFTEFZICcwOjA",)),
        ("-u <url> --flush-session --parse-errors --test-filter=\"subquery\" --eval=\"import hashlib; id2=2; id3=hashlib.md5(id.encode()).hexdigest()\" --referer=\"localhost\"", ("might be injectable", ": syntax error", "back-end DBMS: SQLite", "WHERE or HAVING clause (subquery")),
        ("-u <url> --technique=BU --banner --schema --dump -T users --binary-fields=surname --where \"id>3\"", ("banner: '3.", "INTEGER", "TEXT", "id", "name", "surname", "27 entries", "6E616D6569736E756C6C")),
        ("-u <url> --technique=U --fresh-queries --force-partial --disable-json --dump -T users --dump-format=HTML --answers=\"crack=n\" -v 3", ("LIMIT 0,1)", "nameisnull", "~using default dictionary", "dumped to HTML file")),
        ("-u <url> --flush-session --technique=BU --all", ("30 entries", "Type: boolean-based blind", "Type: UNION query", "luther", "blisset", "fluffy", "179ad45c6ce2cb97cf1029e212046e81", "NULL", "nameisnull", "testpass")),
        ("-u <url> --flush-session --technique=B --keyset --dump -T users", ("using keyset (seek) pagination", "30 entries", "luther", "nameisnull")),   # keyset/seek dump via the SQLite rowid cursor
        ("-u <url> -z \"tec=B\" --hex --fresh-queries --threads=4 --sql-query=\"SELECT * FROM users\"", ("SELECT * FROM users [30]", "nameisnull")),
        ("-u \"<url>&echo=foobar*\" --flush-session", ("might be vulnerable to cross-site scripting",)),
        ("-u \"<base>nosql?name=luther&password=x\" -p password --nosql --flush-session", ("is vulnerable to NoSQL injection", "back-end: 'MongoDB'", "NoSQL: GET parameter 'password'", "s3cr3t")),   # NoSQL (MongoDB) operator-injection detection + blind regexp extraction
        ("-u \"<base>graphql\" --graphql --flush-session --disable-hashing", ("found GraphQL endpoint", "introspection returned", "skipping 2 mutation slot", "GraphQL boolean-based blind", "in-band data exposure", "back-end DBMS: 'SQLite'", "banner: '3.", "GraphQL database tables", "fetched 30 entries from table 'creds'", "db3a16990a0008a3b04707fdef6584a0", "GraphQL scan complete")),   # GraphQL: endpoint detection + introspection + mutation-skip + boolean-blind/in-band + back-end fingerprint + batched blind dump of an injection-only table (SQLite-backed)
        ("-u \"<base>ldap/search?q=x\" --ldap --flush-session --disable-hashing", ("is vulnerable to LDAP injection", "Title: LDAP in-band data exposure", "LDAP: GET parameter 'q' in-band entries", "in-band data exposure", "LDAP scan complete")),   # LDAP: error-based detection (unbalanced paren) + boolean oracle + directory attribute extraction via blind substring probing
        ("-u \"<base>xpath/search?q=x\" --xpath --flush-session --disable-hashing", ("is vulnerable to XPath injection", "Title: XPath boolean-based blind", "XPath: GET parameter 'q' XML tree", "extracted", "XPath scan complete")),   # XPath: error-based detection + boolean oracle + blind XML tree-walking via starts-with character extraction
        ("-u \"<base>ssti/search?q=x\" --ssti --flush-session --disable-hashing", ("is vulnerable to SSTI", "Title: SSTI Jinja2 injection", "back-end template engine: 'Jinja2'", "in-band arithmetic proof confirmed", "SSTI scan complete")),   # SSTI: Jinja2 detection via arithmetic control-pair + boolean oracle + distinguishing probe
        ("-u \"<base>hql/search?name=admin\" -p name --hql --flush-session --disable-hashing", ("is vulnerable to HQL injection", "back-end: 'Hibernate'", "entity 'Users'", "s3cr3t", "HQL scan complete")),   # HQL: error-based Hibernate fingerprint + boolean oracle + error-leaked entity + blind attribute enumeration and substring value extraction
        ("-u <url> --flush-session --esperanto --technique=B --banner", ("using the DBMS-agnostic 'Esperanto' engine", "Esperanto dialect verdict: SQLite", "banner: '3.")),   # Esperanto: DBMS-agnostic boolean-oracle engine drives --banner end-to-end through the real sqlmap handler (fingerprinting skipped, dialect discovered from scratch, banner blind-extracted)
        ("-u \"<base>xxe\" --data=\"<root><q>x</q></root>\" --xxe --file-read=\"%s\" --flush-session" % vulnserver.XXE_READ_FILE, ("the XML body processes DTD/internal entities", "in-band XXE file-read impact confirmed", "Type: XXE injection", "XXE scan complete")),   # XXE: in-band internal-entity reflection (real libxml2/lxml parser) + external file:// entity file read
        ("-u \"<url>&query=*\" --flush-session --technique=Q --banner", ("Title: SQLite inline queries", "banner: '3.")),
        ("-d \"<direct>\" --flush-session --dump -T creds --dump-format=SQLITE --binary-fields=password_hash --where \"user_id=5\"", ("3137396164343563366365326362393763663130323965323132303436653831", "dumped to SQLITE database")),
        ("-d \"<direct>\" --flush-session --banner --schema --sql-query=\"UPDATE users SET name='foobar' WHERE id=4; SELECT * FROM users; SELECT 987654321\"", ("banner: '3.", "INTEGER", "TEXT", "id", "name", "surname", "4,foobar,nameisnull", "'987654321'",)),
        ("-u <base>csrf --data=\"id=1&csrf_token=1\" --banner --answers=\"update=y\" --flush-session --technique=B", ("back-end DBMS: SQLite", "banner: '3.")),
        ("--purge -v 3", ("~ERROR", "~CRITICAL", "deleting the whole directory tree")),
    )

    # The vulnserver's XPath and XXE endpoints render with lxml and its SSTI endpoint with jinja2; where
    # those optional third-party engines are not importable (e.g. PyPy 2.7, which has no lxml wheel), skip
    # just those entries instead of failing the whole run - the rest of the suite is unaffected.
    try:
        __import__("lxml")
    except ImportError:
        TESTS = tuple(_ for _ in TESTS if "--xpath" not in _[0] and "--xxe" not in _[0])
        logger.warning("skipping the XPath and XXE vuln-test entries ('lxml' not available)")
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
        logger.info("%s test final result: PASSED" % label)
    else:
        logger.error("%s test final result: FAILED" % label)

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

def fpTest():
    """
    On-demand false-positive battery ('--fp-test'): a set of deliberately NON-injectable traps that
    each bait a specific FP defense (boolean confirmation, dynamic-content removal, structure-aware
    comparison, canary/sanity gate, reflection, error-regex specificity, length and time heuristics),
    paired with real injectable twins. An A+ engine rejects every trap AND still detects every twin.
    Kept out of the default '--vuln-test' (CI budget); run explicitly against 'vulnserver'.
    """

    FP_TESTS = (
        # false-positive traps -> sqlmap MUST NOT flag these as injectable
        ("-u \"<base>fp?trap=intcast&id=1\" -p id --technique=BEU --level=3 --risk=2 --flush-session", ("~identified the following injection point", "do not appear to be injectable")),      # boolean confirmation / checkFalsePositives
        ("-u \"<base>fp?trap=structrand&id=1\" -p id --technique=BEU --level=3 --risk=2 --flush-session", ("~identified the following injection point", "do not appear to be injectable")),    # structure-aware comparison
        ("-u \"<base>fp?trap=acceptall&id=1\" -p id --technique=BEU --level=3 --risk=2 --flush-session", ("~identified the following injection point", "do not appear to be injectable")),      # canary / sanity gate (reads-everything-true)
        ("-u \"<base>fp?trap=reflect&id=1\" -p id --technique=BEU --level=3 --risk=2 --flush-session", ("~identified the following injection point", "do not appear to be injectable")),        # reflection handling
        ("-u \"<base>fp?trap=errors&id=1\" -p id --technique=BE --level=3 --risk=2 --flush-session", ("~identified the following injection point", "do not appear to be injectable")),          # error-regex specificity
        ("-u \"<base>fp?trap=lengthrand&id=1\" -p id --technique=BEU --level=3 --risk=2 --flush-session", ("~identified the following injection point", "do not appear to be injectable")),     # length heuristics
        ("-u \"<base>fp?trap=slowrand&id=1\" -p id --technique=T --flush-session", ("~identified the following injection point", "do not appear to be injectable")),                           # time-based statistical model
        # true-positive twins -> sqlmap MUST still detect real injection (the discrimination that makes it A+)
        ("-u <url> -p id --technique=B --flush-session", ("identified the following injection point", "Type: boolean-based blind")),
        ("-u \"<url>&json=1\" -p id --technique=B --flush-session", ("identified the following injection point",)),
    )

    return vulnTest(tests=FP_TESTS, label="fp")

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

def payloadLintTest():
    """
    Offline payload-sanity coverage test.

    For every supported back-end DBMS an emulation oracle drives the blind
    enumeration handlers (no live target), so agent.py builds the full range of
    inference payloads it would emit while dumping a schema, and each one is
    checked with lib.utils.sqllint. A planted-malformation self-check first
    proves the pipeline actually catches a defect, so the gate can never pass
    vacuously.
    """

    import lib.core.common as common_module

    from lib.controller.handler import setHandler
    from lib.core.agent import agent
    from lib.core.common import Backend
    from lib.core.datatype import AttribDict
    from lib.core.datatype import InjectionDict
    from lib.core.enums import PAYLOAD
    from lib.core.enums import PLACE
    from lib.core.threads import getCurrentThreadData
    from lib.request.connect import Connect
    from lib.utils.sqllint import checkSanity

    unisonRandom()

    collected = []
    guard = {"count": 0}
    CAP_PER_METHOD = 600

    # A "consistent liar": parse the injected char comparison in whatever form the
    # dialect uses (bare int / CHAR(n) / quoted 'x') and answer so counts->'2',
    # lengths->small, names->'a'. This keeps every dialect's enumeration walking a
    # few shallow levels, exercising the payload builders without a real backend.
    def _oracle(value=None, **kwargs):
        if value is None:
            return None
        sql = agent.removePayloadDelimiters(agent.adjustLateValues(value))
        collected.append(sql)
        guard["count"] += 1
        if guard["count"] > CAP_PER_METHOD:
            raise KeyboardInterrupt
        # UNION/inband path reads the response body: hand back a page carrying the
        # delimited marker value so extraction "succeeds" and keeps producing payloads
        if kwargs.get("content"):
            start, stop, delim = kb.chars.start, kb.chars.stop, kb.chars.delimiter
            return ("x%s%s%s%s%sx" % (start, "1", delim, "1", stop), None, 200)
        upper = sql.upper()
        match = re.search(r">\s*'(.?)'", sql)
        if match:
            return True if match.group(1) == "" else (50 if "COUNT(" in upper else 97) > ord(match.group(1))
        match = re.search(r">\s*(?:N?CHAR|CHR|NCHR)\s*\(\s*(\d+)", sql, re.I)
        if match:
            return (50 if "COUNT(" in upper else 97) > int(match.group(1))
        match = re.search(r">\s*(\d+)", sql)
        if match:
            value_ = int(match.group(1))
            target = 1 if "COUNT(" in upper else (3 if any(_ in upper for _ in ("LENGTH(", "LEN(", "DATALENGTH(")) else 2)
            return target > value_
        match = re.search(r"(\d+)\s*(=|<|>=|<=|<>|!=)\s*(\d+)", sql)
        if match:
            left, operator, right = int(match.group(1)), match.group(2), int(match.group(3))
            return {"=": left == right, "<": left < right, ">=": left >= right, "<=": left <= right, "<>": left != right, "!=": left != right}[operator]
        return False

    def _injection(dbms):
        injection = InjectionDict()
        injection.place = PLACE.GET
        injection.parameter = "id"
        injection.ptype = 1
        injection.prefix = ""
        injection.suffix = ""
        injection.clause = [1]
        injection.dbms = dbms
        boolean = AttribDict()
        boolean.title = "AND boolean-based blind"
        boolean.vector = "AND [INFERENCE]"
        boolean.comment = ""
        boolean.payload = "x"
        boolean.where = 1
        boolean.templatePayload = None
        boolean.matchRatio = None
        boolean.trueCode = None
        boolean.falseCode = None
        injection.data = AttribDict()
        injection.data[PAYLOAD.TECHNIQUE.BOOLEAN] = boolean
        return injection

    def _unionInjection(dbms):
        injection = InjectionDict()
        injection.place = PLACE.GET
        injection.parameter = "id"
        injection.ptype = 1
        injection.prefix = ""
        injection.suffix = ""
        injection.clause = [1]
        injection.dbms = dbms
        union = AttribDict()
        union.title = "Generic UNION query"
        # vector = (position, count, comment, prefix, suffix, char, where,
        #           unionDuplicates, forcePartial, tableFrom, unionTemplate)
        union.vector = (0, 3, "-- -", "", "", "NULL", PAYLOAD.WHERE.ORIGINAL, False, False, None, None)
        union.comment = "-- -"
        union.prefix = ""
        union.suffix = ""
        union.where = PAYLOAD.WHERE.ORIGINAL
        union.templatePayload = None
        union.matchRatio = None
        union.trueCode = None
        union.falseCode = None
        injection.data = AttribDict()
        injection.data[PAYLOAD.TECHNIQUE.UNION] = union
        return injection

    methods = ("getBanner", "getCurrentDb", "getCurrentUser", "getHostname", "isDba",
               "getDbs", "getTables", "getColumns", "getSchema", "getUsers",
               "getPasswordHashes", "getPrivileges", "getRoles", "getStatements",
               "getComments", "getProcedures")

    _stdout = sys.stdout

    def _progress(dbms, count, bad):
        # write to the real stdout (sqlmap's is redirected to a sink during the walk)
        _stdout.write("[payload-lint] %-26s %7d payloads  %s\n" % (dbms, count, ("%d FLAGGED" % bad) if bad else "ok"))
        _stdout.flush()

    class _Sink(object):
        def write(self, *args, **kwargs): pass
        def flush(self, *args, **kwargs): pass

    _queryPage = Connect.queryPage
    _getPageTemplate = common_module.getPageTemplate
    _level = logger.level
    _threads = conf.threads
    threadData = getCurrentThreadData()

    retVal = True
    total = walked = 0
    flagged = []
    allDbms = sorted(queries.keys())

    try:
        conf.batch = True
        conf.threads = 1                    # deterministic, single-threaded (clean output)
        conf.disableHashing = True
        if not conf.base64Parameter:
            conf.base64Parameter = []
        common_module.getPageTemplate = lambda *args, **kwargs: ("<html>x</html>", False)
        Connect.queryPage = staticmethod(_oracle)
        logger.setLevel(logging.CRITICAL)   # mute the emulated walk's "unable to retrieve" noise
        threadData.disableStdOut = True     # mute dataToStdout at its gate
        sys.stdout = _Sink()                # and mute everything else (readInput prompts, tables, ...)

        def _runMethods():
            found = set()
            for name in methods:
                method = getattr(conf.dbmsHandler, name, None)
                if method is None:
                    continue
                del collected[:]
                guard["count"] = 0
                try:
                    method()
                except (KeyboardInterrupt, Exception):
                    pass
                found.update(collected)
            return found

        for dbms in allDbms:
            try:
                Backend.flushForcedDbms(force=True)
                kb.stickyDBMS = False
                Backend.forceDbms(dbms)
                conf.forceDbms = conf.dbms = dbms
                conf.parameters = {PLACE.GET: "id=1"}
                conf.paramDict = {PLACE.GET: {"id": "1"}}
                # a user/column so user-filtered and column-specific query variants
                # (WHERE grantee='...', per-column extraction) are exercised too
                conf.db, conf.tbl, conf.col, conf.user = "testdb", "testtbl", "testcol", "testuser"
                setHandler()
            except Exception:
                _progress(dbms, 0, 0)
                continue

            seen = set()
            # (a) boolean-based blind pass, then (b) UNION-query (inband) pass -
            # two techniques exercise two distinct payload-builder families in agent.py
            for technique, injector in ((PAYLOAD.TECHNIQUE.BOOLEAN, _injection),
                                        (PAYLOAD.TECHNIQUE.UNION, _unionInjection)):
                for key in list(kb.data.keys()):
                    if key.startswith("cached"):
                        kb.data[key] = None
                kb.jsonAggMode = False
                kb.injection = injector(dbms)
                kb.injections = [kb.injection]
                kb.technique = technique
                seen.update(_runMethods())

            bad = [(dbms, p, checkSanity(p)) for p in seen if checkSanity(p)]
            flagged.extend(bad)
            total += len(seen)
            if seen:
                walked += 1
            _progress(dbms, len(seen), len(bad))
    finally:
        sys.stdout = _stdout
        Connect.queryPage = _queryPage
        common_module.getPageTemplate = _getPageTemplate
        Backend.flushForcedDbms(force=True)
        logger.setLevel(_level)
        conf.threads = _threads
        threadData.disableStdOut = False

    # self-check: the linter must flag a known-malformed payload, and the walk
    # must have actually produced payloads (guards against a vacuous pass)
    if not checkSanity("1 AND (SELECT id 1 FROM users)"):
        logger.error("payload-lint self-check failed: a known-malformed payload was not flagged")
        retVal = False
    if total < 1000:
        logger.error("payload-lint self-check failed: only %d payloads generated (walk did not run)" % total)
        retVal = False

    for dbms, payload, issues in flagged[:20]:
        retVal = False
        logger.error("[%s] malformed payload: %s -> %s" % (dbms, payload, "; ".join(issues)))

    clearConsoleLine()
    logger.info("payload-lint: %d payloads across %d/%d DBMSes checked, %d malformed" % (total, walked, len(allDbms), len(flagged)))
    if retVal:
        logger.info("payload-lint final result: PASSED")
    else:
        logger.error("payload-lint final result: FAILED")

    return retVal
