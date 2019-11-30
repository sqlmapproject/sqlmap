#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import codecs
import doctest
import logging
import os
import random
import re
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import traceback

from extra.beep.beep import beep
from extra.vulnserver import vulnserver
from lib.controller.controller import start
from lib.core.common import clearColors
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import randomStr
from lib.core.common import readXmlFile
from lib.core.common import shellExec
from lib.core.compat import round
from lib.core.compat import xrange
from lib.core.convert import encodeBase64
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.exception import SqlmapBaseException
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.log import LOGGER_HANDLER
from lib.core.option import init
from lib.core.option import initOptions
from lib.core.option import setVerbosity
from lib.core.optiondict import optDict
from lib.core.settings import UNICODE_ENCODING
from lib.parse.cmdline import cmdLineParser

class Failures(object):
    failedItems = None
    failedParseOn = None
    failedTraceBack = None

_failures = Failures()
_rand = 0

def vulnTest():
    """
    Runs the testing against 'vulnserver'
    """

    TESTS = (
        (u"-u <url> --flush-session --sql-query=\"SELECT '\u0161u\u0107uraj'\" --technique=U", (u": '\u0161u\u0107uraj'",)),
        (u"-u <url> --flush-session --sql-query=\"SELECT '\u0161u\u0107uraj'\" --technique=B --no-escape", (u": '\u0161u\u0107uraj'",)),
        ("--list-tampers", ("between", "MySQL", "xforwardedfor")),
        ("-r <request> --flush-session -v 5", ("CloudFlare", "possible DBMS: 'SQLite'", "User-agent: foobar")),
        ("-l <log> --flush-session --skip-waf -v 3 --technique=U --union-from=users --banner --parse-errors", ("banner: '3.", "ORDER BY term out of range", "~xp_cmdshell")),
        ("-l <log> --offline --banner -v 5", ("banner: '3.", "~[TRAFFIC OUT]")),
        ("-u <url> --flush-session --encoding=ascii --forms --crawl=2 --threads=2 --banner", ("total of 2 targets", "might be injectable", "Type: UNION query", "banner: '3.")),
        ("-u <url> --flush-session --data='{\"id\": 1}' --banner", ("might be injectable", "3 columns", "Payload: {\"id\"", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "banner: '3.")),
        ("-u <url> --flush-session -H 'Foo: Bar' -H 'Sna: Fu' --data='<root><param name=\"id\" value=\"1*\"/></root>' --union-char=1 --mobile --answers='smartphone=3' --banner --smart -v 5", ("might be injectable", "Payload: <root><param name=\"id\" value=\"1", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "banner: '3.", "Nexus", "Sna: Fu", "Foo: Bar")),
        ("-u <url> --flush-session --method=PUT --data='a=1&b=2&c=3&id=1' --skip-static --dump -T users --start=1 --stop=2", ("might be injectable", "Parameter: id (PUT)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "2 entries")),
        ("-u <url> --flush-session -H 'id: 1*' --tables", ("might be injectable", "Parameter: id #1* ((custom) HEADER)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", " users ")),
        ("-u <url> --flush-session --banner --invalid-logical --technique=B --test-filter='OR boolean' --tamper=space2dash", ("banner: '3.", " LIKE ")),
        ("-u <url> --flush-session --cookie=\"PHPSESSID=d41d8cd98f00b204e9800998ecf8427e; id=1*; id2=2\" --tables --union-cols=3", ("might be injectable", "Cookie #1* ((custom) HEADER)", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", " users ")),
        ("-u <url> --flush-session --null-connection --technique=B --tamper=between,randomcase --banner", ("NULL connection is supported with HEAD method", "banner: '3.")),
        ("-u <url> --flush-session --parse-errors --test-filter=\"subquery\" --eval=\"import hashlib; id2=2; id3=hashlib.md5(id.encode()).hexdigest()\" --referer=\"localhost\"", ("might be injectable", ": syntax error", "back-end DBMS: SQLite", "WHERE or HAVING clause (subquery")),
        ("-u <url> --banner --schema --dump -T users --binary-fields=surname --where \"id>3\"", ("banner: '3.", "INTEGER", "TEXT", "id", "name", "surname", "2 entries", "6E616D6569736E756C6C")),
        ("-u <url> --technique=U --fresh-queries --force-partial --dump -T users --answer=\"crack=n\" -v 3", ("performed 6 queries", "nameisnull", "~using default dictionary")),
        ("-u <url> --flush-session --all", ("5 entries", "Type: boolean-based blind", "Type: time-based blind", "Type: UNION query", "luther", "blisset", "fluffy", "179ad45c6ce2cb97cf1029e212046e81", "NULL", "nameisnull", "testpass")),
        ("-u <url> -z \"tec=B\" --hex --fresh-queries --threads=4 --sql-query=\"SELECT * FROM users\"", ("SELECT * FROM users [5]", "nameisnull")),
        ("-u '<url>&echo=foobar*' --flush-session", ("might be vulnerable to cross-site scripting",)),
        ("-u '<url>&query=*' --flush-session --technique=Q --banner", ("Title: SQLite inline queries", "banner: '3.")),
        ("-d <direct> --flush-session --dump -T users --binary-fields=name --where \"id=3\"", ("7775", "179ad45c6ce2cb97cf1029e212046e81 (testpass)",)),
        ("-d <direct> --flush-session --banner --schema --sql-query=\"UPDATE users SET name='foobar' WHERE id=5; SELECT * FROM users; SELECT 987654321\"", ("banner: '3.", "INTEGER", "TEXT", "id", "name", "surname", "5, foobar, nameisnull", "[*] 987654321",)),
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

    for options, checks in TESTS:
        status = '%d/%d (%d%%) ' % (count, len(TESTS), round(100.0 * count / len(TESTS)))
        dataToStdout("\r[%s] [INFO] complete: %s" % (time.strftime("%X"), status))

        cmd = "%s %s %s --batch" % (sys.executable, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sqlmap.py")), options.replace("<url>", url).replace("<direct>", direct).replace("<request>", request).replace("<log>", log))
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
            if os.path.splitext(filename)[1].lower() == ".py" and filename != "__init__.py":
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

def adjustValueType(tagName, value):
    for family in optDict:
        for name, type_ in optDict[family].items():
            if type(type_) == tuple:
                type_ = type_[0]
            if tagName == name:
                if type_ == "boolean":
                    value = (value == "True")
                elif type_ == "integer":
                    value = int(value)
                elif type_ == "float":
                    value = float(value)
                break
    return value

def liveTest():
    """
    Runs the test of a program against the live testing environment
    """

    retVal = True
    count = 0
    global_ = {}
    vars_ = {}

    livetests = readXmlFile(paths.LIVE_TESTS_XML)
    length = len(livetests.getElementsByTagName("case"))

    element = livetests.getElementsByTagName("global")
    if element:
        for item in element:
            for child in item.childNodes:
                if child.nodeType == child.ELEMENT_NODE and child.hasAttribute("value"):
                    global_[child.tagName] = adjustValueType(child.tagName, child.getAttribute("value"))

    element = livetests.getElementsByTagName("vars")
    if element:
        for item in element:
            for child in item.childNodes:
                if child.nodeType == child.ELEMENT_NODE and child.hasAttribute("value"):
                    var = child.getAttribute("value")
                    vars_[child.tagName] = randomStr(6) if var == "random" else var

    for case in livetests.getElementsByTagName("case"):
        parse_from_console_output = False
        count += 1
        name = None
        parse = []
        switches = dict(global_)
        value = ""
        vulnerable = True
        result = None

        if case.hasAttribute("name"):
            name = case.getAttribute("name")

        if conf.runCase and ((conf.runCase.isdigit() and conf.runCase != count) or not re.search(conf.runCase, name, re.DOTALL)):
            continue

        if case.getElementsByTagName("switches"):
            for child in case.getElementsByTagName("switches")[0].childNodes:
                if child.nodeType == child.ELEMENT_NODE and child.hasAttribute("value"):
                    value = replaceVars(child.getAttribute("value"), vars_)
                    switches[child.tagName] = adjustValueType(child.tagName, value)

        if case.getElementsByTagName("parse"):
            for item in case.getElementsByTagName("parse")[0].getElementsByTagName("item"):
                if item.hasAttribute("value"):
                    value = replaceVars(item.getAttribute("value"), vars_)

                if item.hasAttribute("console_output"):
                    parse_from_console_output = bool(item.getAttribute("console_output"))

                parse.append((value, parse_from_console_output))

        conf.verbose = global_.get("verbose", 1)
        setVerbosity()

        msg = "running live test case: %s (%d/%d)" % (name, count, length)
        logger.info(msg)

        initCase(switches, count)

        test_case_fd = codecs.open(os.path.join(paths.SQLMAP_OUTPUT_PATH, "test_case"), "wb", UNICODE_ENCODING)
        test_case_fd.write("%s\n" % name)

        try:
            result = runCase(parse)
        except SqlmapNotVulnerableException:
            vulnerable = False
        finally:
            conf.verbose = global_.get("verbose", 1)
            setVerbosity()

        if result is True:
            logger.info("test passed")
            cleanCase()
        else:
            errMsg = "test failed"

            if _failures.failedItems:
                errMsg += " at parsing items: %s" % ", ".join(i for i in _failures.failedItems)

            errMsg += " - scan folder: %s" % paths.SQLMAP_OUTPUT_PATH
            errMsg += " - traceback: %s" % bool(_failures.failedTraceBack)

            if not vulnerable:
                errMsg += " - SQL injection not detected"

            logger.error(errMsg)
            test_case_fd.write("%s\n" % errMsg)

            if _failures.failedParseOn:
                console_output_fd = codecs.open(os.path.join(paths.SQLMAP_OUTPUT_PATH, "console_output"), "wb", UNICODE_ENCODING)
                console_output_fd.write(_failures.failedParseOn)
                console_output_fd.close()

            if _failures.failedTraceBack:
                traceback_fd = codecs.open(os.path.join(paths.SQLMAP_OUTPUT_PATH, "traceback"), "wb", UNICODE_ENCODING)
                traceback_fd.write(_failures.failedTraceBack)
                traceback_fd.close()

            beep()

            if conf.stopFail is True:
                return retVal

        test_case_fd.close()
        retVal &= bool(result)

    dataToStdout("\n")

    if retVal:
        logger.info("live test final result: PASSED")
    else:
        logger.error("live test final result: FAILED")

    return retVal

def initCase(switches, count):
    _failures.failedItems = []
    _failures.failedParseOn = None
    _failures.failedTraceBack = None

    paths.SQLMAP_OUTPUT_PATH = tempfile.mkdtemp(prefix="%s%d-" % (MKSTEMP_PREFIX.TESTING, count))
    paths.SQLMAP_DUMP_PATH = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "dump")
    paths.SQLMAP_FILES_PATH = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "files")

    logger.debug("using output directory '%s' for this test case" % paths.SQLMAP_OUTPUT_PATH)

    LOGGER_HANDLER.stream = sys.stdout = tempfile.SpooledTemporaryFile(max_size=0, mode="w+b", prefix="sqlmapstdout-")

    cmdLineOptions = cmdLineParser()

    if switches:
        for key, value in switches.items():
            if key in cmdLineOptions.__dict__:
                cmdLineOptions.__dict__[key] = value

    initOptions(cmdLineOptions, True)
    init()

def cleanCase():
    shutil.rmtree(paths.SQLMAP_OUTPUT_PATH, True)

def runCase(parse):
    retVal = True
    handled_exception = None
    unhandled_exception = None
    result = False
    console = ""

    try:
        result = start()
    except KeyboardInterrupt:
        pass
    except SqlmapBaseException as ex:
        handled_exception = ex
    except Exception as ex:
        unhandled_exception = ex
    finally:
        sys.stdout.seek(0)
        console = sys.stdout.read()
        LOGGER_HANDLER.stream = sys.stdout = sys.__stdout__

    if unhandled_exception:
        _failures.failedTraceBack = "unhandled exception: %s" % str(traceback.format_exc())
        retVal = None
    elif handled_exception:
        _failures.failedTraceBack = "handled exception: %s" % str(traceback.format_exc())
        retVal = None
    elif result is False:  # this means no SQL injection has been detected - if None, ignore
        retVal = False

    console = getUnicode(console, encoding=sys.stdin.encoding)

    if parse and retVal:
        with codecs.open(conf.dumper.getOutputFile(), "rb", UNICODE_ENCODING) as f:
            content = f.read()

        for item, parse_from_console_output in parse:
            parse_on = console if parse_from_console_output else content

            if item.startswith("r'") and item.endswith("'"):
                if not re.search(item[2:-1], parse_on, re.DOTALL):
                    retVal = None
                    _failures.failedItems.append(item)

            elif item not in parse_on:
                retVal = None
                _failures.failedItems.append(item)

        if _failures.failedItems:
            _failures.failedParseOn = console

    elif retVal is False:
        _failures.failedParseOn = console

    return retVal

def replaceVars(item, vars_):
    retVal = item

    if item and vars_:
        for var in re.findall(r"\$\{([^}]+)\}", item):
            if var in vars_:
                retVal = retVal.replace("${%s}" % var, vars_[var])

    return retVal
