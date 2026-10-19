#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Authentication refresh hook loading and replay against a local HTTP server.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.data import conf, kb, paths, cmdLineOptions
from lib.core.enums import MKSTEMP_PREFIX, REDIRECTION
from lib.core.exception import SqlmapConnectionException, SqlmapFilePathException, SqlmapSyntaxException
from lib.core.option import _setAuthRefreshFunction, _setKnowledgeBaseAttributes
from lib.core.threads import getCurrentThreadData
from lib.request import authrefresh
from lib.request.connect import Connect
from lib.request.redirecthandler import SmartRedirectHandler
from thirdparty.six.moves import BaseHTTPServer, socketserver
from thirdparty.six.moves import urllib as _urllib

_GET_PAGE = Connect.__dict__['getPage']
_QUERY_PAGE = Connect.__dict__['queryPage']


def _assertTemplate(testCase, exception):
    match = re.search(r"template script at '([^']+)'", str(exception))
    testCase.assertIsNotNone(match)
    path = match.group(1)
    try:
        testCase.assertTrue(os.path.basename(path).startswith(MKSTEMP_PREFIX.AUTH_REFRESH))
        testCase.assertTrue(os.path.isfile(os.path.join(os.path.dirname(path), '__init__.py')))
        with open(path) as stream:
            source = stream.read()
        namespace = {}
        eval(compile(source, path, 'exec'), namespace)
        testCase.assertEqual(namespace['refresh'](), {'Authorization': 'Bearer <fresh token>'})
        testCase.assertNotIn(paths.SQLMAP_EXTRAS_PATH, path)
    finally:
        os.unlink(path)


class _Server(socketserver.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    daemon_threads = True


class _Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.do_POST()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        token = self.headers.get('X-Auth-Token')
        if self.path == '/refresh':
            self.server.refreshes += 1
            code, body = 200, b'{"token":"fresh"}'
        else:
            with self.server.lock:
                self.server.requests.append((self.path, body, token))
                if token != self.server.token:
                    self.server.expired += 1
                    if self.server.expired >= 2:
                        self.server.bothExpired.set()
            if token != self.server.token and self.server.syncExpired:
                self.server.bothExpired.wait(3)
            code = 200 if token == self.server.token else 401
            body = b'ok' if code == 200 else b'expired'
        self.send_response(302 if self.path == '/redirect' and code == 200 else code)
        if self.path == '/redirect' and code == 200:
            self.send_header('Location', self.server.redirect)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestAuthRefresh(unittest.TestCase):
    def setUp(self):
        self.conf = dict(conf)
        self.cmdLineOptions = dict(cmdLineOptions)
        cmdLineOptions.method = None
        self.kb = dict(kb)
        self.threadData = dict(getCurrentThreadData().__dict__)
        getCurrentThreadData().__dict__.clear()
        getCurrentThreadData().reset()
        self.timeout = socket.getdefaulttimeout()
        self.urlopen = _urllib.request.urlopen
        # Other engine tests replace these descriptors; use the real methods even when an
        # earlier Python 2 fixture restored a bare function instead of a staticmethod.
        self.methods = Connect.__dict__['getPage'], Connect.__dict__['queryPage']
        Connect.getPage, Connect.queryPage = _GET_PAGE, _QUERY_PAGE
        _setKnowledgeBaseAttributes(False)
        kb.wizardMode = True
        self.server = _Server(('127.0.0.1', 0), _Handler)
        self.server.requests = []
        self.server.refreshes = 0
        self.server.token = 'fresh'
        self.server.expired = 0
        self.server.syncExpired = False
        self.server.bothExpired = threading.Event()
        self.server.lock = threading.Lock()
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        conf.url = 'http://127.0.0.1:%d/test' % self.server.server_port
        conf.hostname, conf.scheme, conf.port = '127.0.0.1', 'http', self.server.server_port
        conf.path = '/test'
        conf.httpHeaders = [('X-Auth-Token', 'expired')]
        conf.parameters = {}
        conf.data = None
        conf.abortCode = []
        conf.ignoreCode = []
        conf.authRefresh = 'test_refresh.py'
        conf.batch = True
        conf.keepAlive = False
        conf.retryOn = None
        conf.timeout = 5
        conf.ignoreRedirects = False
        conf.scope = None
        kb.choices.redirect = REDIRECTION.YES
        _urllib.request.urlopen = _urllib.request.build_opener(_urllib.request.ProxyHandler({}), SmartRedirectHandler()).open

        def refresh():
            # A real, application-specific token exchange outside sqlmap's request engine.
            response = _urllib.request.urlopen(conf.url.replace('/test', '/refresh'), timeout=3)
            try:
                return {'X-Auth-Token': json.loads(response.read().decode('ascii'))['token']}
            finally:
                response.close()

        kb.authRefreshFunction = refresh

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        _urllib.request.urlopen = self.urlopen
        Connect.getPage, Connect.queryPage = self.methods
        socket.setdefaulttimeout(self.timeout)
        conf.clear()
        conf.update(self.conf)
        cmdLineOptions.clear()
        cmdLineOptions.update(self.cmdLineOptions)
        kb.clear()
        kb.update(self.kb)
        getCurrentThreadData().__dict__.clear()
        getCurrentThreadData().__dict__.update(self.threadData)

    def test_expiry_mid_scan_preserves_payload_and_reuses_headers(self):
        self.server.token = 'expired'
        self.assertEqual(Connect.getPage()[2], 200)
        self.assertEqual(self.server.refreshes, 0)
        self.server.token = 'fresh'
        payload = b'id=1%20AND%201%3D1&other=keep'
        self.assertEqual(Connect.getPage(get='marker=123', post=payload)[2], 200)
        self.assertEqual(self.server.requests[-2:], [('/test?marker=123', payload, 'expired'), ('/test?marker=123', payload, 'fresh')])
        self.assertEqual(Connect.getPage()[2], 200)
        self.assertEqual(self.server.refreshes, 1)
        self.assertEqual(getCurrentThreadData().lastCode, 200)
        self.assertEqual(getCurrentThreadData().lastPage, 'ok')
        self.assertNotEqual(kb.originalCode, 401)

    def test_second_401_stops_after_one_replay(self):
        kb.authRefreshFunction = lambda: {'X-Auth-Token': 'still-expired'}
        with self.assertRaises(SqlmapConnectionException):
            Connect.getPage()
        self.assertEqual(len(self.server.requests), 2)
        self.assertTrue(kb.authRefreshFailed)

    def test_abort_code_takes_precedence(self):
        conf.abortCode = [401]
        with self.assertRaises(SystemExit):
            Connect.getPage()
        self.assertEqual(self.server.refreshes, 0)
        self.assertEqual(len(self.server.requests), 1)

    def test_without_option_preserves_401_behavior(self):
        conf.authRefresh = None
        with self.assertRaises(SqlmapConnectionException):
            Connect.getPage()
        self.assertEqual(self.server.refreshes, 0)

    def test_concurrent_401s_share_one_refresh(self):
        self.server.syncExpired = True
        results, errors = [], []

        def worker():
            try:
                results.append(Connect.getPage()[2])
            except Exception as ex:
                errors.append(ex)

        workers = [threading.Thread(target=worker) for _ in range(2)]
        for workerThread in workers:
            workerThread.start()
        for workerThread in workers:
            workerThread.join(10)
            self.assertFalse(workerThread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results, [200, 200])
        self.assertEqual(self.server.refreshes, 1)
        self.assertEqual(self.server.expired, 2)

    def test_invalid_hook_results_are_rejected_without_leaking_secrets(self):
        for result in (None, {}, 'secret-token', {'X-Token': 'secret\r\nInjected: value'}, {'Host': 'elsewhere'}, {'X-Token': 42}, {'X-Token': 'secret', 'x-token': 'other'}):
            kb.authRefreshFailed = False
            kb.authRefreshFunction = lambda: result
            with self.assertRaises(SqlmapConnectionException) as caught:
                authrefresh.refresh(0)
            self.assertNotIn('secret', str(caught.exception))
            _assertTemplate(self, caught.exception)
            self.assertEqual(kb.authRefreshVersion, 0)

    def test_hook_exception_is_sanitized(self):
        def refresh():
            raise ValueError('password=secret')
        kb.authRefreshFunction = refresh
        with self.assertRaises(SqlmapConnectionException) as caught:
            Connect.getPage()
        self.assertNotIn('secret', str(caught.exception))
        _assertTemplate(self, caught.exception)
        self.assertEqual(len(self.server.requests), 1)

    def test_credentials_are_scoped_to_scheme_host_and_port(self):
        authrefresh.refresh(0)
        for url in ('http://elsewhere/test', 'https://127.0.0.1/test', 'http://127.0.0.1:1/test'):
            req = _urllib.request.Request(url)
            self.assertIsNone(authrefresh.apply(req))
            self.assertEqual(req.headers, {})
        self.assertTrue(authrefresh.sameOrigin('https://example.com', 'https://example.com:443/path'))

    def test_refresh_overrides_stale_preprocess_headers(self):
        kb.preprocessFunctions = [lambda req: req.add_header('X-Auth-Token', 'expired')]
        self.assertEqual(Connect.getPage()[2], 200)
        self.assertEqual(self.server.refreshes, 1)

    def test_redirect_to_another_port_does_not_receive_refreshed_token(self):
        authrefresh.refresh(0)
        other = _Server(('127.0.0.1', 0), _Handler)
        other.requests, other.token, other.expired = [], None, 0
        other.lock = threading.Lock()
        other.syncExpired = False
        thread = threading.Thread(target=other.serve_forever)
        thread.daemon = True
        thread.start()
        try:
            self.server.redirect = 'http://127.0.0.1:%d/landing' % other.server_port
            Connect.getPage(url=conf.url.replace('/test', '/redirect'))
            self.assertEqual(other.requests, [('/landing', b'', None)])
            self.assertEqual(self.server.refreshes, 1)
        finally:
            other.shutdown()
            other.server_close()
            thread.join(5)

    def test_auth_refresh_latency_is_excluded_from_query_timing(self):
        import lib.request.connect as connect
        originalPage, originalDelta = Connect.getPage, connect.calculateDeltaSeconds

        def getPage(**kwargs):
            getCurrentThreadData().authRefreshTime += 12
            return 'ok', None, 200

        Connect.getPage = staticmethod(getPage)
        connect.calculateDeltaSeconds = lambda start: 15
        try:
            Connect.queryPage(content=True)
            self.assertEqual(getCurrentThreadData().lastQueryDuration, 3)
        finally:
            Connect.getPage = staticmethod(originalPage)
            connect.calculateDeltaSeconds = originalDelta


class TestAuthRefreshLoader(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix='sqlmap-authrefresh-')
        self.oldOption = conf.authRefresh
        self.oldFunction = kb.authRefreshFunction
        self.oldPath = list(sys.path)

    def tearDown(self):
        conf.authRefresh = self.oldOption
        kb.authRefreshFunction = self.oldFunction
        sys.path[:] = self.oldPath
        for name in list(sys.modules):
            if name.startswith('authrefresh_test_'):
                del sys.modules[name]
        shutil.rmtree(self.directory)

    def script(self, name, content):
        path = os.path.join(self.directory, 'authrefresh_test_%s.py' % name)
        with open(path, 'w') as stream:
            stream.write(content)
        conf.authRefresh = path

    def test_load_does_not_call_refresh(self):
        self.script('valid', "def refresh():\n    raise AssertionError('must only run on 401')\n")
        _setAuthRefreshFunction()
        self.assertTrue(callable(kb.authRefreshFunction))

    def test_missing_invalid_and_empty_scripts_point_to_template(self):
        for name, source in (('empty', ''), ('wrong', 'def other():\n    pass\n'), ('args', 'def refresh(req):\n    pass\n'), ('syntax', 'def refresh(:')):
            self.script(name, source)
            with self.assertRaises(SqlmapSyntaxException) as caught:
                _setAuthRefreshFunction()
            _assertTemplate(self, caught.exception)
        conf.authRefresh = os.path.join(self.directory, 'missing.py')
        with self.assertRaises(SqlmapFilePathException) as caught:
            _setAuthRefreshFunction()
        _assertTemplate(self, caught.exception)

    def test_help_is_one_line(self):
        output = subprocess.check_output([sys.executable, os.path.join(paths.SQLMAP_ROOT_PATH, 'sqlmap.py'), '-hh'])
        lines = output.decode('utf-8').splitlines()
        matches = [i for i, line in enumerate(lines) if '--auth-refresh' in line]
        self.assertEqual(len(matches), 1)
        self.assertIn('HTTP 401', lines[matches[0]])
        self.assertLessEqual(len(lines[matches[0]]), 78)
        for option in ('--preprocess', '--postprocess'):
            self.assertLess(matches[0], next(i for i, line in enumerate(lines) if option in line))


if __name__ == '__main__':
    unittest.main()
