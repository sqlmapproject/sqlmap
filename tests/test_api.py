#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit tests for the sqlmap REST API (lib/utils/api.py).

Two complementary angles:
  1. Pure helpers / objects called directly (is_admin, validate_task_options,
     the Database and Task classes, the StdDbOut/LogRecorder IPC writers).
  2. The bottle HTTP routes driven through the WSGI app via a minimal in-process
     test client (no sockets, no network, no scan subprocess) - task lifecycle,
     option get/set, scan status/data/log, admin list/flush, version, auth.

The scan-data assembler/collector helpers (_storeData / _assembleData /
_sanitizeScanData / _cleanIdentifier / writeReportJson) are pinned separately in
test_report.py; here we focus on what that file does not exercise.
"""

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.utils.api as api
from lib.core.data import conf
from lib.core.convert import encodeBase64
from lib.core.enums import CONTENT_STATUS, CONTENT_TYPE
from thirdparty.bottle.bottle import default_app


def _wsgi_call(method, path, body=None, headers=None, remote_addr="127.0.0.1"):
    """
    Drive the module's bottle routes through the WSGI interface in-process.
    Returns (status_code_int, parsed_json_or_None, raw_text).
    """

    app = default_app()
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REMOTE_ADDR": remote_addr,
        "wsgi.input": io.BytesIO(),
        "wsgi.errors": sys.stderr,
        "wsgi.url_scheme": "http",
    }

    if body is not None:
        data = json.dumps(body).encode("utf-8")
        environ["CONTENT_TYPE"] = "application/json"
        environ["CONTENT_LENGTH"] = str(len(data))
        environ["wsgi.input"] = io.BytesIO(data)

    for key, value in (headers or {}).items():
        environ["HTTP_%s" % key.upper().replace("-", "_")] = value

    captured = {}

    def start_response(status, response_headers, exc_info=None):
        captured["status"] = status

    chunks = app(environ, start_response)
    raw = b"".join(chunks).decode("utf-8", "replace")
    code = int(captured["status"].split(" ", 1)[0])

    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = None

    return code, parsed, raw


class _ApiServerCase(unittest.TestCase):
    """
    Stands up just enough of the API server state (IPC database + DataStore globals)
    to drive the routes, snapshotting and restoring every global it touches.
    """

    def setUp(self):
        conf.batch = True

        # snapshot mutated globals
        self._saved = {
            "current_db": api.DataStore.current_db,
            "tasks": api.DataStore.tasks,
            "admin_token": api.DataStore.admin_token,
            "username": api.DataStore.username,
            "password": api.DataStore.password,
            "filepath": api.Database.filepath,
        }

        # fresh in-memory IPC database (same init the server() function performs)
        self.db = api.Database(":memory:")
        self.db.connect()
        self.db.init()

        api.DataStore.current_db = self.db
        api.DataStore.tasks = {}
        api.DataStore.admin_token = "a" * 32
        api.DataStore.username = None
        api.DataStore.password = None
        api.Database.filepath = ":memory:"

    def tearDown(self):
        try:
            self.db.disconnect()
        except Exception:
            pass

        api.DataStore.current_db = self._saved["current_db"]
        api.DataStore.tasks = self._saved["tasks"]
        api.DataStore.admin_token = self._saved["admin_token"]
        api.DataStore.username = self._saved["username"]
        api.DataStore.password = self._saved["password"]
        api.Database.filepath = self._saved["filepath"]

    def _new_task(self):
        code, parsed, _ = _wsgi_call("GET", "/task/new")
        self.assertEqual(code, 200)
        self.assertTrue(parsed["success"])
        return parsed["taskid"]


# ---------------------------------------------------------------------------
# Pure helpers / objects
# ---------------------------------------------------------------------------

class TestGenericHelpers(unittest.TestCase):
    def setUp(self):
        self._saved_token = api.DataStore.admin_token

    def tearDown(self):
        api.DataStore.admin_token = self._saved_token

    def test_is_admin_constant_time_compare(self):
        api.DataStore.admin_token = "deadbeef"
        self.assertTrue(api.is_admin("deadbeef"))
        self.assertFalse(api.is_admin("deadbeer"))
        self.assertFalse(api.is_admin(None))
        self.assertFalse(api.is_admin(""))


class TestValidateTaskOptions(unittest.TestCase):
    def setUp(self):
        self._saved_tasks = api.DataStore.tasks
        api.DataStore.tasks = {"t1": api.Task("t1", "127.0.0.1")}

    def tearDown(self):
        api.DataStore.tasks = self._saved_tasks

    def test_non_dict_rejected(self):
        msg = api.validate_task_options("t1", ["level"], "scan_start")
        self.assertEqual(msg, "Invalid JSON options")

    def test_unsupported_option_rejected(self):
        # reportJson is in RESTAPI_UNSUPPORTED_OPTIONS
        msg = api.validate_task_options("t1", {"reportJson": "x.json"}, "scan_start")
        self.assertIn("Unsupported option", msg)
        self.assertIn("reportJson", msg)

    def test_readonly_option_rejected(self):
        # taskid is in RESTAPI_READONLY_OPTIONS
        msg = api.validate_task_options("t1", {"taskid": "haxx"}, "option_set")
        self.assertIn("Unsupported option", msg)
        self.assertIn("taskid", msg)

    def test_unknown_option_rejected(self):
        msg = api.validate_task_options("t1", {"nosuchoption": 1}, "option_set")
        self.assertIn("Unknown option", msg)
        self.assertIn("nosuchoption", msg)

    def test_valid_options_accepted(self):
        # a real, supported option returns None (no error message)
        self.assertIsNone(api.validate_task_options("t1", {"level": 3, "risk": 2}, "scan_start"))


class TestDatabase(unittest.TestCase):
    """The IPC Database wrapper: connect/init schema, execute SELECT vs DML, disconnect."""

    def setUp(self):
        self.db = api.Database(":memory:")
        self.db.connect("test")
        self.db.init()

    def tearDown(self):
        self.db.disconnect()

    def test_init_creates_expected_schema(self):
        names = set(row[0] for row in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'"))
        self.assertTrue({"logs", "data", "errors"}.issubset(names))

    def test_init_is_idempotent(self):
        # "CREATE TABLE IF NOT EXISTS" - running init twice must not raise
        self.db.init()

    def test_execute_select_returns_rows_dml_returns_none(self):
        self.assertIsNone(self.db.execute("INSERT INTO errors VALUES(NULL, ?, ?)", ("t1", "boom")))
        rows = self.db.execute("SELECT taskid, error FROM errors")
        self.assertEqual(rows, [("t1", "boom")])

    def test_disconnect_is_safe_without_connection(self):
        fresh = api.Database(":memory:")  # never connected
        fresh.disconnect()  # must not raise


class TestTask(unittest.TestCase):
    """The Task object: option defaults, set/get/reset, and the no-process engine paths."""

    def test_initialize_options_sets_api_markers(self):
        t = api.Task("abc123", "10.0.0.1")
        self.assertEqual(t.remote_addr, "10.0.0.1")
        self.assertIs(t.options.api, True)
        self.assertEqual(t.options.taskid, "abc123")
        self.assertIs(t.options.batch, True)
        self.assertIs(t.options.disableColoring, True)
        self.assertIs(t.options.eta, False)

    def test_set_get_reset_options(self):
        t = api.Task("abc123", "10.0.0.1")
        original_level = t.get_option("level")
        t.set_option("level", original_level + 4)
        self.assertEqual(t.get_option("level"), original_level + 4)
        t.reset_options()
        self.assertEqual(t.get_option("level"), original_level)

    def test_get_options_returns_attribdict(self):
        t = api.Task("abc123", "10.0.0.1")
        opts = t.get_options()
        self.assertIs(opts, t.options)
        self.assertIn("level", opts)

    def test_engine_paths_without_process(self):
        t = api.Task("abc123", "10.0.0.1")
        self.assertIsNone(t.engine_process())
        self.assertIsNone(t.engine_get_id())
        self.assertIsNone(t.engine_get_returncode())
        self.assertFalse(t.engine_has_terminated())
        self.assertIsNone(t.engine_stop())
        self.assertIsNone(t.engine_kill())


class TestStdDbOutAndLogRecorder(unittest.TestCase):
    """
    StdDbOut and LogRecorder write engine output/logs into the IPC database
    (conf.databaseCursor). Verify both write paths land the expected rows.
    """

    def setUp(self):
        self.db = api.Database(":memory:")
        self.db.connect("client")
        self.db.init()
        self._saved = {
            "stdout": sys.stdout,
            "stderr": sys.stderr,
            "databaseCursor": conf.get("databaseCursor"),
            "taskid": conf.get("taskid"),
            "partRun": getattr(__import__("lib.core.data", fromlist=["kb"]).kb, "partRun", None),
        }
        conf.databaseCursor = self.db
        conf.taskid = "t1"

    def tearDown(self):
        sys.stdout = self._saved["stdout"]
        sys.stderr = self._saved["stderr"]
        conf.databaseCursor = self._saved["databaseCursor"]
        conf.taskid = self._saved["taskid"]
        self.db.disconnect()

    def test_stdout_write_stores_typed_data(self):
        # StdDbOut hijacks sys.stdout in __init__; restore it immediately and call write() directly
        std = api.StdDbOut("t1", messagetype="stdout")
        sys.stdout = self._saved["stdout"]
        std.write("MySQL >= 5.0", status=CONTENT_STATUS.COMPLETE, content_type=CONTENT_TYPE.DBMS_FINGERPRINT)
        rows = self.db.execute("SELECT taskid, status, content_type FROM data")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "t1")
        self.assertEqual(rows[0][2], CONTENT_TYPE.DBMS_FINGERPRINT)
        # the helpers are noops but must not raise
        std.flush(); std.close(); std.seek()

    def test_stderr_write_stores_error(self):
        std = api.StdDbOut("t1", messagetype="stderr")
        sys.stderr = self._saved["stderr"]
        std.write("something failed")
        rows = self.db.execute("SELECT taskid, error FROM errors")
        self.assertEqual(rows, [("t1", "something failed")])

    def test_logrecorder_emit_stores_log(self):
        import logging
        rec = api.LogRecorder()
        record = logging.LogRecord("sqlmap", logging.INFO, __file__, 1, "hello %s", ("world",), None)
        rec.emit(record)
        rows = self.db.execute("SELECT taskid, level, message FROM logs")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "t1")
        self.assertEqual(rows[0][1], "INFO")
        self.assertEqual(rows[0][2], "hello world")


# ---------------------------------------------------------------------------
# HTTP routes (WSGI test client)
# ---------------------------------------------------------------------------

class TestVersionRoute(_ApiServerCase):
    def test_version(self):
        code, parsed, _ = _wsgi_call("GET", "/version")
        self.assertEqual(code, 200)
        self.assertTrue(parsed["success"])
        self.assertIn("version", parsed)
        self.assertEqual(parsed["api_version"], 2)  # MAJOR of RESTAPI_VERSION "2.0.0"

    def test_security_headers_applied(self):
        app = default_app()
        environ = {
            "REQUEST_METHOD": "GET", "PATH_INFO": "/version",
            "SERVER_NAME": "localhost", "SERVER_PORT": "80", "REMOTE_ADDR": "127.0.0.1",
            "wsgi.input": io.BytesIO(), "wsgi.errors": sys.stderr, "wsgi.url_scheme": "http",
        }
        captured = {}

        def start_response(status, response_headers, exc_info=None):
            captured["headers"] = dict(response_headers)

        b"".join(app(environ, start_response))
        headers = captured["headers"]
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("application/json", headers.get("Content-Type", ""))


class TestTaskLifecycle(_ApiServerCase):
    def test_new_and_delete(self):
        taskid = self._new_task()
        self.assertIn(taskid, api.DataStore.tasks)

        code, parsed, _ = _wsgi_call("GET", "/task/%s/delete" % taskid)
        self.assertEqual(code, 200)
        self.assertTrue(parsed["success"])
        self.assertNotIn(taskid, api.DataStore.tasks)

    def test_delete_unknown_task_404(self):
        code, parsed, _ = _wsgi_call("GET", "/task/deadbeef/delete")
        self.assertEqual(code, 404)
        self.assertFalse(parsed["success"])
        self.assertEqual(parsed["message"], "Non-existing task ID")


class TestOptionRoutes(_ApiServerCase):
    def test_option_list(self):
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("GET", "/option/%s/list" % taskid)
        self.assertEqual(code, 200)
        self.assertTrue(parsed["success"])
        self.assertIn("level", parsed["options"])

    def test_option_list_invalid_task(self):
        code, parsed, _ = _wsgi_call("GET", "/option/nope/list")
        self.assertFalse(parsed["success"])
        self.assertEqual(parsed["message"], "Invalid task ID")

    def test_option_set_then_get(self):
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("POST", "/option/%s/set" % taskid, {"level": 4, "risk": 3})
        self.assertTrue(parsed["success"])

        code, parsed, _ = _wsgi_call("POST", "/option/%s/get" % taskid, ["level", "risk"])
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["options"], {"level": 4, "risk": 3})

    def test_option_set_invalid_task(self):
        code, parsed, _ = _wsgi_call("POST", "/option/nope/set", {"level": 1})
        self.assertFalse(parsed["success"])
        self.assertEqual(parsed["message"], "Invalid task ID")

    def test_option_set_rejects_unsupported(self):
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("POST", "/option/%s/set" % taskid, {"reportJson": "x"})
        self.assertFalse(parsed["success"])
        self.assertIn("Unsupported option", parsed["message"])

    def test_option_get_unknown_option(self):
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("POST", "/option/%s/get" % taskid, ["nosuchoption"])
        self.assertFalse(parsed["success"])
        self.assertIn("Unknown option", parsed["message"])

    def test_option_get_invalid_task(self):
        code, parsed, _ = _wsgi_call("POST", "/option/nope/get", ["level"])
        self.assertFalse(parsed["success"])
        self.assertEqual(parsed["message"], "Invalid task ID")


class TestScanQueryRoutes(_ApiServerCase):
    """status/data/log on a task that has never launched a subprocess (no scan started)."""

    def test_status_not_running(self):
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("GET", "/scan/%s/status" % taskid)
        self.assertEqual(code, 200)
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["status"], "not running")
        self.assertIsNone(parsed["returncode"])

    def test_status_invalid_task(self):
        code, parsed, _ = _wsgi_call("GET", "/scan/nope/status")
        self.assertFalse(parsed["success"])
        self.assertEqual(parsed["message"], "Invalid task ID")

    def test_data_empty(self):
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("GET", "/scan/%s/data" % taskid)
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["data"], [])
        self.assertEqual(parsed["error"], [])

    def test_data_returns_stored_rows(self):
        taskid = self._new_task()
        # store a result row directly into the shared IPC db, then read it back via the route
        api._storeData(self.db, taskid, "MySQL >= 5.0", CONTENT_STATUS.COMPLETE, CONTENT_TYPE.DBMS_FINGERPRINT)
        code, parsed, _ = _wsgi_call("GET", "/scan/%s/data" % taskid)
        self.assertTrue(parsed["success"])
        self.assertEqual(len(parsed["data"]), 1)
        self.assertEqual(parsed["data"][0]["type_name"], "DBMS_FINGERPRINT")
        self.assertEqual(parsed["data"][0]["value"], "MySQL >= 5.0")

    def test_data_invalid_task(self):
        code, parsed, _ = _wsgi_call("GET", "/scan/nope/data")
        self.assertFalse(parsed["success"])

    def test_log_empty(self):
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("GET", "/scan/%s/log" % taskid)
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["log"], [])

    def test_log_returns_stored_rows(self):
        taskid = self._new_task()
        self.db.execute("INSERT INTO logs VALUES(NULL, ?, ?, ?, ?)", (taskid, "00:00:00", "INFO", "started"))
        code, parsed, _ = _wsgi_call("GET", "/scan/%s/log" % taskid)
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["log"], [{"time": "00:00:00", "level": "INFO", "message": "started"}])

    def test_log_invalid_task(self):
        code, parsed, _ = _wsgi_call("GET", "/scan/nope/log")
        self.assertFalse(parsed["success"])

    def test_log_limited_subset(self):
        taskid = self._new_task()
        for i in range(1, 4):
            self.db.execute("INSERT INTO logs VALUES(NULL, ?, ?, ?, ?)", (taskid, "00:00:0%d" % i, "INFO", "m%d" % i))
        code, parsed, _ = _wsgi_call("GET", "/scan/%s/log/1/2" % taskid)
        self.assertTrue(parsed["success"])
        self.assertEqual([m["message"] for m in parsed["log"]], ["m1", "m2"])

    def test_log_limited_bad_range(self):
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("GET", "/scan/%s/log/5/2" % taskid)
        self.assertFalse(parsed["success"])
        self.assertIn("must be digits", parsed["message"])

    def test_log_limited_invalid_task(self):
        code, parsed, _ = _wsgi_call("GET", "/scan/nope/log/1/2")
        self.assertFalse(parsed["success"])
        self.assertEqual(parsed["message"], "Invalid task ID")

    def test_scan_stop_invalid_when_not_running(self):
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("GET", "/scan/%s/stop" % taskid)
        self.assertFalse(parsed["success"])

    def test_scan_kill_invalid_when_not_running(self):
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("GET", "/scan/%s/kill" % taskid)
        self.assertFalse(parsed["success"])


class TestScanStart(_ApiServerCase):
    """scan_start, with the subprocess-spawning seam (engine_start) monkeypatched."""

    def test_scan_start_invalid_task(self):
        code, parsed, _ = _wsgi_call("POST", "/scan/nope/start", {})
        self.assertFalse(parsed["success"])
        self.assertEqual(parsed["message"], "Invalid task ID")

    def test_scan_start_rejects_unsupported_option(self):
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("POST", "/scan/%s/start" % taskid, {"wizard": True})
        self.assertFalse(parsed["success"])
        self.assertIn("Unsupported option", parsed["message"])

    def test_scan_start_launches_engine(self):
        taskid = self._new_task()
        task = api.DataStore.tasks[taskid]

        calls = {"started": False}

        class _FakeProc(object):
            pid = 4242
            returncode = None

            def poll(self):
                return None

            def terminate(self):
                pass

            def kill(self):
                pass

            def wait(self):
                return 0

        def fake_engine_start():
            calls["started"] = True
            task.process = _FakeProc()

        original = task.engine_start
        task.engine_start = fake_engine_start
        try:
            code, parsed, _ = _wsgi_call("POST", "/scan/%s/start" % taskid, {"url": "http://t/?id=1"})
        finally:
            task.engine_start = original

        self.assertTrue(calls["started"])
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["engineid"], 4242)
        # the provided option was applied to the task
        self.assertEqual(task.get_option("url"), "http://t/?id=1")


class TestAdminRoutes(_ApiServerCase):
    def test_admin_list_with_token(self):
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("GET", "/admin/%s/list" % api.DataStore.admin_token)
        self.assertEqual(code, 200)
        self.assertTrue(parsed["success"])
        self.assertIn(taskid, parsed["tasks"])
        self.assertEqual(parsed["tasks_num"], 1)

    def test_admin_list_same_remote_addr_without_token(self):
        # /admin/list (no token) sees only tasks from the requesting remote_addr
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("GET", "/admin/list", remote_addr="127.0.0.1")
        self.assertTrue(parsed["success"])
        self.assertIn(taskid, parsed["tasks"])

    def test_admin_list_other_remote_addr_excluded(self):
        self._new_task()  # created from 127.0.0.1
        code, parsed, _ = _wsgi_call("GET", "/admin/list", remote_addr="10.9.9.9")
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["tasks_num"], 0)

    def test_admin_flush_with_token(self):
        self._new_task()
        self._new_task()
        self.assertEqual(len(api.DataStore.tasks), 2)
        code, parsed, _ = _wsgi_call("GET", "/admin/%s/flush" % api.DataStore.admin_token)
        self.assertTrue(parsed["success"])
        self.assertEqual(len(api.DataStore.tasks), 0)

    def test_admin_flush_only_own_remote_addr(self):
        # task from .1, flush requested by .2 (no token) -> task survives
        taskid = self._new_task()
        code, parsed, _ = _wsgi_call("GET", "/admin/flush", remote_addr="10.0.0.2")
        self.assertTrue(parsed["success"])
        self.assertIn(taskid, api.DataStore.tasks)


class TestAuthentication(_ApiServerCase):
    """check_authentication before_request hook (HTTP Basic) when credentials are configured."""

    def test_no_credentials_allows_access(self):
        api.DataStore.username = None
        api.DataStore.password = None
        code, parsed, _ = _wsgi_call("GET", "/version")
        self.assertEqual(code, 200)
        self.assertTrue(parsed["success"])

    def test_missing_auth_header_denied(self):
        api.DataStore.username = "user"
        api.DataStore.password = "pass"
        code, _, raw = _wsgi_call("GET", "/version")
        self.assertEqual(code, 401)

    def test_wrong_credentials_denied(self):
        api.DataStore.username = "user"
        api.DataStore.password = "pass"
        token = encodeBase64("user:wrong", binary=False)
        code, _, raw = _wsgi_call("GET", "/version", headers={"Authorization": "Basic %s" % token})
        self.assertEqual(code, 401)

    def test_correct_credentials_allowed(self):
        api.DataStore.username = "user"
        api.DataStore.password = "pass"
        token = encodeBase64("user:pass", binary=False)
        code, parsed, _ = _wsgi_call("GET", "/version", headers={"Authorization": "Basic %s" % token})
        self.assertEqual(code, 200)
        self.assertTrue(parsed["success"])

    def test_malformed_basic_credentials_denied(self):
        # base64 of a string without ':' separator -> denied
        api.DataStore.username = "user"
        api.DataStore.password = "pass"
        token = encodeBase64("nocolon", binary=False)
        code, _, _ = _wsgi_call("GET", "/version", headers={"Authorization": "Basic %s" % token})
        self.assertEqual(code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
