#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import logging
import os
import re
import shlex
import socket
import sqlite3
import sys
import tempfile
import time
import urllib2

from lib.core.common import dataToStdout
from lib.core.common import getSafeExString
from lib.core.common import unArrayizeValue
from lib.core.convert import base64pickle
from lib.core.convert import hexencode
from lib.core.convert import dejsonize
from lib.core.convert import jsonize
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import paths
from lib.core.data import logger
from lib.core.datatype import AttribDict
from lib.core.defaults import _defaults
from lib.core.enums import CONTENT_STATUS
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.enums import PART_RUN_CONTENT_TYPES
from lib.core.exception import SqlmapConnectionException
from lib.core.log import LOGGER_HANDLER
from lib.core.optiondict import optDict
from lib.core.settings import RESTAPI_DEFAULT_ADAPTER
from lib.core.settings import IS_WIN
from lib.core.settings import RESTAPI_DEFAULT_ADDRESS
from lib.core.settings import RESTAPI_DEFAULT_PORT
from lib.core.subprocessng import Popen
from lib.parse.cmdline import cmdLineParser
from thirdparty.bottle.bottle import error as return_error
from thirdparty.bottle.bottle import get
from thirdparty.bottle.bottle import hook
from thirdparty.bottle.bottle import post
from thirdparty.bottle.bottle import request
from thirdparty.bottle.bottle import response
from thirdparty.bottle.bottle import run


# global settings
class DataStore(object):
    admin_id = ""
    current_db = None
    tasks = dict()


# API objects
class Database(object):
    filepath = None

    def __init__(self, database=None):
        self.database = self.filepath if database is None else database
        self.connection = None
        self.cursor = None

    def connect(self, who="server"):
        self.connection = sqlite3.connect(self.database, timeout=3, isolation_level=None)
        self.cursor = self.connection.cursor()
        logger.debug("REST-JSON API %s connected to IPC database" % who)

    def disconnect(self):
        if self.cursor:
            self.cursor.close()

        if self.connection:
            self.connection.close()

    def commit(self):
        self.connection.commit()

    def execute(self, statement, arguments=None):
        while True:
            try:
                if arguments:
                    self.cursor.execute(statement, arguments)
                else:
                    self.cursor.execute(statement)
            except sqlite3.OperationalError, ex:
                if not "locked" in getSafeExString(ex):
                    raise
            else:
                break

        if statement.lstrip().upper().startswith("SELECT"):
            return self.cursor.fetchall()

    def init(self):
        self.execute("CREATE TABLE logs("
                  "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                  "taskid INTEGER, time TEXT, "
                  "level TEXT, message TEXT"
                  ")")

        self.execute("CREATE TABLE data("
                  "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                  "taskid INTEGER, status INTEGER, "
                  "content_type INTEGER, value TEXT"
                  ")")

        self.execute("CREATE TABLE errors("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "taskid INTEGER, error TEXT"
                    ")")


class Task(object):
    def __init__(self, taskid, remote_addr):
        self.remote_addr = remote_addr
        self.process = None
        self.output_directory = None
        self.options = None
        self._original_options = None
        self.initialize_options(taskid)

    def initialize_options(self, taskid):
        datatype = {"boolean": False, "string": None, "integer": None, "float": None}
        self.options = AttribDict()

        for _ in optDict:
            for name, type_ in optDict[_].items():
                type_ = unArrayizeValue(type_)
                self.options[name] = _defaults.get(name, datatype[type_])

        # Let sqlmap engine knows it is getting called by the API,
        # the task ID and the file path of the IPC database
        self.options.api = True
        self.options.taskid = taskid
        self.options.database = Database.filepath

        # Enforce batch mode and disable coloring and ETA
        self.options.batch = True
        self.options.disableColoring = True
        self.options.eta = False

        self._original_options = AttribDict(self.options)

    def set_option(self, option, value):
        self.options[option] = value

    def get_option(self, option):
        return self.options[option]

    def get_options(self):
        return self.options

    def reset_options(self):
        self.options = AttribDict(self._original_options)

    def engine_start(self):
        if os.path.exists("sqlmap.py"):
            self.process = Popen(["python", "sqlmap.py", "--pickled-options", base64pickle(self.options)], shell=False, close_fds=not IS_WIN)
        else:
            self.process = Popen(["sqlmap", "--pickled-options", base64pickle(self.options)], shell=False, close_fds=not IS_WIN)

    def engine_stop(self):
        if self.process:
            self.process.terminate()
            return self.process.wait()
        else:
            return None

    def engine_process(self):
        return self.process

    def engine_kill(self):
        if self.process:
            try:
                self.process.kill()
                return self.process.wait()
            except:
                pass
        return None

    def engine_get_id(self):
        if self.process:
            return self.process.pid
        else:
            return None

    def engine_get_returncode(self):
        if self.process:
            self.process.poll()
            return self.process.returncode
        else:
            return None

    def engine_has_terminated(self):
        return isinstance(self.engine_get_returncode(), int)


# Wrapper functions for sqlmap engine
class StdDbOut(object):
    def __init__(self, taskid, messagetype="stdout"):
        # Overwrite system standard output and standard error to write
        # to an IPC database
        self.messagetype = messagetype
        self.taskid = taskid

        if self.messagetype == "stdout":
            sys.stdout = self
        else:
            sys.stderr = self

    def write(self, value, status=CONTENT_STATUS.IN_PROGRESS, content_type=None):
        if self.messagetype == "stdout":
            if content_type is None:
                if kb.partRun is not None:
                    content_type = PART_RUN_CONTENT_TYPES.get(kb.partRun)
                else:
                    # Ignore all non-relevant messages
                    return

            output = conf.database_cursor.execute(
                "SELECT id, status, value FROM data WHERE taskid = ? AND content_type = ?",
                (self.taskid, content_type))

            # Delete partial output from IPC database if we have got a complete output
            if status == CONTENT_STATUS.COMPLETE:
                if len(output) > 0:
                    for index in xrange(len(output)):
                        conf.database_cursor.execute("DELETE FROM data WHERE id = ?",
                                                     (output[index][0],))

                conf.database_cursor.execute("INSERT INTO data VALUES(NULL, ?, ?, ?, ?)",
                                             (self.taskid, status, content_type, jsonize(value)))
                if kb.partRun:
                    kb.partRun = None

            elif status == CONTENT_STATUS.IN_PROGRESS:
                if len(output) == 0:
                    conf.database_cursor.execute("INSERT INTO data VALUES(NULL, ?, ?, ?, ?)",
                                                 (self.taskid, status, content_type,
                                                  jsonize(value)))
                else:
                    new_value = "%s%s" % (dejsonize(output[0][2]), value)
                    conf.database_cursor.execute("UPDATE data SET value = ? WHERE id = ?",
                                                 (jsonize(new_value), output[0][0]))
        else:
            conf.database_cursor.execute("INSERT INTO errors VALUES(NULL, ?, ?)",
                                         (self.taskid, str(value) if value else ""))

    def flush(self):
        pass

    def close(self):
        pass

    def seek(self):
        pass


class LogRecorder(logging.StreamHandler):
    def emit(self, record):
        """
        Record emitted events to IPC database for asynchronous I/O
        communication with the parent process
        """
        conf.database_cursor.execute("INSERT INTO logs VALUES(NULL, ?, ?, ?, ?)",
                                     (conf.taskid, time.strftime("%X"), record.levelname,
                                      record.msg % record.args if record.args else record.msg))


def setRestAPILog():
    if hasattr(conf, "api"):
        try:
            conf.database_cursor = Database(conf.database)
            conf.database_cursor.connect("client")
        except sqlite3.OperationalError, ex:
            raise SqlmapConnectionException, "%s ('%s')" % (ex, conf.database)

        # Set a logging handler that writes log messages to a IPC database
        logger.removeHandler(LOGGER_HANDLER)
        LOGGER_RECORDER = LogRecorder()
        logger.addHandler(LOGGER_RECORDER)


# Generic functions
def is_admin(taskid):
    return DataStore.admin_id == taskid


@hook("after_request")
def security_headers(json_header=True):
    """
    Set some headers across all HTTP responses
    """
    response.headers["Server"] = "Server"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Pragma"] = "no-cache"
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Expires"] = "0"
    if json_header:
        response.content_type = "application/json; charset=UTF-8"

##############################
# HTTP Status Code functions #
##############################


@return_error(401)  # Access Denied
def error401(error=None):
    security_headers(False)
    return "Access denied"


@return_error(404)  # Not Found
def error404(error=None):
    security_headers(False)
    return "Nothing here"


@return_error(405)  # Method Not Allowed (e.g. when requesting a POST method via GET)
def error405(error=None):
    security_headers(False)
    return "Method not allowed"


@return_error(500)  # Internal Server Error
def error500(error=None):
    security_headers(False)
    return "Internal server error"

#############################
# Task management functions #
#############################


# Users' methods
@get("/task/new")
def task_new():
    """
    Create new task ID
    """
    taskid = hexencode(os.urandom(8))
    remote_addr = request.remote_addr

    DataStore.tasks[taskid] = Task(taskid, remote_addr)

    logger.debug("Created new task: '%s'" % taskid)
    return jsonize({"success": True, "taskid": taskid})


@get("/task/<taskid>/delete")
def task_delete(taskid):
    """
    Delete own task ID
    """
    if taskid in DataStore.tasks:
        DataStore.tasks.pop(taskid)

        logger.debug("[%s] Deleted task" % taskid)
        return jsonize({"success": True})
    else:
        logger.warning("[%s] Invalid task ID provided to task_delete()" % taskid)
        return jsonize({"success": False, "message": "Invalid task ID"})

###################
# Admin functions #
###################


@get("/admin/<taskid>/list")
def task_list(taskid=None):
    """
    List task pull
    """
    tasks = {}

    for key in DataStore.tasks:
        if is_admin(taskid) or DataStore.tasks[key].remote_addr == request.remote_addr:
            tasks[key] = dejsonize(scan_status(key))["status"]

    logger.debug("[%s] Listed task pool (%s)" % (taskid, "admin" if is_admin(taskid) else request.remote_addr))
    return jsonize({"success": True, "tasks": tasks, "tasks_num": len(tasks)})

@get("/admin/<taskid>/flush")
def task_flush(taskid):
    """
    Flush task spool (delete all tasks)
    """

    for key in list(DataStore.tasks):
        if is_admin(taskid) or DataStore.tasks[key].remote_addr == request.remote_addr:
            DataStore.tasks[key].engine_kill()
            del DataStore.tasks[key]

    logger.debug("[%s] Flushed task pool (%s)" % (taskid, "admin" if is_admin(taskid) else request.remote_addr))
    return jsonize({"success": True})

##################################
# sqlmap core interact functions #
##################################


# Handle task's options
@get("/option/<taskid>/list")
def option_list(taskid):
    """
    List options for a certain task ID
    """
    if taskid not in DataStore.tasks:
        logger.warning("[%s] Invalid task ID provided to option_list()" % taskid)
        return jsonize({"success": False, "message": "Invalid task ID"})

    logger.debug("[%s] Listed task options" % taskid)
    return jsonize({"success": True, "options": DataStore.tasks[taskid].get_options()})


@post("/option/<taskid>/get")
def option_get(taskid):
    """
    Get the value of an option (command line switch) for a certain task ID
    """
    if taskid not in DataStore.tasks:
        logger.warning("[%s] Invalid task ID provided to option_get()" % taskid)
        return jsonize({"success": False, "message": "Invalid task ID"})

    option = request.json.get("option", "")

    if option in DataStore.tasks[taskid].options:
        logger.debug("[%s] Retrieved value for option %s" % (taskid, option))
        return jsonize({"success": True, option: DataStore.tasks[taskid].get_option(option)})
    else:
        logger.debug("[%s] Requested value for unknown option %s" % (taskid, option))
        return jsonize({"success": False, "message": "Unknown option", option: "not set"})


@post("/option/<taskid>/set")
def option_set(taskid):
    """
    Set an option (command line switch) for a certain task ID
    """
    if taskid not in DataStore.tasks:
        logger.warning("[%s] Invalid task ID provided to option_set()" % taskid)
        return jsonize({"success": False, "message": "Invalid task ID"})

    for option, value in request.json.items():
        DataStore.tasks[taskid].set_option(option, value)

    logger.debug("[%s] Requested to set options" % taskid)
    return jsonize({"success": True})


# Handle scans
@post("/scan/<taskid>/start")
def scan_start(taskid):
    """
    Launch a scan
    """
    if taskid not in DataStore.tasks:
        logger.warning("[%s] Invalid task ID provided to scan_start()" % taskid)
        return jsonize({"success": False, "message": "Invalid task ID"})

    # Initialize sqlmap engine's options with user's provided options, if any
    for option, value in request.json.items():
        DataStore.tasks[taskid].set_option(option, value)

    # Launch sqlmap engine in a separate process
    DataStore.tasks[taskid].engine_start()

    logger.debug("[%s] Started scan" % taskid)
    return jsonize({"success": True, "engineid": DataStore.tasks[taskid].engine_get_id()})


@get("/scan/<taskid>/stop")
def scan_stop(taskid):
    """
    Stop a scan
    """
    if (taskid not in DataStore.tasks or
            DataStore.tasks[taskid].engine_process() is None or
            DataStore.tasks[taskid].engine_has_terminated()):
        logger.warning("[%s] Invalid task ID provided to scan_stop()" % taskid)
        return jsonize({"success": False, "message": "Invalid task ID"})

    DataStore.tasks[taskid].engine_stop()

    logger.debug("[%s] Stopped scan" % taskid)
    return jsonize({"success": True})


@get("/scan/<taskid>/kill")
def scan_kill(taskid):
    """
    Kill a scan
    """
    if (taskid not in DataStore.tasks or
            DataStore.tasks[taskid].engine_process() is None or
            DataStore.tasks[taskid].engine_has_terminated()):
        logger.warning("[%s] Invalid task ID provided to scan_kill()" % taskid)
        return jsonize({"success": False, "message": "Invalid task ID"})

    DataStore.tasks[taskid].engine_kill()

    logger.debug("[%s] Killed scan" % taskid)
    return jsonize({"success": True})


@get("/scan/<taskid>/status")
def scan_status(taskid):
    """
    Returns status of a scan
    """
    if taskid not in DataStore.tasks:
        logger.warning("[%s] Invalid task ID provided to scan_status()" % taskid)
        return jsonize({"success": False, "message": "Invalid task ID"})

    if DataStore.tasks[taskid].engine_process() is None:
        status = "not running"
    else:
        status = "terminated" if DataStore.tasks[taskid].engine_has_terminated() is True else "running"

    logger.debug("[%s] Retrieved scan status" % taskid)
    return jsonize({
        "success": True,
        "status": status,
        "returncode": DataStore.tasks[taskid].engine_get_returncode()
    })


@get("/scan/<taskid>/data")
def scan_data(taskid):
    """
    Retrieve the data of a scan
    """
    json_data_message = list()
    json_errors_message = list()

    if taskid not in DataStore.tasks:
        logger.warning("[%s] Invalid task ID provided to scan_data()" % taskid)
        return jsonize({"success": False, "message": "Invalid task ID"})

    # Read all data from the IPC database for the taskid
    for status, content_type, value in DataStore.current_db.execute(
            "SELECT status, content_type, value FROM data WHERE taskid = ? ORDER BY id ASC",
            (taskid,)):
        json_data_message.append(
            {"status": status, "type": content_type, "value": dejsonize(value)})

    # Read all error messages from the IPC database
    for error in DataStore.current_db.execute(
            "SELECT error FROM errors WHERE taskid = ? ORDER BY id ASC",
            (taskid,)):
        json_errors_message.append(error)

    logger.debug("[%s] Retrieved scan data and error messages" % taskid)
    return jsonize({"success": True, "data": json_data_message, "error": json_errors_message})


# Functions to handle scans' logs
@get("/scan/<taskid>/log/<start>/<end>")
def scan_log_limited(taskid, start, end):
    """
    Retrieve a subset of log messages
    """
    json_log_messages = list()

    if taskid not in DataStore.tasks:
        logger.warning("[%s] Invalid task ID provided to scan_log_limited()" % taskid)
        return jsonize({"success": False, "message": "Invalid task ID"})

    if not start.isdigit() or not end.isdigit() or end < start:
        logger.warning("[%s] Invalid start or end value provided to scan_log_limited()" % taskid)
        return jsonize({"success": False, "message": "Invalid start or end value, must be digits"})

    start = max(1, int(start))
    end = max(1, int(end))

    # Read a subset of log messages from the IPC database
    for time_, level, message in DataStore.current_db.execute(
            ("SELECT time, level, message FROM logs WHERE "
             "taskid = ? AND id >= ? AND id <= ? ORDER BY id ASC"),
            (taskid, start, end)):
        json_log_messages.append({"time": time_, "level": level, "message": message})

    logger.debug("[%s] Retrieved scan log messages subset" % taskid)
    return jsonize({"success": True, "log": json_log_messages})


@get("/scan/<taskid>/log")
def scan_log(taskid):
    """
    Retrieve the log messages
    """
    json_log_messages = list()

    if taskid not in DataStore.tasks:
        logger.warning("[%s] Invalid task ID provided to scan_log()" % taskid)
        return jsonize({"success": False, "message": "Invalid task ID"})

    # Read all log messages from the IPC database
    for time_, level, message in DataStore.current_db.execute(
            "SELECT time, level, message FROM logs WHERE taskid = ? ORDER BY id ASC", (taskid,)):
        json_log_messages.append({"time": time_, "level": level, "message": message})

    logger.debug("[%s] Retrieved scan log messages" % taskid)
    return jsonize({"success": True, "log": json_log_messages})


# Function to handle files inside the output directory
@get("/download/<taskid>/<target>/<filename:path>")
def download(taskid, target, filename):
    """
    Download a certain file from the file system
    """
    if taskid not in DataStore.tasks:
        logger.warning("[%s] Invalid task ID provided to download()" % taskid)
        return jsonize({"success": False, "message": "Invalid task ID"})

    path = os.path.abspath(os.path.join(paths.SQLMAP_OUTPUT_PATH, target, filename))
    # Prevent file path traversal
    if not path.startswith(paths.SQLMAP_OUTPUT_PATH):
        logger.warning("[%s] Forbidden path (%s)" % (taskid, target))
        return jsonize({"success": False, "message": "Forbidden path"})

    if os.path.isfile(path):
        logger.debug("[%s] Retrieved content of file %s" % (taskid, target))
        with open(path, 'rb') as inf:
            file_content = inf.read()
        return jsonize({"success": True, "file": file_content.encode("base64")})
    else:
        logger.warning("[%s] File does not exist %s" % (taskid, target))
        return jsonize({"success": False, "message": "File does not exist"})


def server(host=RESTAPI_DEFAULT_ADDRESS, port=RESTAPI_DEFAULT_PORT, adapter=RESTAPI_DEFAULT_ADAPTER):
    """
    REST-JSON API server
    """
    DataStore.admin_id = hexencode(os.urandom(16))
    Database.filepath = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.IPC, text=False)[1]

    logger.info("Running REST-JSON API server at '%s:%d'.." % (host, port))
    logger.info("Admin ID: %s" % DataStore.admin_id)
    logger.debug("IPC database: %s" % Database.filepath)

    # Initialize IPC database
    DataStore.current_db = Database()
    DataStore.current_db.connect()
    DataStore.current_db.init()

    # Run RESTful API
    try:
        if adapter == "gevent":
            from gevent import monkey
            monkey.patch_all()
        elif adapter == "eventlet":
            import eventlet
            eventlet.monkey_patch()
        logger.debug("Using adapter '%s' to run bottle" % adapter)
        run(host=host, port=port, quiet=True, debug=False, server=adapter)
    except socket.error, ex:
        if "already in use" in getSafeExString(ex):
            logger.error("Address already in use ('%s:%s')" % (host, port))
        else:
            raise
    except ImportError:
        errMsg = "Adapter '%s' is not available on this system" % adapter
        if adapter in ("gevent", "eventlet"):
            errMsg += " (e.g.: 'sudo apt-get install python-%s')" % adapter
        logger.critical(errMsg)

def _client(url, options=None):
    logger.debug("Calling %s" % url)
    try:
        data = None
        if options is not None:
            data = jsonize(options)
        req = urllib2.Request(url, data, {'Content-Type': 'application/json'})
        response = urllib2.urlopen(req)
        text = response.read()
    except:
        if options:
            logger.error("Failed to load and parse %s" % url)
        raise
    return text


def client(host=RESTAPI_DEFAULT_ADDRESS, port=RESTAPI_DEFAULT_PORT):
    """
    REST-JSON API client
    """

    dbgMsg = "Example client access from command line:"
    dbgMsg += "\n\t$ taskid=$(curl http://%s:%d/task/new 2>1 | grep -o -I '[a-f0-9]\{16\}') && echo $taskid" % (host, port)
    dbgMsg += "\n\t$ curl -H \"Content-Type: application/json\" -X POST -d '{\"url\": \"http://testphp.vulnweb.com/artists.php?artist=1\"}' http://%s:%d/scan/$taskid/start" % (host, port)
    dbgMsg += "\n\t$ curl http://%s:%d/scan/$taskid/data" % (host, port)
    dbgMsg += "\n\t$ curl http://%s:%d/scan/$taskid/log" % (host, port)
    logger.debug(dbgMsg)

    addr = "http://%s:%d" % (host, port)
    logger.info("Starting REST-JSON API client to '%s'..." % addr)

    try:
        _client(addr)
    except Exception, ex:
        if not isinstance(ex, urllib2.HTTPError):
            errMsg = "There has been a problem while connecting to the "
            errMsg += "REST-JSON API server at '%s' " % addr
            errMsg += "(%s)" % ex
            logger.critical(errMsg)
            return

    taskid = None
    logger.info("Type 'help' or '?' for list of available commands")

    while True:
        try:
            command = raw_input("api%s> " % (" (%s)" % taskid if taskid else "")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print
            break

        if command in ("data", "log", "status", "stop", "kill"):
            if not taskid:
                logger.error("No task ID in use")
                continue
            raw = _client("%s/scan/%s/%s" % (addr, taskid, command))
            res = dejsonize(raw)
            if not res["success"]:
                logger.error("Failed to execute command %s" % command)
            dataToStdout("%s\n" % raw)

        elif command.startswith("new"):
            if ' ' not in command:
                logger.error("Program arguments are missing")
                continue

            argv = ["sqlmap.py"] + shlex.split(command)[1:]

            try:
                cmdLineOptions = cmdLineParser(argv).__dict__
            except:
                taskid = None
                continue

            for key in list(cmdLineOptions):
                if cmdLineOptions[key] is None:
                    del cmdLineOptions[key]

            raw = _client("%s/task/new" % addr)
            res = dejsonize(raw)
            if not res["success"]:
                logger.error("Failed to create new task")
                continue
            taskid = res["taskid"]
            logger.info("New task ID is '%s'" % taskid)

            raw = _client("%s/scan/%s/start" % (addr, taskid), cmdLineOptions)
            res = dejsonize(raw)
            if not res["success"]:
                logger.error("Failed to start scan")
                continue
            logger.info("Scanning started")

        elif command.startswith("use"):
            taskid = (command.split()[1] if ' ' in command else "").strip("'\"")
            if not taskid:
                logger.error("Task ID is missing")
                taskid = None
                continue
            elif not re.search(r"\A[0-9a-fA-F]{16}\Z", taskid):
                logger.error("Invalid task ID '%s'" % taskid)
                taskid = None
                continue
            logger.info("Switching to task ID '%s' " % taskid)

        elif command in ("list", "flush"):
            raw = _client("%s/admin/%s/%s" % (addr, taskid or 0, command))
            res = dejsonize(raw)
            if not res["success"]:
                logger.error("Failed to execute command %s" % command)
            elif command == "flush":
                taskid = None
            dataToStdout("%s\n" % raw)

        elif command in ("exit", "bye", "quit", 'q'):
            return

        elif command in ("help", "?"):
            msg =  "help        Show this help message\n"
            msg += "new ARGS    Start a new scan task with provided arguments (e.g. 'new -u \"http://testphp.vulnweb.com/artists.php?artist=1\"')\n"
            msg += "use TASKID  Switch current context to different task (e.g. 'use c04d8c5c7582efb4')\n"
            msg += "data        Retrieve and show data for current task\n"
            msg += "log         Retrieve and show log for current task\n"
            msg += "status      Retrieve and show status for current task\n"
            msg += "stop        Stop current task\n"
            msg += "kill        Kill current task\n"
            msg += "list        Display all tasks\n"
            msg += "flush       Flush tasks (delete all tasks)\n"
            msg += "exit        Exit this client\n"

            dataToStdout(msg)

        elif command:
            logger.error("Unknown command '%s'" % command)
