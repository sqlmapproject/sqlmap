#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2006-2015 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import logging
import os
import shutil
import sqlite3
import sys
import tempfile
import time

from subprocess import PIPE

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
from lib.core.enums import PART_RUN_CONTENT_TYPES
from lib.core.log import LOGGER_HANDLER
from lib.core.optiondict import optDict
from lib.core.subprocessng import Popen
from thirdparty.bottle.bottle import error as return_error
from thirdparty.bottle.bottle import get
from thirdparty.bottle.bottle import hook
from thirdparty.bottle.bottle import post
from thirdparty.bottle.bottle import request
from thirdparty.bottle.bottle import response
from thirdparty.bottle.bottle import run

RESTAPI_SERVER_HOST = "127.0.0.1"
RESTAPI_SERVER_PORT = 8775


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
        self.cursor.close()
        self.connection.close()

    def commit(self):
        self.connection.commit()

    def execute(self, statement, arguments=None):
        if arguments:
            self.cursor.execute(statement, arguments)
        else:
            self.cursor.execute(statement)

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
    def __init__(self, taskid):
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
        self.process = Popen(["python", "sqlmap.py", "--pickled-options", base64pickle(self.options)],
                             shell=False, stdin=PIPE, close_fds=False)

    def engine_stop(self):
        if self.process:
            return self.process.terminate()
        else:
            return None

    def engine_process(self):
        return self.process

    def engine_kill(self):
        if self.process:
            return self.process.kill()
        else:
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
        conf.database_cursor = Database(conf.database)
        conf.database_cursor.connect("client")

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
    DataStore.tasks[taskid] = Task(taskid)

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
def task_list(taskid):
    """
    List task pull
    """
    if is_admin(taskid):
        logger.debug("[%s] Listed task pool" % taskid)
        tasks = list(DataStore.tasks)
        return jsonize({"success": True, "tasks": tasks, "tasks_num": len(tasks)})
    else:
        logger.warning("[%s] Unauthorized call to task_list()" % taskid)
        return jsonize({"success": False, "message": "Unauthorized"})


@get("/admin/<taskid>/flush")
def task_flush(taskid):
    """
    Flush task spool (delete all tasks)
    """
    if is_admin(taskid):
        DataStore.tasks = dict()
        logger.debug("[%s] Flushed task pool" % taskid)
        return jsonize({"success": True})
    else:
        logger.warning("[%s] Unauthorized call to task_flush()" % taskid)
        return jsonize({"success": False, "message": "Unauthorized"})

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
    if taskid not in DataStore.tasks:
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
    if taskid not in DataStore.tasks:
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
        logger.warning("[%s] Invalid task ID provided to scan_log_limited()")
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
        logger.warning("[%s] Invalid task ID provided to scan_log()")
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

    # Prevent file path traversal - the lame way
    if ".." in target:
        logger.warning("[%s] Forbidden path (%s)" % (taskid, target))
        return jsonize({"success": False, "message": "Forbidden path"})

    path = os.path.join(paths.SQLMAP_OUTPUT_PATH, target)

    if os.path.exists(path):
        logger.debug("[%s] Retrieved content of file %s" % (taskid, target))
        with open(path, 'rb') as inf:
            file_content = inf.read()
        return jsonize({"success": True, "file": file_content.encode("base64")})
    else:
        logger.warning("[%s] File does not exist %s" % (taskid, target))
        return jsonize({"success": False, "message": "File does not exist"})


def server(host="0.0.0.0", port=RESTAPI_SERVER_PORT):
    """
    REST-JSON API server
    """
    DataStore.admin_id = hexencode(os.urandom(16))
    Database.filepath = tempfile.mkstemp(prefix="sqlmapipc-", text=False)[1]

    logger.info("Running REST-JSON API server at '%s:%d'.." % (host, port))
    logger.info("Admin ID: %s" % DataStore.admin_id)
    logger.debug("IPC database: %s" % Database.filepath)

    # Initialize IPC database
    DataStore.current_db = Database()
    DataStore.current_db.connect()
    DataStore.current_db.init()

    # Run RESTful API
    run(host=host, port=port, quiet=True, debug=False)


def client(host=RESTAPI_SERVER_HOST, port=RESTAPI_SERVER_PORT):
    """
    REST-JSON API client
    """
    addr = "http://%s:%d" % (host, port)
    logger.info("Starting REST-JSON API client to '%s'..." % addr)

    # TODO: write a simple client with requests, for now use curl from command line
    logger.error("Not yet implemented, use curl from command line instead for now, for example:")
    print "\n\t$ taskid=$(curl http://%s:%d/task/new 2>1 | grep -o -I '[a-f0-9]\{16\}') && echo $taskid" % (host, port)
    print ("\t$ curl -H \"Content-Type: application/json\" "
           "-X POST -d '{\"url\": \"http://testphp.vulnweb.com/artists.php?artist=1\"}' "
           "http://%s:%d/scan/$taskid/start") % (host, port)
    print "\t$ curl http://%s:%d/scan/$taskid/data" % (host, port)
    print "\t$ curl http://%s:%d/scan/$taskid/log\n" % (host, port)
