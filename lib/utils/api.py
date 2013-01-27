#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
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
from lib.core.convert import base64unpickle
from lib.core.convert import hexencode
from lib.core.convert import jsonize
from lib.core.data import conf
from lib.core.data import paths
from lib.core.data import logger
from lib.core.datatype import AttribDict
from lib.core.defaults import _defaults
from lib.core.log import LOGGER_HANDLER
from lib.core.optiondict import optDict
from lib.core.subprocessng import Popen as execute
from lib.core.subprocessng import send_all
from lib.core.subprocessng import recv_some
from thirdparty.bottle.bottle import abort
from thirdparty.bottle.bottle import error
from thirdparty.bottle.bottle import get
from thirdparty.bottle.bottle import hook
from thirdparty.bottle.bottle import post
from thirdparty.bottle.bottle import request
from thirdparty.bottle.bottle import response
from thirdparty.bottle.bottle import run
from thirdparty.bottle.bottle import static_file

RESTAPI_SERVER_HOST = "127.0.0.1"
RESTAPI_SERVER_PORT = 8775

# Local global variables
adminid = ""
procs = dict()
tasks = AttribDict()

# Wrapper functions
class StdDbOut(object):
    encoding = "UTF-8"

    def __init__(self, type_="stdout"):
        # Overwrite system standard output and standard error to write
        # to a temporary I/O database
        self.type = type_

        if self.type == "stdout":
            sys.stdout = self
        else:
            sys.stderr = self

    def write(self, string):
        if self.type == "stdout":
            conf.ipc_database_cursor.execute("INSERT INTO stdout VALUES(NULL, ?, ?)", (time.strftime("%X"), string))
        else:
            conf.ipc_database_cursor.execute("INSERT INTO stderr VALUES(NULL, ?, ?)", (time.strftime("%X"), string))

    def flush(self):
        pass

    def close(self):
        pass

    def seek(self):
        pass

class LogRecorder(logging.StreamHandler):
    def emit(self, record):
        """
        Record emitted events to temporary database for asynchronous I/O
        communication with the parent process
        """
        conf.ipc_database_cursor.execute("INSERT INTO logs VALUES(NULL, ?, ?, ?)",
                                         (time.strftime("%X"), record.levelname,
                                         record.msg % record.args if record.args else record.msg))

def setRestAPILog():
    if hasattr(conf, "ipc_database"):
        conf.ipc_database_connection = sqlite3.connect(conf.ipc_database, timeout=1, isolation_level=None)
        conf.ipc_database_cursor = conf.ipc_database_connection.cursor()

        # Set a logging handler that writes log messages to a temporary
        # I/O database
        logger.removeHandler(LOGGER_HANDLER)
        LOGGER_RECORDER = LogRecorder()
        logger.addHandler(LOGGER_RECORDER)

# Generic functions
def is_admin(taskid):
    global adminid
    if adminid != taskid:
        return False
    else:
        return True

def init_options():
    dataype = {"boolean": False, "string": None, "integer": None, "float": None}
    options = AttribDict()

    for _ in optDict:
        for name, type_ in optDict[_].items():
            type_ = unArrayizeValue(type_)
            options[name] = _defaults.get(name, dataype[type_])

    # Enforce batch mode and disable coloring
    options.batch = True
    options.disableColoring = True

    return options

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

@error(401)  # Access Denied
def error401(error=None):
    security_headers(False)
    return "Access denied"

@error(404)  # Not Found
def error404(error=None):
    security_headers(False)
    return "Nothing here"

@error(405)  # Method Not Allowed (e.g. when requesting a POST method via GET)
def error405(error=None):
    security_headers(False)
    return "Method not allowed"

@error(500)  # Internal Server Error
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
    global procs
    global tasks

    taskid = hexencode(os.urandom(16))
    tasks[taskid] = init_options()
    procs[taskid] = AttribDict()

    _, ipc_database_filepath = tempfile.mkstemp(prefix="sqlmapipc-", text=False)

    # Initiate the temporary database for asynchronous I/O with the
    # sqlmap engine
    procs[taskid].ipc_database_connection = sqlite3.connect(ipc_database_filepath, timeout=1, isolation_level=None)
    procs[taskid].ipc_database_cursor = procs[taskid].ipc_database_connection.cursor()
    procs[taskid].ipc_database_cursor.execute("CREATE TABLE logs(id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, level TEXT, message TEXT)")
    procs[taskid].ipc_database_cursor.execute("CREATE TABLE stdout(id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, message TEXT)")
    procs[taskid].ipc_database_cursor.execute("CREATE TABLE stderr(id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, message TEXT)")

    # Set the temporary database to use for asynchronous I/O communication
    tasks[taskid].ipc_database = ipc_database_filepath

    return jsonize({"taskid": taskid})

@get("/task/<taskid>/destroy")
def task_destroy(taskid):
    """
    Destroy own task ID
    """
    if taskid in tasks and not is_admin(taskid):
        tasks.pop(taskid)
        return jsonize({"success": True})
    else:
        abort(500, "Invalid task ID")

# Admin's methods
@get("/task/<taskid>/list")
def task_list(taskid):
    """
    List all active tasks
    """
    if is_admin(taskid):
        return jsonize({"tasks": tasks})
    else:
        abort(401)

@get("/task/<taskid>/flush")
def task_flush(taskid):
    """
    Flush task spool (destroy all tasks except admin)
    """
    global adminid
    global tasks

    if is_admin(taskid):
        admin_task = tasks[adminid]
        tasks = AttribDict()
        tasks[adminid] = admin_task

        return jsonize({"success": True})
    else:
        abort(401)

##################################
# sqlmap core interact functions #
##################################

# Admin's methods
@get("/status/<taskid>")
def status(taskid):
    """
    Verify the status of the API as well as the core
    """

    if is_admin(taskid):
        tasks_num = len(tasks)
        return jsonize({"tasks": tasks_num})
    else:
        abort(401)

@get("/cleanup/<taskid>")
def cleanup(taskid):
    """
    Destroy all sessions except admin ID and all output directories
    """
    global tasks

    if is_admin(taskid):
        for task, options in tasks.items():
            shutil.rmtree(options.oDir)
            shutil.rmtree(options.ipc_database)

        admin_task = tasks[adminid]
        tasks = AttribDict()
        tasks[adminid] = admin_task


        return jsonize({"success": True})
    else:
        abort(401)

# Functions to handle options
@get("/option/<taskid>/list")
def option_list(taskid):
    """
    List options for a certain task ID
    """
    if taskid not in tasks:
        abort(500, "Invalid task ID")

    return jsonize(tasks[taskid])

@post("/option/<taskid>/get")
def option_get(taskid):
    """
    Get the value of an option (command line switch) for a certain task ID
    """
    if taskid not in tasks:
        abort(500, "Invalid task ID")

    option = request.json.get("option", "")

    if option in tasks[taskid]:
        return jsonize({option: tasks[taskid][option]})
    else:
        return jsonize({option: None})

@post("/option/<taskid>/set")
def option_set(taskid):
    """
    Set an option (command line switch) for a certain task ID
    """
    global tasks

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    for key, value in request.json.items():
        tasks[taskid][key] = value

    return jsonize({"success": True})

# Function to handle scans
@post("/scan/<taskid>/start")
def scan_start(taskid):
    """
    Launch a scan
    """
    global tasks
    global procs

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    # Initialize sqlmap engine's options with user's provided options, if any
    for key, value in request.json.items():
        tasks[taskid][key] = value

    # Overwrite output directory value to a temporary directory
    tasks[taskid].oDir = tempfile.mkdtemp(prefix="sqlmapoutput-")

    # Launch sqlmap engine in a separate thread
    logger.debug("starting a scan for task ID %s" % taskid)

    # Launch sqlmap engine
    procs[taskid].child = execute("python sqlmap.py --pickled-options %s" % base64pickle(tasks[taskid]), shell=True, stdin=PIPE)

    return jsonize({"success": True})

@get("/scan/<taskid>/output")
def scan_output(taskid):
    """
    Read the standard output of sqlmap core execution
    """
    global procs
    global tasks

    json_stdout_message = []
    json_stderr_message = []

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    # Read all stdout messages from the temporary I/O database
    procs[taskid].ipc_database_cursor.execute("SELECT message FROM stdout")
    db_stdout_messages = procs[taskid].ipc_database_cursor.fetchall()

    for message in db_stdout_messages:
        json_stdout_message.append(message)

    # Read all stderr messages from the temporary I/O database
    procs[taskid].ipc_database_cursor.execute("SELECT message FROM stderr")
    db_stderr_messages = procs[taskid].ipc_database_cursor.fetchall()

    for message in db_stderr_messages:
        json_stderr_message.append(message)

    return jsonize({"stdout": json_stdout_message, "stderr": json_stderr_message})

@get("/scan/<taskid>/delete")
def scan_delete(taskid):
    """
    Delete a scan and corresponding temporary output directory
    """
    global tasks

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    shutil.rmtree(tasks[taskid].oDir)
    shutil.rmtree(tasks[taskid].ipc_database)

    return jsonize({"success": True})

# Functions to handle scans' logs
@get("/scan/<taskid>/log/<start>/<end>")
def scan_log_limited(taskid, start, end):
    """
    Retrieve a subset of log messages
    """
    global procs

    json_log_messages = {}

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    if not start.isdigit() or not end.isdigit() or end < start:
        abort(500, "Invalid start or end value, must be digits")

    start = max(1, int(start))
    end = max(1, int(end))

    # Read a subset of log messages from the temporary I/O database
    procs[taskid].ipc_database_cursor.execute("SELECT id, time, level, message FROM logs WHERE id >= ? AND id <= ?", (start, end))
    db_log_messages = procs[taskid].ipc_database_cursor.fetchall()

    for (id_, time_, level, message) in db_log_messages:
        json_log_messages[id_] = {"time": time_, "level": level, "message": message}

    return jsonize({"log": json_log_messages})

@get("/scan/<taskid>/log")
def scan_log(taskid):
    """
    Retrieve the log messages
    """
    global procs

    json_log_messages = {}

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    # Read all log messages from the temporary I/O database
    procs[taskid].ipc_database_cursor.execute("SELECT id, time, level, message FROM logs")
    db_log_messages = procs[taskid].ipc_database_cursor.fetchall()

    for (id_, time_, level, message) in db_log_messages:
        json_log_messages[id_] = {"time": time_, "level": level, "message": message}

    return jsonize({"log": json_log_messages})

# Function to handle files inside the output directory
@get("/download/<taskid>/<target>/<filename:path>")
def download(taskid, target, filename):
    """
    Download a certain file from the file system
    """
    if taskid not in tasks:
        abort(500, "Invalid task ID")

    # Prevent file path traversal - the lame way
    if target.startswith("."):
        abort(500)

    path = os.path.join(paths.SQLMAP_OUTPUT_PATH, target)
    if os.path.exists(path):
        return static_file(filename, root=path)
    else:
        abort(500)

def server(host="0.0.0.0", port=RESTAPI_SERVER_PORT):
    """
    REST-JSON API server
    """
    global adminid
    global tasks

    adminid = hexencode(os.urandom(16))
    tasks[adminid] = init_options()

    logger.info("running REST-JSON API server at '%s:%d'.." % (host, port))
    logger.info("the admin task ID is: %s" % adminid)

    # Run RESTful API
    run(host=host, port=port, quiet=False, debug=False)

def client(host=RESTAPI_SERVER_HOST, port=RESTAPI_SERVER_PORT):
    """
    REST-JSON API client
    """
    addr = "http://%s:%d" % (host, port)
    logger.info("starting debug REST-JSON client to '%s'..." % addr)

    # TODO: write a simple client with requests, for now use curl from command line
    logger.error("not yet implemented, use curl from command line instead for now, for example:")
    print "\n\t$ curl http://%s:%d/task/new" % (host, port)
    print "\t$ curl -H \"Content-Type: application/json\" -X POST -d '{\"url\": \"http://testphp.vulnweb.com/artists.php?artist=1\"}' http://%s:%d/scan/:taskid/start" % (host, port)
    print "\t$ curl http://%s:%d/scan/:taskid/output" % (host, port)
    print "\t$ curl http://%s:%d/scan/:taskid/log\n" % (host, port)
