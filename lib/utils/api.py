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
db = None
db_filepath = None
tasks = dict()

# API objects
class Database(object):
    global db_filepath

    LOGS_TABLE = "CREATE TABLE logs(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid INTEGER, time TEXT, level TEXT, message TEXT)"
    DATA_TABLE = "CREATE TABLE data(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid INTEGER, status INTEGER, content_type INTEGER, value TEXT)"
    ERRORS_TABLE = "CREATE TABLE errors(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid INTEGER, error TEXT)"

    def __init__(self, database=None):
        if database:
            self.database = database
        else:
            self.database = db_filepath

    def connect(self, who="server"):
        self.connection = sqlite3.connect(self.database, timeout=3, isolation_level=None)
        self.cursor = self.connection.cursor()
        logger.debug("REST-JSON API %s connected to IPC database" % who)

    def disconnect(self):
        self.cursor.close()
        self.connection.close()

    def commit(self):
        self.cursor.commit()

    def execute(self, statement, arguments=None):
        if arguments:
            self.cursor.execute(statement, arguments)
        else:
            self.cursor.execute(statement)

        if statement.lstrip().upper().startswith("SELECT"):
            return self.cursor.fetchall()

    def init(self):
        self.execute(self.LOGS_TABLE)
        self.execute(self.DATA_TABLE)
        self.execute(self.ERRORS_TABLE)

class Task(object):
    global db_filepath

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

        # Let sqlmap engine knows it is getting called by the API, the task ID and the file path of the IPC database
        self.options.api = True
        self.options.taskid = taskid
        self.options.database = db_filepath

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

    def set_output_directory(self):
        if not self.output_directory or not os.path.isdir(self.output_directory):
            self.output_directory = tempfile.mkdtemp(prefix="sqlmapoutput-")
            self.set_option("oDir", self.output_directory)

    def clean_filesystem(self):
        if self.output_directory:
            shutil.rmtree(self.output_directory)

    def engine_start(self):
        self.process = Popen("python sqlmap.py --pickled-options %s" % base64pickle(self.options), shell=True, stdin=PIPE, close_fds=False)

    def engine_stop(self):
        if self.process:
            return self.process.terminate()
        else:
            return None

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
        self.process.poll()
        return self.process.returncode

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

            output = conf.database_cursor.execute("SELECT id, status, value FROM data WHERE taskid = ? AND content_type = ?",
                                                  (self.taskid, content_type))

            #print >>sys.__stdout__, "output: %s\nvalue: %s\nstatus: %d\ncontent_type: %d\nkb.partRun: %s\n--------------" % (output, value, status, content_type, kb.partRun)

            # Delete partial output from IPC database if we have got a complete output
            if status == CONTENT_STATUS.COMPLETE:
                if len(output) > 0:
                    for index in xrange(0, len(output)):
                        conf.database_cursor.execute("DELETE FROM data WHERE id = ?", (output[index][0],))

                conf.database_cursor.execute("INSERT INTO data VALUES(NULL, ?, ?, ?, ?)", (self.taskid, status, content_type, jsonize(value)))
                if kb.partRun:
                    kb.partRun = None

            elif status == CONTENT_STATUS.IN_PROGRESS:
                if len(output) == 0:
                    conf.database_cursor.execute("INSERT INTO data VALUES(NULL, ?, ?, ?, ?)",
                                                 (self.taskid, status, content_type, jsonize(value)))
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
    global adminid
    if adminid != taskid:
        return False
    else:
        return True

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
    global tasks

    taskid = hexencode(os.urandom(8))
    tasks[taskid] = Task(taskid)

    logger.debug("Created new task ID: %s" % taskid)
    return jsonize({"taskid": taskid})

@get("/task/<taskid>/delete")
def task_delete(taskid):
    """
    Delete own task ID
    """
    if taskid in tasks:
        tasks[taskid].clean_filesystem()
        tasks.pop(taskid)

        logger.debug("Deleted task ID: %s" % taskid)
        return jsonize({"success": True})
    else:
        abort(500, "Invalid task ID")

###################
# Admin functions #
###################

@get("/admin/<taskid>/list")
def task_list(taskid):
    """
    List task pull
    """
    if is_admin(taskid):
        logger.debug("Listed task pull")
        task_list = list(tasks)
        return jsonize({"tasks": task_list, "tasks_num": len(tasks)})
    else:
        abort(401)

@get("/admin/<taskid>/flush")
def task_flush(taskid):
    """
    Flush task spool (delete all tasks)
    """
    global tasks

    if is_admin(taskid):
        for task in tasks:
            tasks[task].clean_filesystem()

        tasks = dict()
        logger.debug("Flushed task pull")
        return jsonize({"success": True})
    else:
        abort(401)

##################################
# sqlmap core interact functions #
##################################

# Handle task's options
@get("/option/<taskid>/list")
def option_list(taskid):
    """
    List options for a certain task ID
    """
    if taskid not in tasks:
        abort(500, "Invalid task ID")

    return jsonize({"options": tasks[taskid].get_options()})

@post("/option/<taskid>/get")
def option_get(taskid):
    """
    Get the value of an option (command line switch) for a certain task ID
    """
    global tasks

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    option = request.json.get("option", "")

    if option in tasks[taskid]:
        return jsonize({option: tasks[taskid].get_option(option)})
    else:
        return jsonize({option: "not set"})

@post("/option/<taskid>/set")
def option_set(taskid):
    """
    Set an option (command line switch) for a certain task ID
    """
    global tasks

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    for option, value in request.json.items():
        tasks[taskid].set_option(option, value)

    return jsonize({"success": True})

# Handle scans
@post("/scan/<taskid>/start")
def scan_start(taskid):
    """
    Launch a scan
    """
    global tasks

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    tasks[taskid].reset_options()

    # Initialize sqlmap engine's options with user's provided options, if any
    for option, value in request.json.items():
        tasks[taskid].set_option(option, value)

    # Overwrite output directory value to a temporary directory
    tasks[taskid].set_output_directory()

    # Launch sqlmap engine in a separate process
    tasks[taskid].engine_start()

    logger.debug("Started scan for task ID %s" % taskid)
    return jsonize({"success": True, "engineid": tasks[taskid].engine_get_id()})

@get("/scan/<taskid>/stop")
def scan_stop(taskid):
    """
    Stop a scan
    """
    global tasks

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    tasks[taskid].engine_stop()

    logger.debug("Stopped scan for task ID %s" % taskid)
    return jsonize({"success": True})

@get("/scan/<taskid>/kill")
def scan_kill(taskid):
    """
    Kill a scan
    """
    global tasks

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    tasks[taskid].engine_kill()

    logger.debug("Killed scan for task ID %s" % taskid)
    return jsonize({"success": True})

@get("/scan/<taskid>/status")
def scan_status(taskid):
    """
    Returns status of a scan
    """
    global tasks

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    status = "terminated" if tasks[taskid].engine_has_terminated() is True else "running"

    logger.debug("Requested status of scan for task ID %s" % taskid)
    return jsonize({"status": status, "returncode": tasks[taskid].engine_get_returncode()})

@get("/scan/<taskid>/data")
def scan_data(taskid):
    """
    Retrieve the data of a scan
    """
    global db
    global tasks
    json_data_message = list()
    json_errors_message = list()

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    # Read all data from the IPC database for the taskid
    for status, content_type, value in db.execute("SELECT status, content_type, value FROM data WHERE taskid = ? ORDER BY id ASC", (taskid,)):
        json_data_message.append({"status": status, "type": content_type, "value": dejsonize(value)})

    # Read all error messages from the IPC database
    for error in db.execute("SELECT error FROM errors WHERE taskid = ? ORDER BY id ASC", (taskid,)):
        json_errors_message.append(error)

    logger.debug("Retrieved data and error messages for scan for task ID %s" % taskid)
    return jsonize({"data": json_data_message, "error": json_errors_message})

# Functions to handle scans' logs
@get("/scan/<taskid>/log/<start>/<end>")
def scan_log_limited(taskid, start, end):
    """
    Retrieve a subset of log messages
    """
    global db
    global tasks
    json_log_messages = list()

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    if not start.isdigit() or not end.isdigit() or end < start:
        abort(500, "Invalid start or end value, must be digits")

    start = max(1, int(start))
    end = max(1, int(end))

    # Read a subset of log messages from the IPC database
    for time_, level, message in db.execute("SELECT time, level, message FROM logs WHERE taskid = ? AND id >= ? AND id <= ? ORDER BY id ASC", (taskid, start, end)):
        json_log_messages.append({"time": time_, "level": level, "message": message})

    logger.debug("Retrieved subset of log messages for scan for task ID %s" % taskid)
    return jsonize({"log": json_log_messages})

@get("/scan/<taskid>/log")
def scan_log(taskid):
    """
    Retrieve the log messages
    """
    global db
    global tasks
    json_log_messages = list()

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    # Read all log messages from the IPC database
    for time_, level, message in db.execute("SELECT time, level, message FROM logs WHERE taskid = ? ORDER BY id ASC", (taskid,)):
        json_log_messages.append({"time": time_, "level": level, "message": message})

    logger.debug("Retrieved log messages for scan for task ID %s" % taskid)
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
        abort(500, "File does not exist")

def server(host="0.0.0.0", port=RESTAPI_SERVER_PORT):
    """
    REST-JSON API server
    """
    global adminid
    global db
    global db_filepath

    adminid = hexencode(os.urandom(16))
    db_filepath = tempfile.mkstemp(prefix="sqlmapipc-", text=False)[1]

    logger.info("Running REST-JSON API server at '%s:%d'.." % (host, port))
    logger.info("Admin ID: %s" % adminid)
    logger.debug("IPC database: %s" % db_filepath)

    # Initialize IPC database
    db = Database()
    db.connect()
    db.init()

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
    print "\n\t$ curl http://%s:%d/task/new" % (host, port)
    print "\t$ curl -H \"Content-Type: application/json\" -X POST -d '{\"url\": \"http://testphp.vulnweb.com/artists.php?artist=1\"}' http://%s:%d/scan/:taskid/start" % (host, port)
    print "\t$ curl http://%s:%d/scan/:taskid/data" % (host, port)
    print "\t$ curl http://%s:%d/scan/:taskid/log\n" % (host, port)
