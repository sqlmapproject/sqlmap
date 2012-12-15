#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import json
import optparse
import os
import shutil
import sys
import tempfile
import threading

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", ".."))

from extra.bottle.bottle import abort
from extra.bottle.bottle import error
from extra.bottle.bottle import get
from extra.bottle.bottle import hook
from extra.bottle.bottle import post
from extra.bottle.bottle import request
from extra.bottle.bottle import response
from extra.bottle.bottle import run
from extra.bottle.bottle import static_file
from extra.bottle.bottle import template
from lib.controller.controller import start
from lib.core.convert import hexencode
from lib.core.data import paths
from lib.core.datatype import AttribDict
from lib.core.data import cmdLineOptions
from lib.core.data import kb
from lib.core.data import logger
from lib.core.log import LOGGER_OUTPUT
from lib.core.exception import SqlmapMissingDependence
from lib.core.option import init
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import RESTAPI_SERVER_PORT

# Local global variables
adminid = ""
tasks = AttribDict()

# Generic functions
def jsonize(data):
    return json.dumps(data, sort_keys=False, indent=4)

def is_admin(taskid):
    global adminid
    if adminid != taskid:
        return False
    else:
        return True

@hook("after_request")
def security_headers():
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
    response.content_type = "application/json; charset=UTF-8"

##############################
# HTTP Status Code functions #
##############################

@error(401) # Access Denied
def error401(error=None):
    return "Access denied"

@error(404) # Not Found
def error404(error=None):
    return "Nothing here"

@error(405) # Method Not Allowed (e.g. when requesting a POST method via GET)
def error405(error=None):
    return "Method not allowed"

@error(500) # Internal Server Error
def error500(error=None):
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

    taskid = hexencode(os.urandom(16))
    tasks[taskid] = AttribDict(cmdLineOptions)

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
        busy = kb.get("busyFlag")
        tasks_num = len(tasks)
        return jsonize({"busy": busy, "tasks": tasks_num})
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
            if "oDir" in options and options.oDir is not None:
                shutil.rmtree(options.oDir)

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

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    # Initialize sqlmap engine's options with user's provided options
    # within the JSON request
    for key, value in request.json.items():
        tasks[taskid][key] = value

    # Overwrite output directory (oDir) value to a temporary directory
    tasks[taskid].oDir = tempfile.mkdtemp(prefix="sqlmap-")

    init(tasks[taskid], True)

    # Launch sqlmap engine in a separate thread
    thread = threading.Thread(target=start)
    thread.daemon = True
    thread.start()

    return jsonize({"success": True})

@get("/scan/<taskid>/output")
def scan_output(taskid):
    """
    Read the standard output of sqlmap core execution
    """
    global tasks

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    sys.stdout.seek(0)
    output = sys.stdout.read()
    sys.stdout.flush()
    sys.stdout.truncate(0)

    return jsonize({"output": output})

@get("/scan/<taskid>/delete")
def scan_delete(taskid):
    """
    Delete a scan and corresponding temporary output directory
    """
    global tasks

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    if "oDir" in tasks[taskid] and tasks[taskid].oDir is not None:
        shutil.rmtree(tasks[taskid].oDir)

    return jsonize({"success": True})

# Function to handle scans' logs
@get("/scan/<taskid>/log")
def scan_log(taskid):
    """
    Read the informational log messages
    """
    if taskid not in tasks:
        abort(500, "Invalid task ID")

    LOGGER_OUTPUT.seek(0)
    output = LOGGER_OUTPUT.read()
    LOGGER_OUTPUT.flush()
    LOGGER_OUTPUT.truncate(0)

    return jsonize({"log": output})

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

def restAPISetup(host="0.0.0.0", port=RESTAPI_SERVER_PORT):
    """
    Setup REST-JSON API
    """
    global adminid
    global tasks

    adminid = hexencode(os.urandom(16))
    tasks[adminid] = AttribDict(cmdLineOptions)

    logger.info("running REST-JSON API server at '%s:%d'.." % (host, port))
    logger.info("the admin task ID is: %s" % adminid)

def restAPIRun(host="0.0.0.0", port=RESTAPI_SERVER_PORT):
    """
    Run REST-JSON API
    """
    run(host=host, port=port, quiet=False, debug=False)

def client(host, port):
    """
    REST-JSON API client
    """
    addr = "http://%s:%d" % (host, port)
    print "[*] starting debug REST-JSON client to '%s'..." % addr

    # TODO: write a simple client with urllib2, for now use curl from command line
    print "[!] not yet implemented, use curl from command line instead for now, for example:"
    print "\n\t$ curl --proxy http://127.0.0.1:8080 http://127.0.0.1:%s/task/new" % port
    print "\t$ curl --proxy http://127.0.0.1:8080 -H \"Content-Type: application/json\" -X POST -d '{\"url\": \"http://testphp.vulnweb.com/artists.php?artist=1\"}' http://127.0.0.1:%d/scan/<taskID>/start" % port
    print "\t$ curl --proxy http://127.0.0.1:8080 http://127.0.0.1:8775/scan/<taskID>/output"
    print "\t$ curl --proxy http://127.0.0.1:8080 http://127.0.0.1:8775/scan/<taskID>/log\n"

if __name__ == "__main__":
    """
    REST-JSON API wrapper function
    """
    parser = optparse.OptionParser()
    parser.add_option("-s", "--server", help="Act as a REST-JSON API server", default=RESTAPI_SERVER_PORT, action="store_true")
    parser.add_option("-c", "--client", help="Act as a REST-JSON API client", default=RESTAPI_SERVER_PORT, action="store_true")
    parser.add_option("-H", "--host", help="Host of the REST-JSON API server", default="0.0.0.0", action="store")
    parser.add_option("-p", "--port", help="Port of the the REST-JSON API server", default=RESTAPI_SERVER_PORT, action="store")
    (args, _) = parser.parse_args()

    if args.server is True:
        restAPIrun(args.host, args.port)
    elif args.client is True:
        client(args.host, args.port)
