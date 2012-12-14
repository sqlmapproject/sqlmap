#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import optparse
import os
import sys
import tempfile
import threading

try:
    import simplejson as json
except ImportError:
    import json

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
from lib.core.exception import SqlmapMissingDependence
from lib.core.option import init
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import RESTAPI_SERVER_PORT

# Local global variables
options = {}
output = ""
adminid = ""
tasks = []

# Generic functions
def jsonize(data):
    return json.dumps(data, sort_keys=False)

def is_admin(taskid):
    global adminid
    if adminid != taskid:
        return False
    else:
        return True

@hook('after_request')
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
    global options
    taskid = hexencode(os.urandom(16))
    options[taskid] = AttribDict(cmdLineOptions)
    options[taskid]["oDir"] = tempfile.mkdtemp(prefix="sqlmap-")
    tasks.append(taskid)
    return jsonize({"taskid": taskid})

@get("/task/<taskid>/destroy")
def task_destroy(taskid):
    """
    Destroy own task ID
    """
    if taskid in tasks:
        tasks.remove(taskid)
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
    Flush task spool (destroy all tasks)
    """
    global tasks
    if is_admin(taskid):
        tasks = []
        return jsonize({"success": True})
    else:
        abort(401)

##################################
# sqlmap core interact functions #
##################################

@get("/option/<taskid>/list")
def option_list(taskid):
    """
    List options for a certain task ID
    """
    global options
    if taskid not in tasks:
        abort(500, "Invalid task ID")

    return jsonize(options[taskid])

@post("/option/<taskid>/get")
def option_get(taskid):
    """
    Get the value of an option (command line switch) for a certain task ID
    """
    global options
    if taskid not in tasks:
        abort(500, "Invalid task ID")

    option = request.json.get("option", "")

    if option in options[taskid]:
        print {option: options[taskid][option]}
        return jsonize({option: options[taskid][option]})
    else:
        return jsonize({option: None})

@post("/option/<taskid>/set")
def option_set(taskid):
    """
    Set an option (command line switch) for a certain task ID
    """
    global options
    if taskid not in tasks:
        abort(500, "Invalid task ID")

    for key, value in request.json.items():
        options[taskid][key] = value

    return jsonize({"success": True})

@post("/scan/<taskid>/start")
def scan(taskid):
    """
    Launch a scan
    """
    global options
    if taskid not in tasks:
        abort(500, "Invalid task ID")

    # Initialize sqlmap engine's options with user's provided options
    # within the JSON request
    for key, value in request.json.items():
        options[taskid][key] = value
    init(options[taskid], True)

    # Launch sqlmap engine in a separate thread
    thread = threading.Thread(target=start)
    thread.daemon = True
    thread.start()

    return jsonize({"success": True})

@get("/scan/<taskid>/status")
def scan_status(taskid):
    """
    Verify if sqlmap core is currently running
    """
    if taskid not in tasks:
        abort(500, "Invalid task ID")

    return jsonize({"busy": kb.get("busyFlag")})

@get("/scan/<taskid>/output")
def scan_output(taskid):
    """
    Read the standard output of sqlmap core execution
    """
    if taskid not in tasks:
        abort(500, "Invalid task ID")

    global output
    sys.stdout.seek(len(output))
    output = sys.stdout.read()
    sys.stdout.truncate(0)
    return jsonize({"output": output})

@get("/download/<taskid>/<target>/<filename:path>")
def download(taskid, target, filename):
    """
    Download a certain file from the file system
    """
    if taskid not in tasks:
        abort(500, "Invalid task ID")

    path = os.path.join(paths.SQLMAP_OUTPUT_PATH, target)
    if os.path.exists(path):
        return static_file(filename, root=path)
    else:
        abort(500)

def restAPIsetup(host="0.0.0.0", port=RESTAPI_SERVER_PORT):
    """
    Initiate REST-JSON API
    """
    global adminid
    global options
    global tasks
    adminid = hexencode(os.urandom(16))
    options[adminid] = AttribDict(cmdLineOptions)
    options[adminid]["oDir"] = tempfile.mkdtemp(prefix="sqlmap-")
    tasks.append(adminid)
    logger.info("Running REST-JSON API server at '%s:%d'.." % (host, port))
    logger.info("The admin task ID is: %s" % adminid)

def restAPIrun(host="0.0.0.0", port=RESTAPI_SERVER_PORT):
    run(host=host, port=port)

def client(host, port):
    addr = "http://%s:%d" % (host, port)
    print "[INFO] Starting debug REST-JSON client to '%s'..." % addr

    # TODO: write a simple client with urllib2, for now use curl from command line
    print "[ERROR] Not yet implemented, use curl from command line instead for now, for example:"
    print "\n\t$ curl --proxy http://127.0.0.1:8080 http://127.0.0.1:%s/task/new" % port
    print "\t$ curl --proxy http://127.0.0.1:8080 -H \"Content-Type: application/json\" -X POST -d '{\"url\": \"<target URL>\"}' http://127.0.0.1:%d/scan/<task ID>/start\n" % port

if __name__ == "__main__":
    """
    Standalone REST-JSON API wrapper function
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
