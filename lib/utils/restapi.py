#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import optparse
import os
import sys
import threading

try:
    import simplejson as json
except ImportError:
    import json

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", ".."))

from extra.bottle.bottle import abort
from extra.bottle.bottle import debug
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
options = AttribDict()
adminid = ""
tasks = []

# Generic functions
def jsonize(data):
    return json.dumps(data, sort_keys=False)

def is_admin(taskid):
    global adminid
    #print "[INFO] Admin ID:   %s" % adminid
    #print "[INFO] Task ID: %s" % taskid
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
    taskid = hexencode(os.urandom(32))
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
@post("/scan/<taskid>")
def scan(taskid):
    """
    Mount a scan with sqlmap
    """
    global options

    if taskid not in tasks:
        abort(500, "Invalid task ID")

    # Initialize sqlmap engine's options with user's provided options
    # within the JSON request
    for key, value in request.json.items():
        if key != "taskid":
            options[key] = value
    init(options, True)

    # Launch sqlmap engine in a separate thread
    thread = threading.Thread(target=start)
    thread.daemon = True
    thread.start()

    return jsonize({"success": True})

@post("/download/<taskid>/<target>/<filename:path>")
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

def restAPIrun(host="0.0.0.0", port=RESTAPI_SERVER_PORT):
    """
    Initiate REST-JSON API
    """
    global adminid
    global options
    global tasks
    adminid = hexencode(os.urandom(32))
    tasks.append(adminid)
    options = AttribDict(cmdLineOptions)
    logger.info("Running REST-JSON API server at '%s:%d'.." % (host, port))
    logger.info("The admin task ID is: %s" % adminid)
    run(host=host, port=port)

def client(host, port):
    addr = "http://%s:%d" % (host, port)
    print "[INFO] Starting debug REST-JSON client to '%s'..." % addr

    # TODO: write a simple client with urllib2, for now use curl from command line
    print "[ERROR] Not yet implemented, use curl from command line instead for now, for example:"
    print "\n\t$ curl --proxy http://127.0.0.1:8080 http://127.0.0.1:%s/task/new" % port
    print "\t$ curl --proxy http://127.0.0.1:8080 -H \"Content-Type: application/json\" -X POST -d '{\"targetUrl\": \"<target URL>\"}' http://127.0.0.1:%d/scan/<task ID>\n" % port

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
