#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import argparse
import os
import sys

try:
    import simplejson as json
except ImportError:
    import json

try:
    from extra.bottle.bottle import abort
    from extra.bottle.bottle import debug
    from extra.bottle.bottle import error
    from extra.bottle.bottle import get
    from extra.bottle.bottle import post
    from extra.bottle.bottle import request
    from extra.bottle.bottle import response
    from extra.bottle.bottle import Response
    from extra.bottle.bottle import run
    from extra.bottle.bottle import static_file
    from extra.bottle.bottle import template
except ImportError:
    try:
        from bottle import *
    except ImportError, e:
        print "[x] '%s'" % str(e)
        sys.exit(1)

try:
    sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", ".."))
    from lib.controller.controller import start
    from lib.core.convert import hexencode
    from lib.core.datatype import AttribDict
    from lib.core.data import cmdLineOptions
    from lib.core.data import kb
    from lib.core.data import logger
    from lib.core.exception import SqlmapMissingDependence
    from lib.core.option import init
    from lib.core.settings import UNICODE_ENCODING
    from lib.core.settings import RESTAPI_SERVER_PORT
except ImportError:
    RESTAPI_SERVER_PORT = 8775

# local global variables
session_ids = []
admin_id = ""

Response(headers={"X-Frame-Options": "sameorigin", "X-XSS-Protection": "1; mode=block"})


# Generic functions
def jsonize(data):
    #return json.dumps(data, sort_keys=False, indent=4)
    return json.dumps(data, sort_keys=False)


def is_admin(session_id):
    global admin_id
    #print "[INFO] Admin ID:   %s" % admin_id
    #print "[INFO] Session ID: %s" % session_id
    if admin_id != session_id:
        return False
    else:
        return True


# HTTP Status Code functions
@error(401) # Access Denied
def error401(error):
    return "Access denied"


@error(404) # Not Found
def error404(error):
    return "Nothing here"


@error(405) # Method Not Allowed (e.g. when requesting a POST method via GET)
def error405(error):
    return "Method not allowed"


@error(500) # Internal Server Error
def error500(error):
    return "Internal server error"


################################
# Session management functions #
################################

# Users' methods
@get("/session/new")
def session_new():
    """
    Create new session token
    """
    global session_ids
    session_id = hexencode(os.urandom(32))
    session_ids.append(session_id)
    response.content_type = "application/json; charset=UTF-8"
    return jsonize({"sessionid": session_id})


@post("/session/destroy")
def session_destroy():
    """
    Destroy own session token
    """
    session_id = request.json.get("sessionid", "")
    if session_id in session_ids:
        session_ids.remove(session_id)
        return "Done"
    else:
        abort(500)

# Admin's methods
@post("/session/list")
def session_list():
    """
    List all active sessions
    """
    if is_admin(request.json.get("sessionid", "")):
        response.content_type = "application/json; charset=UTF-8"
        return jsonize({"sessions": session_ids})
    else:
        abort(401)


@post("/session/flush")
def session_flush():
    """
    Flush session spool (destroy all sessions)
    """
    global session_ids
    if is_admin(request.json.get("sessionid", "")):
        session_ids = []
    else:
        abort(401)


@post("/download/<target>/<filename:path>")
def download(target, filename):
    """
    Download a certain file from the file system
    """
    path = os.path.join(paths.SQLMAP_OUTPUT_PATH, target)
    if os.path.exists(path):
        return static_file(filename, root=path)
    else:
        abort(500)


def restAPIrun(host="0.0.0.0", port=RESTAPI_SERVER_PORT):
    """
    Initiate REST-JSON API
    """
    global admin_id
    admin_id = hexencode(os.urandom(32))
    options = AttribDict(cmdLineOptions)
    logger.info("Running REST-JSON API server at '%s:%d'.." % (host, port))
    logger.info("The admin session ID is: %s" % admin_id)
    run(host=host, port=port)

def client(host, port):
    addr = "http://%s:%d" % (host, port)
    print "[INFO] Starting debug REST-JSON client to '%s'..." % addr

    # TODO: write a simple client with urllib2, for now use curl from command line
    print "[ERROR] Not yet implemented, use curl from command line instead for now, for example:"
    print "\n\t$ curl --proxy http://127.0.0.1:8080 http://%s:%s/session/new" % (host, port)
    print "\t$ curl --proxy http://127.0.0.1:8080 -H \"Content-Type: application/json\" -X POST -d '{\"sessionid\": \"<admin session id>\"}' http://%s:%d/session/list\n" % (host, port)

if __name__ == "__main__":
    """
    Standalone REST-JSON API wrapper function
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", help="Act as a REST-JSON API server", default=RESTAPI_SERVER_PORT, action="store_true", required=False)
    parser.add_argument("-c", "--client", help="Act as a REST-JSON API client", default=RESTAPI_SERVER_PORT, action="store_true", required=False)
    parser.add_argument("-H", "--host", help="Host of the REST-JSON API server", default="0.0.0.0", action="store", required=False)
    parser.add_argument("-p", "--port", help="Port of the the REST-JSON API server", default=RESTAPI_SERVER_PORT, action="store", required=False)
    args = parser.parse_args()

    if args.server is True:
        restAPIrun(args.host, args.port)
    elif args.client is True:
        client(args.host, args.port)
