#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import sys
import json
import os

from extra.bottle.bottle import abort, error, get, post, request, run, template, debug
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


# local global variables
session_ids = []
admin_id = ""


# Generic functions
def jsonize(data):
    return json.dumps(data, sort_keys=False, indent=4)


def is_admin(session_id):
    global admin_id
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
    return jsonize({"sessionid": session_id})


@post("/session/destroy")
def session_destroy():
    """
    Destroy own session token
    """
    # TODO: replace use of request.forms with JSON
    session_id = request.forms.get("sessionid", "")
    #<sessionid:re:x[0-9a-fA-F]+>
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
    # TODO: replace use of request.forms with JSON
    if is_admin(request.forms.get("sessionid", "")):
        return jsonize({"sessions": session_ids})
    else:
        abort(401)


@get("/session/flush")
def session_flush():
    """
    Flush session spool (destroy all sessions)
    """
    global session_ids
    if is_admin(request.forms.get("sessionid", "")):
        session_ids = []
    else:
        abort(401)


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


if __name__ == "__main__":
    addr = "http://localhost:%d" % (int(sys.argv[1]) if len(sys.argv) > 1 else RESTAPI_SERVER_PORT)
    print "[i] Starting debug REST-JSON client to '%s'..." % addr

    # TODO: write a simple client with urllib2, for now use curl from command line
