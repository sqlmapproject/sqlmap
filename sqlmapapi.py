#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import logging
import optparse

from sqlmap import modulePath
from lib.core.common import setPaths
from lib.core.data import paths
from lib.core.data import logger
from lib.utils.api import client
from lib.utils.api import server

RESTAPI_SERVER_HOST = "127.0.0.1"
RESTAPI_SERVER_PORT = 8775

if __name__ == "__main__":
    """
    REST-JSON API main function
    """
    # Set default logging level to debug
    logger.setLevel(logging.DEBUG)

    # Initialize path variable
    paths.SQLMAP_ROOT_PATH = modulePath()
    setPaths()

    # Parse command line options
    apiparser = optparse.OptionParser()
    apiparser.add_option("-s", "--server", help="Act as a REST-JSON API server", default=RESTAPI_SERVER_PORT, action="store_true")
    apiparser.add_option("-c", "--client", help="Act as a REST-JSON API client", default=RESTAPI_SERVER_PORT, action="store_true")
    apiparser.add_option("-H", "--host", help="Host of the REST-JSON API server", default=RESTAPI_SERVER_HOST, action="store")
    apiparser.add_option("-p", "--port", help="Port of the the REST-JSON API server", default=RESTAPI_SERVER_PORT, type="int", action="store")
    (args, _) = apiparser.parse_args()

    # Start the client or the server
    if args.server is True:
        server(args.host, args.port)
    elif args.client is True:
        client(args.host, args.port)
    else:
        apiparser.print_help()
