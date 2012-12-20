#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import argparse
import logging

from _sqlmap import modulePath
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

    paths.SQLMAP_ROOT_PATH = modulePath()
    setPaths()

    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", help="Act as a REST-JSON API server", default=RESTAPI_SERVER_PORT, action="store_true")
    parser.add_argument("-c", "--client", help="Act as a REST-JSON API client", default=RESTAPI_SERVER_PORT, action="store_true")
    parser.add_argument("-H", "--host", help="Host of the REST-JSON API server", default=RESTAPI_SERVER_HOST, action="store")
    parser.add_argument("-p", "--port", help="Port of the the REST-JSON API server", default=RESTAPI_SERVER_PORT, action="store")
    args = parser.parse_args()

    if args.server is True:
        server(args.host, args.port)
    elif args.client is True:
        client(args.host, args.port)
