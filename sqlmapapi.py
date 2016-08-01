#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import logging
import optparse
import sys

sys.dont_write_bytecode = True

from lib.utils import versioncheck  # this has to be the first non-standard import

from sqlmap import modulePath
from lib.core.common import setPaths
from lib.core.data import logger
from lib.core.settings import RESTAPI_DEFAULT_ADAPTER
from lib.core.settings import RESTAPI_DEFAULT_ADDRESS
from lib.core.settings import RESTAPI_DEFAULT_PORT
from lib.utils.api import client
from lib.utils.api import server

def main():
    """
    REST-JSON API main function
    """

    # Set default logging level to debug
    logger.setLevel(logging.DEBUG)

    # Initialize paths
    setPaths(modulePath())

    # Parse command line options
    apiparser = optparse.OptionParser()
    apiparser.add_option("-s", "--server", help="Act as a REST-JSON API server", default=RESTAPI_DEFAULT_PORT, action="store_true")
    apiparser.add_option("-c", "--client", help="Act as a REST-JSON API client", default=RESTAPI_DEFAULT_PORT, action="store_true")
    apiparser.add_option("-H", "--host", help="Host of the REST-JSON API server", default=RESTAPI_DEFAULT_ADDRESS, action="store")
    apiparser.add_option("-p", "--port", help="Port of the the REST-JSON API server", default=RESTAPI_DEFAULT_PORT, type="int", action="store")
    apiparser.add_option("--adapter", help="Server (bottle) adapter to use (default %s)" % RESTAPI_DEFAULT_ADAPTER, default=RESTAPI_DEFAULT_ADAPTER, action="store")
    (args, _) = apiparser.parse_args()

    # Start the client or the server
    if args.server is True:
        server(args.host, args.port, adapter=args.adapter)
    elif args.client is True:
        client(args.host, args.port)
    else:
        apiparser.print_help()

if __name__ == "__main__":
    main()
