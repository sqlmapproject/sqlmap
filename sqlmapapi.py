#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import sys

sys.dont_write_bytecode = True

__import__("lib.utils.versioncheck")  # this has to be the first non-standard import

import logging
import os
import warnings

warnings.filterwarnings(action="ignore", category=UserWarning)
warnings.filterwarnings(action="ignore", category=DeprecationWarning)

try:
    from optparse import OptionGroup
    from optparse import OptionParser as ArgumentParser

    ArgumentParser.add_argument = ArgumentParser.add_option

    def _add_argument(self, *args, **kwargs):
        return self.add_option(*args, **kwargs)

    OptionGroup.add_argument = _add_argument

except ImportError:
    from argparse import ArgumentParser

finally:
    def get_actions(instance):
        for attr in ("option_list", "_group_actions", "_actions"):
            if hasattr(instance, attr):
                return getattr(instance, attr)

    def get_groups(parser):
        return getattr(parser, "option_groups", None) or getattr(parser, "_action_groups")

    def get_all_options(parser):
        retVal = set()

        for option in get_actions(parser):
            if hasattr(option, "option_strings"):
                retVal.update(option.option_strings)
            else:
                retVal.update(option._long_opts)
                retVal.update(option._short_opts)

        for group in get_groups(parser):
            for option in get_actions(group):
                if hasattr(option, "option_strings"):
                    retVal.update(option.option_strings)
                else:
                    retVal.update(option._long_opts)
                    retVal.update(option._short_opts)

        return retVal

from lib.core.common import getUnicode
from lib.core.common import setPaths
from lib.core.data import logger
from lib.core.patch import dirtyPatches
from lib.core.patch import resolveCrossReferences
from lib.core.settings import RESTAPI_DEFAULT_ADAPTER
from lib.core.settings import RESTAPI_DEFAULT_ADDRESS
from lib.core.settings import RESTAPI_DEFAULT_PORT
from lib.core.settings import UNICODE_ENCODING
from lib.utils.api import client
from lib.utils.api import server

try:
    from sqlmap import modulePath
except ImportError:
    def modulePath():
        return getUnicode(os.path.dirname(os.path.realpath(__file__)), encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)

def main():
    """
    REST-JSON API main function
    """

    dirtyPatches()
    resolveCrossReferences()

    # Set default logging level to debug
    logger.setLevel(logging.DEBUG)

    # Initialize paths
    setPaths(modulePath())

    # Parse command line options
    apiparser = ArgumentParser()
    apiparser.add_argument("-s", "--server", help="Run as a REST-JSON API server", action="store_true")
    apiparser.add_argument("-c", "--client", help="Run as a REST-JSON API client", action="store_true")
    apiparser.add_argument("-H", "--host", help="Host of the REST-JSON API server (default \"%s\")" % RESTAPI_DEFAULT_ADDRESS, default=RESTAPI_DEFAULT_ADDRESS)
    apiparser.add_argument("-p", "--port", help="Port of the REST-JSON API server (default %d)" % RESTAPI_DEFAULT_PORT, default=RESTAPI_DEFAULT_PORT, type=int)
    apiparser.add_argument("--adapter", help="Server (bottle) adapter to use (default \"%s\")" % RESTAPI_DEFAULT_ADAPTER, default=RESTAPI_DEFAULT_ADAPTER)
    apiparser.add_argument("--database", help="Set IPC database filepath (optional)")
    apiparser.add_argument("--username", help="Basic authentication username (optional)")
    apiparser.add_argument("--password", help="Basic authentication password (optional)")
    (args, _) = apiparser.parse_known_args() if hasattr(apiparser, "parse_known_args") else apiparser.parse_args()

    # Start the client or the server
    if args.server:
        server(args.host, args.port, adapter=args.adapter, username=args.username, password=args.password, database=args.database)
    elif args.client:
        client(args.host, args.port, username=args.username, password=args.password)
    else:
        apiparser.print_help()

if __name__ == "__main__":
    main()
