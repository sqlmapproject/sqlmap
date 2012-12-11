#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from SimpleXMLRPCServer import SimpleXMLRPCServer

from lib.controller.controller import start
from lib.core.datatype import AttribDict
from lib.core.data import cmdLineOptions
from lib.core.data import logger
from lib.core.option import init
from lib.core.settings import XML_RPC_SERVER_PORT
from lib.core.settings import UNICODE_ENCODING

class XMLRPCServer:
    def __init__(self):
        self.reset()

    def reset(self):
        self.options = AttribDict(cmdLineOptions)

    def set_option(self, name, value):
        self.options[name] = value

    def get_option(self, name):
        return self.options[name]

    def get_option_names(self):
        return self.options.keys()

    def run(self):
        init(self.options, True)
        return start()

    def serve(self):
        server = SimpleXMLRPCServer(addr=("", XML_RPC_SERVER_PORT), logRequests=False, allow_none=True, encoding=UNICODE_ENCODING)
        server.register_introspection_functions()
        server.register_function(self.reset)
        server.register_function(self.set_option)
        server.register_function(self.get_option)
        server.register_function(self.get_option_names)
        server.register_function(self.run)
        server.serve_forever()
