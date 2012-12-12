#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import sys
import xmlrpclib

try:
    from SimpleXMLRPCServer import SimpleXMLRPCServer

    from lib.controller.controller import start
    from lib.core.datatype import AttribDict
    from lib.core.data import cmdLineOptions
    from lib.core.data import logger
    from lib.core.option import init
    from lib.core.settings import UNICODE_ENCODING
    from lib.core.settings import XMLRPC_SERVER_PORT
except ImportError:
    pass

class XMLRPCServer:
    def __init__(self, port):
        self.port = port
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
        server = SimpleXMLRPCServer(addr=("", self.port), logRequests=False, allow_none=True, encoding=UNICODE_ENCODING)
        server.register_function(self.reset)
        server.register_function(self.set_option)
        server.register_function(self.get_option)
        server.register_function(self.get_option_names)
        server.register_function(self.run)
        logger.info("Registering RPC methods: %s" % str(server.system_listMethods()).strip("[]"))
        server.register_introspection_functions()
        logger.info("Running XML-RPC server at '0.0.0.0:%d'..." % self.port)
        server.serve_forever()

if __name__ == "__main__":
    try:
        import readline
    except ImportError:
        pass

    server = xmlrpclib.ServerProxy("http://localhost:%d" % (int(sys.argv[1]) if len(sys.argv) > 1 else 8776))

    print "[o] Server instance: 'server'"
    print "[i] Available RPC methods: %s" % str(server.system.listMethods()).strip("[]")
    print "[i] Sample usage: 'server.system.listMethods()'"

    while True:
        try:
            _ = raw_input("> ")
            if not _.startswith("print"):
                print eval(_) or ""
            else:
                exec(_)
        except KeyboardInterrupt:
            exit(0)
        except Exception, ex:
            print "[x] '%s'" % str(ex)
