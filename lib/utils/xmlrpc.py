#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import sys
import threading
import xmlrpclib

try:
    from SimpleXMLRPCServer import SimpleXMLRPCServer

    from lib.controller.controller import start
    from lib.core.datatype import AttribDict
    from lib.core.data import cmdLineOptions
    from lib.core.data import kb
    from lib.core.data import logger
    from lib.core.option import init
    from lib.core.settings import UNICODE_ENCODING
    from lib.core.settings import XMLRPC_SERVER_PORT
except ImportError:
    XMLRPC_SERVER_PORT = 8776

class XMLRPCServer:
    def __init__(self, port):
        self.port = port
        self.reset()

        self.server = SimpleXMLRPCServer(addr=("", self.port), logRequests=False, allow_none=True, encoding=UNICODE_ENCODING)
        self.server.register_function(self.reset)
        self.server.register_function(self.set_option)
        self.server.register_function(self.get_option)
        self.server.register_function(self.get_option_names)
        self.server.register_function(self.run)
        logger.info("Registering RPC methods: %s" % str(self.server.system_listMethods()).strip("[]"))
        self.server.register_introspection_functions()
        logger.info("Running XML-RPC server at '0.0.0.0:%d'..." % self.port)

    def reset(self):
        self.options = AttribDict(cmdLineOptions)

    def set_option(self, name, value):
        self.options[name] = value

    def get_option(self, name):
        return self.options[name]

    def get_option_names(self):
        return self.options.keys()

    def is_busy(self):
        return kb.get("busyFlag")

    def run(self):
        if not self.is_busy():
            init(self.options, True)
            thread = threading.Thread(target=start)
            thread.daemon = True
            thread.start()
        else:
            raise Exception, "sqlmap busy"

    def serve(self):
        self.server.serve_forever()

if __name__ == "__main__":
    try:
        import readline
    except ImportError:
        pass

    try:
        addr = "http://localhost:%d" % (int(sys.argv[1]) if len(sys.argv) > 1 else XMLRPC_SERVER_PORT)
        print "[i] Starting debug XML-RPC client to '%s'..." % addr

        server = xmlrpclib.ServerProxy(addr)
        print "[i] Available RPC methods: %s" % str(server.system.listMethods()).strip("[]")
        print "[i] Server instance name: 'server'"
        print "[i] Sample usage: 'server.system.listMethods()'"
    except Exception, ex:
        if ex:
            print "[x] '%s'" % str(ex)
    else:
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
