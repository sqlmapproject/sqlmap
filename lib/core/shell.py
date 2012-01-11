#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import atexit
import os
import rlcompleter

from lib.core import readlineng as readline
from lib.core.common import Backend
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.enums import OS

def saveHistory():
    historyPath = os.path.expanduser(paths.SQLMAP_HISTORY)
    readline.write_history_file(historyPath)

def loadHistory():
    historyPath = os.path.expanduser(paths.SQLMAP_HISTORY)

    if os.path.exists(historyPath):
        try:
            readline.read_history_file(historyPath)
        except IOError, msg:
            warnMsg = "there was a problem loading the history file '%s' (%s)" % (historyPath, msg)
            logger.warn(warnMsg)

class CompleterNG(rlcompleter.Completer):
    def global_matches(self, text):
        """
        Compute matches when text is a simple name.
        Return a list of all names currently defined in self.namespace
        that match.
        """

        matches = []
        n = len(text)

        for ns in [ self.namespace ]:
            for word in ns:
                if word[:n] == text:
                    matches.append(word)

        return matches

def autoCompletion(sqlShell=False, osShell=False):
    # First of all we check if the readline is available, by default
    # it is not in Python default installation on Windows
    if not readline._readline:
        return

    if osShell:
        if Backend.isOs(OS.WINDOWS):
            # Reference: http://en.wikipedia.org/wiki/List_of_DOS_commands
            completer = CompleterNG({
                                      "copy": None, "del": None, "dir": None,
                                      "echo": None, "md": None, "mem": None,
                                      "move": None, "net": None, "netstat -na": None,
                                      "ver": None, "xcopy": None, "whoami": None,
                                    })

        else:
            # Reference: http://en.wikipedia.org/wiki/List_of_Unix_commands
            completer = CompleterNG({
                                      "cp": None, "rm": None, "ls": None, 
                                      "echo": None, "mkdir": None, "free": None,
                                      "mv": None, "ifconfig": None, "netstat -natu": None,
                                      "pwd": None, "uname": None, "id": None,
                                    })

        readline.set_completer(completer.complete)
        readline.parse_and_bind("tab: complete")

    loadHistory()
    atexit.register(saveHistory)
