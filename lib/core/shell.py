#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import atexit
import os
import rlcompleter

from lib.core import readlineng as readline
from lib.core.common import backend
from lib.core.data import kb
from lib.core.data import paths
from lib.core.data import queries

def saveHistory():
    historyPath = os.path.expanduser(paths.SQLMAP_HISTORY)
    readline.write_history_file(historyPath)

def loadHistory():
    historyPath = os.path.expanduser(paths.SQLMAP_HISTORY)

    if os.path.exists(historyPath):
        readline.read_history_file(historyPath)

def queriesForAutoCompletion():
    autoComplQueries = {}

    for item in queries[backend.getIdentifiedDbms()]._toflat():
        if item._has_key('query') and len(item.query) > 1 and item._name != 'blind':
            autoComplQueries[item.query] = None

    return autoComplQueries

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

    if sqlShell:
        completer = CompleterNG(queriesForAutoCompletion())
    elif osShell:
        if kb.os == "Windows":
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
