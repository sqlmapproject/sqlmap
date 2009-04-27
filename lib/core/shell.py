#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""



import atexit
import os
import rlcompleter

from lib.core import readlineng as readline
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

    for _, query in queries[kb.dbms].items():
        if isinstance(query, str) and len(query) > 1:
            autoComplQuery = query
        elif isinstance(query, dict) and "inband" in query:
            autoComplQuery = query["inband"]["query"]
        else:
            continue

        autoComplQueries[autoComplQuery] = None

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
    if not readline.haveReadline:
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
