#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import atexit
import os

from lib.core import readlineng as readline
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.enums import OS
from lib.core.settings import MAX_HISTORY_LENGTH

try:
    import rlcompleter

    class CompleterNG(rlcompleter.Completer):
        def global_matches(self, text):
            """
            Compute matches when text is a simple name.
            Return a list of all names currently defined in self.namespace
            that match.
            """

            matches = []
            n = len(text)

            for ns in (self.namespace,):
                for word in ns:
                    if word[:n] == text:
                        matches.append(word)

            return matches
except:
    readline._readline = None

def readlineAvailable():
    """
    Check if the readline is available. By default
    it is not in Python default installation on Windows
    """

    return readline._readline is not None

def clearHistory():
    if not readlineAvailable():
        return

    readline.clear_history()

def saveHistory(completion=None):
    if not readlineAvailable():
        return

    if completion == AUTOCOMPLETE_TYPE.SQL:
        historyPath = paths.SQL_SHELL_HISTORY
    elif completion == AUTOCOMPLETE_TYPE.OS:
        historyPath = paths.OS_SHELL_HISTORY
    else:
        historyPath = paths.SQLMAP_SHELL_HISTORY

    try:
        with open(historyPath, "w+"):
            pass
    except:
        pass

    readline.set_history_length(MAX_HISTORY_LENGTH)
    try:
        readline.write_history_file(historyPath)
    except IOError, msg:
        warnMsg = "there was a problem writing the history file '%s' (%s)" % (historyPath, msg)
        logger.warn(warnMsg)

def loadHistory(completion=None):
    if not readlineAvailable():
        return

    clearHistory()

    if completion == AUTOCOMPLETE_TYPE.SQL:
        historyPath = paths.SQL_SHELL_HISTORY
    elif completion == AUTOCOMPLETE_TYPE.OS:
        historyPath = paths.OS_SHELL_HISTORY
    else:
        historyPath = paths.SQLMAP_SHELL_HISTORY

    if os.path.exists(historyPath):
        try:
            readline.read_history_file(historyPath)
        except IOError, msg:
            warnMsg = "there was a problem loading the history file '%s' (%s)" % (historyPath, msg)
            logger.warn(warnMsg)

def autoCompletion(completion=None, os=None, commands=None):
    if not readlineAvailable():
        return

    if completion == AUTOCOMPLETE_TYPE.OS:
        if os == OS.WINDOWS:
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

    elif commands:
        completer = CompleterNG(dict(((_, None) for _ in commands)))
        readline.set_completer_delims(' ')
        readline.set_completer(completer.complete)
        readline.parse_and_bind("tab: complete")

    loadHistory(completion)
    atexit.register(saveHistory, completion)
