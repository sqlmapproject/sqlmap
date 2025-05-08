#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import atexit
import os

from lib.core import readlineng as readline
from lib.core.common import getSafeExString
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.enums import OS
from lib.core.settings import IS_WIN
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
    try:
        if not readlineAvailable():
            return

        if completion == AUTOCOMPLETE_TYPE.SQL:
            historyPath = paths.SQL_SHELL_HISTORY
        elif completion == AUTOCOMPLETE_TYPE.OS:
            historyPath = paths.OS_SHELL_HISTORY
        elif completion == AUTOCOMPLETE_TYPE.API:
            historyPath = paths.API_SHELL_HISTORY
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
        except IOError as ex:
            warnMsg = "there was a problem writing the history file '%s' (%s)" % (historyPath, getSafeExString(ex))
            logger.warning(warnMsg)
    except KeyboardInterrupt:
        pass

def loadHistory(completion=None):
    if not readlineAvailable():
        return

    clearHistory()

    if completion == AUTOCOMPLETE_TYPE.SQL:
        historyPath = paths.SQL_SHELL_HISTORY
    elif completion == AUTOCOMPLETE_TYPE.OS:
        historyPath = paths.OS_SHELL_HISTORY
    elif completion == AUTOCOMPLETE_TYPE.API:
        historyPath = paths.API_SHELL_HISTORY
    else:
        historyPath = paths.SQLMAP_SHELL_HISTORY

    if os.path.exists(historyPath):
        try:
            readline.read_history_file(historyPath)
        except IOError as ex:
            warnMsg = "there was a problem loading the history file '%s' (%s)" % (historyPath, getSafeExString(ex))
            logger.warning(warnMsg)
        except UnicodeError:
            if IS_WIN:
                warnMsg = "there was a problem loading the history file '%s'. " % historyPath
                warnMsg += "More info can be found at 'https://github.com/pyreadline/pyreadline/issues/30'"
                logger.warning(warnMsg)

def autoCompletion(completion=None, os=None, commands=None):
    if not readlineAvailable():
        return

    if completion == AUTOCOMPLETE_TYPE.OS:
        if os == OS.WINDOWS:
            # Reference: http://en.wikipedia.org/wiki/List_of_DOS_commands
            completer = CompleterNG({
                "attrib": None, "copy": None, "del": None,
                "dir": None, "echo": None, "fc": None,
                "label": None, "md": None, "mem": None,
                "move": None, "net": None, "netstat -na": None,
                "tree": None, "truename": None, "type": None,
                "ver": None, "vol": None, "xcopy": None,
            })

        else:
            # Reference: http://en.wikipedia.org/wiki/List_of_Unix_commands
            completer = CompleterNG({
                "cat": None, "chmod": None, "chown": None,
                "cp": None, "cut": None, "date": None, "df": None,
                "diff": None, "du": None, "echo": None, "env": None,
                "file": None, "find": None, "free": None, "grep": None,
                "id": None, "ifconfig": None, "ls": None, "mkdir": None,
                "mv": None, "netstat": None, "pwd": None, "rm": None,
                "uname": None, "whoami": None,
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
