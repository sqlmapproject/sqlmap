#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import codecs

import lib.controller.checks
import lib.core.common
import lib.core.threads
import lib.core.convert
import lib.core.option
import lib.request.connect
import lib.utils.search
import lib.utils.sqlalchemy
import thirdparty.ansistrm.ansistrm

from lib.request.templates import getPageTemplate

from lib.core.common import filterNone
from lib.core.common import getSafeExString
from lib.core.common import isListLike
from lib.core.common import singleTimeWarnMessage
from lib.core.common import readInput
from lib.core.convert import stdoutencode
from lib.core.option import _setHTTPHandlers
from lib.core.option import setVerbosity
from lib.core.option import _setWafFunctions
from lib.core.settings import IS_WIN
from thirdparty.six.moves import http_client as _http_client

def dirtyPatches():
    """
    Place for "dirty" Python related patches
    """

    # accept overly long result lines (e.g. SQLi results in HTTP header responses)
    _http_client._MAXLINE = 1 * 1024 * 1024

    # add support for inet_pton() on Windows OS
    if IS_WIN:
        from thirdparty.wininetpton import win_inet_pton

    # Reference: https://github.com/nodejs/node/issues/12786#issuecomment-298652440
    codecs.register(lambda name: codecs.lookup("utf-8") if name == "cp65001" else None)

    # Reference: http://bugs.python.org/issue17849
    if hasattr(_http_client, "LineAndFileWrapper"):
        def _(self, *args):
            return self._readline()

        _http_client.LineAndFileWrapper._readline = _http_client.LineAndFileWrapper.readline
        _http_client.LineAndFileWrapper.readline = _

def resolveCrossReferences():
    """
    Place for cross-reference resolution
    """

    lib.core.threads.readInput = readInput
    lib.core.common.getPageTemplate = getPageTemplate
    lib.core.convert.filterNone = filterNone
    lib.core.convert.isListLike = isListLike
    lib.core.convert.singleTimeWarnMessage = singleTimeWarnMessage
    lib.core.option._pympTempLeakPatch = pympTempLeakPatch
    lib.request.connect.setHTTPHandlers = _setHTTPHandlers
    lib.utils.search.setHTTPHandlers = _setHTTPHandlers
    lib.controller.checks.setVerbosity = setVerbosity
    lib.controller.checks.setWafFunctions = _setWafFunctions
    lib.utils.sqlalchemy.getSafeExString = getSafeExString
    thirdparty.ansistrm.ansistrm.stdoutencode = stdoutencode

def pympTempLeakPatch(tempDir):
    """
    Patch for "pymp" leaking directories inside Python3
    """

    try:
        import multiprocessing.util
        multiprocessing.util.get_temp_dir = lambda: tempDir
    except:
        pass
