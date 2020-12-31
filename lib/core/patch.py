#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import codecs
import os
import random
import re
import sys

import lib.controller.checks
import lib.core.common
import lib.core.convert
import lib.core.option
import lib.core.threads
import lib.request.connect
import lib.utils.search
import lib.utils.sqlalchemy
import thirdparty.ansistrm.ansistrm
import thirdparty.chardet.universaldetector

from lib.core.common import filterNone
from lib.core.common import getSafeExString
from lib.core.common import isDigit
from lib.core.common import isListLike
from lib.core.common import readInput
from lib.core.common import shellExec
from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.convert import stdoutEncode
from lib.core.data import conf
from lib.core.enums import PLACE
from lib.core.option import _setHTTPHandlers
from lib.core.option import setVerbosity
from lib.core.settings import IS_WIN
from lib.request.templates import getPageTemplate
from thirdparty import six
from thirdparty.six.moves import http_client as _http_client

_rand = 0

def dirtyPatches():
    """
    Place for "dirty" Python related patches
    """

    # accept overly long result lines (e.g. SQLi results in HTTP header responses)
    _http_client._MAXLINE = 1 * 1024 * 1024

    # prevent double chunked encoding in case of sqlmap chunking (Note: Python3 does it automatically if 'Content-length' is missing)
    if six.PY3:
        if not hasattr(_http_client.HTTPConnection, "__send_output"):
            _http_client.HTTPConnection.__send_output = _http_client.HTTPConnection._send_output

        def _send_output(self, *args, **kwargs):
            if conf.get("chunked") and "encode_chunked" in kwargs:
                kwargs["encode_chunked"] = False
            self.__send_output(*args, **kwargs)

        _http_client.HTTPConnection._send_output = _send_output

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

    # to prevent too much "guessing" in case of binary data retrieval
    thirdparty.chardet.universaldetector.MINIMUM_THRESHOLD = 0.90

    match = re.search(r" --method[= ](\w+)", " ".join(sys.argv))
    if match and match.group(1).upper() != PLACE.POST:
        PLACE.CUSTOM_POST = PLACE.CUSTOM_POST.replace("POST", "%s (body)" % match.group(1))

    # https://github.com/sqlmapproject/sqlmap/issues/4314
    try:
        os.urandom(1)
    except NotImplementedError:
        if six.PY3:
            os.urandom = lambda size: bytes(random.randint(0, 255) for _ in range(size))
        else:
            os.urandom = lambda size: "".join(chr(random.randint(0, 255)) for _ in xrange(size))

def resolveCrossReferences():
    """
    Place for cross-reference resolution
    """

    lib.core.threads.isDigit = isDigit
    lib.core.threads.readInput = readInput
    lib.core.common.getPageTemplate = getPageTemplate
    lib.core.convert.filterNone = filterNone
    lib.core.convert.isListLike = isListLike
    lib.core.convert.shellExec = shellExec
    lib.core.convert.singleTimeWarnMessage = singleTimeWarnMessage
    lib.core.option._pympTempLeakPatch = pympTempLeakPatch
    lib.request.connect.setHTTPHandlers = _setHTTPHandlers
    lib.utils.search.setHTTPHandlers = _setHTTPHandlers
    lib.controller.checks.setVerbosity = setVerbosity
    lib.utils.sqlalchemy.getSafeExString = getSafeExString
    thirdparty.ansistrm.ansistrm.stdoutEncode = stdoutEncode

def pympTempLeakPatch(tempDir):
    """
    Patch for "pymp" leaking directories inside Python3
    """

    try:
        import multiprocessing.util
        multiprocessing.util.get_temp_dir = lambda: tempDir
    except:
        pass

def unisonRandom():
    """
    Unifying random generated data across different Python versions
    """

    def _lcg():
        global _rand
        a = 1140671485
        c = 128201163
        m = 2 ** 24
        _rand = (a * _rand + c) % m
        return _rand

    def _randint(a, b):
        _ = a + (_lcg() % (b - a + 1))
        return _

    def _choice(seq):
        return seq[_randint(0, len(seq) - 1)]

    def _sample(population, k):
        return [_choice(population) for _ in xrange(k)]

    def _seed(seed):
        global _rand
        _rand = seed

    random.choice = _choice
    random.randint = _randint
    random.sample = _sample
    random.seed = _seed
