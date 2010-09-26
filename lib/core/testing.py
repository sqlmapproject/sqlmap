#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2010 Miroslav Stampar <miroslav.stampar@gmail.com>

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

import codecs
import logging
import os
import re
import sys
import tempfile
import time

from xml.dom import minidom

from lib.controller.controller import start
from lib.core.common import dataToStdout
from lib.core.common import getCompiledRegex
from lib.core.common import getConsoleWidth
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.option import init
from lib.parse.cmdline import cmdLineParser

def smokeTest():
    """
    This will run the basic smoke testing of a program
    """
    import doctest
    retVal = True
    count, length = 0, 0
    
    for root, _, files in os.walk(paths.SQLMAP_ROOT_PATH):
        for file in files:
            length += 1
    
    for root, _, files in os.walk(paths.SQLMAP_ROOT_PATH):
        for file in files:
            if os.path.splitext(file)[1].lower() == '.py' and file != '__init__.py':
                path = os.path.join(root, os.path.splitext(file)[0])
                path = path.replace(paths.SQLMAP_ROOT_PATH, '.')
                path = path.replace(os.sep, '.').lstrip('.')
                try:
                    __import__(path)
                    module = sys.modules[path]
                except Exception, msg:
                    retVal = False
                    dataToStdout("\r")
                    errMsg = "smoke test failed at importing module '%s' (%s):\n%s" % (path, os.path.join(paths.SQLMAP_ROOT_PATH, file), msg)
                    logger.error(errMsg)
                else:
                    # Run doc tests
                    # Reference: http://docs.python.org/library/doctest.html
                    (failure_count, test_count) = doctest.testmod(module)
                    if failure_count > 0:
                        retVal = False

            count += 1
            status = '%d/%d (%d%s)' % (count, length, round(100.0*count/length), '%')
            dataToStdout("\r[%s] [INFO] complete: %s" % (time.strftime("%X"), status))

    dataToStdout("\r%s\r" % (" "*(getConsoleWidth()-1)))
    if retVal:
        logger.info("smoke test result: passed")
    else:
        logger.info("smoke test result: failed")
    
    return retVal

def liveTest():
    """
    This will run the test of a program against the live testing environment
    """
    vars = {}
    xfile = codecs.open(paths.LIVE_TESTS_XML, 'r', conf.dataEncoding)
    livetests = minidom.parse(xfile).documentElement
    xfile.close()
    
    global_ = livetests.getElementsByTagName("global")
    if global_:
        for item in global_:
            for child in item.childNodes:
                if child.nodeType == child.ELEMENT_NODE and child.hasAttribute("value"):
                    vars[child.tagName] = child.getAttribute("value")

    for case in livetests.getElementsByTagName("case"):
        log = []
        session = []
        switches = {}

        if case.getElementsByTagName("switches"):
            for child in case.getElementsByTagName("switches")[0].childNodes:
                if child.nodeType == child.ELEMENT_NODE and child.hasAttribute("value"):
                    switches[child.tagName] = replaceVars(child.getAttribute("value"), vars)

        if case.getElementsByTagName("log"):
            for item in case.getElementsByTagName("log")[0].getElementsByTagName("item"):
                if item.hasAttribute("value"):
                    log.append(replaceVars(item.getAttribute("value"), vars))

        if case.getElementsByTagName("session"):
            for item in case.getElementsByTagName("session")[0].getElementsByTagName("item"):
                if item.hasAttribute("value"):
                    session.append(replaceVars(item.getAttribute("value"), vars))

        runCase(switches, log, session)

def initCase():
    paths.SQLMAP_OUTPUT_PATH = tempfile.mkdtemp()
    paths.SQLMAP_DUMP_PATH   = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "dump")
    paths.SQLMAP_FILES_PATH  = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "files")
    cmdLineOptions = cmdLineParser()
    cmdLineOptions.liveTest = cmdLineOptions.smokeTest = False
    init(cmdLineOptions)
    conf.suppressOutput = True
    logger.setLevel(logging.CRITICAL)

def runCase(switches, log=None, session=None):
    initCase()
    for key, value in switches.items():
        conf[key] = value
    start()

def replaceVars(item, vars):
    retVal = item
    if item and vars:
        for var in re.findall(getCompiledRegex("\$\{([^}]+)\}"), item):
            if var in vars:
                retVal = retVal.replace("${%s}" % var, vars[var])
    return retVal