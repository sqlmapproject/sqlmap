#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import doctest
import os
import re
import shutil
import sys
import tempfile
import time

from lib.controller.controller import start
from lib.core.common import beep
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import readXmlFile
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.option import init
from lib.core.option import __setVerbosity
from lib.core.optiondict import optDict
from lib.parse.cmdline import cmdLineParser

def smokeTest():
    """
    This will run the basic smoke testing of a program
    """
    retVal = True
    count, length = 0, 0

    for root, _, files in os.walk(paths.SQLMAP_ROOT_PATH):
        if 'extra' in root:
            continue

        for ifile in files:
            length += 1

    for root, _, files in os.walk(paths.SQLMAP_ROOT_PATH):
        if 'extra' in root:
            continue

        for ifile in files:
            if os.path.splitext(ifile)[1].lower() == '.py' and ifile != '__init__.py':
                path = os.path.join(root, os.path.splitext(ifile)[0])
                path = path.replace(paths.SQLMAP_ROOT_PATH, '.')
                path = path.replace(os.sep, '.').lstrip('.')
                try:
                    __import__(path)
                    module = sys.modules[path]
                except Exception, msg:
                    retVal = False
                    dataToStdout("\r")
                    errMsg = "smoke test failed at importing module '%s' (%s):\n%s" % (path, os.path.join(root, ifile), msg)
                    logger.error(errMsg)
                else:
                    # Run doc tests
                    # Reference: http://docs.python.org/library/doctest.html
                    (failure_count, test_count) = doctest.testmod(module)
                    if failure_count > 0:
                        retVal = False

            count += 1
            status = '%d/%d (%d%s) ' % (count, length, round(100.0*count/length), '%')
            dataToStdout("\r[%s] [INFO] complete: %s" % (time.strftime("%X"), status))

    clearConsoleLine()
    if retVal:
        logger.info("smoke test final result: PASSED")
    else:
        logger.error("smoke test final result: FAILED")

    return retVal

def adjustValueType(tagName, value):
    for family in optDict.keys():
        for name, type_ in optDict[family].items():
            if type(type_) == tuple:
                type_ = type_[0]
            if tagName == name:
                if type_ == "boolean":
                    value = (value == "True")
                elif type_ == "integer":
                    value = int(value)
                elif type_ == "float":
                    value = float(value)
                break
    return value

def liveTest():
    """
    This will run the test of a program against the live testing environment
    """
    retVal = True
    count = 0
    global_ = {}
    vars_ = {}
    livetests = readXmlFile(paths.LIVE_TESTS_XML)
    length = len(livetests.getElementsByTagName("case"))

    element = livetests.getElementsByTagName("global")
    if element:
        for item in element:
            for child in item.childNodes:
                if child.nodeType == child.ELEMENT_NODE and child.hasAttribute("value"):
                    global_[child.tagName] = adjustValueType(child.tagName, child.getAttribute("value"))

    element = livetests.getElementsByTagName("vars")
    if element:
        for item in element:
            for child in item.childNodes:
                if child.nodeType == child.ELEMENT_NODE and child.hasAttribute("value"):
                    vars_[child.tagName] = child.getAttribute("value")

    for case in livetests.getElementsByTagName("case"):
        count += 1

        if conf.runCase and conf.runCase != count:
            continue

        name = None
        log = []
        session = []
        switches = dict(global_)

        if case.hasAttribute("name"):
            name = case.getAttribute("name")

        if case.getElementsByTagName("switches"):
            for child in case.getElementsByTagName("switches")[0].childNodes:
                if child.nodeType == child.ELEMENT_NODE and child.hasAttribute("value"):
                    value = replaceVars(child.getAttribute("value"), vars_)
                    switches[child.tagName] = adjustValueType(child.tagName, value)

        if case.getElementsByTagName("log"):
            for item in case.getElementsByTagName("log")[0].getElementsByTagName("item"):
                if item.hasAttribute("value"):
                    log.append(replaceVars(item.getAttribute("value"), vars_))

        if case.getElementsByTagName("session"):
            for item in case.getElementsByTagName("session")[0].getElementsByTagName("item"):
                if item.hasAttribute("value"):
                    session.append(replaceVars(item.getAttribute("value"), vars_))

        msg = "running live test case '%s' (%d/%d)" % (name, count, length)
        logger.info(msg)
        result = runCase(switches, log, session)
        if result:
            logger.info("test passed")
        else:
            logger.error("test failed")
            beep()
        retVal &= result

    dataToStdout("\n")
    if retVal:
        logger.info("live test final result: PASSED")
    else:
        logger.error("live test final result: FAILED")

    return retVal

def initCase(switches=None):
    paths.SQLMAP_OUTPUT_PATH = tempfile.mkdtemp()
    paths.SQLMAP_DUMP_PATH = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "dump")
    paths.SQLMAP_FILES_PATH = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "files")
    cmdLineOptions = cmdLineParser()
    cmdLineOptions.liveTest = cmdLineOptions.smokeTest = False

    if switches:
        for key, value in switches.items():
            if key in cmdLineOptions.__dict__:
                cmdLineOptions.__dict__[key] = value

    conf.sessionFile = None
    init(cmdLineOptions, True)
    __setVerbosity()

def cleanCase():
    shutil.rmtree(paths.SQLMAP_OUTPUT_PATH, True)
    paths.SQLMAP_OUTPUT_PATH = os.path.join(paths.SQLMAP_ROOT_PATH, "output")
    paths.SQLMAP_DUMP_PATH = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "dump")
    paths.SQLMAP_FILES_PATH = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "files")
    conf.verbose = 1
    __setVerbosity()

def runCase(switches=None, log=None, session=None):
    retVal = True
    initCase(switches)

    result = start()
    if result == False: #if None ignore
        retVal = False

    if session and retVal:
        ifile = open(conf.sessionFile, 'r')
        content = ifile.read()
        ifile.close()
        for item in session:
            if item.startswith("r'") and item.endswith("'"):
                if not re.search(item[2:-1], content, re.DOTALL):
                    retVal = False
                    break
            elif content.find(item) < 0:
                retVal = False
                break

    if log and retVal:
        ifile = open(conf.dumper.getOutputFile(), 'r')
        content = ifile.read()
        ifile.close()
        for item in log:
            if item.startswith("r'") and item.endswith("'"):
                if not re.search(item[2:-1], content, re.DOTALL):
                    retVal = False
                    break
            elif content.find(item) < 0:
                retVal = False
                break

    cleanCase()
    return retVal

def replaceVars(item, vars_):
    retVal = item
    if item and vars_:
        for var in re.findall("\$\{([^}]+)\}", item):
            if var in vars_:
                retVal = retVal.replace("${%s}" % var, vars_[var])
    return retVal
