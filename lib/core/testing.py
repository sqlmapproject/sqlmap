#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import doctest
import os
import re
import shutil
import StringIO
import sys
import tempfile
import time
import traceback

from extra.beep.beep import beep
from lib.controller.controller import start
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import getUnicode
from lib.core.common import randomStr
from lib.core.common import readXmlFile
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.log import LOGGER_HANDLER
from lib.core.option import init
from lib.core.optiondict import optDict
from lib.core.settings import UNICODE_ENCODING
from lib.parse.cmdline import cmdLineParser

failedItem = None
failedParseOn = None

def smokeTest():
    """
    This will run the basic smoke testing of a program
    """
    retVal = True
    count, length = 0, 0

    for root, _, files in os.walk(paths.SQLMAP_ROOT_PATH):
        if any(_ in root for _ in ("thirdparty", "extra")):
            continue

        for ifile in files:
            length += 1

    for root, _, files in os.walk(paths.SQLMAP_ROOT_PATH):
        if any(_ in root for _ in ("thirdparty", "extra")):
            continue

        for ifile in files:
            if os.path.splitext(ifile)[1].lower() == ".py" and ifile != "__init__.py":
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
            status = '%d/%d (%d%%) ' % (count, length, round(100.0 * count / length))
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
    global failedItem
    global failedParseOn

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
                    var = child.getAttribute("value")
                    vars_[child.tagName] = randomStr(6) if var == "random" else var

    for case in livetests.getElementsByTagName("case"):
        console_output = False
        count += 1
        name = None
        parse = []
        switches = dict(global_)
        value = ""

        if case.hasAttribute("name"):
            name = case.getAttribute("name")

        if conf.runCase and ((conf.runCase.isdigit() and conf.runCase != count) or not re.search(conf.runCase, name, re.DOTALL)):
            continue

        if case.getElementsByTagName("switches"):
            for child in case.getElementsByTagName("switches")[0].childNodes:
                if child.nodeType == child.ELEMENT_NODE and child.hasAttribute("value"):
                    value = replaceVars(child.getAttribute("value"), vars_)
                    switches[child.tagName] = adjustValueType(child.tagName, value)

        if case.getElementsByTagName("parse"):
            for item in case.getElementsByTagName("parse")[0].getElementsByTagName("item"):
                if item.hasAttribute("value"):
                    value = replaceVars(item.getAttribute("value"), vars_)

                if item.hasAttribute("console_output"):
                    console_output = bool(item.getAttribute("console_output"))

                parse.append((value, console_output))

        msg = "running live test case '%s' (%d/%d)" % (name, count, length)
        logger.info(msg)

        result = runCase(switches, parse)

        if result:
            logger.info("test passed")
            cleanCase()
        else:
            errMsg = "test failed "
            if failedItem:
                errMsg += "at parsing item: %s - scan folder is %s" % (failedItem, paths.SQLMAP_OUTPUT_PATH)
                console_output_fd = codecs.open("%s%sconsole_output" % (paths.SQLMAP_OUTPUT_PATH, os.sep), "wb", UNICODE_ENCODING)
                console_output_fd.write(failedParseOn)
                console_output_fd.close()

            logger.error(errMsg)
            beep()

            if conf.stopFail is True:
                return retVal

        retVal &= result

    dataToStdout("\n")

    if retVal:
        logger.info("live test final result: PASSED")
    else:
        logger.error("live test final result: FAILED")

    return retVal

def initCase(switches=None):
    global failedItem
    global failedParseOn
    failedItem = None
    failedParseOn = None

    paths.SQLMAP_OUTPUT_PATH = tempfile.mkdtemp(prefix="sqlmaptest-")
    paths.SQLMAP_DUMP_PATH = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "dump")
    paths.SQLMAP_FILES_PATH = os.path.join(paths.SQLMAP_OUTPUT_PATH, "%s", "files")

    logger.debug("using output directory '%s' for this test case" % paths.SQLMAP_OUTPUT_PATH)

    cmdLineOptions = cmdLineParser()
    cmdLineOptions.liveTest = cmdLineOptions.smokeTest = False

    if switches:
        for key, value in switches.items():
            if key in cmdLineOptions.__dict__:
                cmdLineOptions.__dict__[key] = value

    init(cmdLineOptions, True)

def cleanCase():
    shutil.rmtree(paths.SQLMAP_OUTPUT_PATH, True)

def runCase(switches=None, parse=None):
    global failedItem
    global failedParseOn

    initCase(switches)

    LOGGER_HANDLER.stream = sys.stdout = StringIO.StringIO()
    retVal = True
    exception = None
    result = False
    console = ""

    try:
        result = start()
    except KeyboardInterrupt:
        raise
    except Exception, e:
        exception = e
    finally:
        sys.stdout.seek(0)
        console = sys.stdout.read()
        LOGGER_HANDLER.stream = sys.stdout = sys.__stdout__

    if exception:
        logger.error("unhandled exception occurred ('%s')" % str(exception))
        tback = traceback.format_exc()
        retVal = False
    elif result is False:  # if None, ignore
        logger.error("the test did not run")
        retVal = False

    if parse and retVal:
        console = getUnicode(console, system=True)
        with codecs.open(conf.dumper.getOutputFile(), "rb", UNICODE_ENCODING) as f:
            content = f.read()

        for item, console_output in parse:
            parse_on = console if console_output else content

            if item.startswith("r'") and item.endswith("'"):
                if not re.search(item[2:-1], parse_on, re.DOTALL):
                    retVal = False
                    failedItem = item
                    break

            elif item not in parse_on:
                retVal = False
                failedItem = item
                break

        if failedItem is not None:
            failedParseOn = console

    return retVal

def replaceVars(item, vars_):
    retVal = item

    if item and vars_:
        for var in re.findall("\$\{([^}]+)\}", item):
            if var in vars_:
                retVal = retVal.replace("${%s}" % var, vars_[var])

    return retVal
