#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re
import time

from subprocess import PIPE
from subprocess import Popen as execute

from lib.core.common import dataToStdout
from lib.core.common import getUnicode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.settings import IS_WIN
from lib.core.settings import REVISION
from lib.core.settings import UNICODE_ENCODING
from lib.core.subprocessng import pollProcess

def update():
    if not conf.updateAll:
        return

    rootDir = paths.SQLMAP_ROOT_PATH

    infoMsg = "updating sqlmap to the latest development version from the "
    infoMsg += "GitHub repository"
    logger.info(infoMsg)

    debugMsg = "sqlmap will try to update itself using 'git' command"
    logger.debug(debugMsg)

    dataToStdout("\r[%s] [INFO] update in progress " % time.strftime("%X"))
    process = execute("git pull %s" % rootDir, shell=True, stdout=PIPE, stderr=PIPE)
    pollProcess(process, True)
    stdout, stderr = process.communicate()

    if not process.returncode:
        logger.info("%s the latest revision '%s'" % ("already at" if "Already" in stdout else "updated to", REVISION))
    else:
        logger.error("update could not be completed (%s)" % repr(stderr))

        if IS_WIN:
            infoMsg = "for Windows platform it's recommended "
            infoMsg += "to use a GitHub for Windows client for updating "
            infoMsg += "purposes (http://windows.github.com/)"
        else:
            infoMsg = "for Linux platform it's recommended "
            infoMsg += "to use a standard 'git' package (e.g.: 'sudo apt-get install git')"

        logger.info(infoMsg)
