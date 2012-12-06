#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re
import time

from subprocess import PIPE
from subprocess import Popen as execute

from lib.core.common import dataToStdout
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.revision import getRevisionNumber
from lib.core.settings import GIT_REPOSITORY
from lib.core.settings import IS_WIN
from lib.core.subprocessng import pollProcess

def update():
    if not conf.updateAll:
        return

    success = False
    rootDir = paths.SQLMAP_ROOT_PATH

    if not os.path.exists(os.path.join(rootDir, ".git")):
        errMsg = "not a git repository. Please checkout the 'sqlmapproject/sqlmap' repository "
        errMsg += "from GitHub (e.g. git clone https://github.com/sqlmapproject/sqlmap.git sqlmap-dev)"
        logger.error(errMsg)
    else:
        infoMsg = "updating sqlmap to the latest development version from the "
        infoMsg += "GitHub repository"
        logger.info(infoMsg)

        debugMsg = "sqlmap will try to update itself using 'git' command"
        logger.debug(debugMsg)

        dataToStdout("\r[%s] [INFO] update in progress " % time.strftime("%X"))
        process = execute("git pull %s HEAD" % GIT_REPOSITORY, shell=True, stdout=PIPE, stderr=PIPE)
        pollProcess(process, True)
        stdout, stderr = process.communicate()
        success = not process.returncode

        if success:
            import lib.core.settings
            _ = lib.core.settings.REVISION = getRevisionNumber()
            logger.info("%s the latest revision '%s'" % ("already at" if "Already" in stdout else "updated to", _))
        else:
            logger.error("update could not be completed ('%s')" % re.sub(r"\W+", " ", stderr).strip())

    if not success:
        if IS_WIN:
            infoMsg = "for Windows platform it's recommended "
            infoMsg += "to use a GitHub for Windows client for updating "
            infoMsg += "purposes (http://windows.github.com/) or just "
            infoMsg += "download the latest snapshot from "
            infoMsg += "https://github.com/sqlmapproject/sqlmap/downloads"
        else:
            infoMsg = "for Linux platform it's required "
            infoMsg += "to install a standard 'git' package (e.g.: 'sudo apt-get install git')"

        logger.info(infoMsg)
