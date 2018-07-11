#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import glob
import os
import re
import shutil
import subprocess
import sys
import time
import urllib
import zipfile

from lib.core.common import dataToStdout
from lib.core.common import getSafeExString
from lib.core.common import getLatestRevision
from lib.core.common import pollProcess
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.revision import getRevisionNumber
from lib.core.settings import GIT_REPOSITORY
from lib.core.settings import IS_WIN
from lib.core.settings import VERSION
from lib.core.settings import ZIPBALL_PAGE
from lib.core.settings import UNICODE_ENCODING

def update():
    if not conf.updateAll:
        return

    success = False

    if not os.path.exists(os.path.join(paths.SQLMAP_ROOT_PATH, ".git")):
        warnMsg = "not a git repository. It is recommended to clone the 'sqlmapproject/sqlmap' repository "
        warnMsg += "from GitHub (e.g. 'git clone --depth 1 %s sqlmap')" % GIT_REPOSITORY
        logger.warn(warnMsg)

        if VERSION == getLatestRevision():
            logger.info("already at the latest revision '%s'" % getRevisionNumber())
            return

        message = "do you want to try to fetch the latest 'zipball' from repository and extract it (experimental) ? [y/N]"
        if readInput(message, default='N', boolean=True):
            directory = os.path.abspath(paths.SQLMAP_ROOT_PATH)

            try:
                open(os.path.join(directory, "sqlmap.py"), "w+b")
            except Exception, ex:
                errMsg = "unable to update content of directory '%s' ('%s')" % (directory, getSafeExString(ex))
                logger.error(errMsg)
            else:
                attrs = os.stat(os.path.join(directory, "sqlmap.py")).st_mode
                for wildcard in ('*', ".*"):
                    for _ in glob.glob(os.path.join(directory, wildcard)):
                        try:
                            if os.path.isdir(_):
                                shutil.rmtree(_)
                            else:
                                os.remove(_)
                        except:
                            pass

                if glob.glob(os.path.join(directory, '*')):
                    errMsg = "unable to clear the content of directory '%s'" % directory
                    logger.error(errMsg)
                else:
                    try:
                        archive = urllib.urlretrieve(ZIPBALL_PAGE)[0]

                        with zipfile.ZipFile(archive) as f:
                            for info in f.infolist():
                                info.filename = re.sub(r"\Asqlmap[^/]+", "", info.filename)
                                if info.filename:
                                    f.extract(info, directory)

                        filepath = os.path.join(paths.SQLMAP_ROOT_PATH, "lib", "core", "settings.py")
                        if os.path.isfile(filepath):
                            with open(filepath, "rb") as f:
                                version = re.search(r"(?m)^VERSION\s*=\s*['\"]([^'\"]+)", f.read()).group(1)
                                logger.info("updated to the latest version '%s#dev'" % version)
                                success = True
                    except Exception, ex:
                        logger.error("update could not be completed ('%s')" % getSafeExString(ex))
                    else:
                        if not success:
                            logger.error("update could not be completed")
                        else:
                            try:
                                os.chmod(os.path.join(directory, "sqlmap.py"), attrs)
                            except OSError:
                                logger.warning("could not set the file attributes of '%s'" % os.path.join(directory, "sqlmap.py"))
    else:
        infoMsg = "updating sqlmap to the latest development revision from the "
        infoMsg += "GitHub repository"
        logger.info(infoMsg)

        debugMsg = "sqlmap will try to update itself using 'git' command"
        logger.debug(debugMsg)

        dataToStdout("\r[%s] [INFO] update in progress " % time.strftime("%X"))

        try:
            process = subprocess.Popen("git checkout . && git pull %s HEAD" % GIT_REPOSITORY, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=paths.SQLMAP_ROOT_PATH.encode(sys.getfilesystemencoding() or UNICODE_ENCODING))
            pollProcess(process, True)
            stdout, stderr = process.communicate()
            success = not process.returncode
        except (IOError, OSError), ex:
            success = False
            stderr = getSafeExString(ex)

        if success:
            logger.info("%s the latest revision '%s'" % ("already at" if "Already" in stdout else "updated to", getRevisionNumber()))
        else:
            if "Not a git repository" in stderr:
                errMsg = "not a valid git repository. Please checkout the 'sqlmapproject/sqlmap' repository "
                errMsg += "from GitHub (e.g. 'git clone --depth 1 %s sqlmap')" % GIT_REPOSITORY
                logger.error(errMsg)
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
            infoMsg = "for Linux platform it's recommended "
            infoMsg += "to install a standard 'git' package (e.g.: 'sudo apt-get install git')"

        logger.info(infoMsg)
