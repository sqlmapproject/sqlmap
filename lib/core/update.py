#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re
import shutil
import sys
import time

from distutils.dir_util import mkpath

from subprocess import PIPE
from subprocess import Popen as execute

from lib.core.common import dataToStdout
from lib.core.common import getUnicode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.exception import sqlmapFilePathException
from lib.core.settings import IS_WIN
from lib.core.settings import UNICODE_ENCODING
from lib.core.subprocessng import pollProcess
from lib.request.connect import Connect as Request

def update():
    if not conf.updateAll:
        return

    rootDir = paths.SQLMAP_ROOT_PATH

    infoMsg = "updating sqlmap to latest development version from the "
    infoMsg += "subversion repository"
    logger.info(infoMsg)

    try:
        import pysvn

        debugMsg = "sqlmap will update itself using installed python-svn "
        debugMsg += "third-party library, http://pysvn.tigris.org/"
        logger.debug(debugMsg)

        def notify(event_dict):
            action = getUnicode(event_dict['action'])
            index = action.find('_')
            prefix = action[index + 1].upper() if index != -1 else action.capitalize()

            if action.find('_update') != -1:
                return

            if action.find('_completed') == -1:
                dataToStdout("%s\t%s\n" % (prefix, event_dict['path']))
            else:
                revision = getUnicode(event_dict['revision'], UNICODE_ENCODING)
                index = revision.find('number ')

                if index != -1:
                    revision = revision[index+7:].strip('>')

                logger.info('updated to the latest revision %s' % revision)

        client = pysvn.Client()
        client.callback_notify = notify

        try:
            client.update(rootDir)
        except pysvn.ClientError, e:
            errMsg = "unable to update sqlmap from subversion: '%s'. " % str(e)
            errMsg += "You are strongly advised to checkout "
            errMsg += "the clean copy from repository manually "
            if IS_WIN:
                errMsg += "(e.g. Right click -> TortoiseSVN -> Checkout... and type "
                errMsg += "\"https://svn.sqlmap.org/sqlmap/trunk/sqlmap\" into field \"URL of repository\")"
            else:
                errMsg += "(e.g. \"svn checkout https://svn.sqlmap.org/sqlmap/trunk/sqlmap sqlmap-dev\")"
            logger.error(errMsg)

    except ImportError, _:
        debugMsg = "sqlmap will try to update itself using 'svn' command"
        logger.debug(debugMsg)

        dataToStdout("\r[%s] [INFO] update in progress " % time.strftime("%X"))
        process = execute("svn update %s" % rootDir, shell=True, stdout=PIPE)
        pollProcess(process)
        svnStdout, _ = process.communicate()

        if svnStdout:
            revision = re.search("revision\s+([\d]+)", svnStdout, re.I)

            if revision:
                logger.info('updated to the latest revision %s' % revision.group(1))

        if IS_WIN:
            infoMsg = "for Windows platform it's recommended "
            infoMsg += "to use a TortoiseSVN GUI client for updating "
            infoMsg += "purposes (http://tortoisesvn.net/downloads.html)"
            logger.info(infoMsg)
