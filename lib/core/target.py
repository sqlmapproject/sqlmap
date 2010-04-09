#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

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

import os
import time

from lib.core.common import dataToSessionFile
from lib.core.common import paramToDict
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.dump import dumper
from lib.core.exception import sqlmapFilePathException
from lib.core.exception import sqlmapGenericException
from lib.core.exception import sqlmapSyntaxException
from lib.core.session import resumeConfKb

def __setRequestParams():
    """
    Check and set the parameters and perform checks on 'data' option for
    HTTP method POST.
    """

    if conf.direct:
        conf.parameters[None] = "direct connection"
        return

    __testableParameters = False

    # Perform checks on GET parameters
    if conf.parameters.has_key("GET") and conf.parameters["GET"]:
        parameters = conf.parameters["GET"]
        __paramDict = paramToDict("GET", parameters)

        if __paramDict:
            conf.paramDict["GET"] = __paramDict
            __testableParameters = True

    # Perform checks on POST parameters
    if conf.method == "POST" and not conf.data:
        errMsg = "HTTP POST method depends on HTTP data value to be posted"
        raise sqlmapSyntaxException, errMsg

    if conf.data:
        conf.parameters["POST"] = conf.data
        __paramDict = paramToDict("POST", conf.data)

        if __paramDict:
            conf.paramDict["POST"] = __paramDict
            __testableParameters = True

        conf.method = "POST"

    # Perform checks on Cookie parameters
    if conf.cookie:
        conf.parameters["Cookie"] = conf.cookie
        __paramDict = paramToDict("Cookie", conf.cookie)

        if __paramDict:
            conf.paramDict["Cookie"] = __paramDict
            __testableParameters = True

    # Perform checks on User-Agent header value
    if conf.httpHeaders:
        for httpHeader, headerValue in conf.httpHeaders:
            if httpHeader == "User-Agent":
                # No need for url encoding/decoding the user agent
                conf.parameters["User-Agent"] = headerValue

                condition  = not conf.testParameter
                condition |= "User-Agent" in conf.testParameter
                condition |= "user-agent" in conf.testParameter
                condition |= "useragent" in conf.testParameter
                condition |= "ua" in conf.testParameter

                if condition:
                    conf.paramDict["User-Agent"] = { "User-Agent": headerValue }
                    __testableParameters = True

    if not conf.parameters:
        errMsg  = "you did not provide any GET, POST and Cookie "
        errMsg += "parameter, neither an User-Agent header"
        raise sqlmapGenericException, errMsg

    elif not __testableParameters:
        errMsg  = "all testable parameters you provided are not present "
        errMsg += "within the GET, POST and Cookie parameters"
        raise sqlmapGenericException, errMsg

def __setOutputResume():
    """
    Check and set the output text file and the resume functionality.
    """

    if not conf.sessionFile:
        conf.sessionFile = "%s%ssession" % (conf.outputPath, os.sep)

    logger.info("using '%s' as session file" % conf.sessionFile)

    if os.path.exists(conf.sessionFile):
        if not conf.flushSession:
            readSessionFP = open(conf.sessionFile, "r")
            lines = readSessionFP.readlines()
    
            for line in lines:
                if line.count("][") == 4:
                    line = line.split("][")
    
                    if len(line) != 5:
                        continue
    
                    url, _, _, expression, value = line
    
                    if not value:
                        continue
    
                    if url[0] == "[":
                        url = url[1:]
    
                    if value[-1] == "\n":
                        value = value[:-1]
    
                    if url != conf.url:
                        continue
    
                    if url not in kb.resumedQueries.keys():
                        kb.resumedQueries[url] = {}
                        kb.resumedQueries[url][expression] = value
    
                    resumeConfKb(expression, url, value)
    
                    if expression not in kb.resumedQueries[url].keys():
                        kb.resumedQueries[url][expression] = value
                    elif len(value) >= len(kb.resumedQueries[url][expression]):
                        kb.resumedQueries[url][expression] = value
    
            readSessionFP.close()
        else:
            try:
                os.remove(conf.sessionFile)
                logger.info("flushing session file")
            except OSError, msg:
                errMsg = "unable to flush the session file (%s)" % msg
                raise sqlmapFilePathException, errMsg

    try:
        conf.sessionFP = open(conf.sessionFile, "a")
        dataToSessionFile("\n[%s]\n" % time.strftime("%X %x"))
    except IOError:
        errMsg = "unable to write on the session file specified"
        raise sqlmapFilePathException, errMsg

def __createFilesDir():
    """
    Create the file directory.
    """

    if not conf.rFile:
        return

    conf.filePath = paths.SQLMAP_FILES_PATH % conf.hostname

    if not os.path.isdir(conf.filePath):
        os.makedirs(conf.filePath, 0755)

def __createDumpDir():
    """
    Create the dump directory.
    """

    if not conf.dumpTable and not conf.dumpAll:
        return

    conf.dumpPath = paths.SQLMAP_DUMP_PATH % conf.hostname

    if not os.path.isdir(conf.dumpPath):
        os.makedirs(conf.dumpPath, 0755)

def __createTargetDirs():
    """
    Create the output directory.
    """

    conf.outputPath = "%s%s%s" % (paths.SQLMAP_OUTPUT_PATH, os.sep, conf.hostname)

    if not os.path.isdir(paths.SQLMAP_OUTPUT_PATH):
        os.makedirs(paths.SQLMAP_OUTPUT_PATH, 0755)

    if not os.path.isdir(conf.outputPath):
        os.makedirs(conf.outputPath, 0755)

    dumper.setOutputFile()

    __createDumpDir()
    __createFilesDir()

def initTargetEnv():
    """
    Initialize target environment.
    """

    if conf.multipleTargets:
        if conf.cj:
            conf.cj.clear()

        conf.paramDict    = {}
        conf.parameters   = {}
        conf.sessionFile  = None

        kb.dbms           = None
        kb.dbmsDetected   = False
        kb.dbmsVersion    = [ "Unknown" ]
        kb.injParameter   = None
        kb.injPlace       = None
        kb.injType        = None
        kb.parenthesis    = None
        kb.unionComment   = ""
        kb.unionCount     = None
        kb.unionPosition  = None

def setupTargetEnv():
    __createTargetDirs()
    __setRequestParams()
    __setOutputResume()
