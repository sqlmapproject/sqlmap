#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
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



import difflib
import os
import re
import shutil
import sys
import tempfile
import urlparse
import zipfile

from distutils.dir_util import mkpath
from xml.dom.minidom import Document

from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapFilePathException
from lib.core.settings import MSSQL_VERSIONS_URL
from lib.core.settings import SQLMAP_VERSION_URL
from lib.core.settings import SQLMAP_SOURCE_URL
from lib.core.settings import VERSION
from lib.request.connect import Connect as Request


def __updateMSSQLXML():
    infoMsg = "updating Microsoft SQL Server XML versions file"
    logger.info(infoMsg)

    try:
        mssqlVersionsHtmlString, _ = Request.getPage(url=MSSQL_VERSIONS_URL, direct=True)
    except sqlmapConnectionException, _:
        __mssqlPath     = urlparse.urlsplit(MSSQL_VERSIONS_URL)
        __mssqlHostname = __mssqlPath[1]

        warnMsg  = "sqlmap was unable to connect to %s," % __mssqlHostname
        warnMsg += " check your Internet connection and retry"
        logger.warn(warnMsg)

        return

    releases      = re.findall("class=\"BCC_DV_01DarkBlueTitle\">SQL Server ([\d\.]+) Builds", mssqlVersionsHtmlString, re.I | re.M)
    releasesCount = len(releases)

    # Create the minidom document
    doc = Document()

    # Create the <root> base element
    root = doc.createElement("root")
    doc.appendChild(root)

    for index in range(0, releasesCount):
        release = releases[index]

        # Skip Microsoft SQL Server 6.5 because the HTML
        # table is in another format
        if release == "6.5":
            continue

        # Create the <signatures> base element
        signatures = doc.createElement("signatures")
        signatures.setAttribute("release", release)
        root.appendChild(signatures)

        startIdx = mssqlVersionsHtmlString.index("SQL Server %s Builds" % releases[index])

        if index == releasesCount - 1:
            stopIdx  = len(mssqlVersionsHtmlString)
        else:
            stopIdx  = mssqlVersionsHtmlString.index("SQL Server %s Builds" % releases[index + 1])

        mssqlVersionsReleaseString = mssqlVersionsHtmlString[startIdx:stopIdx]
        servicepackVersion = re.findall("</td><td>[7\.0|2000|2005|2008]*(.*?)</td><td.*?([\d\.]+)</td>[\r]*\n", mssqlVersionsReleaseString, re.I | re.M)

        for servicePack, version in servicepackVersion:
            if servicePack.startswith(" "):
                servicePack = servicePack[1:]
            if "/" in servicePack:
                servicePack = servicePack[:servicePack.index("/")]
            if "(" in servicePack:
                servicePack = servicePack[:servicePack.index("(")]
            if "-" in servicePack:
                servicePack = servicePack[:servicePack.index("-")]
            if "*" in servicePack:
                servicePack = servicePack[:servicePack.index("*")]

            servicePack = servicePack.replace("\t", " ")
            servicePack = servicePack.replace("  ", " ")
            servicePack = servicePack.replace("No SP", "0")
            servicePack = servicePack.replace("RTM", "0")
            servicePack = servicePack.replace("SP", "")
            servicePack = servicePack.replace("<a href=\"http:", "")

            if servicePack.endswith(" "):
                servicePack = servicePack[:-1]

            if servicePack and version:
                # Create the main <card> element
                signature = doc.createElement("signature")
                signatures.appendChild(signature)

                # Create a <version> element
                versionElement = doc.createElement("version")
                signature.appendChild(versionElement)

                # Give the <version> elemenet some text
                versionText = doc.createTextNode(version)
                versionElement.appendChild(versionText)

                # Create a <servicepack> element
                servicepackElement = doc.createElement("servicepack")
                signature.appendChild(servicepackElement)

                # Give the <servicepack> elemenet some text
                servicepackText = doc.createTextNode(servicePack)
                servicepackElement.appendChild(servicepackText)

    # Get the XML old file content to a local variable
    mssqlXml = open(paths.MSSQL_XML, "r")
    oldMssqlXml = mssqlXml.read()
    oldMssqlXmlSignatures = oldMssqlXml.count("<signature>")
    oldMssqlXmlList = oldMssqlXml.splitlines(1)
    mssqlXml.close()

    # Backup the XML old file
    shutil.copy(paths.MSSQL_XML, "%s.bak" % paths.MSSQL_XML)

    # Save our newly created XML to the signatures file
    mssqlXml = open(paths.MSSQL_XML, "w")
    doc.writexml(writer=mssqlXml, addindent="    ", newl="\n")
    mssqlXml.close()

    # Get the XML new file content to a local variable
    mssqlXml = open(paths.MSSQL_XML, "r")
    newMssqlXml = mssqlXml.read()
    newMssqlXmlSignatures = newMssqlXml.count("<signature>")
    newMssqlXmlList = newMssqlXml.splitlines(1)
    mssqlXml.close()

    # If the new XML versions file differs from the old one it probably
    # means that we have got new Microsoft SQL Server versions
    if oldMssqlXmlSignatures != newMssqlXmlSignatures:
        infoMsg  = "Microsoft SQL Server XML versions file updated successfully. "

        if oldMssqlXmlSignatures < newMssqlXmlSignatures:
            infoMsg += "%d " % (newMssqlXmlSignatures - oldMssqlXmlSignatures)
            infoMsg += "new signatures added since the last update"

        # NOTE: This should never happen, in this rare case it might
        # be that the Microsoft SQL Server versions database
        # (MSSQL_VERSIONS_URL) changed its structure
        else:
            infoMsg += "%d " % (oldMssqlXmlSignatures - newMssqlXmlSignatures)
            infoMsg += "signatures removed since the last update"

        logger.info(infoMsg)

        message = "Do you want to see the differences? [Y/n] "
        test = readInput(message, default="Y")

        if not test or test[0] in ("y", "Y"):
            infoMsg = "Differences:"
            logger.info(infoMsg)

            # Compare the old XML file with the new one
            diff = difflib.unified_diff(oldMssqlXmlList, newMssqlXmlList, "%s.bak" % paths.MSSQL_XML, paths.MSSQL_XML)
            sys.stdout.writelines(diff)
    else:
        infoMsg  = "no new Microsoft SQL Server versions since the "
        infoMsg += "last update"
        logger.info(infoMsg)


def __createFile(pathname, data):
    mkpath(os.path.dirname(pathname))

    fileFP = open(pathname, "wb")
    fileFP.write(data)
    fileFP.close()


def __extractZipFile(tempDir, zipFile, sqlmapNewestVersion):
    # Check if the saved binary file is really a ZIP file
    if zipfile.is_zipfile(zipFile):
        sqlmapZipFile = zipfile.ZipFile(zipFile)
    else:
        raise sqlmapFilePathException, "the downloaded file does not seem to be a ZIP file"

    # Extract each file within the ZIP file in the temporary directory
    for info in sqlmapZipFile.infolist():
        if info.filename[-1] != '/':
            data = sqlmapZipFile.read(info.filename)
            __createFile(os.path.join(tempDir, info.filename), data)


def __updateSqlmap():
    infoMsg = "updating sqlmap"
    logger.info(infoMsg)

    debugMsg = "checking if a new version is available"
    logger.debug(debugMsg)

    try:
        sqlmapNewestVersion, _ = Request.getPage(url=SQLMAP_VERSION_URL, direct=True)
    except sqlmapConnectionException, _:
        __sqlmapPath     = urlparse.urlsplit(SQLMAP_VERSION_URL)
        __sqlmapHostname = __sqlmapPath[1]

        warnMsg  = "sqlmap was unable to connect to %s" % __sqlmapHostname
        warnMsg += ", check your Internet connection and retry"
        logger.warn(warnMsg)

        return

    sqlmapNewestVersion = str(sqlmapNewestVersion).replace("\n", "")

    if not re.search("^([\w\.\-]+)$", sqlmapNewestVersion):
        errMsg = "sqlmap version is in a wrong syntax"
        logger.error(errMsg)

        return

    if sqlmapNewestVersion == VERSION:
        infoMsg = "you are already running sqlmap latest stable version"
        logger.info(infoMsg)

        return

    elif sqlmapNewestVersion > VERSION:
        infoMsg  = "sqlmap latest stable version is %s. " % sqlmapNewestVersion
        infoMsg += "Going to download it from the SourceForge File List page"
        logger.info(infoMsg)

    elif sqlmapNewestVersion < VERSION:
        infoMsg  = "you are running a version of sqlmap more updated than "
        infoMsg += "the latest stable version (%s)" % sqlmapNewestVersion
        logger.info(infoMsg)

        return

    sqlmapBinaryStringUrl = SQLMAP_SOURCE_URL % sqlmapNewestVersion

    try:
        sqlmapBinaryString, _ = Request.getPage(url=sqlmapBinaryStringUrl, direct=True)
    except sqlmapConnectionException, _:
        __sqlmapPath     = urlparse.urlsplit(sqlmapBinaryStringUrl)
        __sqlmapHostname = __sqlmapPath[1]

        warnMsg  = "sqlmap was unable to connect to %s" % __sqlmapHostname
        warnMsg += ", check your Internet connection and retry"
        logger.warn(warnMsg)

        return

    debugMsg  = 'saving the sqlmap compressed source to a ZIP file into '
    debugMsg += 'the temporary directory and extract it'
    logger.debug(debugMsg)

    tempDir = tempfile.gettempdir()
    zipFile = os.path.join(tempDir, "sqlmap-%s.zip" % sqlmapNewestVersion)
    __createFile(zipFile, sqlmapBinaryString)
    __extractZipFile(tempDir, zipFile, sqlmapNewestVersion)

    # For each file and directory in the temporary directory copy it
    # to the sqlmap root path and set right permission
    # TODO: remove files not needed anymore and all pyc within the
    # sqlmap root path in the end
    for root, dirs, files in os.walk(os.path.join(tempDir, "sqlmap-%s" % sqlmapNewestVersion)):
        # Just for development release
        if '.svn' in root:
            continue

        cleanRoot = root.replace(tempDir, "")
        cleanRoot = cleanRoot.replace("%ssqlmap-%s" % (os.sep, sqlmapNewestVersion), "")

        if cleanRoot.startswith(os.sep):
            cleanRoot = cleanRoot[1:]

        for f in files:
            # Just for development release
            if f.endswith(".pyc") or f.endswith(".pyo"):
                continue

            srcFile = os.path.join(root, f)
            dstFile = os.path.join(paths.SQLMAP_ROOT_PATH, os.path.join(cleanRoot, f))

            if f == "sqlmap.conf" and os.path.exists(dstFile):
                infoMsg = "backupping configuration file to '%s.bak'" % dstFile
                logger.info(infoMsg)
                shutil.move(dstFile, "%s.bak" % dstFile)

            if os.path.exists(dstFile):
                debugMsg = "replacing file '%s'" % dstFile
            else:
                debugMsg = "creating new file '%s'" % dstFile

            logger.debug(debugMsg)

            mkpath(os.path.dirname(dstFile))
            shutil.copy(srcFile, dstFile)

            if f.endswith(".py"):
                os.chmod(dstFile, 0755)

    infoMsg = "sqlmap updated successfully"
    logger.info(infoMsg)


def update():
    if not conf.updateAll:
        return

    __updateSqlmap()
    __updateMSSQLXML()
