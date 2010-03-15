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

import difflib
import os
import re
import shutil
import sys
import tempfile
import time
import urlparse
import zipfile

from distutils.dir_util import mkpath
from xml.dom.minidom import Document

from subprocess import PIPE
from subprocess import Popen as execute

from lib.core.common import dataToStdout
from lib.core.common import pollProcess
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapFilePathException
from lib.core.settings import MSSQL_VERSIONS_URL
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
            if servicePack.startswith("+"):
                servicePack = "0%s" % servicePack

            servicePack = servicePack.replace("\t", " ")
            servicePack = servicePack.replace("  ", " ")
            servicePack = servicePack.replace("No SP", "0")
            servicePack = servicePack.replace("RTM", "0")
            servicePack = servicePack.replace("SP", "")
            servicePack = servicePack.replace("Service Pack", "")
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

def __updateSqlmap():
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
            action = str(event_dict['action'])
            index = action.find('_')
            prefix = action[index + 1].upper() if index != -1 else action.capitalize()

            if action.find('_update') != -1:
                return

            if action.find('_completed') == -1:
                print "%s\t%s" % (prefix, event_dict['path'])
            else:
                revision = str(event_dict['revision'])
                index = revision.find('number ')

                if index != -1:
                    revision = revision[index+7:].strip('>')

                logger.info('updated to the latest revision %s' % revision)

        client = pysvn.Client()
        client.callback_notify = notify
        client.update(rootDir)
    except ImportError, _:
        debugMsg = "sqlmap will try to update itself using 'svn' command"
        logger.debug(debugMsg)

        process = execute("svn update %s" % rootDir, shell=True, stdout=PIPE, stderr=PIPE)

        dataToStdout("\r[%s] [INFO] update in progress " % time.strftime("%X"))
        pollProcess(process)
        svnStdout, svnStderr = process.communicate()

        if svnStderr:
            errMsg = svnStderr.strip()
            logger.error(errMsg)
        elif svnStdout:
            revision = re.search("revision\s+([\d]+)", svnStdout, re.I)
            if revision:
                logger.info('updated to the latest revision %s' % revision.group(1))

def update():
    if not conf.updateAll:
        return

    __updateSqlmap()
    __updateMSSQLXML()
