#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import difflib
import os
import re
import sys
import urllib2
import urlparse

from xml.dom.minidom import Document

# Path to the XML file with signatures
MSSQL_XML = os.path.abspath("../../xml/banner/mssql.xml")

# Url to update Microsoft SQL Server XML versions file from
MSSQL_VERSIONS_URL = "http://www.sqlsecurity.com/FAQs/SQLServerVersionDatabase/tabid/63/Default.aspx"

def updateMSSQLXML():
    if not os.path.exists(MSSQL_XML):
        errMsg = "[ERROR] file '%s' does not exist. please run the script from it's parent directory." % MSSQL_XML
        print errMsg
        return

    infoMsg = "[INFO] retrieving data from '%s'" % MSSQL_VERSIONS_URL
    print infoMsg

    try:
        req = urllib2.Request(MSSQL_VERSIONS_URL)
        f = urllib2.urlopen(req)
        mssqlVersionsHtmlString = f.read()
        f.close()
    except urllib2.URLError:
        __mssqlPath     = urlparse.urlsplit(MSSQL_VERSIONS_URL)
        __mssqlHostname = __mssqlPath[1]

        warnMsg  = "[WARNING] sqlmap was unable to connect to %s," % __mssqlHostname
        warnMsg += " check your Internet connection and retry"
        print warnMsg

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
            servicePack = servicePack.replace("No SP", "0")
            servicePack = servicePack.replace("RTM", "0")
            servicePack = servicePack.replace("SP", "")
            servicePack = servicePack.replace("Service Pack", "")
            servicePack = servicePack.replace("<a href=\"http:", "")
            servicePack = servicePack.replace("  ", " ")
            servicePack = servicePack.replace("+ ", "+")
            servicePack = servicePack.replace(" +", "+")

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

    # Save our newly created XML to the signatures file
    mssqlXml = codecs.open(MSSQL_XML, "w", "utf8")
    doc.writexml(writer=mssqlXml, addindent="    ", newl="\n")
    mssqlXml.close()

    infoMsg  = "[INFO] done. retrieved data parsed and saved into '%s'" % MSSQL_XML
    print infoMsg

if __name__ == "__main__":
    updateMSSQLXML()
