#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import re

from xml.etree import ElementTree as et

from lib.core.common import getSafeExString
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import paths
from lib.core.datatype import AttribDict
from lib.core.exception import SqlmapInstallationException
from lib.core.settings import PAYLOAD_XML_FILES

def cleanupVals(text, tag):
    if tag == "clause" and '-' in text:
        text = re.sub(r"(\d+)-(\d+)", lambda match: ','.join(str(_) for _ in xrange(int(match.group(1)), int(match.group(2)) + 1)), text)

    if tag in ("clause", "where"):
        text = text.split(',')

    if hasattr(text, "isdigit") and text.isdigit():
        text = int(text)

    elif isinstance(text, list):
        count = 0

        for _ in text:
            text[count] = int(_) if _.isdigit() else _
            count += 1

        if len(text) == 1 and tag not in ("clause", "where"):
            text = text[0]

    return text

def parseXmlNode(node):
    for element in node.findall("boundary"):
        boundary = AttribDict()

        for child in element:
            if child.text:
                values = cleanupVals(child.text, child.tag)
                boundary[child.tag] = values
            else:
                boundary[child.tag] = None

        conf.boundaries.append(boundary)

    for element in node.findall("test"):
        test = AttribDict()

        for child in element:
            if child.text and child.text.strip():
                values = cleanupVals(child.text, child.tag)
                test[child.tag] = values
            else:
                if len(child.findall("*")) == 0:
                    test[child.tag] = None
                    continue
                else:
                    test[child.tag] = AttribDict()

                for gchild in child:
                    if gchild.tag in test[child.tag]:
                        prevtext = test[child.tag][gchild.tag]
                        test[child.tag][gchild.tag] = [prevtext, gchild.text]
                    else:
                        test[child.tag][gchild.tag] = gchild.text

        conf.tests.append(test)

def loadBoundaries():
    """
    Loads boundaries from XML

    >>> conf.boundaries = []
    >>> loadBoundaries()
    >>> len(conf.boundaries) > 0
    True
    """

    try:
        doc = et.parse(paths.BOUNDARIES_XML)
    except Exception as ex:
        errMsg = "something appears to be wrong with "
        errMsg += "the file '%s' ('%s'). Please make " % (paths.BOUNDARIES_XML, getSafeExString(ex))
        errMsg += "sure that you haven't made any changes to it"
        raise SqlmapInstallationException(errMsg)

    root = doc.getroot()
    parseXmlNode(root)

def loadPayloads():
    """
    Loads payloads/tests from XML

    >>> conf.tests = []
    >>> loadPayloads()
    >>> len(conf.tests) > 0
    True
    """

    for payloadFile in PAYLOAD_XML_FILES:
        payloadFilePath = os.path.join(paths.SQLMAP_XML_PAYLOADS_PATH, payloadFile)

        try:
            doc = et.parse(payloadFilePath)
        except Exception as ex:
            errMsg = "something appears to be wrong with "
            errMsg += "the file '%s' ('%s'). Please make " % (payloadFilePath, getSafeExString(ex))
            errMsg += "sure that you haven't made any changes to it"
            raise SqlmapInstallationException(errMsg)

        root = doc.getroot()
        parseXmlNode(root)
