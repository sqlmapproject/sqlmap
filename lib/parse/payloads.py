#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from xml.etree import ElementTree as et

from lib.core.data import conf
from lib.core.data import paths
from lib.core.datatype import advancedDict

def cleanupVals(values, tag):
    count = 0

    for value in values:
        if value.isdigit():
            value = int(value)
        else:
            value = str(value)

        values[count] = value
        count += 1

    if len(values) == 1 and tag not in ("clause", "where"):
        values = values[0]

    return values

def parseXmlNode(node):
    for element in node.getiterator('boundary'):
        boundary = advancedDict()

        for child in element.getchildren():
            if child.text:
                values = cleanupVals(child.text.split(','), child.tag)
                boundary[child.tag] = values
            else:
                boundary[child.tag] = None

        conf.boundaries.append(boundary)

    for element in node.getiterator('test'):
        test = advancedDict()

        for child in element.getchildren():
            if child.text and child.text.strip():
                values = cleanupVals(child.text.split(','), child.tag)
                test[child.tag] = values
            else:
                if len(child.getchildren()) == 0:
                    test[child.tag] = None
                    continue
                else:
                    test[child.tag] = advancedDict()

                for gchild in child.getchildren():
                    if gchild.tag in test[child.tag]:
                        prevtext = test[child.tag][gchild.tag]
                        test[child.tag][gchild.tag] = [prevtext, gchild.text]
                    else:
                        test[child.tag][gchild.tag] = gchild.text

        conf.tests.append(test)

def loadPayloads():
    doc = et.parse(paths.PAYLOADS_XML)
    root = doc.getroot()
    parseXmlNode(root)
