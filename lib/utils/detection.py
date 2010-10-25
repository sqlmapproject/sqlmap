#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import sre_constants

from lib.core.common import getCompiledRegex
from lib.core.common import readXmlFile
from lib.core.convert import urldecode
from lib.core.data import conf
from lib.core.data import paths
from lib.core.data import logger


rules = None

def __adjustGrammar(string):
    string = re.sub('\ADetects', 'Detected', string)
    string = re.sub('\Afinds', 'Found', string)
    string = re.sub('attempts\Z', 'attempt', string)
    string = re.sub('injections\Z', 'injection', string)
    string = re.sub('attacks\Z', 'attack', string)

    return string

def checkPayload(payload):
    """
    This method checks if the generated payload is detectable by the
    PHPIDS filter rules
    """

    global rules

    payload = urldecode(payload)

    if not rules:
        xmlrules = readXmlFile(paths.DETECTION_RULES_XML)
        rules = []

        for xmlrule in xmlrules.getElementsByTagName("filter"):
            rule = "(?i)%s" % xmlrule.getElementsByTagName('rule')[0].childNodes[0].nodeValue
            desc = __adjustGrammar(xmlrule.getElementsByTagName('description')[0].childNodes[0].nodeValue)
            rules.append((rule, desc))

    if payload:
        for rule, desc in rules:
            try:
                regObj = getCompiledRegex(rule)
                if regObj.search(payload):
                    logger.warn("highly probable IDS/IPS detection: '%s: %s'" % (desc, payload))
            except: # Some issues with some regex expressions in Python 2.5
                pass
