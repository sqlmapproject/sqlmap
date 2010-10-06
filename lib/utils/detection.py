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

import re
import sre_constants

from lib.core.common import getCompiledRegex
from lib.core.common import readXmlFile
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

def checkPayload(string):
    """
    This method checks if the generated payload is detectable by the
    PHPIDS filter rules
    """

    global rules

    if not rules:
        xmlrules = readXmlFile(paths.DETECTION_RULES_XML)
        rules = []

        for xmlrule in xmlrules.getElementsByTagName("filter"):
            try:
                rule = "(?i)%s" % xmlrule.getElementsByTagName('rule')[0].childNodes[0].nodeValue
                desc = __adjustGrammar(xmlrule.getElementsByTagName('description')[0].childNodes[0].nodeValue)
                rules.append((rule, desc))
            except sre_constants.error: # Some issues with some regex expressions in Python 2.5
                pass
    
    for rule, desc in rules:
        regObj = getCompiledRegex(rule)

        if regObj.search(string):
            logger.warn("highly probable IDS/IPS detection: '%s'" % desc)
