#!/usr/bin/env python

"""
$Id: parenthesis.py 1003 2010-01-02 02:02:12Z inquisb $

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
import re
import urllib2
from xml.dom import minidom

from lib.core.data import logger

rules = None

def checkPayload(string):
    """
    This method checks if the generated payload is detectable by an PHPIDS filter rules
    """
    global rules

    if not rules:
        url = 'https://svn.phpids.org/svn/trunk/lib/IDS/default_filter.xml'
        request = urllib2.Request(url)
        response = urllib2.urlopen(request)
        xmlrules = minidom.parse(response).documentElement
        response.close()
        rules = []
        for xmlrule in xmlrules.getElementsByTagName("filter"):
            try:
                rule = re.compile(xmlrule.getElementsByTagName('rule')[0].childNodes[0].nodeValue)
                desc = xmlrule.getElementsByTagName('description')[0].childNodes[0].nodeValue
                desc = desc.replace('Detects', 'Detected').replace('finds', 'Found').replace('attempts', 'attempt').replace('injections', 'injection').replace('attacks', 'attack')
                rules.append((rule, desc))
            except:
                pass
    
    for rule, desc in rules:
        if rule.search(string, re.IGNORECASE):
            logger.warn("highly probable IDS/IPS detection: '%s'" % desc)
