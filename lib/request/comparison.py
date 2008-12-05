#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2008 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

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



import md5
import re

from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger


def comparison(page, headers=None, content=False):
    regExpResults = None

    if conf.eString and conf.eString in page:
        index              = page.index(conf.eString)
        length             = len(conf.eString)
        pageWithoutString  = page[:index]
        pageWithoutString += page[index+length:]
        page               = pageWithoutString

    if conf.eRegexp:
        regExpResults = re.findall(conf.eRegexp, page, re.I | re.M)

    if conf.eRegexp and regExpResults:
        for regExpResult in regExpResults:
            index              = page.index(regExpResult)
            length             = len(regExpResult)
            pageWithoutRegExp  = page[:index]
            pageWithoutRegExp += page[index+length:]
            page               = pageWithoutRegExp

    if conf.string:
        if conf.string in page:
            return True
        else:
            return False

    elif conf.regexp:
        if re.search(conf.regexp, page, re.I | re.M):
            return True
        else:
            return False

    else:
        return md5.new(page).hexdigest()
