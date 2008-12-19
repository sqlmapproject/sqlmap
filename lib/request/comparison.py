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


def comparison(page, headers=None, content=False):
    regExpResults = None

    # String to be excluded before calculating page hash
    if conf.eString and conf.eString in page:
        index              = page.index(conf.eString)
        length             = len(conf.eString)
        pageWithoutString  = page[:index]
        pageWithoutString += page[index+length:]
        page               = pageWithoutString

    # Regular expression matches to be excluded before calculating page hash
    if conf.eRegexp:
        regExpResults = re.findall(conf.eRegexp, page, re.I | re.M)

        if regExpResults:
            for regExpResult in regExpResults:
                index              = page.index(regExpResult)
                length             = len(regExpResult)
                pageWithoutRegExp  = page[:index]
                pageWithoutRegExp += page[index+length:]
                page               = pageWithoutRegExp

    # String to match in page when the query is valid
    if conf.string:
        if conf.string in page:
            return True
        else:
            return False

    # Regular expression to match in page when the query is valid
    if conf.regexp:
        if re.search(conf.regexp, page, re.I | re.M):
            return True
        else:
            return False

    # By default it returns the page content MD5 hash
    if not conf.equalLines and not conf.pageLengths:
        return md5.new(page).hexdigest()

    # Comparison algorithm based on page length value
    elif conf.pageLengths:
        minValue = conf.pageLengths[0]
        maxValue = conf.pageLengths[1]

        if len(page) >= minValue and len(page) <= maxValue:
            return True

    # Comparison algorithm based on page content's stable lines subset
    elif conf.equalLines:
        counter   = 0
        trueLines = 0
        pageLines = page.split("\n")

        for commonLine in conf.equalLines:
            if counter >= len(pageLines):
                break

            if commonLine in pageLines:
                trueLines += 1

            counter += 1

        # TODO: just debug prints
        #print "trueLines:", trueLines, "len(conf.equalLines):", len(conf.equalLines)
        #print "result:", ( trueLines * 100 ) / len(conf.equalLines)

        if ( trueLines * 100 ) / len(conf.equalLines) >= 98:
            return True
        else:
            return False
