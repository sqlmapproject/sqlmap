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

import urllib2

from lib.core.exception import sqlmapConnectionException

class SmartRedirectHandler(urllib2.HTTPRedirectHandler):
    # maximum number of redirections to any single URL
    # this is needed because of the state that cookies introduce
    max_repeats = 4

    # maximum total number of redirections (regardless of URL) before
    # assuming we're in a loop
    max_redirections = 10

    def common_http_redirect(self, result, headers, code):
        if "location" in headers:
            result.redurl = headers.getheaders("location")[0].split("?")[0]
        elif "uri" in headers:
            result.redurl = headers.getheaders("uri")[0].split("?")[0]

        result.redcode = code

        return result

    def http_error_301(self, req, fp, code, msg, headers):
        self.infinite_loop_check(req)
        result = urllib2.HTTPRedirectHandler.http_error_301(self, req, fp, code, msg, headers)
        return self.common_http_redirect(result, headers, code)

    def http_error_302(self, req, fp, code, msg, headers):
        self.infinite_loop_check(req)
        result = urllib2.HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)
        return self.common_http_redirect(result, headers, code)

    def infinite_loop_check(self, req):
        if hasattr(req, 'redirect_dict') and (req.redirect_dict.get(req.get_full_url(), 0) >= self.max_repeats or len(req.redirect_dict) >= self.max_redirections):
            errMsg  = "infinite redirect loop detected (%s). " % ", ".join(item for item in req.redirect_dict.keys())
            errMsg += "please check all provided parameters and/or provide missing ones."
            raise sqlmapConnectionException, errMsg
