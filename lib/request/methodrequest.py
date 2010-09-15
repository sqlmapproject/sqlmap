#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2010 Miroslav Stampar <miroslav.stampar@gmail.com>

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


class MethodRequest(urllib2.Request):
    ''' Used to create HEAD/PUT/DELETE/... requests with urllib2 '''
    def set_method(self, method):
        self.method = method.upper()
    def get_method(self):
        return getattr(self, 'method', urllib2.Request.get_method(self))
