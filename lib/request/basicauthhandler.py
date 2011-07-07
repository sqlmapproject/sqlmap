#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import urllib2

class SmartHTTPBasicAuthHandler(urllib2.HTTPBasicAuthHandler):
    """
    Reference: http://selenic.com/hg/rev/6c51a5056020
    Fix for a: http://bugs.python.org/issue8797
    """
    def __init__(self, *args, **kwargs):
        urllib2.HTTPBasicAuthHandler.__init__(self, *args, **kwargs)
        self.retried_req = set()
        self.retried_count = 0

    def reset_retry_count(self):
        # Python 2.6.5 will call this on 401 or 407 errors and thus loop
        # forever. We disable reset_retry_count completely and reset in
        # http_error_auth_reqed instead.
        pass

    def http_error_auth_reqed(self, auth_header, host, req, headers):
        # Reset the retry counter once for each request.
        if hash(req) not in self.retried_req:
            self.retried_req.add(hash(req))
            self.retried_count = 0
        else:
            if self.retried_count > 5:
                raise urllib2.HTTPError(req.get_full_url(), 401, "basic auth failed",
                                headers, None)
            else:
                self.retried_count += 1

        return urllib2.HTTPBasicAuthHandler.http_error_auth_reqed(
                        self, auth_header, host, req, headers)
