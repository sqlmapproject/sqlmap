#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from thirdparty.six.moves import urllib as _urllib

class SmartHTTPBasicAuthHandler(_urllib.request.HTTPBasicAuthHandler):
    """
    Reference: http://selenic.com/hg/rev/6c51a5056020
    Fix for a: http://bugs.python.org/issue8797
    """

    def __init__(self, *args, **kwargs):
        _urllib.request.HTTPBasicAuthHandler.__init__(self, *args, **kwargs)
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
                raise _urllib.error.HTTPError(req.get_full_url(), 401, "basic auth failed", headers, None)
            else:
                self.retried_count += 1

        return _urllib.request.HTTPBasicAuthHandler.http_error_auth_reqed(self, auth_header, host, req, headers)
