#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import re
import tempfile

from lib.core.common import openFile
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapGenericException
from thirdparty import six
from thirdparty.six.moves import urllib as _urllib


def createTemplate():
    handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.AUTH_REFRESH, suffix=".py")
    os.close(handle)

    with openFile(filename, "w+") as f:
        f.write("#!/usr/bin/env\n\ndef refresh():\n    # Obtain a fresh token here (use a timeout for login requests).\n    # Custom headers also work, e.g. {'X-Auth-Token': token}.\n    return {'Authorization': 'Bearer <fresh token>'}\n")
    with openFile(os.path.join(os.path.dirname(filename), "__init__.py"), "w+") as f:
        f.write("pass")

    return filename


def sameOrigin(first, second):
    # checkSameHost deliberately ignores schemes and ports, which is unsuitable for credentials.
    def origin(url):
        parts = _urllib.parse.urlsplit(url)
        return parts.scheme.lower(), parts.hostname, parts.port or (443 if parts.scheme.lower() == "https" else 80)

    return origin(first) == origin(second)


def apply(req):
    """Overlay refreshed headers after preprocess hooks; return the credential generation sent."""

    if not conf.authRefresh or not sameOrigin(req.get_full_url(), conf.url):
        return None

    with kb.locks.authRefresh:
        if kb.authRefreshFailed:
            raise SqlmapGenericException("authentication refresh failed; cannot continue with expired credentials")
        for name, value in kb.authRefreshHeaders.items():
            # Hooks/raw request files can leave differently-cased copies of the same header.
            for headers in (req.headers, req.unredirected_hdrs):
                for key in list(headers):
                    if key.lower() == name.lower():
                        del headers[key]
            req.add_header(name, value)
        return kb.authRefreshVersion


def refresh(version):
    """Refresh once for all workers that sent the same expired credentials."""

    with kb.locks.authRefresh:
        if kb.authRefreshFailed:
            raise SqlmapConnectionException("authentication refresh failed; cannot continue with expired credentials")
        if version != kb.authRefreshVersion:
            return

        logger.info("refreshing authentication after HTTP 401")
        try:
            headers = kb.authRefreshFunction()
            if not isinstance(headers, dict) or not headers:
                raise ValueError()
            for name, value in headers.items():
                if not isinstance(name, six.string_types) or not re.match(r"\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z", name):
                    raise ValueError()
                if not isinstance(value, six.string_types) or not value or re.search(r"[\x00-\x1f\x7f]", value):
                    raise ValueError()
                value.encode("latin-1")
                if name.lower() in ("host", "content-length", "transfer-encoding", "connection", "proxy-authorization"):
                    raise ValueError()
            if len(set(_.lower() for _ in headers)) != len(headers):
                raise ValueError()
        except Exception:
            kb.authRefreshFailed = True
            # Hook exceptions can contain tokens/passwords; do not include their text.
            raise SqlmapConnectionException("auth refresh hook failed or returned invalid headers. Expected a non-empty dictionary of authentication headers. You can find a template script at '%s'" % createTemplate())

        kb.authRefreshHeaders = dict(headers)
        kb.authRefreshVersion += 1


def stripHeaders(headers):
    """Remove refreshed credentials before following a redirect to another origin."""

    names = set(_.lower() for _ in kb.authRefreshHeaders)
    return dict((name, value) for name, value in headers.items() if name.lower() not in names)
