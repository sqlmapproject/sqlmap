#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# Native, dependency-free HTTP "Negotiate" (SPNEGO/Kerberos) authentication, built on the in-tree
# pure-Python Kerberos client (extra/kerberos). No 'pykerberos'/'gssapi'/'requests-kerberos' needed.
# The TGT and per-service tickets are obtained once and cached; a fresh AP-REQ is minted for every
# request from the cached ticket (as replay caches require), so an entire scan costs a single AS+TGS
# exchange and the token is sent pre-emptively (no extra 401 round-trip per request). Python 2.7 / 3.x.

import base64
import logging
import threading

from lib.core.common import getSafeExString
from lib.core.common import singleTimeLogMessage
from lib.core.convert import getText
from lib.core.enums import HTTP_HEADER
from thirdparty.six.moves import urllib as _urllib

from extra.kerberos.client import getServiceTicket
from extra.kerberos.client import getTGT
from extra.kerberos.client import KerberosError
from extra.kerberos.client import spnegoFromTicket
from extra.kerberos.discovery import discoverKdc

class HTTPNegotiateAuthHandler(_urllib.request.BaseHandler):
    handler_order = 480

    def __init__(self, realm, username, password, kdcHost=None, kdcPort=None):
        self.realm = realm.upper()
        self.username = username
        self.password = password
        self.kdcHost = kdcHost                             # None -> discovered from the realm on first use
        self.kdcPort = kdcPort
        self._tgt = None
        self._tickets = {}                                 # target host -> service-ticket dict
        self._tgtFailure = None                            # realm-wide failure (bad creds / KDC down)
        self._hostFailures = {}                            # per-host failure (e.g. no HTTP/<host> SPN)
        self._lock = threading.Lock()

    def _serviceTicket(self, host):
        with self._lock:
            if self._tgtFailure is not None:               # TGT unobtainable -> nothing in the realm works
                raise self._tgtFailure
            if host in self._hostFailures:                 # this host already failed -> don't retry it
                raise self._hostFailures[host]
            if host not in self._tickets:
                if self._tgt is None:
                    if self.kdcHost is None:               # krb5.conf / DNS SRV / realm-name discovery
                        self.kdcHost, self.kdcPort = discoverKdc(self.realm)
                    try:
                        self._tgt = getTGT(self.realm, self.username, self.password, self.kdcHost, self.kdcPort)
                    except Exception as ex:                # cache so the AS exchange runs at most once
                        self._tgtFailure = ex
                        raise
                try:
                    self._tickets[host] = getServiceTicket(self._tgt, self.realm, self.username, ["HTTP", host], self.kdcHost, self.kdcPort)
                except Exception as ex:                    # host-specific -> other hosts remain usable
                    self._hostFailures[host] = ex
                    raise
            return self._tickets[host]

    def _requestHandler(self, req):
        host = _urllib.parse.urlsplit(req.get_full_url()).hostname
        if host:
            try:
                token = spnegoFromTicket(self._serviceTicket(host), self.realm, self.username)
                req.add_unredirected_header(HTTP_HEADER.AUTHORIZATION, "Negotiate %s" % getText(base64.b64encode(token)))
            except KerberosError as ex:
                # bad credentials / KDC-refused: log once, fall through unauthenticated (server 401s)
                singleTimeLogMessage("Negotiate (Kerberos) authentication failed: %s" % getSafeExString(ex), logging.ERROR)
            except Exception as ex:
                # unreachable KDC, malformed reply, etc. - never let it crash the run
                singleTimeLogMessage("could not obtain a Kerberos ticket (is the KDC '%s:%s' reachable?): %s" % (self.kdcHost, self.kdcPort, getSafeExString(ex)), logging.ERROR)
        return req

    def http_request(self, req):
        return self._requestHandler(req)

    https_request = http_request
