#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re
import socket

from lib.core.common import filterNone
from lib.core.common import getSafeExString
from lib.core.compat import LooseVersion
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from lib.core.settings import PYVERSION
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import urllib as _urllib

ssl = None
try:
    import ssl as _ssl
    ssl = _ssl
except ImportError:
    pass

_protocols = filterNone(getattr(ssl, _, None) for _ in ("PROTOCOL_TLS_CLIENT", "PROTOCOL_TLSv1_2", "PROTOCOL_TLSv1_1", "PROTOCOL_TLSv1", "PROTOCOL_SSLv3", "PROTOCOL_SSLv23", "PROTOCOL_SSLv2"))
_lut = dict((getattr(ssl, _), _) for _ in dir(ssl) if _.startswith("PROTOCOL_"))
_contexts = {}

class HTTPSConnection(_http_client.HTTPSConnection):
    """
    Connection class that enables usage of newer SSL protocols.

    Reference: http://bugs.python.org/msg128686

    NOTE: use https://check-tls.akamaized.net/ to check if (e.g.) TLS/SNI is working properly
    """

    def __init__(self, *args, **kwargs):
        # NOTE: Dirty patch for https://bugs.python.org/issue38251 / https://github.com/sqlmapproject/sqlmap/issues/4158
        if hasattr(ssl, "_create_default_https_context"):
            if None not in _contexts:
                _contexts[None] = ssl._create_default_https_context()
            kwargs["context"] = _contexts[None]

        self.retrying = False

        _http_client.HTTPSConnection.__init__(self, *args, **kwargs)

    def connect(self):
        def create_sock():
            sock = socket.create_connection((self.host, self.port), self.timeout)
            if getattr(self, "_tunnel_host", None):
                self.sock = sock
                self._tunnel()
            return sock

        success = False

        # Reference(s): https://docs.python.org/2/library/ssl.html#ssl.SSLContext
        #               https://www.mnot.net/blog/2014/12/27/python_2_and_tls_sni
        if hasattr(ssl, "SSLContext"):
            for protocol in (_ for _ in _protocols if _ >= ssl.PROTOCOL_TLSv1):
                try:
                    sock = create_sock()
                    if protocol not in _contexts:
                        _contexts[protocol] = ssl.SSLContext(protocol)

                        # Disable certificate and hostname validation enabled by default with PROTOCOL_TLS_CLIENT
                        _contexts[protocol].check_hostname = False
                        _contexts[protocol].verify_mode = ssl.CERT_NONE

                        if getattr(self, "cert_file", None) and getattr(self, "key_file", None):
                            _contexts[protocol].load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
                        try:
                            # Reference(s): https://askubuntu.com/a/1263098
                            #               https://askubuntu.com/a/1250807
                            _contexts[protocol].set_ciphers("DEFAULT@SECLEVEL=1")
                        except (ssl.SSLError, AttributeError):
                            pass
                    result = _contexts[protocol].wrap_socket(sock, do_handshake_on_connect=True, server_hostname=self.host if re.search(r"\A[\d.]+\Z", self.host or "") is None else None)
                    if result:
                        success = True
                        self.sock = result
                        _protocols.remove(protocol)
                        _protocols.insert(0, protocol)
                        break
                    else:
                        sock.close()
                except (ssl.SSLError, socket.error, _http_client.BadStatusLine) as ex:
                    self._tunnel_host = None
                    logger.debug("SSL connection error occurred for '%s' ('%s')" % (_lut[protocol], getSafeExString(ex)))

        elif hasattr(ssl, "wrap_socket"):
            for protocol in _protocols:
                try:
                    sock = create_sock()
                    _ = ssl.wrap_socket(sock, keyfile=getattr(self, "key_file"), certfile=getattr(self, "cert_file"), ssl_version=protocol)
                    if _:
                        success = True
                        self.sock = _
                        _protocols.remove(protocol)
                        _protocols.insert(0, protocol)
                        break
                    else:
                        sock.close()
                except (ssl.SSLError, socket.error, _http_client.BadStatusLine) as ex:
                    self._tunnel_host = None
                    logger.debug("SSL connection error occurred for '%s' ('%s')" % (_lut[protocol], getSafeExString(ex)))

        if not success:
            errMsg = "can't establish SSL connection"
            # Reference: https://docs.python.org/2/library/ssl.html
            if LooseVersion(PYVERSION) < LooseVersion("2.7.9"):
                errMsg += " (please retry with Python >= 2.7.9)"

            if kb.sslSuccess and not self.retrying:
                self.retrying = True

                for _ in xrange(conf.retries):
                    try:
                        self.connect()
                    except SqlmapConnectionException:
                        pass
                    else:
                        return

            raise SqlmapConnectionException(errMsg)
        else:
            kb.sslSuccess = True

class HTTPSHandler(_urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(HTTPSConnection if ssl else _http_client.HTTPSConnection, req)
