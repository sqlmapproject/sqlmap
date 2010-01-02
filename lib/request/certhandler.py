import httplib
import urllib2

class HTTPSCertAuthHandler(urllib2.HTTPSHandler):
    def __init__(self, key_file, cert_file):
        urllib2.HTTPSHandler.__init__(self)
        self.key_file = key_file
        self.cert_file = cert_file
    def https_open(self, req):
        return self.do_open(self.getConnection, req)
    def getConnection(self, host):
        return httplib.HTTPSConnection(host, key_file=self.key_file, cert_file=self.cert_file)
