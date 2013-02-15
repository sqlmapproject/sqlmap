#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re
import httplib
from lib.request.connect import Connect as Request
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import PLACE
from lib.core.common import getHostHeader

class Waf(object):
    """
    This class defines waf vendors and attack vectors for identification
    """
    attack_vectors = [
        '/Admin_Files/',
        '<script>alert(1)</script>',
        '%3Cscript%3Ealert%281%29%3C/script%3E',
        '../../../../etc/passwd',
        '<invalid>hello'
    ]

    def __init__(self):
        self.vendor = None

    def identify(self):
        pass

    @staticmethod
    def matchheader(headers, field, match):
        headers = dict(headers.items())
        if field in headers:
            if field == 'set-cookie':
                values = headers[field].split('; ')
            else:
                values = [headers[field]]
            for value in values:
                if re.match(match, value, re.IGNORECASE):
                    return True
        return False

class WafProfense(Waf):
    def __init__(self):
        self.vendor = 'Profense'

    def identify(self):
        page, headers, code = Request.getPage(content=True)
        return Waf.matchheader(headers, 'server', 'profense')

class WafNetContinuum(Waf):
    def __init__(self):
        self.vendor = 'NetContinuum'

    def identify(self):
        page, headers, code = Request.getPage(content=True)
        return Waf.matchheader(headers, 'set-cookie', '^NCI__SessionId=')

class WafBarracuda(Waf):
    def __init__(self):
        self.vendor = 'Barracuda'

    def identify(self):
        page, headers, code = Request.getPage(content=True)
        return Waf.matchheader(headers, 'set-cookie', '^barra_counter_session=')

class WafHyperGuard(Waf):
    def __init__(self):
        self.vendor = 'HyperGuard'

    def identify(self):
        page, headers, code = Request.getPage(content=True)
        return Waf.matchheader(headers, 'set-cookie', '^WODSESSION=')

class WafBinarySec(Waf):
    def __init__(self):
        self.vendor = 'BinarySec'

    def identify(self):
        page, headers, code = Request.getPage(content=True)
        return Waf.matchheader(headers, 'server', 'BinarySec')

class WafTeros(Waf):
    def __init__(self):
        self.vendor = 'Teros'

    def identify(self):
        page, headers, code = Request.getPage(content=True)
        return Waf.matchheader(headers, 'set-cookie', '^st8id=')

class WafF5Trafficshield(Waf):
    def __init__(self):
        self.vendor = 'F5 Trafficshield'

    def identify(self):
        page, headers, code = Request.getPage(content=True)
        if Waf.matchheader(headers, 'cookie', '^ASINFO='):
            return True
        if Waf.matchheader(headers, 'server', 'F5-TrafficShield'):
            return True
        return False

class WafF5ASM(Waf):
    def __init__(self):
        self.vendor = 'F5 ASM'

    def identify(self):
        page, headers, code = Request.getPage(content=True)
        return Waf.matchheader(headers, 'set-cookie', '^TS[a-zA-Z0-9]{3,6}=')

class WafAirlock(Waf):
    def __init__(self):
        self.vendor = 'Airlock'

    def identify(self):
        page, headers, code = Request.getPage(content=True)
        return Waf.matchheader(headers, 'set-cookie', '^AL[_-]?(SESS|LB)=')

class WafCitrixNetScaler(Waf):
    def __init__(self):
        self.vendor = 'Citrix NetScaler'

    def identify(self):
        page, headers, code = Request.getPage(content=True)
        if Waf.matchheader(headers, 'set-cookie', '^(ns_af=|citrix_ns_id|NSC_)'):
            return True

        for attack_vector in Waf.attack_vectors:
            get = attack_vector
            page, headers, code = Request.getPage(content=True, get=get)
            if Waf.matchheader(headers, 'Cneonction', 'close') or Waf.matchheader(headers, 'nnCoection', 'close'):
                return True
        return False

class WafModSecurity(Waf):
    def __init__(self):
        self.vendor = 'ModSecurity'

    def identify(self):
        for attack_vector in Waf.attack_vectors:
            get = attack_vector
            page, headers, code = Request.getPage(content=True, get=get)
            if code == 501:
                return True
        return False

class WafIBMWebApplicationSecurity(Waf):
    def __init__(self):
        self.vendor = 'IBM Web Application Security'

    def identify(self):
        get = '/Admin_Files/'
        page, headers, code = Request.getPage(content=True, get=get)
        if page is None:
            return True
        return False

class WafIBMDataPower(Waf):
    def __init__(self):
        self.vendor = 'IBM DataPower'

    def identify(self):
        page, headers, code = Request.getPage(content=True)
        return Waf.matchheader(headers, 'X-Backside-Transport', '^(OK|FAIL)')

class WafDenyALL(Waf):
    def __init__(self):
        self.vendor = 'DenyALL'

    def identify(self):
        page, headers, code = Request.getPage(content=True)
        if Waf.matchheader(headers, 'set-cookie', '^sessioncookie='):
            return True
        for attack_vector in Waf.attack_vectors:
            get = attack_vector
            conn, _, _ = Request.getPage(response=True, get=get)
            if conn.code == 200:
                if conn.msg == 'Condition Intercepted':
                    return True
        return False

class WafdotDefender(Waf):
    def __init__(self):
        self.vendor = 'dotDefender'

    def identify(self):
        for attack_vector in Waf.attack_vectors:
            get = attack_vector
            page, headers, code = Request.getPage(content=True, get=get)
            if Waf.matchheader(headers, 'X-dotDefender-denied', '^1$'):
                return True
        return False

class WafwebAppSecure(Waf):
    def __init__(self):
        self.vendor = 'webApp.secure'

    def identify(self):
        page, headers, code = Request.getPage(content=True)
        if code == 403:
            return False
        get = 'nx=@@'
        page, headers, code = Request.getPage(content=True, get=get)
        if code == 403:
            return True
        return False

class WafBIGIP(Waf):
    def __init__(self):
        self.vendor = 'BIG-IP'

    def identify(self):
        for attack_vector in Waf.attack_vectors:
            get = attack_vector
            page, headers, code = Request.getPage(content=True, get=get)
            if Waf.matchheader(headers, 'X-Cnection', '^close$'):
                return True
        return False

class WafURLScan(Waf):
    def __init__(self):
        self.vendor = 'URLScan'

    def identify(self):
        auxHeaders = dict()
        auxHeaders['Translate'] = 'z'*10
        auxHeaders['If'] = 'z'*10
        auxHeaders['Lock-Token'] = 'z'*10
        auxHeaders['Transfer-Encoding'] = 'z'*10
        page, headers, code1 = Request.getPage(content=True)
        page, headers, code2 = Request.getPage(content=True, auxHeaders=auxHeaders)
        if code1 != code2 and code2 == 404:
            return True
        return False

class WafWebKnight(Waf):
    def __init__(self):
        self.vendor = 'WebKnight'

    def identify(self):
        for attack_vector in Waf.attack_vectors:
            get = attack_vector
            page, headers, code = Request.getPage(content=True, get=get)
            if code == 999:
                return True
        return False

class WafSecureIIS(Waf):
    def __init__(self):
        self.vendor = 'SecureIIS'

    def identify(self):
        auxHeaders = dict()
        auxHeaders['Transfer-Encoding'] = 'z' * 1025
        page, headers, code = Request.getPage(content=True, auxHeaders=auxHeaders)
        if code == 404:
            return True
        return False

class WafImperva(Waf):
    def __init__(self):
        self.vendor = 'Imperva'

    def identify(self):
        for attack_vector in Waf.attack_vectors:
            conn = httplib.HTTPConnection(getHostHeader(conf.url), conf.port)
            conn.request('GET', '/' + attack_vector)
            r = conn.getresponse()
            if r.version == 10:
                return True
        return False

class WafISAServer(Waf):
    def __init__(self):
        self.vendor = 'ISA Server'

    def identify(self):
        auxHeaders = dict()
        auxHeaders['Host'] = '123456'
        conn, _, _ = Request.getPage(response=True, auxHeaders=auxHeaders)
        if conn.msg == 'Forbidden ( The server denied the specified Uniform Resource Locator (URL). Contact the server administrator.  )':
            return True
        return False

wafs = [
    WafProfense(),
    WafNetContinuum(),
    WafBarracuda(),
    WafHyperGuard(),
    WafBinarySec(),
    WafTeros(),
    WafF5Trafficshield(),
    WafF5ASM(),
    WafAirlock(),
    WafCitrixNetScaler(),
    WafModSecurity(),
    WafIBMWebApplicationSecurity(),
    WafIBMDataPower(),
    WafDenyALL(),
    WafdotDefender(),
    WafwebAppSecure(),
    WafBIGIP(),
    WafURLScan(),
    WafWebKnight(),
    WafSecureIIS(),
    WafImperva(),
    WafISAServer()
]
