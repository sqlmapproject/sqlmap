#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import cookielib
import glob
import httplib
import inspect
import os
import re
import subprocess
import sys
import urllib2

sys.dont_write_bytecode = True

NAME, VERSION, AUTHOR = "WAF Detectify", "0.1", "sqlmap developers (@sqlmap)"
TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Cache-Control": "max-age=0"}
SQLMAP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCRIPTS_DIR = os.path.join(SQLMAP_DIR, "waf")
LEVEL_COLORS = {"o": "\033[00;94m", "x": "\033[00;91m", "!": "\033[00;93m", "i": "\033[00;92m"}
CACHE = {}
WAF_FUNCTIONS = []

def get_page(get=None, url=None, host=None, data=None):
    key = (get, url, host, data)

    if key in CACHE:
        return CACHE[key]

    page, headers, code = None, {}, httplib.OK

    url = url or ("%s%s%s" % (sys.argv[1], '?' if '?' not in sys.argv[1] else '&', get) if get else sys.argv[1])
    if not url.startswith("http"):
        url = "http://%s" % url

    try:
        req = urllib2.Request("".join(url[_].replace(' ', "%20") if _ > url.find('?') else url[_] for _ in xrange(len(url))), data, HEADERS)
        conn = urllib2.urlopen(req, timeout=TIMEOUT)
        page = conn.read()
        headers = conn.info()
    except Exception, ex:
        code = getattr(ex, "code", None)
        page = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", "")
        headers = ex.info() if hasattr(ex, "info") else {}

    result = CACHE[key] = page, headers, code

    return result

def colorize(message):
    if not subprocess.mswindows and sys.stdout.isatty():
        message = re.sub(r"\[(.)\]", lambda match: "[%s%s\033[00;49m]" % (LEVEL_COLORS[match.group(1)], match.group(1)), message)
        message = message.replace("@sqlmap", "\033[00;96m@sqlmap\033[00;49m")
        message = message.replace(NAME, "\033[00;93m%s\033[00;49m" % NAME)

    return message

def main():
    global WAF_FUNCTIONS

    print colorize("%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR))

    if len(sys.argv) < 2:
        exit(colorize("[x] usage: python %s <hostname>" % os.path.split(__file__)[-1]))

    cookie_jar = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie_jar))
    urllib2.install_opener(opener)

    sys.path.insert(0, SQLMAP_DIR)

    for found in glob.glob(os.path.join(SCRIPTS_DIR, "*.py")):
        dirname, filename = os.path.split(found)
        dirname = os.path.abspath(dirname)

        if filename == "__init__.py":
            continue

        if dirname not in sys.path:
            sys.path.insert(0, dirname)

        try:
            if filename[:-3] in sys.modules:
                del sys.modules[filename[:-3]]
            module = __import__(filename[:-3].encode(sys.getfilesystemencoding() or "utf8"))
        except ImportError, msg:
            exit(colorize("[x] cannot import WAF script '%s' (%s)" % (filename[:-3], msg)))

        _ = dict(inspect.getmembers(module))
        if "detect" not in _:
            exit(colorize("[x] missing function 'detect(get_page)' in WAF script '%s'" % found))
        else:
            WAF_FUNCTIONS.append((_["detect"], _.get("__product__", filename[:-3])))

    WAF_FUNCTIONS = sorted(WAF_FUNCTIONS, key=lambda _: "generic" in _[1].lower())

    print colorize("[i] %d WAF scripts loaded" % len(WAF_FUNCTIONS))

    found = False
    for function, product in WAF_FUNCTIONS:
        if found and "unknown" in product.lower():
            continue

        if function(get_page):
            print colorize("[!] WAF/IPS identified as '%s'" % product)
            found = True

    if not found:
        print colorize("[o] nothing found")

    print

if __name__ == "__main__":
    main()
