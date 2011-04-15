#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import cookielib
import re
import socket
import sys
import urllib
import urllib2
import ConfigParser

from operator import itemgetter

def main():

    TIMEOUT         = 10
    CONFIG_FILE     = 'sqlharvest.cfg'
    TABLES_FILE     = 'tables.txt'
    USER_AGENT      = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; AskTB5.3)'
    SEARCH_URL      = 'http://www.google.com/m?source=mobileproducts&dc=gorganic'
    MAX_FILE_SIZE   = 2*1024*1024 # if a result (.sql) file for downloading is more than 2MB in size just skip it
    QUERY           = 'CREATE TABLE ext:sql'
    REGEX_URLS      = r';u=([^"]+)'
    REGEX_RESULT    = r'CREATE TABLE\s*(/\*.*\*/)?\s*(IF NOT EXISTS)?\s*(?P<result>[^\(;]+)'

    tables = dict()
    refiles = re.compile(REGEX_URLS)
    retables = re.compile(REGEX_RESULT, re.I)

    cookies = cookielib.CookieJar()
    cookie_processor = urllib2.HTTPCookieProcessor(cookies)
    opener = urllib2.build_opener(cookie_processor)
    opener.addheaders = [('User-Agent', USER_AGENT)]

    conn = opener.open(SEARCH_URL)
    page = conn.read() #set initial cookie values

    config = ConfigParser.ConfigParser()
    config.read(CONFIG_FILE)
    if not config.has_section('options'):
        config.add_section('options')

    if not config.has_option('options',  'index'):
        config.set('options',  'index', '0')

    i = int(config.get('options',  'index'))

    try:
        f = open(TABLES_FILE, 'r')
        for line in f.xreadlines():
            if len(line) > 0 and ',' in line:
                temp = line.split(',')
                tables[temp[0]] = int(temp[1])
        f.close()
    except:
        pass

    socket.setdefaulttimeout(TIMEOUT)

    files, oldFiles = None, None
    try:
        while True:
            abort = False
            oldFiles = files
            files = []

            try:
                conn = opener.open('%s&q=%s&start=%d&sa=N' % (SEARCH_URL, QUERY.replace(' ', '+'), i*10))
                page = conn.read()
                for match in refiles.finditer(page):
                    files.append(urllib.unquote(match.group(1)))
                    if len(files) >= 10: break
                abort = (files == oldFiles)

            except KeyboardInterrupt:
                raise

            except Exception, msg:
                print msg

            if abort:
                break

            sys.stdout.write("\n---------------\n")
            sys.stdout.write("Result page #%d\n" % (i+1))
            sys.stdout.write("---------------\n")

            for sqlfile in files:
                print sqlfile
                try:
                    req = urllib2.Request(sqlfile)
                    response = urllib2.urlopen(req)

                    if response.headers.has_key('Content-Length'):
                        if int(response.headers.get('Content-Length')) > MAX_FILE_SIZE:
                            continue

                    page = response.read()
                    found = False
                    counter = 0

                    for match in retables.finditer(page):
                        counter += 1
                        table = match.group("result").strip().strip("`").strip("\"").strip("'").replace('"."', ".").replace("].[", ".").strip('[').strip(']')

                        if table and '>' not in table and '<' not in table and '--' not in table and ' ' not in table:
                            found = True
                            sys.stdout.write('*')

                            if table in tables:
                                tables[table] += 1
                            else:
                                tables[table] = 1
                    if found:
                        sys.stdout.write("\n")

                except KeyboardInterrupt:
                    raise

                except Exception, msg:
                    print msg

            else:
                i += 1

    except KeyboardInterrupt:
        pass

    finally:
        f = open(TABLES_FILE, 'w+')

        tables = sorted(tables.items(), key=itemgetter(1), reverse=True)

        for table, count in tables:
            f.write("%s,%d\n" % (table, count))

        f.close()
        config.set('options',  'index', str(i+1))

        f = open(CONFIG_FILE, 'w+')
        config.write(f)
        f.close()

if __name__ == "__main__":
    main()
