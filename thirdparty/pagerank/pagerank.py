#!/usr/bin/env python
#
#  Script for getting Google Page Rank of page
#  Google Toolbar 3.0.x/4.0.x Pagerank Checksum Algorithm
#
#  original from http://pagerank.gamesaga.net/
#  this version was adapted from http://www.djangosnippets.org/snippets/221/
#  by Corey Goldberg - 2010
#
#  important update (http://www.seroundtable.com/google-pagerank-change-14132.html)
#  by Miroslav Stampar - 2012
#
#  Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php

import sys
import urllib
import urllib2

def get_pagerank(url, timeout=10):
    url = url.encode('utf8') if isinstance(url, unicode) else url
    _ = 'http://toolbarqueries.google.com/tbr?client=navclient-auto&features=Rank&ch=%s&q=info:%s' % (check_hash(hash_url(url)), urllib.quote(url))
    try:
        req = urllib2.Request(_)
        rank = urllib2.urlopen(req, timeout=timeout).read().strip()[9:]
    except:
        rank = 'N/A'
    else:
        rank = '0' if not rank or not rank.isdigit() else rank
    return rank

def int_str(string_, integer, factor):
    for i in xrange(len(string_)) :
        integer *= factor
        integer &= 0xFFFFFFFF
        integer += ord(string_[i])

    return integer

def hash_url(string_):
    c1 = int_str(string_, 0x1505, 0x21)
    c2 = int_str(string_, 0, 0x1003F)

    c1 >>= 2
    c1 = ((c1 >> 4) & 0x3FFFFC0) | (c1 & 0x3F)
    c1 = ((c1 >> 4) & 0x3FFC00) | (c1 & 0x3FF)
    c1 = ((c1 >> 4) & 0x3C000) | (c1 & 0x3FFF)

    t1 = (c1 & 0x3C0) << 4
    t1 |= c1 & 0x3C
    t1 = (t1 << 2) | (c2 & 0xF0F)

    t2 = (c1 & 0xFFFFC000) << 4
    t2 |= c1 & 0x3C00
    t2 = (t2 << 0xA) | (c2 & 0xF0F0000)

    return (t1 | t2)

def check_hash(hash_int):
    hash_str = '%u' % (hash_int)
    flag = 0
    check_byte = 0

    i = len(hash_str) - 1
    while i >= 0:
        byte = int(hash_str[i])
        if 1 == (flag % 2):
            byte *= 2;
            byte = byte / 10 + byte % 10
        check_byte += byte
        flag += 1
        i -= 1

    check_byte %= 10
    if 0 != check_byte:
        check_byte = 10 - check_byte
        if 1 == flag % 2:
            if 1 == check_byte % 2:
                check_byte += 9
            check_byte >>= 1

    return '7' + str(check_byte) + hash_str

def main():
    print get_pagerank(sys.argv[1]) if len(sys.argv) > 1 else "[x] missing hostname"

if __name__ == "__main__":
    main()
