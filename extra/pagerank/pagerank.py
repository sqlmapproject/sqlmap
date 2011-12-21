#!/usr/bin/env python
#
#  Script for getting Google Page Rank of page
#  Google Toolbar 3.0.x/4.0.x Pagerank Checksum Algorithm
#
#  original from http://pagerank.gamesaga.net/
#  this version was adapted from http://www.djangosnippets.org/snippets/221/
#  by Corey Goldberg - 2010
#
#  Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php

import urllib

def get_pagerank(url):
    hsh = check_hash(hash_url(url))
    gurl = 'http://www.google.com/search?client=navclient-auto&features=Rank:&q=info:%s&ch=%s' % (urllib.quote(url), hsh)
    try:
        f = urllib.urlopen(gurl)
        rank = f.read().strip()[9:]
    except Exception:
        rank = 'N/A'
    if rank == '':
        rank = '0'
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
