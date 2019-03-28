#!/usr/bin/env python

"""
cloak.py - Simple file encryption/compression utility

Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import os
import struct
import sys
import zlib

from optparse import OptionError
from optparse import OptionParser

if sys.version_info >= (3, 0):
    xrange = range

def hideAscii(data):
    retVal = b""
    for i in xrange(len(data)):
        value = data[i] if isinstance(data[i], int) else ord(data[i])
        retVal += struct.pack('B', value ^ (127 if value < 128 else 0))

    return retVal

def cloak(inputFile=None, data=None):
    if data is None:
        with open(inputFile, "rb") as f:
            data = f.read()

    return hideAscii(zlib.compress(data))

def decloak(inputFile=None, data=None):
    if data is None:
        with open(inputFile, "rb") as f:
            data = f.read()
    try:
        data = zlib.decompress(hideAscii(data))
    except Exception as ex:
        print(ex)
        print('ERROR: the provided input file \'%s\' does not contain valid cloaked content' % inputFile)
        sys.exit(1)
    finally:
        f.close()

    return data

def main():
    usage = '%s [-d] -i <input file> [-o <output file>]' % sys.argv[0]
    parser = OptionParser(usage=usage, version='0.1')

    try:
        parser.add_option('-d', dest='decrypt', action="store_true", help='Decrypt')
        parser.add_option('-i', dest='inputFile', help='Input file')
        parser.add_option('-o', dest='outputFile', help='Output file')

        (args, _) = parser.parse_args()

        if not args.inputFile:
            parser.error('Missing the input file, -h for help')

    except (OptionError, TypeError) as ex:
        parser.error(ex)

    if not os.path.isfile(args.inputFile):
        print('ERROR: the provided input file \'%s\' is non existent' % args.inputFile)
        sys.exit(1)

    if not args.decrypt:
        data = cloak(args.inputFile)
    else:
        data = decloak(args.inputFile)

    if not args.outputFile:
        if not args.decrypt:
            args.outputFile = args.inputFile + '_'
        else:
            args.outputFile = args.inputFile[:-1]

    f = open(args.outputFile, 'wb')
    f.write(data)
    f.close()

if __name__ == '__main__':
    main()
