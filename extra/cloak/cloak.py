#!/usr/bin/env python

"""
cloak.py - Simple file encryption/compression utility

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import bz2
import os
import sys

from optparse import OptionError
from optparse import OptionParser

def hideAscii(data):
    retVal = ""
    for i in xrange(len(data)):
        if ord(data[i]) < 128:
            retVal += chr(ord(data[i]) ^ 127)
        else:
            retVal += data[i]

    return retVal

def cloak(inputFile):
    f = open(inputFile, 'rb')
    data = bz2.compress(f.read())
    f.close()

    return hideAscii(data)

def decloak(inputFile):
    f = open(inputFile, 'rb')
    try:
        data = bz2.decompress(hideAscii(f.read()))
    except:
        print 'ERROR: the provided input file \'%s\' does not contain valid cloaked content' % inputFile
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

    except (OptionError, TypeError), e:
        parser.error(e)

    if not os.path.isfile(args.inputFile):
        print 'ERROR: the provided input file \'%s\' is non existent' % args.inputFile
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
