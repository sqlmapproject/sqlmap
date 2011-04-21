#!/usr/bin/env python

"""
$Id$

safe2bin.py - Simple safe(hex) to binary format converter

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import binascii
import re
import string
import os
import sys

from optparse import OptionError
from optparse import OptionParser

# Regex used for recognition of hex encoded characters
HEX_ENCODED_CHAR_REGEX = r"(?P<result>\\x[0-9A-Fa-f]{2})"

# Raw chars that will be safe encoded to their slash (\) representations (e.g. newline to \n)
SAFE_ENCODE_SLASH_REPLACEMENTS = "\\\t\n\r\x0b\x0c"

def safecharencode(value):
    """
    Returns safe representation of a given basestring value

    >>> safecharencode(u'test123')
    u'test123'
    >>> safecharencode(u'test\x01\x02\xff')
    u'test\\01\\02\\03\\ff'
    """

    retVal = value

    if isinstance(value, basestring):
        for char in SAFE_ENCODE_SLASH_REPLACEMENTS:
            retVal = retVal.replace(char, repr(char).strip('\''))

        retVal = reduce(lambda x, y: x + (y if (y in string.printable or ord(y) > 255) else '\\x%02x' % ord(y)), retVal, unicode())

    elif isinstance(value, list):
        for i in xrange(len(value)):
            retVal[i] = safecharencode(value[i])

    return retVal

def safechardecode(value):
    """
    Reverse function to safecharencode
    """

    retVal = value
    if isinstance(value, basestring):
        regex = re.compile(HEX_ENCODED_CHAR_REGEX)

        while True:
            match = regex.search(retVal)
            if match:
                retVal = retVal.replace(match.group("result"), unichr(ord(binascii.unhexlify(match.group("result").lstrip('\\x')))))
            else:
                break

        for char in SAFE_ENCODE_SLASH_REPLACEMENTS[::-1]:
            retVal = retVal.replace(repr(char).strip('\''), char)

    elif isinstance(value, (list, tuple)):
        for i in xrange(len(value)):
            retVal[i] = safechardecode(value[i])

    return retVal

def main():
    usage = '%s -i <input file> [-o <output file>]' % sys.argv[0]
    parser  = OptionParser(usage=usage, version='0.1')

    try:
        parser.add_option('-i', dest='inputFile', help='Input file')
        parser.add_option('-o', dest='outputFile', help='Output file')

        (args, _) = parser.parse_args()

        if not args.inputFile:
            parser.error('Missing the input file, -h for help')

    except (OptionError, TypeError), e:
        parser.error(e)

    if not os.path.isfile(args.inputFile):
        print 'ERROR: the provided input file \'%s\' is not a regular file' % args.inputFile
        sys.exit(1)

    f = open(args.inputFile, 'r')
    data = f.read()
    f.close()

    if not args.outputFile:
        args.outputFile = args.inputFile + '.bin'

    f = open(args.outputFile, 'wb')
    f.write(safechardecode(data))
    f.close()

if __name__ == '__main__':
    main()
