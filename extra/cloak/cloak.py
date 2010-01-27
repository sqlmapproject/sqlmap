#!/usr/bin/env python

"""
cloak.py - Simple file encryption and/or compression utility
Copyright (C) 2010  Miroslav Stampar, Bernardo Damele A. G.
email(s): miroslav.stampar@gmail.com, bernardo.damele@gmail.com

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
"""

import os
import sys
import bz2

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
    retVal = ""
    
    f = open(inputFile, 'rb')
    original = f.read()
    f.close()
    
    data = bz2.compress(original)
    
    return hideAscii(data)
        
def decloak(inputFile):
    retVal = ""
    
    f = open(inputFile, 'rb')
    original = f.read()
    f.close()
    
    data = bz2.decompress(hideAscii(original))
    
    return data

def main():
    usage = '%s [-d] -i <input file> [-o <output file>]' % sys.argv[0]
    parser  = OptionParser(usage=usage, version='0.1')

    try:
        parser.add_option('-d', dest='decrypt', action="store_true", help='Decrypt')
        parser.add_option('-i', dest='inputFile', help='Input file')
        parser.add_option('-o', dest='outputFile', help='Output file')

        (args, _) = parser.parse_args()

        if not args.inputFile:
            parser.error('Missing the input file, -h for help')

    except (OptionError, TypeError), e:
        parser.error(e)
    
    if args.inputFile == '*':
        pass
    elif not os.path.isfile(args.inputFile):
        print 'ERROR: the provided input file \'%s\' is not a regular file' % args.inputFile
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
        
    fpOut      = open(args.outputFile, 'wb')
    sys.stdout = fpOut
    sys.stdout.write(data)
    sys.stdout.close()


if __name__ == '__main__':
    main()