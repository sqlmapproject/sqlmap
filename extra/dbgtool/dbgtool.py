#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""



import os
import sys
import struct

from optparse import OptionError
from optparse import OptionParser


def convert(inputFile):
    fileStat = os.stat(inputFile)
    fileSize = fileStat.st_size

    if fileSize > 65280:
        print 'ERROR: the provided input file \'%s\' is too big for debug.exe' % inputFile
        sys.exit(1)

    script     = 'n %s\r\nr cx\r\n' % os.path.basename(inputFile.replace('.', '_'))
    script    += "%x\r\nf 0100 ffff 00\r\n" % fileSize
    scrString  = ""
    counter    = 256
    counter2   = 0

    fp          = open(inputFile, 'rb')
    fileContent = fp.read()

    for fileChar in fileContent:
        unsignedFileChar = struct.unpack('B', fileChar)[0]

        if unsignedFileChar != 0:
            counter2 += 1

            if not scrString:
                scrString  = "e %0x %02x" % (counter, unsignedFileChar)
            else:
                scrString += " %02x" % unsignedFileChar
        elif scrString:
            script   += "%s\r\n" % scrString
            scrString = ""
            counter2  = 0

        counter += 1

        if counter2 == 20:
            script    += "%s\r\n" % scrString
            scrString  = ""
            counter2   = 0

    script += "w\r\nq\r\n"

    return script


def main(inputFile, outputFile):
    if not os.path.isfile(inputFile):
        print 'ERROR: the provided input file \'%s\' is not a regular file' % inputFile
        sys.exit(1)

    script = convert(inputFile)

    if outputFile:
        fpOut      = open(outputFile, 'w')
        sys.stdout = fpOut
        sys.stdout.write(script)
        sys.stdout.close()
    else:
        print script


if __name__ == '__main__':
    usage = '%s -i <input file> [-o <output file>]' % sys.argv[0]
    parser  = OptionParser(usage=usage, version='0.1')

    try:
        parser.add_option('-i', dest='inputFile', help='Input binary file')

        parser.add_option('-o', dest='outputFile', help='Output debug.exe text file')

        (args, _) = parser.parse_args()

        if not args.inputFile:
            parser.error('Missing the input file, -h for help')

    except (OptionError, TypeError), e:
        parser.error(e)

    inputFile  = args.inputFile
    outputFile = args.outputFile

    main(inputFile, outputFile)
