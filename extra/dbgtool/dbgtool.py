#!/usr/bin/env python

"""
dbgtool.py - Portable executable to ASCII debug script converter

Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import os
import sys

from optparse import OptionError
from optparse import OptionParser

def convert(inputFile):
    fileStat = os.stat(inputFile)
    fileSize = fileStat.st_size

    if fileSize > 65280:
        print("ERROR: the provided input file '%s' is too big for debug.exe" % inputFile)
        sys.exit(1)

    script = "n %s\nr cx\n" % os.path.basename(inputFile.replace(".", "_"))
    script += "%x\nf 0100 ffff 00\n" % fileSize
    scrString = ""
    counter = 256
    counter2 = 0

    fp = open(inputFile, "rb")
    fileContent = fp.read()

    for fileChar in fileContent:
        unsignedFileChar = fileChar if sys.version_info >= (3, 0) else ord(fileChar)

        if unsignedFileChar != 0:
            counter2 += 1

            if not scrString:
                scrString = "e %0x %02x" % (counter, unsignedFileChar)
            else:
                scrString += " %02x" % unsignedFileChar
        elif scrString:
            script += "%s\n" % scrString
            scrString = ""
            counter2 = 0

        counter += 1

        if counter2 == 20:
            script += "%s\n" % scrString
            scrString = ""
            counter2 = 0

    script += "w\nq\n"

    return script

def main(inputFile, outputFile):
    if not os.path.isfile(inputFile):
        print("ERROR: the provided input file '%s' is not a regular file" % inputFile)
        sys.exit(1)

    script = convert(inputFile)

    if outputFile:
        fpOut = open(outputFile, "w")
        sys.stdout = fpOut
        sys.stdout.write(script)
        sys.stdout.close()
    else:
        print(script)

if __name__ == "__main__":
    usage = "%s -i <input file> [-o <output file>]" % sys.argv[0]
    parser = OptionParser(usage=usage, version="0.1")

    try:
        parser.add_option("-i", dest="inputFile", help="Input binary file")

        parser.add_option("-o", dest="outputFile", help="Output debug.exe text file")

        (args, _) = parser.parse_args()

        if not args.inputFile:
            parser.error("Missing the input file, -h for help")

    except (OptionError, TypeError) as ex:
        parser.error(ex)

    inputFile = args.inputFile
    outputFile = args.outputFile

    main(inputFile, outputFile)
