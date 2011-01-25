#! /usr/bin/env python

# Runs pylint on all python scripts found in a directory tree
# Reference: http://rowinggolfer.blogspot.com/2009/08/pylint-recursively.html

import os
import re
import sys

total = 0.0
count = 0

def check(module):
    global total, count

    if module[-3:] == ".py":

        print "CHECKING ", module
        pout = os.popen('pylint %s'% module, 'r')
        for line in pout:
            if  re.match("E....:.", line):
                print line
            if "Your code has been rated at" in line:
                print line
                score = re.findall("\d.\d\d", line)[0]
                total += float(score)
                count += 1

if __name__ == "__main__":
    try:
        print sys.argv   
        BASE_DIRECTORY = sys.argv[1]
    except IndexError:
        print "no directory specified, defaulting to current working directory"
        BASE_DIRECTORY = os.getcwd()

    print "looking for *.py scripts in subdirectories of ", BASE_DIRECTORY 
    for root, dirs, files in os.walk(BASE_DIRECTORY):
        for name in files:
            filepath = os.path.join(root, name)
            check(filepath)

    print "==" * 50
    print "%d modules found"% count
    print "AVERAGE SCORE = %.02f"% (total / count)
