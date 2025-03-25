#! /usr/bin/env python

from __future__ import print_function

import os
import sys

def check(filepath):
    if filepath.endswith(".py"):
        content = open(filepath, "rb").read()
        pattern = "\n\n\n".encode("ascii")

        if pattern in content:
            index = content.find(pattern)
            print(filepath, repr(content[index - 30:index + 30]))

if __name__ == "__main__":
    try:
        BASE_DIRECTORY = sys.argv[1]
    except IndexError:
        print("no directory specified, defaulting to current working directory")
        BASE_DIRECTORY = os.getcwd()

    print("looking for *.py scripts in subdirectories of '%s'" % BASE_DIRECTORY)
    for root, dirs, files in os.walk(BASE_DIRECTORY):
        if any(_ in root for _ in ("extra", "thirdparty")):
            continue
        for name in files:
            filepath = os.path.join(root, name)
            check(filepath)
