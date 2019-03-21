#!/usr/bin/env python2

import sys

if sys.version_info[:2] >= (2, 7):
    from collections import OrderedDict
else:
    from ordereddict import OrderedDict
