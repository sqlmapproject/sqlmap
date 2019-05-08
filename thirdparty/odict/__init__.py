#!/usr/bin/env python

import sys

if sys.version_info[:2] >= (2, 7):
    from collections import OrderedDict
else:
    from ordereddict import OrderedDict
