#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Standalone launcher for the DBMS-agnostic Esperanto engine. Run it straight from this
directory - no sqlmap, no PYTHONPATH, no `-m` incantation:

    python run.py -u 'http://host/vuln?id=1*' --string <true-marker> --tables --dump -T users
    python run.py --self-test
    python run.py --live                 # local DBMS dev harness

The package is fully self-contained (bundled wordlists, no sqlmap imports in the engine),
so the whole directory can be copied elsewhere and still run. sqlmap uses the very same
package via `from extra.esperanto import buildHandler`, handing the engine its own boolean
oracle (checkBooleanExpression); this launcher is only for standalone use.
"""

import importlib
import os
import sys

# make this package importable by its own (folder) name from any working directory, so
# the relative imports inside resolve, then hand off to the CLI in __main__
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
main = importlib.import_module("%s.__main__" % os.path.basename(_HERE)).main

if __name__ == "__main__":
    sys.exit(main())
