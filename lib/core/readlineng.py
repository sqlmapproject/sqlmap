#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

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

Based on IPython readline library (IPython/rlineimpl.py), imports and
provides the "correct" version of readline for the platform.
In addition to normal readline stuff, this module provides haveReadline
boolean and _outputfile variable used in genutils.
"""



import sys

from lib.core.data import logger
from lib.core.settings import IS_WIN
from lib.core.settings import PLATFORM


try:
    from readline import *
    import readline as _rl

    haveReadline = True
except ImportError:
    try:
        from pyreadline import *
        import pyreadline as _rl

        haveReadline = True
    except ImportError:    
        haveReadline = False

if IS_WIN is True and haveReadline:
    try:
        _outputfile=_rl.GetOutputFile()
    except AttributeError:
        debugMsg  = "Failed GetOutputFile when using platform's "
        debugMsg += "readline library"
        logger.debug(debugMsg)

        haveReadline = False

# Test to see if libedit is being used instead of GNU readline.
# Thanks to Boyd Waters for this patch.
uses_libedit = False

if PLATFORM == 'darwin' and haveReadline:
    import commands

    (status, result) = commands.getstatusoutput( "otool -L %s | grep libedit" % _rl.__file__ )

    if status == 0 and len(result) > 0:
        # We are bound to libedit - new in Leopard
        _rl.parse_and_bind("bind ^I rl_complete")

        debugMsg  = "Leopard libedit detected when using platform's "
        debugMsg += "readline library"
        logger.debug(debugMsg)

        uses_libedit = True


# the clear_history() function was only introduced in Python 2.4 and is
# actually optional in the readline API, so we must explicitly check for its
# existence.  Some known platforms actually don't have it.  This thread:
# http://mail.python.org/pipermail/python-dev/2003-August/037845.html
# has the original discussion.
if haveReadline:
    try:
        _rl.clear_history
    except AttributeError:
        def clear_history():
            pass

        _rl.clear_history = clear_history
