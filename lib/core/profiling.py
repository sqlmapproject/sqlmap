#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import os
import cProfile

from lib.core.common import getUnicode
from lib.core.data import logger
from lib.core.data import paths
from lib.core.settings import UNICODE_ENCODING

def profile(profileOutputFile=None, dotOutputFile=None, imageOutputFile=None):
    """
    This will run the program and present profiling data in a nice looking graph
    """
    try:
        from extra.gprof2dot import gprof2dot
        from extra.xdot import xdot
        import gobject
        import gtk
        import pydot
    except ImportError, e:
        errMsg = "profiling requires third-party libraries (%s)" % getUnicode(e, UNICODE_ENCODING)
        logger.error(errMsg)
        return

    if profileOutputFile is None:
        profileOutputFile = os.path.join(paths.SQLMAP_OUTPUT_PATH, "sqlmap_profile.raw")

    if dotOutputFile is None:
        dotOutputFile = os.path.join(paths.SQLMAP_OUTPUT_PATH, "sqlmap_profile.dot")

    if imageOutputFile is None:
        imageOutputFile = os.path.join(paths.SQLMAP_OUTPUT_PATH, "sqlmap_profile.png")

    if os.path.exists(profileOutputFile):
        os.remove(profileOutputFile)

    if os.path.exists(dotOutputFile):
        os.remove(dotOutputFile)

    if os.path.exists(imageOutputFile):
        os.remove(imageOutputFile)

    infoMsg = "profiling the execution into file %s" % profileOutputFile
    logger.info(infoMsg)

    # Start sqlmap main function and generate a raw profile file
    cProfile.run("start()", profileOutputFile)

    infoMsg = "converting profile data into a dot file '%s'" % dotOutputFile
    logger.info(infoMsg)

    # Create dot file by using extra/gprof2dot/gprof2dot.py
    # http://code.google.com/p/jrfonseca/wiki/Gprof2Dot
    dotFilePointer = codecs.open(dotOutputFile, 'wt', UNICODE_ENCODING)
    parser = gprof2dot.PstatsParser(profileOutputFile)
    profile = parser.parse()
    profile.prune(0.5/100.0, 0.1/100.0)
    dot = gprof2dot.DotWriter(dotFilePointer)
    dot.graph(profile, gprof2dot.TEMPERATURE_COLORMAP)
    dotFilePointer.close()

    infoMsg = "converting dot file into a graph image '%s'" % imageOutputFile
    logger.info(infoMsg)

    # Create graph image (png) by using pydot (python-pydot)
    # http://code.google.com/p/pydot/
    pydotGraph = pydot.graph_from_dot_file(dotOutputFile)
    pydotGraph.write_png(imageOutputFile)

    infoMsg = "displaying interactive graph with xdot library"
    logger.info(infoMsg)

    # Display interactive Graphviz dot file by using extra/xdot/xdot.py
    # http://code.google.com/p/jrfonseca/wiki/XDot
    win = xdot.DotWindow()
    win.connect('destroy', gtk.main_quit)
    win.set_filter("dot")
    win.open_file(dotOutputFile)
    gobject.timeout_add(1000, win.update, dotOutputFile)
    gtk.main()
