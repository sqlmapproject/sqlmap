#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
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
"""
import codecs

from ConfigParser import NoSectionError
from ConfigParser import RawConfigParser

from lib.core.common import checkFile
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.optiondict import optDict

config = None

def configFileProxy(section, option, boolean=False, integer=False):
    """
    Parse configuration file and save settings into the configuration
    advanced dictionary.
    """

    global config

    if config.has_option(section, option):
        value = config.get(section, option)

        if not value:
            value = None
        elif value.isdigit():
            value = int(value)
        elif value in ("false", "False"):
            value = False
        elif value in ("true", "True"):
            value = True

        if value:
            conf[option] = value
        else:
            conf[option] = None
    else:
        debugMsg  = "missing requested option '%s' (section " % option
        debugMsg += "'%s') into the configuration file, " % section
        debugMsg += "ignoring. Skipping to next."
        logger.debug(debugMsg)

def configFileParser(configFile):
    """
    Parse configuration file and save settings into the configuration
    advanced dictionary.
    """

    global config

    debugMsg = "parsing configuration file"
    logger.debug(debugMsg)

    checkFile(configFile)
    config = RawConfigParser()
    config.readfp(codecs.open(configFile, "r", "UTF8"))

    if not config.has_section("Target"):
        raise NoSectionError, "Target in the configuration file is mandatory"

    condition  = not config.has_option("Target", "url")
    condition &= not config.has_option("Target", "list")
    condition &= not config.has_option("Target", "googleDork")

    if condition:
        errMsg  = "missing a mandatory option in the configuration "
        errMsg += "file (url, list or googleDork)"
        raise sqlmapMissingMandatoryOptionException, errMsg

    for family, optionData in optDict.items():
        for option, data in optionData.items():
            boolean = False
            integer = False

            if isinstance(data, (tuple, dict, set)):
                data = data[0]

            if data == "boolean":
                boolean = True
            elif data == "integer":
                integer = True

            configFileProxy(family, option, boolean, integer)
