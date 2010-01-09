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
"""

import sys

from optparse import OptionError
from optparse import OptionGroup
from optparse import OptionParser

from lib.core.data import logger
from lib.core.settings import VERSION_STRING

def cmdLineParser():
    """
    This function parses the command line parameters and arguments
    """

    usage = "%s [options]" % sys.argv[0]
    parser = OptionParser(usage=usage, version=VERSION_STRING)

    try:
        parser.add_option("-v", dest="verbose", type="int", default=1,
                          help="Verbosity level: 0-5 (default 1)")

        # Target options
        target = OptionGroup(parser, "Target", "At least one of these "
                             "options has to be specified to set the source "
                             "to get target urls from.")

        target.add_option("-u", "--url", dest="url", help="Target url")

        target.add_option("-l", dest="list", help="Parse targets from Burp "
                          "or WebScarab logs")

        target.add_option("-g", dest="googleDork",
                          help="Process Google dork results as target urls")

        target.add_option("-c", dest="configFile",
                          help="Load options from a configuration INI file")

        # Request options
        request = OptionGroup(parser, "Request", "These options can be used "
                              "to specify how to connect to the target url.")

        request.add_option("--method", dest="method", default="GET",
                           help="HTTP method, GET or POST (default GET)")

        request.add_option("--data", dest="data",
                           help="Data string to be sent through POST")

        request.add_option("--cookie", dest="cookie",
                           help="HTTP Cookie header")

        request.add_option("--drop-set-cookie", dest="dropSetCookie", action="store_true",
                           help="Ignore Set-Cookie header from response")

        request.add_option("--user-agent", dest="agent",
                           help="HTTP User-Agent header")

        request.add_option("-a", dest="userAgentsFile",
                           help="Load a random HTTP User-Agent "
                                "header from file")

        request.add_option("--referer", dest="referer",
                           help="HTTP Referer header")

        request.add_option("--headers", dest="headers",
                           help="Extra HTTP headers newline separated")

        request.add_option("--auth-type", dest="aType",
                           help="HTTP Authentication type "
                                "(Basic, Digest or NTLM)")

        request.add_option("--auth-cred", dest="aCred",
                           help="HTTP Authentication credentials "
                                "(name:password)")
                                
        request.add_option("--auth-cert", dest="aCert",
                           help="HTTPs Authentication certificate ("
                                "key_file,cert_file)")

        request.add_option("--proxy", dest="proxy",
                           help="Use a HTTP proxy to connect to the target url")

        request.add_option("--threads", dest="threads", type="int", default=1,
                           help="Maximum number of concurrent HTTP "
                                "requests (default 1)")

        request.add_option("--delay", dest="delay", type="float",
                           help="Delay in seconds between each HTTP request")

        request.add_option("--timeout", dest="timeout", type="float", default=30,
                           help="Seconds to wait before timeout connection "
                                "(default 30)")

        request.add_option("--retries", dest="retries", type="int", default=3,
                           help="Retries when the connection timeouts "
                                "(default 3)")
        request.add_option("--scope", dest="scope", 
                           help="Regex expression for filtering targets "
                                "from provided Burp or WebScarab log")

        # Injection options
        injection = OptionGroup(parser, "Injection", "These options can be "
                                "used to specify which parameters to test "
                                "for, provide custom injection payloads and "
                                "how to parse and compare HTTP responses "
                                "page content when using the blind SQL "
                                "injection technique.")

        injection.add_option("-p", dest="testParameter",
                             help="Testable parameter(s)")

        injection.add_option("--dbms", dest="dbms",
                             help="Force back-end DBMS to this value")

        injection.add_option("--os", dest="os",
                             help="Force back-end DBMS operating system "
                                  "to this value")

        injection.add_option("--prefix", dest="prefix",
                             help="Injection payload prefix string")

        injection.add_option("--postfix", dest="postfix",
                             help="Injection payload postfix string")

        injection.add_option("--string", dest="string",
                             help="String to match in page when the "
                                  "query is valid")

        injection.add_option("--regexp", dest="regexp",
                             help="Regexp to match in page when the "
                                  "query is valid")

        injection.add_option("--excl-str", dest="eString",
                             help="String to be excluded before comparing "
                                  "page contents")

        injection.add_option("--excl-reg", dest="eRegexp",
                             help="Matches to be excluded before "
                                  "comparing page contents")

        # Techniques options
        techniques = OptionGroup(parser, "Techniques", "These options can "
                                 "be used to test for specific SQL injection "
                                 "technique or to use one of them to exploit "
                                 "the affected parameter(s) rather than using "
                                 "the default blind SQL injection technique.")

        techniques.add_option("--stacked-test", dest="stackedTest",
                              action="store_true",
                              help="Test for stacked queries (multiple "
                                   "statements) support")

        techniques.add_option("--time-test", dest="timeTest",
                              action="store_true",
                              help="Test for time based blind SQL injection")

        techniques.add_option("--time-sec", dest="timeSec",
                              type="int", default=5,
                              help="Seconds to delay the DBMS response "
                                   "(default 5)")

        techniques.add_option("--union-test", dest="unionTest",
                              action="store_true",
                              help="Test for UNION query (inband) SQL injection")

        techniques.add_option("--union-tech", dest="uTech",
                              help="Technique to test for UNION query SQL injection")

        techniques.add_option("--union-use", dest="unionUse",
                              action="store_true",
                              help="Use the UNION query (inband) SQL injection "
                                   "to retrieve the queries output. No "
                                   "need to go blind")

        # Fingerprint options
        fingerprint = OptionGroup(parser, "Fingerprint")

        fingerprint.add_option("-f", "--fingerprint", dest="extensiveFp",
                               action="store_true",
                               help="Perform an extensive DBMS version fingerprint")

        # Enumeration options
        enumeration = OptionGroup(parser, "Enumeration", "These options can "
                                  "be used to enumerate the back-end database "
                                  "management system information, structure "
                                  "and data contained in the tables. Moreover "
                                  "you can run your own SQL statements.")

        enumeration.add_option("-b", "--banner", dest="getBanner",
                               action="store_true", help="Retrieve DBMS banner")

        enumeration.add_option("--current-user", dest="getCurrentUser",
                               action="store_true",
                               help="Retrieve DBMS current user")

        enumeration.add_option("--current-db", dest="getCurrentDb",
                               action="store_true",
                               help="Retrieve DBMS current database")

        enumeration.add_option("--is-dba", dest="isDba",
                               action="store_true",
                               help="Detect if the DBMS current user is DBA")

        enumeration.add_option("--users", dest="getUsers", action="store_true",
                               help="Enumerate DBMS users")

        enumeration.add_option("--passwords", dest="getPasswordHashes",
                               action="store_true",
                               help="Enumerate DBMS users password hashes (opt -U)")

        enumeration.add_option("--privileges", dest="getPrivileges",
                               action="store_true",
                               help="Enumerate DBMS users privileges (opt -U)")

        enumeration.add_option("--dbs", dest="getDbs", action="store_true",
                               help="Enumerate DBMS databases")

        enumeration.add_option("--tables", dest="getTables", action="store_true",
                               help="Enumerate DBMS database tables (opt -D)")

        enumeration.add_option("--columns", dest="getColumns", action="store_true",
                               help="Enumerate DBMS database table columns "
                                    "(req -T opt -D)")

        enumeration.add_option("--dump", dest="dumpTable", action="store_true",
                               help="Dump DBMS database table entries "
                                    "(req -T, opt -D, -C)")

        enumeration.add_option("--dump-all", dest="dumpAll", action="store_true",
                               help="Dump all DBMS databases tables entries")

        enumeration.add_option("-D", dest="db",
                               help="DBMS database to enumerate")

        enumeration.add_option("-T", dest="tbl",
                               help="DBMS database table to enumerate")

        enumeration.add_option("-C", dest="col",
                               help="DBMS database table column to enumerate")

        enumeration.add_option("-U", dest="user",
                               help="DBMS user to enumerate")

        enumeration.add_option("--exclude-sysdbs", dest="excludeSysDbs",
                               action="store_true",
                               help="Exclude DBMS system databases when "
                                    "enumerating tables")

        enumeration.add_option("--start", dest="limitStart", type="int",
                               help="First query output entry to retrieve")

        enumeration.add_option("--stop", dest="limitStop", type="int",
                               help="Last query output entry to retrieve")

        enumeration.add_option("--first", dest="firstChar", type="int",
                               help="First query output word character to retrieve")

        enumeration.add_option("--last", dest="lastChar", type="int",
                               help="Last query output word character to retrieve")

        enumeration.add_option("--sql-query", dest="query",
                               help="SQL statement to be executed")

        enumeration.add_option("--sql-shell", dest="sqlShell",
                               action="store_true",
                               help="Prompt for an interactive SQL shell")

        # User-defined function options
        udf = OptionGroup(parser, "User-defined function injection", "These "
                          "options can be used to create custom user-defined "
                          "functions.")

        udf.add_option("--udf-inject", dest="udfInject", action="store_true",
                       help="Inject custom user-defined functions")

        udf.add_option("--shared-lib", dest="shLib",
                       help="Local path of the shared library")

        # File system options
        filesystem = OptionGroup(parser, "File system access", "These options "
                                 "can be used to access the back-end database "
                                 "management system underlying file system.")

        filesystem.add_option("--read-file", dest="rFile",
                              help="Read a file from the back-end DBMS "
                                   "file system")

        filesystem.add_option("--write-file", dest="wFile",
                              help="Write a local file on the back-end "
                                   "DBMS file system")

        filesystem.add_option("--dest-file", dest="dFile",
                              help="Back-end DBMS absolute filepath to "
                                   "write to")

        # Takeover options
        takeover = OptionGroup(parser, "Operating system access", "This "
                               "option can be used to access the back-end "
                               "database management system underlying "
                               "operating system.")

        takeover.add_option("--os-cmd", dest="osCmd",
                            help="Execute an operating system command")

        takeover.add_option("--os-shell", dest="osShell", action="store_true",
                            help="Prompt for an interactive operating "
                                 "system shell")

        takeover.add_option("--os-pwn", dest="osPwn", action="store_true",
                            help="Prompt for an out-of-band shell, "
                                 "meterpreter or VNC")

        takeover.add_option("--os-smbrelay", dest="osSmb", action="store_true",
                            help="One click prompt for an OOB shell, "
                                 "meterpreter or VNC")

        takeover.add_option("--os-bof", dest="osBof", action="store_true",
                            help="Stored procedure buffer overflow "
                                 "exploitation")

        takeover.add_option("--priv-esc", dest="privEsc", action="store_true",
                            help="User priv escalation by abusing Windows "
                                 "access tokens")

        takeover.add_option("--msf-path", dest="msfPath",
                            help="Local path where Metasploit Framework 3 "
                                 "is installed")

        takeover.add_option("--tmp-path", dest="tmpPath",
                            help="Remote absolute path of temporary files "
                                 "directory")

        # Windows registry options
        windows = OptionGroup(parser, "Windows registry access", "This "
                               "option can be used to access the back-end "
                               "database management system Windows "
                               "registry.")

        windows.add_option("--reg-read", dest="regRead", action="store_true",
                            help="Read a Windows registry key value")

        windows.add_option("--reg-add", dest="regAdd", action="store_true",
                            help="Write a Windows registry key value data")

        windows.add_option("--reg-del", dest="regDel", action="store_true",
                            help="Delete a Windows registry key value")

        windows.add_option("--reg-key", dest="regKey",
                            help="Windows registry key")

        windows.add_option("--reg-value", dest="regVal",
                            help="Windows registry key value")

        windows.add_option("--reg-data", dest="regData",
                            help="Windows registry key value data")

        windows.add_option("--reg-type", dest="regType",
                            help="Windows registry key value type")

        # Miscellaneous options
        miscellaneous = OptionGroup(parser, "Miscellaneous")

        miscellaneous.add_option("-s", dest="sessionFile",
                                 help="Save and resume all data retrieved "
                                      "on a session file")
                                      
        miscellaneous.add_option("--eta", dest="eta", action="store_true",
                                 help="Display for each output the "
                                      "estimated time of arrival")

        miscellaneous.add_option("--gpage", dest="googlePage", type="int",
                               help="Use google dork results from specified page number")

        miscellaneous.add_option("--update", dest="updateAll", action="store_true",
                                help="Update sqlmap to the latest stable version")

        miscellaneous.add_option("--save", dest="saveCmdline", action="store_true",
                                 help="Save options on a configuration INI file")

        miscellaneous.add_option("--batch", dest="batch", action="store_true",
                                 help="Never ask for user input, use the default behaviour")

        miscellaneous.add_option("--cleanup", dest="cleanup", action="store_true",
                                 help="Clean up the DBMS by sqlmap specific "
                                      "UDF and tables")

        parser.add_option_group(target)
        parser.add_option_group(request)
        parser.add_option_group(injection)
        parser.add_option_group(techniques)
        parser.add_option_group(fingerprint)
        parser.add_option_group(enumeration)
        parser.add_option_group(udf)
        parser.add_option_group(filesystem)
        parser.add_option_group(takeover)
        parser.add_option_group(windows)
        parser.add_option_group(miscellaneous)

        (args, _) = parser.parse_args()

        if not args.url and not args.list and not args.googleDork and not args.configFile and not args.updateAll:
            errMsg  = "missing a mandatory parameter ('-u', '-l', '-g', '-c' or '--update'), "
            errMsg += "-h for help"
            parser.error(errMsg)

        return args
    except (OptionError, TypeError), e:
        parser.error(e)

    debugMsg = "parsing command line"
    logger.debug(debugMsg)
