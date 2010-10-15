#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import sys

from optparse import OptionError
from optparse import OptionGroup
from optparse import OptionParser
from optparse import SUPPRESS_HELP

from lib.core.convert import utf8decode
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

        target.add_option("-d", dest="direct", help="Direct "
                          "connection to the database")

        target.add_option("-u", "--url", dest="url", help="Target url")

        target.add_option("-l", dest="list", help="Parse targets from Burp "
                          "or WebScarab proxy logs")

        target.add_option("-r", dest="requestFile",
                          help="Load HTTP request from a file")

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

        request.add_option("--cookie-urlencode", dest="cookieUrlencode",
                             action="store_true", default=False,
                             help="URL Encode generated cookie injections")

        request.add_option("--drop-set-cookie", dest="dropSetCookie",
                           action="store_true", default=False,
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
                           help="HTTP authentication type "
                                "(Basic, Digest or NTLM)")

        request.add_option("--auth-cred", dest="aCred",
                           help="HTTP authentication credentials "
                                "(name:password)")

        request.add_option("--auth-cert", dest="aCert",
                           help="HTTP authentication certificate ("
                                "key_file,cert_file)")

        request.add_option("--keep-alive", dest="keepAlive", action="store_true",
                           default=False, help="Use persistent HTTP(s) connections")

        request.add_option("--proxy", dest="proxy",
                           help="Use a HTTP proxy to connect to the target url")

        request.add_option("--proxy-cred", dest="pCred",
                           help="HTTP proxy authentication credentials "
                                "(name:password)")

        request.add_option("--ignore-proxy", dest="ignoreProxy", action="store_true",
                           default=False, help="Ignore system default HTTP proxy")

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
                           help="Regexp to filter targets from provided proxy log")

        request.add_option("--safe-url", dest="safUrl", 
                           help="Url address to visit frequently during testing")

        request.add_option("--safe-freq", dest="saFreq", type="int", default=0,
                           help="Test requests between two visits to a given safe url")

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

        injection.add_option("--threshold", dest="thold", type="float",
                             help="Page comparison threshold value (0.0-1.0)")

        injection.add_option("--text-only", dest="textOnly",
                             action="store_true", default=False,
                             help="Compare pages based only on their textual content")

        injection.add_option("--use-between", dest="useBetween",
                             action="store_true", default=False,
                             help="Use operator BETWEEN instead of default '>'")

        injection.add_option("--tamper", dest="tamper",
                             help="Use given module(s) for tampering injection data")

        # Techniques options
        techniques = OptionGroup(parser, "Techniques", "These options can "
                                 "be used to test for specific SQL injection "
                                 "technique or to use one of them to exploit "
                                 "the affected parameter(s) rather than using "
                                 "the default blind SQL injection technique.")

        techniques.add_option("--stacked-test", dest="stackedTest",
                              action="store_true", default=False,
                              help="Test for stacked queries (multiple "
                                   "statements) support")

        techniques.add_option("--time-test", dest="timeTest",
                              action="store_true", default=False,
                              help="Test for time based blind SQL injection")

        techniques.add_option("--time-sec", dest="timeSec",
                              type="int", default=5,
                              help="Seconds to delay the DBMS response "
                                   "(default 5)")

        techniques.add_option("--union-test", dest="unionTest",
                              action="store_true", default=False,
                              help="Test for UNION query (inband) SQL injection")

        techniques.add_option("--union-tech", dest="uTech",
                              help="Technique to test for UNION query SQL injection")

        techniques.add_option("--union-use", dest="unionUse",
                              action="store_true", default=False,
                              help="Use the UNION query (inband) SQL injection "
                                   "to retrieve the queries output. No "
                                   "need to go blind")

        # Fingerprint options
        fingerprint = OptionGroup(parser, "Fingerprint")

        fingerprint.add_option("-f", "--fingerprint", dest="extensiveFp",
                               action="store_true", default=False,
                               help="Perform an extensive DBMS version fingerprint")

        # Enumeration options
        enumeration = OptionGroup(parser, "Enumeration", "These options can "
                                  "be used to enumerate the back-end database "
                                  "management system information, structure "
                                  "and data contained in the tables. Moreover "
                                  "you can run your own SQL statements.")

        enumeration.add_option("-b", "--banner", dest="getBanner",
                               action="store_true", default=False, help="Retrieve DBMS banner")

        enumeration.add_option("--current-user", dest="getCurrentUser",
                               action="store_true", default=False,
                               help="Retrieve DBMS current user")

        enumeration.add_option("--current-db", dest="getCurrentDb",
                               action="store_true", default=False,
                               help="Retrieve DBMS current database")

        enumeration.add_option("--is-dba", dest="isDba",
                               action="store_true", default=False,
                               help="Detect if the DBMS current user is DBA")

        enumeration.add_option("--users", dest="getUsers", action="store_true",
                               default=False, help="Enumerate DBMS users")

        enumeration.add_option("--passwords", dest="getPasswordHashes",
                               action="store_true", default=False,
                               help="Enumerate DBMS users password hashes")

        enumeration.add_option("--privileges", dest="getPrivileges",
                               action="store_true", default=False,
                               help="Enumerate DBMS users privileges")

        enumeration.add_option("--roles", dest="getRoles",
                               action="store_true", default=False,
                               help="Enumerate DBMS users roles")

        enumeration.add_option("--dbs", dest="getDbs", action="store_true",
                               default=False, help="Enumerate DBMS databases")

        enumeration.add_option("--tables", dest="getTables", action="store_true",
                               default=False, help="Enumerate DBMS database tables")

        enumeration.add_option("--columns", dest="getColumns", action="store_true",
                               default=False, help="Enumerate DBMS database table columns")

        enumeration.add_option("--dump", dest="dumpTable", action="store_true",
                               default=False, help="Dump DBMS database table entries")

        enumeration.add_option("--dump-all", dest="dumpAll", action="store_true",
                               default=False, help="Dump all DBMS databases tables entries")

        enumeration.add_option("--search", dest="search", action="store_true",
                               default=False, help="Search column(s), table(s) and/or database name(s)")

        enumeration.add_option("-D", dest="db",
                               help="DBMS database to enumerate")

        enumeration.add_option("-T", dest="tbl",
                               help="DBMS database table to enumerate")

        enumeration.add_option("-C", dest="col",
                               help="DBMS database table column to enumerate")

        enumeration.add_option("-U", dest="user",
                               help="DBMS user to enumerate")

        enumeration.add_option("--exclude-sysdbs", dest="excludeSysDbs",
                               action="store_true", default=False,
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
                               action="store_true", default=False,
                               help="Prompt for an interactive SQL shell")

        enumeration.add_option("--common-exists", dest="cExists", action="store_true",
                               default=False, help="Check existence of common tables")

        enumeration.add_option("--exists", dest="tableFile",
                               help="Check existence of user specified tables")

        # User-defined function options
        udf = OptionGroup(parser, "User-defined function injection", "These "
                          "options can be used to create custom user-defined "
                          "functions.")

        udf.add_option("--udf-inject", dest="udfInject", action="store_true",
                       default=False, help="Inject custom user-defined functions")

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
        takeover = OptionGroup(parser, "Operating system access", "These "
                               "options can be used to access the back-end "
                               "database management system underlying "
                               "operating system.")

        takeover.add_option("--os-cmd", dest="osCmd",
                            help="Execute an operating system command")

        takeover.add_option("--os-shell", dest="osShell",
                            action="store_true", default=False,
                            help="Prompt for an interactive operating "
                                 "system shell")

        takeover.add_option("--os-pwn", dest="osPwn",
                            action="store_true", default=False,
                            help="Prompt for an out-of-band shell, "
                                 "meterpreter or VNC")

        takeover.add_option("--os-smbrelay", dest="osSmb",
                            action="store_true", default=False,
                            help="One click prompt for an OOB shell, "
                                 "meterpreter or VNC")

        takeover.add_option("--os-bof", dest="osBof",
                            action="store_true", default=False,
                            help="Stored procedure buffer overflow "
                                 "exploitation")

        takeover.add_option("--priv-esc", dest="privEsc",
                            action="store_true", default=False,
                            help="Database process' user privilege escalation")

        takeover.add_option("--msf-path", dest="msfPath",
                            help="Local path where Metasploit Framework 3 "
                                 "is installed")

        takeover.add_option("--tmp-path", dest="tmpPath",
                            help="Remote absolute path of temporary files "
                                 "directory")

        # Windows registry options
        windows = OptionGroup(parser, "Windows registry access", "These "
                               "options can be used to access the back-end "
                               "database management system Windows "
                               "registry.")

        windows.add_option("--reg-read", dest="regRead",
                            action="store_true", default=False,
                            help="Read a Windows registry key value")

        windows.add_option("--reg-add", dest="regAdd",
                            action="store_true", default=False,
                            help="Write a Windows registry key value data")

        windows.add_option("--reg-del", dest="regDel",
                            action="store_true", default=False,
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

        miscellaneous.add_option("-o", dest="optimize",
                                 action="store_true", default=False,
                                 help="General optimization switch")

        miscellaneous.add_option("-x", dest="xmlFile",
                                 help="Dump the data into an XML file")

        miscellaneous.add_option("-s", dest="sessionFile",
                                 help="Save and resume all data retrieved "
                                      "on a session file")

        miscellaneous.add_option("--flush-session", dest="flushSession",
                                 action="store_true", default=False,
                                 help="Flush session file for current target")

        miscellaneous.add_option("--forms", dest="forms",
                                 action="store_true", default=False,
                                 help="Parse and test forms on target url")

        miscellaneous.add_option("--eta", dest="eta",
                                 action="store_true", default=False,
                                 help="Display for each output the "
                                      "estimated time of arrival")

        miscellaneous.add_option("--gpage", dest="googlePage", type="int",
                                 help="Use google dork results from specified page number")

        miscellaneous.add_option("--update", dest="updateAll",
                                  action="store_true", default=False,
                                  help="Update sqlmap")

        miscellaneous.add_option("--save", dest="saveCmdline",
                                 action="store_true", default=False,
                                 help="Save options on a configuration INI file")

        miscellaneous.add_option("--batch", dest="batch",
                                 action="store_true", default=False,
                                 help="Never ask for user input, use the default behaviour")

        miscellaneous.add_option("--cleanup", dest="cleanup",
                                 action="store_true", default=False,
                                 help="Clean up the DBMS by sqlmap specific "
                                      "UDF and tables")

        miscellaneous.add_option("--replicate", dest="replicate",
                                 action="store_true", default=False,
                                 help="Replicate dumped data into a sqlite3 database")

        # Hidden and/or experimental options
        parser.add_option("--profile", dest="profile", action="store_true",
                          default=False, help=SUPPRESS_HELP)

        parser.add_option("--cpu-throttle", dest="cpuThrottle", type="int", default=10,
                          help=SUPPRESS_HELP)

        parser.add_option("--common-prediction", dest="useCommonPrediction", action="store_true",
                          default=False, help=SUPPRESS_HELP)

        parser.add_option("--null-connection", dest="useNullConnection", action="store_true",
                          default=False, help=SUPPRESS_HELP)

        parser.add_option("--smoke-test", dest="smokeTest", action="store_true",
                          default=False, help=SUPPRESS_HELP)

        parser.add_option("--live-test", dest="liveTest", action="store_true",
                          default=False, help=SUPPRESS_HELP)

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

        args = []
        for arg in sys.argv:
            try:
                args.append(utf8decode(arg))
            except:
                args.append(unicode(arg, sys.getfilesystemencoding()))
        (args, _) = parser.parse_args(args)

        if not args.direct and not args.url and not args.list and not args.googleDork and not args.configFile\
            and not args.requestFile and not args.updateAll and not args.smokeTest and not args.liveTest:
            errMsg  = "missing a mandatory parameter ('-d', '-u', '-l', '-r', '-g', '-c' or '--update'), "
            errMsg += "-h for help"
            parser.error(errMsg)

        return args
    except (OptionError, TypeError), e:
        parser.error(e)

    debugMsg = "parsing command line"
    logger.debug(debugMsg)
