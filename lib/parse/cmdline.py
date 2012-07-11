#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import sys

from optparse import OptionError
from optparse import OptionGroup
from optparse import OptionParser
from optparse import SUPPRESS_HELP

from lib.core.common import expandMnemonics
from lib.core.common import getUnicode
from lib.core.data import logger
from lib.core.defaults import defaults
from lib.core.settings import BASIC_HELP_ITEMS
from lib.core.settings import IS_WIN
from lib.core.settings import VERSION_STRING

def cmdLineParser():
    """
    This function parses the command line parameters and arguments
    """

    usage = "%s%s [options]" % ("python " if not IS_WIN else "", \
            "\"%s\"" % sys.argv[0] if " " in sys.argv[0] else sys.argv[0])

    parser = OptionParser(usage=usage)

    try:
        parser.add_option("--hh", dest="advancedHelp",
                          action="store_true",
                          help="Show advanced help message and exit")

        parser.add_option("-v", dest="verbose", type="int",
                          help="Verbosity level: 0-6 (default %d)" % defaults.verbose)

        # Target options
        target = OptionGroup(parser, "Target", "At least one of these "
                             "options has to be specified to set the source "
                             "to get target urls from")

        target.add_option("-d", dest="direct", help="Direct "
                          "connection to the database")

        target.add_option("-u", "--url", dest="url", help="Target url")

        target.add_option("-l", dest="logFile", help="Parse targets from Burp "
                          "or WebScarab proxy logs")

        target.add_option("-m", dest="bulkFile", help="Scan multiple targets enlisted "
                          "in a given textual file ")

        target.add_option("-r", dest="requestFile",
                          help="Load HTTP request from a file")

        target.add_option("-g", dest="googleDork",
                          help="Process Google dork results as target urls")

        target.add_option("-c", dest="configFile",
                          help="Load options from a configuration INI file")

        # Request options
        request = OptionGroup(parser, "Request", "These options can be used "
                              "to specify how to connect to the target url")

        request.add_option("--data", dest="data",
                           help="Data string to be sent through POST")

        request.add_option("--param-del", dest="pDel",
                           help="Character used for splitting parameter values")

        request.add_option("--cookie", dest="cookie",
                           help="HTTP Cookie header")

        request.add_option("--load-cookies", dest="loC",
                           help="File containing cookies in Netscape/wget format")

        request.add_option("--cookie-urlencode", dest="cookieUrlencode",
                             action="store_true",
                             help="URL Encode generated cookie injections")

        request.add_option("--drop-set-cookie", dest="dropSetCookie",
                           action="store_true",
                           help="Ignore Set-Cookie header from response")

        request.add_option("--user-agent", dest="agent",
                           help="HTTP User-Agent header")

        request.add_option("--random-agent", dest="randomAgent",
                           action="store_true",
                           help="Use randomly selected HTTP User-Agent header")

        request.add_option("--randomize", dest="rParam",
                           help="Randomly change value for given parameter(s)")

        request.add_option("--force-ssl", dest="forceSSL",
                           action="store_true",
                           help="Force usage of SSL/HTTPS requests")

        request.add_option("--host", dest="host",
                           help="HTTP Host header")

        request.add_option("--referer", dest="referer",
                           help="HTTP Referer header")

        request.add_option("--headers", dest="headers",
                           help="Extra headers (e.g. \"Accept-Language: fr\\nETag: 123\")")

        request.add_option("--auth-type", dest="aType",
                           help="HTTP authentication type "
                                "(Basic, Digest or NTLM)")

        request.add_option("--auth-cred", dest="aCred",
                           help="HTTP authentication credentials "
                                "(name:password)")

        request.add_option("--auth-cert", dest="aCert",
                           help="HTTP authentication certificate ("
                                "key_file,cert_file)")

        request.add_option("--proxy", dest="proxy",
                           help="Use a HTTP proxy to connect to the target url")

        request.add_option("--proxy-cred", dest="pCred",
                           help="HTTP proxy authentication credentials "
                                "(name:password)")

        request.add_option("--ignore-proxy", dest="ignoreProxy", action="store_true",
                           help="Ignore system default HTTP proxy")

        request.add_option("--delay", dest="delay", type="float",
                           help="Delay in seconds between each HTTP request")

        request.add_option("--timeout", dest="timeout", type="float",
                           help="Seconds to wait before timeout connection "
                                "(default %d)" % defaults.timeout)

        request.add_option("--retries", dest="retries", type="int",
                           help="Retries when the connection timeouts "
                                "(default %d)" % defaults.retries)

        request.add_option("--scope", dest="scope",
                           help="Regexp to filter targets from provided proxy log")

        request.add_option("--safe-url", dest="safUrl",
                           help="Url address to visit frequently during testing")

        request.add_option("--safe-freq", dest="saFreq", type="int",
                           help="Test requests between two visits to a given safe url")

        request.add_option("--skip-urlencode", dest="skipUrlEncode",
                           action="store_true",
                           help="Skip URL encoding of POST data")

        request.add_option("--eval", dest="evalCode",
                           help="Evaluate provided Python code before the request (e.g. \"import hashlib;id2=hashlib.md5(id).hexdigest()\")")

        # Optimization options
        optimization = OptionGroup(parser, "Optimization", "These "
                               "options can be used to optimize the "
                               "performance of sqlmap")

        optimization.add_option("-o", dest="optimize",
                                 action="store_true",
                                 help="Turn on all optimization switches")

        optimization.add_option("--predict-output", dest="predictOutput", action="store_true",
                          help="Predict common queries output")

        optimization.add_option("--keep-alive", dest="keepAlive", action="store_true",
                           help="Use persistent HTTP(s) connections")

        optimization.add_option("--null-connection", dest="nullConnection", action="store_true",
                          help="Retrieve page length without actual HTTP response body")

        optimization.add_option("--threads", dest="threads", type="int",
                           help="Max number of concurrent HTTP(s) "
                                "requests (default %d)" % defaults.threads)

        # Injection options
        injection = OptionGroup(parser, "Injection", "These options can be "
                                "used to specify which parameters to test "
                                "for, provide custom injection payloads and "
                                "optional tampering scripts")

        injection.add_option("-p", dest="testParameter",
                             help="Testable parameter(s)")

        injection.add_option("--dbms", dest="dbms",
                             help="Force back-end DBMS to this value")

        injection.add_option("--os", dest="os",
                             help="Force back-end DBMS operating system "
                                  "to this value")

        injection.add_option("--invalid-bignum", dest="invalidBignum",
                             action="store_true",
                             help="Use big numbers for invalidating values")

        injection.add_option("--invalid-logical", dest="invalidLogical",
                             action="store_true",
                             help="Use logical operations for invalidating values")

        injection.add_option("--no-cast", dest="noCast",
                             action="store_true",
                             help="Turn off payload casting mechanism")

        injection.add_option("--prefix", dest="prefix",
                             help="Injection payload prefix string")

        injection.add_option("--suffix", dest="suffix",
                             help="Injection payload suffix string")

        injection.add_option("--skip", dest="skip",
                             help="Skip testing for given parameter(s)")

        injection.add_option("--tamper", dest="tamper",
                             help="Use given script(s) for tampering injection data")

        # Detection options
        detection = OptionGroup(parser, "Detection", "These options can be "
                                "used to specify how to parse "
                                "and compare page content from "
                                "HTTP responses when using blind SQL "
                                "injection technique")

        detection.add_option("--level", dest="level", type="int",
                             help="Level of tests to perform (1-5, "
                                  "default %d)" % defaults.level)

        detection.add_option("--risk", dest="risk", type="int",
                             help="Risk of tests to perform (0-3, "
                                  "default %d)" % defaults.level)

        detection.add_option("--string", dest="string",
                             help="String to match when "
                                  "query is evaluated to True")

        detection.add_option("--regexp", dest="regexp",
                             help="Regexp to match when "
                                  "query is evaluated to True")

        detection.add_option("--code", dest="code", type="int",
                             help="HTTP code to match when "
                                  "query is evaluated to True")

        detection.add_option("--text-only", dest="textOnly",
                             action="store_true",
                             help="Compare pages based only on the textual content")

        detection.add_option("--titles", dest="titles",
                             action="store_true",
                             help="Compare pages based only on their titles")

        # Techniques options
        techniques = OptionGroup(parser, "Techniques", "These options can be "
                                 "used to tweak testing of specific SQL "
                                 "injection techniques")

        techniques.add_option("--technique", dest="tech",
                              help="SQL injection techniques to test for "
                                   "(default \"%s\")" % defaults.tech)

        techniques.add_option("--time-sec", dest="timeSec",
                              type="int",
                              help="Seconds to delay the DBMS response "
                                   "(default %d)" % defaults.timeSec)

        techniques.add_option("--union-cols", dest="uCols",
                              help="Range of columns to test for UNION query SQL injection")

        techniques.add_option("--union-char", dest="uChar",
                              help="Character to use for bruteforcing number of columns")

        techniques.add_option("--dns-domain", dest="dName",
                              help="Domain name used for DNS exfiltration attack")

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
                                  "you can run your own SQL statements")

        enumeration.add_option("-b", "--banner", dest="getBanner",
                               action="store_true", help="Retrieve DBMS banner")

        enumeration.add_option("--current-user", dest="getCurrentUser",
                               action="store_true",
                               help="Retrieve DBMS current user")

        enumeration.add_option("--current-db", dest="getCurrentDb",
                               action="store_true",
                               help="Retrieve DBMS current database")

        enumeration.add_option("--hostname", dest="getHostname",
                               action="store_true",
                               help="Retrieve DBMS server hostname")

        enumeration.add_option("--is-dba", dest="isDba",
                               action="store_true",
                               help="Detect if the DBMS current user is DBA")

        enumeration.add_option("--users", dest="getUsers", action="store_true",
                               help="Enumerate DBMS users")

        enumeration.add_option("--passwords", dest="getPasswordHashes",
                               action="store_true",
                               help="Enumerate DBMS users password hashes")

        enumeration.add_option("--privileges", dest="getPrivileges",
                               action="store_true",
                               help="Enumerate DBMS users privileges")

        enumeration.add_option("--roles", dest="getRoles",
                               action="store_true",
                               help="Enumerate DBMS users roles")

        enumeration.add_option("--dbs", dest="getDbs", action="store_true",
                               help="Enumerate DBMS databases")

        enumeration.add_option("--tables", dest="getTables", action="store_true",
                               help="Enumerate DBMS database tables")

        enumeration.add_option("--columns", dest="getColumns", action="store_true",
                               help="Enumerate DBMS database table columns")

        enumeration.add_option("--schema", dest="getSchema", action="store_true",
                               help="Enumerate DBMS schema")

        enumeration.add_option("--count", dest="getCount", action="store_true",
                               help="Retrieve number of entries for table(s)")

        enumeration.add_option("--dump", dest="dumpTable", action="store_true",
                               help="Dump DBMS database table entries")

        enumeration.add_option("--dump-all", dest="dumpAll", action="store_true",
                               help="Dump all DBMS databases tables entries")

        enumeration.add_option("--search", dest="search", action="store_true",
                               help="Search column(s), table(s) and/or database name(s)")

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

        enumeration.add_option("--sql-file", dest="sqlFile",
                               help="Execute SQL statements from given file(s)")

        # User-defined function options
        brute = OptionGroup(parser, "Brute force", "These "
                          "options can be used to run brute force "
                          "checks")

        brute.add_option("--common-tables", dest="commonTables", action="store_true",
                               help="Check existence of common tables")

        brute.add_option("--common-columns", dest="commonColumns", action="store_true",
                               help="Check existence of common columns")

        # User-defined function options
        udf = OptionGroup(parser, "User-defined function injection", "These "
                          "options can be used to create custom user-defined "
                          "functions")

        udf.add_option("--udf-inject", dest="udfInject", action="store_true",
                       help="Inject custom user-defined functions")

        udf.add_option("--shared-lib", dest="shLib",
                       help="Local path of the shared library")

        # File system options
        filesystem = OptionGroup(parser, "File system access", "These options "
                                 "can be used to access the back-end database "
                                 "management system underlying file system")

        filesystem.add_option("--file-read", dest="rFile",
                              help="Read a file from the back-end DBMS "
                                   "file system")

        filesystem.add_option("--file-write", dest="wFile",
                              help="Write a local file on the back-end "
                                   "DBMS file system")

        filesystem.add_option("--file-dest", dest="dFile",
                              help="Back-end DBMS absolute filepath to "
                                   "write to")

        # Takeover options
        takeover = OptionGroup(parser, "Operating system access", "These "
                               "options can be used to access the back-end "
                               "database management system underlying "
                               "operating system")

        takeover.add_option("--os-cmd", dest="osCmd",
                            help="Execute an operating system command")

        takeover.add_option("--os-shell", dest="osShell",
                            action="store_true",
                            help="Prompt for an interactive operating "
                                 "system shell")

        takeover.add_option("--os-pwn", dest="osPwn",
                            action="store_true",
                            help="Prompt for an out-of-band shell, "
                                 "meterpreter or VNC")

        takeover.add_option("--os-smbrelay", dest="osSmb",
                            action="store_true",
                            help="One click prompt for an OOB shell, "
                                 "meterpreter or VNC")

        takeover.add_option("--os-bof", dest="osBof",
                            action="store_true",
                            help="Stored procedure buffer overflow "
                                 "exploitation")

        takeover.add_option("--priv-esc", dest="privEsc",
                            action="store_true",
                            help="Database process' user privilege escalation")

        takeover.add_option("--msf-path", dest="msfPath",
                            help="Local path where Metasploit Framework "
                                 "is installed")

        takeover.add_option("--tmp-path", dest="tmpPath",
                            help="Remote absolute path of temporary files "
                                 "directory")

        # Windows registry options
        windows = OptionGroup(parser, "Windows registry access", "These "
                               "options can be used to access the back-end "
                               "database management system Windows "
                               "registry")

        windows.add_option("--reg-read", dest="regRead",
                            action="store_true",
                            help="Read a Windows registry key value")

        windows.add_option("--reg-add", dest="regAdd",
                            action="store_true",
                            help="Write a Windows registry key value data")

        windows.add_option("--reg-del", dest="regDel",
                            action="store_true",
                            help="Delete a Windows registry key value")

        windows.add_option("--reg-key", dest="regKey",
                            help="Windows registry key")

        windows.add_option("--reg-value", dest="regVal",
                            help="Windows registry key value")

        windows.add_option("--reg-data", dest="regData",
                            help="Windows registry key value data")

        windows.add_option("--reg-type", dest="regType",
                            help="Windows registry key value type")

        # General options
        general = OptionGroup(parser, "General", "These options can be used "
                             "to set some general working parameters" )

        #general.add_option("-x", dest="xmlFile",
        #                    help="Dump the data into an XML file")

        general.add_option("-t", dest="trafficFile",
                            help="Log all HTTP traffic into a "
                            "textual file")

        general.add_option("--batch", dest="batch",
                            action="store_true",
                            help="Never ask for user input, use the default behaviour")

        general.add_option("--charset", dest="charset",
                            help="Force character encoding used for data retrieval")

        general.add_option("--check-tor", dest="checkTor",
                                  action="store_true",
                                  help="Check to see if Tor is used properly")

        general.add_option("--crawl", dest="crawlDepth", type="int",
                                  help="Crawl the website starting from the target url")

        general.add_option("--csv-del", dest="csvDel",
                                  help="Delimiting character used in CSV output "
                                  "(default \"%s\")" % defaults.csvDel)

        general.add_option("--dbms-cred", dest="dCred",
                            help="DBMS authentication credentials (user:password)")

        general.add_option("--eta", dest="eta",
                            action="store_true",
                            help="Display for each output the "
                                 "estimated time of arrival")

        general.add_option("--flush-session", dest="flushSession",
                            action="store_true",
                            help="Flush session files for current target")

        general.add_option("--forms", dest="forms",
                                  action="store_true",
                                  help="Parse and test forms on target url")

        general.add_option("--fresh-queries", dest="freshQueries",
                            action="store_true",
                            help="Ignores query results stored in session file")

        general.add_option("--hex", dest="hexConvert",
                            action="store_true",
                            help="Uses DBMS hex function(s) for data retrieval")

        general.add_option("--output-dir", dest="oDir",
                            action="store",
                            help="Custom output directory path")

        general.add_option("--parse-errors", dest="parseErrors",
                                  action="store_true",
                                  help="Parse and display DBMS error messages from responses")

        general.add_option("--replicate", dest="replicate",
                                  action="store_true",
                                  help="Replicate dumped data into a sqlite3 database")

        general.add_option("--save", dest="saveCmdline",
                            action="store_true",
                            help="Save options to a configuration INI file")

        general.add_option("--tor", dest="tor",
                                  action="store_true",
                                  help="Use Tor anonymity network")

        general.add_option("--tor-port", dest="torPort",
                                  help="Set Tor proxy port other than default")

        general.add_option("--tor-type", dest="torType",
                                  help="Set Tor proxy type (HTTP - default, SOCKS4 or SOCKS5)")

        general.add_option("--update", dest="updateAll",
                            action="store_true",
                            help="Update sqlmap")

        # Miscellaneous options
        miscellaneous = OptionGroup(parser, "Miscellaneous")

        miscellaneous.add_option("-z", dest="mnemonics",
                               help="Use short mnemonics (e.g. \"flu,bat,ban,tec=EU\")")

        miscellaneous.add_option("--beep", dest="beep",
                                  action="store_true",
                                  help="Sound alert when SQL injection found")

        miscellaneous.add_option("--check-payload", dest="checkPayload",
                                  action="store_true",
                                  help="Offline WAF/IPS/IDS payload detection testing")

        miscellaneous.add_option("--check-waf", dest="checkWaf",
                                  action="store_true",
                                  help="Check for existence of WAF/IPS/IDS protection")

        miscellaneous.add_option("--cleanup", dest="cleanup",
                                  action="store_true",
                                  help="Clean up the DBMS by sqlmap specific "
                                  "UDF and tables")

        miscellaneous.add_option("--dependencies", dest="dependencies",
                                  action="store_true",
                                  help="Check for missing sqlmap dependencies")

        miscellaneous.add_option("--disable-hash", dest="disableHash",
                                  action="store_true",
                                  help="Disable password hash cracking mechanism")

        miscellaneous.add_option("--disable-like", dest="disableLike",
                                  action="store_true",
                                  help="Disable LIKE search of identificator names")

        miscellaneous.add_option("--gpage", dest="googlePage", type="int",
                                  help="Use Google dork results from specified page number")

        miscellaneous.add_option("--mobile", dest="mobile",
                                  action="store_true",
                                  help="Imitate smartphone through HTTP User-Agent header")

        miscellaneous.add_option("--page-rank", dest="pageRank",
                                  action="store_true",
                                  help="Display page rank (PR) for Google dork results")

        miscellaneous.add_option("--purge-output", dest="purgeOutput",
                                  action="store_true",
                                  help="Safely remove all content from output directory")

        miscellaneous.add_option("--smart", dest="smart",
                                  action="store_true",
                                  help="Conduct through tests only if positive heuristic(s)")

        miscellaneous.add_option("--test-filter", dest="tstF",
                                  help="Select tests by payloads and/or titles (e.g. ROW)")

        miscellaneous.add_option("--wizard", dest="wizard",
                                  action="store_true",
                                  help="Simple wizard interface for beginner users")

        # Hidden and/or experimental options
        parser.add_option("--profile", dest="profile", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--cpu-throttle", dest="cpuThrottle", type="int",
                          help=SUPPRESS_HELP)

        parser.add_option("--smoke-test", dest="smokeTest", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--live-test", dest="liveTest", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--real-test", dest="realTest", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--run-case", dest="runCase", type="int",
                          help=SUPPRESS_HELP)

        parser.add_option_group(target)
        parser.add_option_group(request)
        parser.add_option_group(optimization)
        parser.add_option_group(injection)
        parser.add_option_group(detection)
        parser.add_option_group(techniques)
        parser.add_option_group(fingerprint)
        parser.add_option_group(enumeration)
        parser.add_option_group(brute)
        parser.add_option_group(udf)
        parser.add_option_group(filesystem)
        parser.add_option_group(takeover)
        parser.add_option_group(windows)
        parser.add_option_group(general)
        parser.add_option_group(miscellaneous)

        # Dirty hack for making a short option -hh
        option = parser.get_option("--hh")
        option._short_opts = ["-hh"]
        option._long_opts = []

        # Dirty hack for inherent help message of switch -h
        option = parser.get_option("-h")
        option.help = option.help.capitalize().replace("this help", "basic help")

        args = []
        advancedHelp = True

        for arg in sys.argv:
            args.append(getUnicode(arg, system=True))

        # Hide non-basic options in basic help case
        for i in xrange(len(sys.argv)):
            if sys.argv[i] == '-hh':
                sys.argv[i] = '-h'
            elif sys.argv[i] == '-h':
                advancedHelp = False
                for group in parser.option_groups[:]:
                    found = False
                    for option in group.option_list:
                        if option.dest not in BASIC_HELP_ITEMS:
                            option.help = SUPPRESS_HELP
                        else:
                            found = True
                    if not found:
                        parser.option_groups.remove(group)

        try:
            (args, _) = parser.parse_args(args)
        except SystemExit:
            if '-h' in sys.argv and not advancedHelp:
                print "\n[!] to see full list of options run with '-hh'"
            raise

        # Expand given mnemonic options (e.g. -z "ign,flu,bat")
        for i in xrange(len(sys.argv) - 1):
            if sys.argv[i] == '-z':
                expandMnemonics(sys.argv[i+1], parser, args)

        if not any((args.direct, args.url, args.logFile, args.bulkFile, args.googleDork, args.configFile, \
            args.requestFile, args.updateAll, args.smokeTest, args.liveTest, args.realTest, args.wizard, args.dependencies, args.purgeOutput)):
            errMsg = "missing a mandatory option (-d, -u, -l, -m, -r, -g, -c, --wizard, --update, --purge-output or --dependencies), "
            errMsg += "use -h for basic or -hh for advanced help"
            parser.error(errMsg)

        return args

    except (OptionError, TypeError), e:
        parser.error(e)

    except SystemExit:
        # Protection against Windows dummy double clicking
        if IS_WIN:
            print "\nPress Enter to continue...",
            raw_input()
        raise

    debugMsg = "parsing command line"
    logger.debug(debugMsg)
