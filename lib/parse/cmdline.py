#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re
import shlex
import sys

from optparse import OptionError
from optparse import OptionGroup
from optparse import OptionParser
from optparse import SUPPRESS_HELP

from lib.core.common import checkDeprecatedOptions
from lib.core.common import checkSystemEncoding
from lib.core.common import dataToStdout
from lib.core.common import expandMnemonics
from lib.core.common import getUnicode
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import logger
from lib.core.defaults import defaults
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.exception import SqlmapShellQuitException
from lib.core.exception import SqlmapSyntaxException
from lib.core.settings import BASIC_HELP_ITEMS
from lib.core.settings import DUMMY_URL
from lib.core.settings import IS_WIN
from lib.core.settings import MAX_HELP_OPTION_LENGTH
from lib.core.settings import VERSION_STRING
from lib.core.shell import autoCompletion
from lib.core.shell import clearHistory
from lib.core.shell import loadHistory
from lib.core.shell import saveHistory

def cmdLineParser(argv=None):
    """
    This function parses the command line parameters and arguments
    """

    if not argv:
        argv = sys.argv

    checkSystemEncoding()

    # Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
    _ = getUnicode(os.path.basename(argv[0]), encoding=sys.stdin.encoding)

    usage = "%s%s [options]" % ("python " if not IS_WIN else "", \
            "\"%s\"" % _ if " " in _ else _)

    parser = OptionParser(usage=usage)

    try:
        parser.add_option("--hh", dest="advancedHelp",
                          action="store_true",
                          help="Show advanced help message and exit")

        parser.add_option("--version", dest="showVersion",
                          action="store_true",
                          help="Show program's version number and exit")

        parser.add_option("-v", dest="verbose", type="int",
                          help="Verbosity level: 0-6 (default %d)" % defaults.verbose)

        # Target options
        target = OptionGroup(parser, "Target", "At least one of these "
                             "options has to be provided to define the target(s)")

        target.add_option("-d", dest="direct", help="Connection string "
                          "for direct database connection")

        target.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.site.com/vuln.php?id=1\")")

        target.add_option("-l", dest="logFile", help="Parse target(s) from Burp "
                          "or WebScarab proxy log file")

        target.add_option("-x", dest="sitemapUrl", help="Parse target(s) from remote sitemap(.xml) file")

        target.add_option("-m", dest="bulkFile", help="Scan multiple targets given "
                          "in a textual file ")

        target.add_option("-r", dest="requestFile",
                          help="Load HTTP request from a file")

        target.add_option("-g", dest="googleDork",
                          help="Process Google dork results as target URLs")

        target.add_option("-c", dest="configFile",
                          help="Load options from a configuration INI file")

        # Request options
        request = OptionGroup(parser, "Request", "These options can be used "
                              "to specify how to connect to the target URL")

        request.add_option("--method", dest="method",
                           help="Force usage of given HTTP method (e.g. PUT)")

        request.add_option("--data", dest="data",
                           help="Data string to be sent through POST")

        request.add_option("--param-del", dest="paramDel",
                           help="Character used for splitting parameter values")

        request.add_option("--cookie", dest="cookie",
                           help="HTTP Cookie header value")

        request.add_option("--cookie-del", dest="cookieDel",
                           help="Character used for splitting cookie values")

        request.add_option("--load-cookies", dest="loadCookies",
                           help="File containing cookies in Netscape/wget format")

        request.add_option("--drop-set-cookie", dest="dropSetCookie",
                           action="store_true",
                           help="Ignore Set-Cookie header from response")

        request.add_option("--user-agent", dest="agent",
                           help="HTTP User-Agent header value")

        request.add_option("--random-agent", dest="randomAgent",
                           action="store_true",
                           help="Use randomly selected HTTP User-Agent header value")

        request.add_option("--host", dest="host",
                           help="HTTP Host header value")

        request.add_option("--referer", dest="referer",
                           help="HTTP Referer header value")

        request.add_option("-H", "--header", dest="header",
                           help="Extra header (e.g. \"X-Forwarded-For: 127.0.0.1\")")

        request.add_option("--headers", dest="headers",
                           help="Extra headers (e.g. \"Accept-Language: fr\\nETag: 123\")")

        request.add_option("--auth-type", dest="authType",
                           help="HTTP authentication type "
                                "(Basic, Digest, NTLM or PKI)")

        request.add_option("--auth-cred", dest="authCred",
                           help="HTTP authentication credentials "
                                "(name:password)")

        request.add_option("--auth-file", dest="authFile",
                           help="HTTP authentication PEM cert/private key file")

        request.add_option("--ignore-401", dest="ignore401", action="store_true",
                          help="Ignore HTTP Error 401 (Unauthorized)")

        request.add_option("--ignore-proxy", dest="ignoreProxy", action="store_true",
                           help="Ignore system default proxy settings")

        request.add_option("--ignore-redirects", dest="ignoreRedirects", action="store_true",
                          help="Ignore redirection attempts")

        request.add_option("--ignore-timeouts", dest="ignoreTimeouts", action="store_true",
                          help="Ignore connection timeouts")

        request.add_option("--proxy", dest="proxy",
                           help="Use a proxy to connect to the target URL")

        request.add_option("--proxy-cred", dest="proxyCred",
                           help="Proxy authentication credentials "
                                "(name:password)")

        request.add_option("--proxy-file", dest="proxyFile",
                           help="Load proxy list from a file")

        request.add_option("--tor", dest="tor",
                                  action="store_true",
                                  help="Use Tor anonymity network")

        request.add_option("--tor-port", dest="torPort",
                                  help="Set Tor proxy port other than default")

        request.add_option("--tor-type", dest="torType",
                                  help="Set Tor proxy type (HTTP, SOCKS4 or SOCKS5 (default))")

        request.add_option("--check-tor", dest="checkTor",
                                  action="store_true",
                                  help="Check to see if Tor is used properly")

        request.add_option("--delay", dest="delay", type="float",
                           help="Delay in seconds between each HTTP request")

        request.add_option("--timeout", dest="timeout", type="float",
                           help="Seconds to wait before timeout connection "
                                "(default %d)" % defaults.timeout)

        request.add_option("--retries", dest="retries", type="int",
                           help="Retries when the connection timeouts "
                                "(default %d)" % defaults.retries)

        request.add_option("--randomize", dest="rParam",
                           help="Randomly change value for given parameter(s)")

        request.add_option("--safe-url", dest="safeUrl",
                           help="URL address to visit frequently during testing")

        request.add_option("--safe-post", dest="safePost",
                           help="POST data to send to a safe URL")

        request.add_option("--safe-req", dest="safeReqFile",
                           help="Load safe HTTP request from a file")

        request.add_option("--safe-freq", dest="safeFreq", type="int",
                           help="Test requests between two visits to a given safe URL")

        request.add_option("--skip-urlencode", dest="skipUrlEncode",
                           action="store_true",
                           help="Skip URL encoding of payload data")

        request.add_option("--csrf-token", dest="csrfToken",
                           help="Parameter used to hold anti-CSRF token")

        request.add_option("--csrf-url", dest="csrfUrl",
                           help="URL address to visit to extract anti-CSRF token")

        request.add_option("--force-ssl", dest="forceSSL",
                           action="store_true",
                           help="Force usage of SSL/HTTPS")

        request.add_option("--hpp", dest="hpp",
                                  action="store_true",
                                  help="Use HTTP parameter pollution method")

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

        injection.add_option("--skip", dest="skip",
                             help="Skip testing for given parameter(s)")

        injection.add_option("--skip-static", dest="skipStatic", action="store_true",
                             help="Skip testing parameters that not appear to be dynamic")

        injection.add_option("--param-exclude", dest="paramExclude",
                           help="Regexp to exclude parameters from testing (e.g. \"ses\")")

        injection.add_option("--dbms", dest="dbms",
                             help="Force back-end DBMS to this value")

        injection.add_option("--dbms-cred", dest="dbmsCred",
                            help="DBMS authentication credentials (user:password)")

        injection.add_option("--os", dest="os",
                             help="Force back-end DBMS operating system "
                                  "to this value")

        injection.add_option("--invalid-bignum", dest="invalidBignum",
                             action="store_true",
                             help="Use big numbers for invalidating values")

        injection.add_option("--invalid-logical", dest="invalidLogical",
                             action="store_true",
                             help="Use logical operations for invalidating values")

        injection.add_option("--invalid-string", dest="invalidString",
                             action="store_true",
                             help="Use random strings for invalidating values")

        injection.add_option("--no-cast", dest="noCast",
                             action="store_true",
                             help="Turn off payload casting mechanism")

        injection.add_option("--no-escape", dest="noEscape",
                             action="store_true",
                             help="Turn off string escaping mechanism")

        injection.add_option("--prefix", dest="prefix",
                             help="Injection payload prefix string")

        injection.add_option("--suffix", dest="suffix",
                             help="Injection payload suffix string")

        injection.add_option("--tamper", dest="tamper",
                             help="Use given script(s) for tampering injection data")

        # Detection options
        detection = OptionGroup(parser, "Detection", "These options can be "
                                "used to customize the detection phase")

        detection.add_option("--level", dest="level", type="int",
                             help="Level of tests to perform (1-5, "
                                  "default %d)" % defaults.level)

        detection.add_option("--risk", dest="risk", type="int",
                             help="Risk of tests to perform (1-3, "
                                  "default %d)" % defaults.risk)

        detection.add_option("--string", dest="string",
                             help="String to match when "
                                  "query is evaluated to True")

        detection.add_option("--not-string", dest="notString",
                             help="String to match when "
                                  "query is evaluated to False")

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
                              help="SQL injection techniques to use "
                                   "(default \"%s\")" % defaults.tech)

        techniques.add_option("--time-sec", dest="timeSec",
                              type="int",
                              help="Seconds to delay the DBMS response "
                                   "(default %d)" % defaults.timeSec)

        techniques.add_option("--union-cols", dest="uCols",
                              help="Range of columns to test for UNION query SQL injection")

        techniques.add_option("--union-char", dest="uChar",
                              help="Character to use for bruteforcing number of columns")

        techniques.add_option("--union-from", dest="uFrom",
                              help="Table to use in FROM part of UNION query SQL injection")

        techniques.add_option("--dns-domain", dest="dnsDomain",
                              help="Domain name used for DNS exfiltration attack")

        techniques.add_option("--second-order", dest="secondOrder",
                             help="Resulting page URL searched for second-order "
                                  "response")

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

        enumeration.add_option("-a", "--all", dest="getAll",
                               action="store_true", help="Retrieve everything")

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

        enumeration.add_option("--comments", dest="getComments", action="store_true",
                               help="Retrieve DBMS comments")

        enumeration.add_option("-D", dest="db",
                               help="DBMS database to enumerate")

        enumeration.add_option("-T", dest="tbl",
                               help="DBMS database table(s) to enumerate")

        enumeration.add_option("-C", dest="col",
                               help="DBMS database table column(s) to enumerate")

        enumeration.add_option("-X", dest="excludeCol",
                               help="DBMS database table column(s) to not enumerate")

        enumeration.add_option("-U", dest="user",
                               help="DBMS user to enumerate")

        enumeration.add_option("--exclude-sysdbs", dest="excludeSysDbs",
                               action="store_true",
                               help="Exclude DBMS system databases when "
                                    "enumerating tables")

        enumeration.add_option("--pivot-column", dest="pivotColumn",
                               help="Pivot column name")

        enumeration.add_option("--where", dest="dumpWhere",
                               help="Use WHERE condition while table dumping")

        enumeration.add_option("--start", dest="limitStart", type="int",
                               help="First dump table entry to retrieve")

        enumeration.add_option("--stop", dest="limitStop", type="int",
                               help="Last dump table entry to retrieve")

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

        # Brute force options
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
                            help="Prompt for an OOB shell, "
                                 "Meterpreter or VNC")

        takeover.add_option("--os-smbrelay", dest="osSmb",
                            action="store_true",
                            help="One click prompt for an OOB shell, "
                                 "Meterpreter or VNC")

        takeover.add_option("--os-bof", dest="osBof",
                            action="store_true",
                            help="Stored procedure buffer overflow "
                                 "exploitation")

        takeover.add_option("--priv-esc", dest="privEsc",
                            action="store_true",
                            help="Database process user privilege escalation")

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
                             "to set some general working parameters")

        general.add_option("-s", dest="sessionFile",
                            help="Load session from a stored (.sqlite) file")

        general.add_option("-t", dest="trafficFile",
                            help="Log all HTTP traffic into a "
                            "textual file")

        general.add_option("--batch", dest="batch",
                            action="store_true",
                            help="Never ask for user input, use the default behaviour")

        general.add_option("--binary-fields", dest="binaryFields",
                          help="Result fields having binary values (e.g. \"digest\")")

        general.add_option("--charset", dest="charset",
                            help="Force character encoding used for data retrieval")

        general.add_option("--check-internet", dest="checkInternet",
                            action="store_true",
                            help="Check Internet connection before assessing the target")

        general.add_option("--crawl", dest="crawlDepth", type="int",
                            help="Crawl the website starting from the target URL")

        general.add_option("--crawl-exclude", dest="crawlExclude",
                           help="Regexp to exclude pages from crawling (e.g. \"logout\")")

        general.add_option("--csv-del", dest="csvDel",
                                  help="Delimiting character used in CSV output "
                                  "(default \"%s\")" % defaults.csvDel)

        general.add_option("--dump-format", dest="dumpFormat",
                                  help="Format of dumped data (CSV (default), HTML or SQLITE)")

        general.add_option("--eta", dest="eta",
                            action="store_true",
                            help="Display for each output the estimated time of arrival")

        general.add_option("--flush-session", dest="flushSession",
                            action="store_true",
                            help="Flush session files for current target")

        general.add_option("--forms", dest="forms",
                                  action="store_true",
                                  help="Parse and test forms on target URL")

        general.add_option("--fresh-queries", dest="freshQueries",
                            action="store_true",
                            help="Ignore query results stored in session file")

        general.add_option("--har", dest="harFile",
                           help="Log all HTTP traffic into a HAR file")

        general.add_option("--hex", dest="hexConvert",
                            action="store_true",
                            help="Use DBMS hex function(s) for data retrieval")

        general.add_option("--output-dir", dest="outputDir",
                            action="store",
                            help="Custom output directory path")

        general.add_option("--parse-errors", dest="parseErrors",
                                  action="store_true",
                                  help="Parse and display DBMS error messages from responses")

        general.add_option("--save", dest="saveConfig",
                            help="Save options to a configuration INI file")

        general.add_option("--scope", dest="scope",
                           help="Regexp to filter targets from provided proxy log")

        general.add_option("--test-filter", dest="testFilter",
                           help="Select tests by payloads and/or titles (e.g. ROW)")

        general.add_option("--test-skip", dest="testSkip",
                           help="Skip tests by payloads and/or titles (e.g. BENCHMARK)")

        general.add_option("--update", dest="updateAll",
                            action="store_true",
                            help="Update sqlmap")

        # Miscellaneous options
        miscellaneous = OptionGroup(parser, "Miscellaneous")

        miscellaneous.add_option("-z", dest="mnemonics",
                               help="Use short mnemonics (e.g. \"flu,bat,ban,tec=EU\")")

        miscellaneous.add_option("--alert", dest="alert",
                                  help="Run host OS command(s) when SQL injection is found")

        miscellaneous.add_option("--answers", dest="answers",
                                  help="Set question answers (e.g. \"quit=N,follow=N\")")

        miscellaneous.add_option("--beep", dest="beep", action="store_true",
                                  help="Beep on question and/or when SQL injection is found")

        miscellaneous.add_option("--cleanup", dest="cleanup",
                                  action="store_true",
                                  help="Clean up the DBMS from sqlmap specific "
                                  "UDF and tables")

        miscellaneous.add_option("--dependencies", dest="dependencies",
                                  action="store_true",
                                  help="Check for missing (non-core) sqlmap dependencies")

        miscellaneous.add_option("--disable-coloring", dest="disableColoring",
                                  action="store_true",
                                  help="Disable console output coloring")

        miscellaneous.add_option("--gpage", dest="googlePage", type="int",
                                  help="Use Google dork results from specified page number")

        miscellaneous.add_option("--identify-waf", dest="identifyWaf",
                                  action="store_true",
                                  help="Make a thorough testing for a WAF/IPS/IDS protection")

        miscellaneous.add_option("--mobile", dest="mobile",
                                  action="store_true",
                                  help="Imitate smartphone through HTTP User-Agent header")

        miscellaneous.add_option("--offline", dest="offline",
                                  action="store_true",
                                  help="Work in offline mode (only use session data)")

        miscellaneous.add_option("--purge-output", dest="purgeOutput",
                                  action="store_true",
                                  help="Safely remove all content from output directory")

        miscellaneous.add_option("--skip-waf", dest="skipWaf",
                                  action="store_true",
                                  help="Skip heuristic detection of WAF/IPS/IDS protection")

        miscellaneous.add_option("--smart", dest="smart",
                                  action="store_true",
                                  help="Conduct thorough tests only if positive heuristic(s)")

        miscellaneous.add_option("--sqlmap-shell", dest="sqlmapShell", action="store_true",
                                  help="Prompt for an interactive sqlmap shell")

        miscellaneous.add_option("--tmp-dir", dest="tmpDir",
                                  help="Local directory for storing temporary files")

        miscellaneous.add_option("--web-root", dest="webRoot",
                                  help="Web server document root directory (e.g. \"/var/www\")")

        miscellaneous.add_option("--wizard", dest="wizard",
                                  action="store_true",
                                  help="Simple wizard interface for beginner users")

        # Hidden and/or experimental options
        parser.add_option("--dummy", dest="dummy", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--murphy-rate", dest="murphyRate", type="int",
                          help=SUPPRESS_HELP)

        parser.add_option("--disable-precon", dest="disablePrecon", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--disable-stats", dest="disableStats", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--profile", dest="profile", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--force-dns", dest="forceDns", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--force-threads", dest="forceThreads", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--smoke-test", dest="smokeTest", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--live-test", dest="liveTest", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--stop-fail", dest="stopFail", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--run-case", dest="runCase", help=SUPPRESS_HELP)

        # API options
        parser.add_option("--api", dest="api", action="store_true",
                          help=SUPPRESS_HELP)

        parser.add_option("--taskid", dest="taskid", help=SUPPRESS_HELP)

        parser.add_option("--database", dest="database", help=SUPPRESS_HELP)

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

        # Dirty hack to display longer options without breaking into two lines
        def _(self, *args):
            retVal = parser.formatter._format_option_strings(*args)
            if len(retVal) > MAX_HELP_OPTION_LENGTH:
                retVal = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - parser.formatter.indent_increment)) % retVal
            return retVal

        parser.formatter._format_option_strings = parser.formatter.format_option_strings
        parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser, type(parser))

        # Dirty hack for making a short option '-hh'
        option = parser.get_option("--hh")
        option._short_opts = ["-hh"]
        option._long_opts = []

        # Dirty hack for inherent help message of switch '-h'
        option = parser.get_option("-h")
        option.help = option.help.capitalize().replace("this help", "basic help")

        _ = []
        prompt = False
        advancedHelp = True
        extraHeaders = []

        # Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
        for arg in argv:
            _.append(getUnicode(arg, encoding=sys.stdin.encoding))

        argv = _
        checkDeprecatedOptions(argv)

        prompt = "--sqlmap-shell" in argv

        if prompt:
            parser.usage = ""
            cmdLineOptions.sqlmapShell = True

            _ = ["x", "q", "exit", "quit", "clear"]

            for option in parser.option_list:
                _.extend(option._long_opts)
                _.extend(option._short_opts)

            for group in parser.option_groups:
                for option in group.option_list:
                    _.extend(option._long_opts)
                    _.extend(option._short_opts)

            autoCompletion(AUTOCOMPLETE_TYPE.SQLMAP, commands=_)

            while True:
                command = None

                try:
                    command = raw_input("sqlmap-shell> ").strip()
                    command = getUnicode(command, encoding=sys.stdin.encoding)
                except (KeyboardInterrupt, EOFError):
                    print
                    raise SqlmapShellQuitException

                if not command:
                    continue
                elif command.lower() == "clear":
                    clearHistory()
                    dataToStdout("[i] history cleared\n")
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                elif command.lower() in ("x", "q", "exit", "quit"):
                    raise SqlmapShellQuitException
                elif command[0] != '-':
                    dataToStdout("[!] invalid option(s) provided\n")
                    dataToStdout("[i] proper example: '-u http://www.site.com/vuln.php?id=1 --banner'\n")
                else:
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    loadHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    break

            try:
                for arg in shlex.split(command):
                    argv.append(getUnicode(arg, encoding=sys.stdin.encoding))
            except ValueError, ex:
                raise SqlmapSyntaxException, "something went wrong during command line parsing ('%s')" % ex.message

        for i in xrange(len(argv)):
            if argv[i] == "-hh":
                argv[i] = "-h"
            elif len(argv[i]) > 1 and all(ord(_) in xrange(0x2018, 0x2020) for _ in ((argv[i].split('=', 1)[-1].strip() or ' ')[0], argv[i][-1])):
                dataToStdout("[!] copy-pasting illegal (non-console) quote characters from Internet is, well, illegal (%s)\n" % argv[i])
                raise SystemExit
            elif len(argv[i]) > 1 and u"\uff0c" in argv[i].split('=', 1)[-1]:
                dataToStdout("[!] copy-pasting illegal (non-console) comma characters from Internet is, well, illegal (%s)\n" % argv[i])
                raise SystemExit
            elif re.search(r"\A-\w=.+", argv[i]):
                dataToStdout("[!] potentially miswritten (illegal '=') short option detected ('%s')\n" % argv[i])
                raise SystemExit
            elif argv[i] == "-H":
                if i + 1 < len(argv):
                    extraHeaders.append(argv[i + 1])
            elif re.match(r"\A\d+!\Z", argv[i]) and argv[max(0, i - 1)] == "--threads" or re.match(r"\A--threads.+\d+!\Z", argv[i]):
                argv[i] = argv[i][:-1]
                conf.skipThreadCheck = True
            elif argv[i] == "--version":
                print VERSION_STRING.split('/')[-1]
                raise SystemExit
            elif argv[i] in ("-h", "--help"):
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

        for verbosity in (_ for _ in argv if re.search(r"\A\-v+\Z", _)):
            try:
                if argv.index(verbosity) == len(argv) - 1 or not argv[argv.index(verbosity) + 1].isdigit():
                    conf.verbose = verbosity.count('v') + 1
                    del argv[argv.index(verbosity)]
            except (IndexError, ValueError):
                pass

        try:
            (args, _) = parser.parse_args(argv)
        except UnicodeEncodeError, ex:
            dataToStdout("\n[!] %s\n" % ex.object.encode("unicode-escape"))
            raise SystemExit
        except SystemExit:
            if "-h" in argv and not advancedHelp:
                dataToStdout("\n[!] to see full list of options run with '-hh'\n")
            raise

        if extraHeaders:
            if not args.headers:
                args.headers = ""
            delimiter = "\\n" if "\\n" in args.headers else "\n"
            args.headers += delimiter + delimiter.join(extraHeaders)

        # Expand given mnemonic options (e.g. -z "ign,flu,bat")
        for i in xrange(len(argv) - 1):
            if argv[i] == "-z":
                expandMnemonics(argv[i + 1], parser, args)

        if args.dummy:
            args.url = args.url or DUMMY_URL

        if not any((args.direct, args.url, args.logFile, args.bulkFile, args.googleDork, args.configFile, \
            args.requestFile, args.updateAll, args.smokeTest, args.liveTest, args.wizard, args.dependencies, \
            args.purgeOutput, args.sitemapUrl)):
            errMsg = "missing a mandatory option (-d, -u, -l, -m, -r, -g, -c, -x, --wizard, --update, --purge-output or --dependencies), "
            errMsg += "use -h for basic or -hh for advanced help\n"
            parser.error(errMsg)

        return args

    except (OptionError, TypeError), e:
        parser.error(e)

    except SystemExit:
        # Protection against Windows dummy double clicking
        if IS_WIN:
            dataToStdout("\nPress Enter to continue...")
            raw_input()
        raise

    debugMsg = "parsing command line"
    logger.debug(debugMsg)
