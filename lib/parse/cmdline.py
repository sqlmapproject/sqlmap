#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import os
import re
import shlex
import sys

try:
    from optparse import OptionError as ArgumentError
    from optparse import OptionGroup
    from optparse import OptionParser as ArgumentParser
    from optparse import SUPPRESS_HELP as SUPPRESS

    ArgumentParser.add_argument = ArgumentParser.add_option

    def _add_argument_group(self, *args, **kwargs):
        return self.add_option_group(OptionGroup(self, *args, **kwargs))

    ArgumentParser.add_argument_group = _add_argument_group

    def _add_argument(self, *args, **kwargs):
        return self.add_option(*args, **kwargs)

    OptionGroup.add_argument = _add_argument

except ImportError:
    from argparse import ArgumentParser
    from argparse import ArgumentError
    from argparse import SUPPRESS

finally:
    def get_actions(instance):
        for attr in ("option_list", "_group_actions", "_actions"):
            if hasattr(instance, attr):
                return getattr(instance, attr)

    def get_groups(parser):
        return getattr(parser, "option_groups", None) or getattr(parser, "_action_groups")

    def get_all_options(parser):
        retVal = set()

        for option in get_actions(parser):
            if hasattr(option, "option_strings"):
                retVal.update(option.option_strings)
            else:
                retVal.update(option._long_opts)
                retVal.update(option._short_opts)

        for group in get_groups(parser):
            for option in get_actions(group):
                if hasattr(option, "option_strings"):
                    retVal.update(option.option_strings)
                else:
                    retVal.update(option._long_opts)
                    retVal.update(option._short_opts)

        return retVal

from lib.core.common import checkOldOptions
from lib.core.common import checkSystemEncoding
from lib.core.common import dataToStdout
from lib.core.common import expandMnemonics
from lib.core.common import getSafeExString
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import logger
from lib.core.defaults import defaults
from lib.core.dicts import DEPRECATED_OPTIONS
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.exception import SqlmapShellQuitException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSyntaxException
from lib.core.option import _createHomeDirectories
from lib.core.settings import BASIC_HELP_ITEMS
from lib.core.settings import DUMMY_URL
from lib.core.settings import IGNORED_OPTIONS
from lib.core.settings import INFERENCE_UNKNOWN_CHAR
from lib.core.settings import IS_WIN
from lib.core.settings import MAX_HELP_OPTION_LENGTH
from lib.core.settings import VERSION_STRING
from lib.core.shell import autoCompletion
from lib.core.shell import clearHistory
from lib.core.shell import loadHistory
from lib.core.shell import saveHistory
from thirdparty.six.moves import input as _input

def cmdLineParser(argv=None):
    """
    This function parses the command line parameters and arguments
    """

    if not argv:
        argv = sys.argv

    checkSystemEncoding()

    # Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
    _ = getUnicode(os.path.basename(argv[0]), encoding=sys.stdin.encoding)

    usage = "%s%s [options]" % ("%s " % os.path.basename(sys.executable) if not IS_WIN else "", "\"%s\"" % _ if " " in _ else _)
    parser = ArgumentParser(usage=usage)

    try:
        parser.add_argument("--hh", dest="advancedHelp", action="store_true",
            help="Show advanced help message and exit")

        parser.add_argument("--version", dest="showVersion", action="store_true",
            help="Show program's version number and exit")

        parser.add_argument("-v", dest="verbose", type=int,
            help="Verbosity level: 0-6 (default %d)" % defaults.verbose)

        # Target options
        target = parser.add_argument_group("Target", "At least one of these options has to be provided to define the target(s)")

        target.add_argument("-u", "--url", dest="url",
            help="Target URL (e.g. \"http://www.site.com/vuln.php?id=1\")")

        target.add_argument("-d", dest="direct",
            help="Connection string for direct database connection")

        target.add_argument("-l", dest="logFile",
            help="Parse target(s) from Burp or WebScarab proxy log file")

        target.add_argument("-m", dest="bulkFile",
            help="Scan multiple targets given in a textual file ")

        target.add_argument("-r", dest="requestFile",
            help="Load HTTP request from a file")

        target.add_argument("-g", dest="googleDork",
            help="Process Google dork results as target URLs")

        target.add_argument("-c", dest="configFile",
            help="Load options from a configuration INI file")

        # Request options
        request = parser.add_argument_group("Request", "These options can be used to specify how to connect to the target URL")

        request.add_argument("-A", "--user-agent", dest="agent",
            help="HTTP User-Agent header value")

        request.add_argument("-H", "--header", dest="header",
            help="Extra header (e.g. \"X-Forwarded-For: 127.0.0.1\")")

        request.add_argument("--method", dest="method",
            help="Force usage of given HTTP method (e.g. PUT)")

        request.add_argument("--data", dest="data",
            help="Data string to be sent through POST (e.g. \"id=1\")")

        request.add_argument("--param-del", dest="paramDel",
            help="Character used for splitting parameter values (e.g. &)")

        request.add_argument("--cookie", dest="cookie",
            help="HTTP Cookie header value (e.g. \"PHPSESSID=a8d127e..\")")

        request.add_argument("--cookie-del", dest="cookieDel",
            help="Character used for splitting cookie values (e.g. ;)")

        request.add_argument("--live-cookies", dest="liveCookies",
            help="Live cookies file used for loading up-to-date values")

        request.add_argument("--load-cookies", dest="loadCookies",
            help="File containing cookies in Netscape/wget format")

        request.add_argument("--drop-set-cookie", dest="dropSetCookie", action="store_true",
            help="Ignore Set-Cookie header from response")

        request.add_argument("--mobile", dest="mobile", action="store_true",
            help="Imitate smartphone through HTTP User-Agent header")

        request.add_argument("--random-agent", dest="randomAgent", action="store_true",
            help="Use randomly selected HTTP User-Agent header value")

        request.add_argument("--host", dest="host",
            help="HTTP Host header value")

        request.add_argument("--referer", dest="referer",
            help="HTTP Referer header value")

        request.add_argument("--headers", dest="headers",
            help="Extra headers (e.g. \"Accept-Language: fr\\nETag: 123\")")

        request.add_argument("--auth-type", dest="authType",
            help="HTTP authentication type (Basic, Digest, Bearer, ...)")

        request.add_argument("--auth-cred", dest="authCred",
            help="HTTP authentication credentials (name:password)")

        request.add_argument("--auth-file", dest="authFile",
            help="HTTP authentication PEM cert/private key file")

        request.add_argument("--ignore-code", dest="ignoreCode",
            help="Ignore (problematic) HTTP error code (e.g. 401)")

        request.add_argument("--ignore-proxy", dest="ignoreProxy", action="store_true",
            help="Ignore system default proxy settings")

        request.add_argument("--ignore-redirects", dest="ignoreRedirects", action="store_true",
            help="Ignore redirection attempts")

        request.add_argument("--ignore-timeouts", dest="ignoreTimeouts", action="store_true",
            help="Ignore connection timeouts")

        request.add_argument("--proxy", dest="proxy",
            help="Use a proxy to connect to the target URL")

        request.add_argument("--proxy-cred", dest="proxyCred",
            help="Proxy authentication credentials (name:password)")

        request.add_argument("--proxy-file", dest="proxyFile",
            help="Load proxy list from a file")

        request.add_argument("--proxy-freq", dest="proxyFreq", type=int,
            help="Requests between change of proxy from a given list")

        request.add_argument("--tor", dest="tor", action="store_true",
            help="Use Tor anonymity network")

        request.add_argument("--tor-port", dest="torPort",
            help="Set Tor proxy port other than default")

        request.add_argument("--tor-type", dest="torType",
            help="Set Tor proxy type (HTTP, SOCKS4 or SOCKS5 (default))")

        request.add_argument("--check-tor", dest="checkTor", action="store_true",
            help="Check to see if Tor is used properly")

        request.add_argument("--delay", dest="delay", type=float,
            help="Delay in seconds between each HTTP request")

        request.add_argument("--timeout", dest="timeout", type=float,
            help="Seconds to wait before timeout connection (default %d)" % defaults.timeout)

        request.add_argument("--retries", dest="retries", type=int,
            help="Retries when the connection timeouts (default %d)" % defaults.retries)

        request.add_argument("--retry-on", dest="retryOn",
            help="Retry request on regexp matching content (e.g. \"drop\")")

        request.add_argument("--randomize", dest="rParam",
            help="Randomly change value for given parameter(s)")

        request.add_argument("--safe-url", dest="safeUrl",
            help="URL address to visit frequently during testing")

        request.add_argument("--safe-post", dest="safePost",
            help="POST data to send to a safe URL")

        request.add_argument("--safe-req", dest="safeReqFile",
            help="Load safe HTTP request from a file")

        request.add_argument("--safe-freq", dest="safeFreq", type=int,
            help="Regular requests between visits to a safe URL")

        request.add_argument("--skip-urlencode", dest="skipUrlEncode", action="store_true",
            help="Skip URL encoding of payload data")

        request.add_argument("--csrf-token", dest="csrfToken",
            help="Parameter used to hold anti-CSRF token")

        request.add_argument("--csrf-url", dest="csrfUrl",
            help="URL address to visit for extraction of anti-CSRF token")

        request.add_argument("--csrf-method", dest="csrfMethod",
            help="HTTP method to use during anti-CSRF token page visit")

        request.add_argument("--csrf-retries", dest="csrfRetries", type=int,
            help="Retries for anti-CSRF token retrieval (default %d)" % defaults.csrfRetries)

        request.add_argument("--force-ssl", dest="forceSSL", action="store_true",
            help="Force usage of SSL/HTTPS")

        request.add_argument("--chunked", dest="chunked", action="store_true",
            help="Use HTTP chunked transfer encoded (POST) requests")

        request.add_argument("--hpp", dest="hpp", action="store_true",
            help="Use HTTP parameter pollution method")

        request.add_argument("--eval", dest="evalCode",
            help="Evaluate provided Python code before the request (e.g. \"import hashlib;id2=hashlib.md5(id).hexdigest()\")")

        # Optimization options
        optimization = parser.add_argument_group("Optimization", "These options can be used to optimize the performance of sqlmap")

        optimization.add_argument("-o", dest="optimize", action="store_true",
            help="Turn on all optimization switches")

        optimization.add_argument("--predict-output", dest="predictOutput", action="store_true",
            help="Predict common queries output")

        optimization.add_argument("--keep-alive", dest="keepAlive", action="store_true",
            help="Use persistent HTTP(s) connections")

        optimization.add_argument("--null-connection", dest="nullConnection", action="store_true",
            help="Retrieve page length without actual HTTP response body")

        optimization.add_argument("--threads", dest="threads", type=int,
            help="Max number of concurrent HTTP(s) requests (default %d)" % defaults.threads)

        # Injection options
        injection = parser.add_argument_group("Injection", "These options can be used to specify which parameters to test for, provide custom injection payloads and optional tampering scripts")

        injection.add_argument("-p", dest="testParameter",
            help="Testable parameter(s)")

        injection.add_argument("--skip", dest="skip",
            help="Skip testing for given parameter(s)")

        injection.add_argument("--skip-static", dest="skipStatic", action="store_true",
            help="Skip testing parameters that not appear to be dynamic")

        injection.add_argument("--param-exclude", dest="paramExclude",
            help="Regexp to exclude parameters from testing (e.g. \"ses\")")

        injection.add_argument("--param-filter", dest="paramFilter",
            help="Select testable parameter(s) by place (e.g. \"POST\")")

        injection.add_argument("--dbms", dest="dbms",
            help="Force back-end DBMS to provided value")

        injection.add_argument("--dbms-cred", dest="dbmsCred",
            help="DBMS authentication credentials (user:password)")

        injection.add_argument("--os", dest="os",
            help="Force back-end DBMS operating system to provided value")

        injection.add_argument("--invalid-bignum", dest="invalidBignum", action="store_true",
            help="Use big numbers for invalidating values")

        injection.add_argument("--invalid-logical", dest="invalidLogical", action="store_true",
            help="Use logical operations for invalidating values")

        injection.add_argument("--invalid-string", dest="invalidString", action="store_true",
            help="Use random strings for invalidating values")

        injection.add_argument("--no-cast", dest="noCast", action="store_true",
            help="Turn off payload casting mechanism")

        injection.add_argument("--no-escape", dest="noEscape", action="store_true",
            help="Turn off string escaping mechanism")

        injection.add_argument("--prefix", dest="prefix",
            help="Injection payload prefix string")

        injection.add_argument("--suffix", dest="suffix",
            help="Injection payload suffix string")

        injection.add_argument("--tamper", dest="tamper",
            help="Use given script(s) for tampering injection data")

        # Detection options
        detection = parser.add_argument_group("Detection", "These options can be used to customize the detection phase")

        detection.add_argument("--level", dest="level", type=int,
            help="Level of tests to perform (1-5, default %d)" % defaults.level)

        detection.add_argument("--risk", dest="risk", type=int,
            help="Risk of tests to perform (1-3, default %d)" % defaults.risk)

        detection.add_argument("--string", dest="string",
            help="String to match when query is evaluated to True")

        detection.add_argument("--not-string", dest="notString",
            help="String to match when query is evaluated to False")

        detection.add_argument("--regexp", dest="regexp",
            help="Regexp to match when query is evaluated to True")

        detection.add_argument("--code", dest="code", type=int,
            help="HTTP code to match when query is evaluated to True")

        detection.add_argument("--smart", dest="smart", action="store_true",
            help="Perform thorough tests only if positive heuristic(s)")

        detection.add_argument("--text-only", dest="textOnly", action="store_true",
            help="Compare pages based only on the textual content")

        detection.add_argument("--titles", dest="titles", action="store_true",
            help="Compare pages based only on their titles")

        # Techniques options
        techniques = parser.add_argument_group("Techniques", "These options can be used to tweak testing of specific SQL injection techniques")

        techniques.add_argument("--technique", dest="technique",
            help="SQL injection techniques to use (default \"%s\")" % defaults.technique)

        techniques.add_argument("--time-sec", dest="timeSec", type=int,
            help="Seconds to delay the DBMS response (default %d)" % defaults.timeSec)

        techniques.add_argument("--union-cols", dest="uCols",
            help="Range of columns to test for UNION query SQL injection")

        techniques.add_argument("--union-char", dest="uChar",
            help="Character to use for bruteforcing number of columns")

        techniques.add_argument("--union-from", dest="uFrom",
            help="Table to use in FROM part of UNION query SQL injection")

        techniques.add_argument("--dns-domain", dest="dnsDomain",
            help="Domain name used for DNS exfiltration attack")

        techniques.add_argument("--second-url", dest="secondUrl",
            help="Resulting page URL searched for second-order response")

        techniques.add_argument("--second-req", dest="secondReq",
            help="Load second-order HTTP request from file")

        # Fingerprint options
        fingerprint = parser.add_argument_group("Fingerprint")

        fingerprint.add_argument("-f", "--fingerprint", dest="extensiveFp", action="store_true",
            help="Perform an extensive DBMS version fingerprint")

        # Enumeration options
        enumeration = parser.add_argument_group("Enumeration", "These options can be used to enumerate the back-end database management system information, structure and data contained in the tables")

        enumeration.add_argument("-a", "--all", dest="getAll", action="store_true",
            help="Retrieve everything")

        enumeration.add_argument("-b", "--banner", dest="getBanner", action="store_true",
            help="Retrieve DBMS banner")

        enumeration.add_argument("--current-user", dest="getCurrentUser", action="store_true",
            help="Retrieve DBMS current user")

        enumeration.add_argument("--current-db", dest="getCurrentDb", action="store_true",
            help="Retrieve DBMS current database")

        enumeration.add_argument("--hostname", dest="getHostname", action="store_true",
            help="Retrieve DBMS server hostname")

        enumeration.add_argument("--is-dba", dest="isDba", action="store_true",
            help="Detect if the DBMS current user is DBA")

        enumeration.add_argument("--users", dest="getUsers", action="store_true",
            help="Enumerate DBMS users")

        enumeration.add_argument("--passwords", dest="getPasswordHashes", action="store_true",
            help="Enumerate DBMS users password hashes")

        enumeration.add_argument("--privileges", dest="getPrivileges", action="store_true",
            help="Enumerate DBMS users privileges")

        enumeration.add_argument("--roles", dest="getRoles", action="store_true",
            help="Enumerate DBMS users roles")

        enumeration.add_argument("--dbs", dest="getDbs", action="store_true",
            help="Enumerate DBMS databases")

        enumeration.add_argument("--tables", dest="getTables", action="store_true",
            help="Enumerate DBMS database tables")

        enumeration.add_argument("--columns", dest="getColumns", action="store_true",
            help="Enumerate DBMS database table columns")

        enumeration.add_argument("--schema", dest="getSchema", action="store_true",
            help="Enumerate DBMS schema")

        enumeration.add_argument("--count", dest="getCount", action="store_true",
            help="Retrieve number of entries for table(s)")

        enumeration.add_argument("--dump", dest="dumpTable", action="store_true",
            help="Dump DBMS database table entries")

        enumeration.add_argument("--dump-all", dest="dumpAll", action="store_true",
            help="Dump all DBMS databases tables entries")

        enumeration.add_argument("--search", dest="search", action="store_true",
            help="Search column(s), table(s) and/or database name(s)")

        enumeration.add_argument("--comments", dest="getComments", action="store_true",
            help="Check for DBMS comments during enumeration")

        enumeration.add_argument("--statements", dest="getStatements", action="store_true",
            help="Retrieve SQL statements being run on DBMS")

        enumeration.add_argument("-D", dest="db",
            help="DBMS database to enumerate")

        enumeration.add_argument("-T", dest="tbl",
            help="DBMS database table(s) to enumerate")

        enumeration.add_argument("-C", dest="col",
            help="DBMS database table column(s) to enumerate")

        enumeration.add_argument("-X", dest="exclude",
            help="DBMS database identifier(s) to not enumerate")

        enumeration.add_argument("-U", dest="user",
            help="DBMS user to enumerate")

        enumeration.add_argument("--exclude-sysdbs", dest="excludeSysDbs", action="store_true",
            help="Exclude DBMS system databases when enumerating tables")

        enumeration.add_argument("--pivot-column", dest="pivotColumn",
            help="Pivot column name")

        enumeration.add_argument("--where", dest="dumpWhere",
            help="Use WHERE condition while table dumping")

        enumeration.add_argument("--start", dest="limitStart", type=int,
            help="First dump table entry to retrieve")

        enumeration.add_argument("--stop", dest="limitStop", type=int,
            help="Last dump table entry to retrieve")

        enumeration.add_argument("--first", dest="firstChar", type=int,
            help="First query output word character to retrieve")

        enumeration.add_argument("--last", dest="lastChar", type=int,
            help="Last query output word character to retrieve")

        enumeration.add_argument("--sql-query", dest="sqlQuery",
            help="SQL statement to be executed")

        enumeration.add_argument("--sql-shell", dest="sqlShell", action="store_true",
            help="Prompt for an interactive SQL shell")

        enumeration.add_argument("--sql-file", dest="sqlFile",
            help="Execute SQL statements from given file(s)")

        # Brute force options
        brute = parser.add_argument_group("Brute force", "These options can be used to run brute force checks")

        brute.add_argument("--common-tables", dest="commonTables", action="store_true",
            help="Check existence of common tables")

        brute.add_argument("--common-columns", dest="commonColumns", action="store_true",
            help="Check existence of common columns")

        brute.add_argument("--common-files", dest="commonFiles", action="store_true",
            help="Check existence of common files")

        # User-defined function options
        udf = parser.add_argument_group("User-defined function injection", "These options can be used to create custom user-defined functions")

        udf.add_argument("--udf-inject", dest="udfInject", action="store_true",
            help="Inject custom user-defined functions")

        udf.add_argument("--shared-lib", dest="shLib",
            help="Local path of the shared library")

        # File system options
        filesystem = parser.add_argument_group("File system access", "These options can be used to access the back-end database management system underlying file system")

        filesystem.add_argument("--file-read", dest="fileRead",
            help="Read a file from the back-end DBMS file system")

        filesystem.add_argument("--file-write", dest="fileWrite",
            help="Write a local file on the back-end DBMS file system")

        filesystem.add_argument("--file-dest", dest="fileDest",
            help="Back-end DBMS absolute filepath to write to")

        # Takeover options
        takeover = parser.add_argument_group("Operating system access", "These options can be used to access the back-end database management system underlying operating system")

        takeover.add_argument("--os-cmd", dest="osCmd",
            help="Execute an operating system command")

        takeover.add_argument("--os-shell", dest="osShell", action="store_true",
            help="Prompt for an interactive operating system shell")

        takeover.add_argument("--os-pwn", dest="osPwn", action="store_true",
            help="Prompt for an OOB shell, Meterpreter or VNC")

        takeover.add_argument("--os-smbrelay", dest="osSmb", action="store_true",
            help="One click prompt for an OOB shell, Meterpreter or VNC")

        takeover.add_argument("--os-bof", dest="osBof", action="store_true",
            help="Stored procedure buffer overflow "
                                 "exploitation")

        takeover.add_argument("--priv-esc", dest="privEsc", action="store_true",
            help="Database process user privilege escalation")

        takeover.add_argument("--msf-path", dest="msfPath",
            help="Local path where Metasploit Framework is installed")

        takeover.add_argument("--tmp-path", dest="tmpPath",
            help="Remote absolute path of temporary files directory")

        # Windows registry options
        windows = parser.add_argument_group("Windows registry access", "These options can be used to access the back-end database management system Windows registry")

        windows.add_argument("--reg-read", dest="regRead", action="store_true",
            help="Read a Windows registry key value")

        windows.add_argument("--reg-add", dest="regAdd", action="store_true",
            help="Write a Windows registry key value data")

        windows.add_argument("--reg-del", dest="regDel", action="store_true",
            help="Delete a Windows registry key value")

        windows.add_argument("--reg-key", dest="regKey",
            help="Windows registry key")

        windows.add_argument("--reg-value", dest="regVal",
            help="Windows registry key value")

        windows.add_argument("--reg-data", dest="regData",
            help="Windows registry key value data")

        windows.add_argument("--reg-type", dest="regType",
            help="Windows registry key value type")

        # General options
        general = parser.add_argument_group("General", "These options can be used to set some general working parameters")

        general.add_argument("-s", dest="sessionFile",
            help="Load session from a stored (.sqlite) file")

        general.add_argument("-t", dest="trafficFile",
            help="Log all HTTP traffic into a textual file")

        general.add_argument("--answers", dest="answers",
            help="Set predefined answers (e.g. \"quit=N,follow=N\")")

        general.add_argument("--base64", dest="base64Parameter",
            help="Parameter(s) containing Base64 encoded data")

        general.add_argument("--base64-safe", dest="base64Safe", action="store_true",
            help="Use URL and filename safe Base64 alphabet (RFC 4648)")

        general.add_argument("--batch", dest="batch", action="store_true",
            help="Never ask for user input, use the default behavior")

        general.add_argument("--binary-fields", dest="binaryFields",
            help="Result fields having binary values (e.g. \"digest\")")

        general.add_argument("--check-internet", dest="checkInternet", action="store_true",
            help="Check Internet connection before assessing the target")

        general.add_argument("--cleanup", dest="cleanup", action="store_true",
            help="Clean up the DBMS from sqlmap specific UDF and tables")

        general.add_argument("--crawl", dest="crawlDepth", type=int,
            help="Crawl the website starting from the target URL")

        general.add_argument("--crawl-exclude", dest="crawlExclude",
            help="Regexp to exclude pages from crawling (e.g. \"logout\")")

        general.add_argument("--csv-del", dest="csvDel",
            help="Delimiting character used in CSV output (default \"%s\")" % defaults.csvDel)

        general.add_argument("--charset", dest="charset",
            help="Blind SQL injection charset (e.g. \"0123456789abcdef\")")

        general.add_argument("--dump-format", dest="dumpFormat",
            help="Format of dumped data (CSV (default), HTML or SQLITE)")

        general.add_argument("--encoding", dest="encoding",
            help="Character encoding used for data retrieval (e.g. GBK)")

        general.add_argument("--eta", dest="eta", action="store_true",
            help="Display for each output the estimated time of arrival")

        general.add_argument("--flush-session", dest="flushSession", action="store_true",
            help="Flush session files for current target")

        general.add_argument("--forms", dest="forms", action="store_true",
            help="Parse and test forms on target URL")

        general.add_argument("--fresh-queries", dest="freshQueries", action="store_true",
            help="Ignore query results stored in session file")

        general.add_argument("--gpage", dest="googlePage", type=int,
            help="Use Google dork results from specified page number")

        general.add_argument("--har", dest="harFile",
            help="Log all HTTP traffic into a HAR file")

        general.add_argument("--hex", dest="hexConvert", action="store_true",
            help="Use hex conversion during data retrieval")

        general.add_argument("--output-dir", dest="outputDir", action="store",
            help="Custom output directory path")

        general.add_argument("--parse-errors", dest="parseErrors", action="store_true",
            help="Parse and display DBMS error messages from responses")

        general.add_argument("--preprocess", dest="preprocess",
            help="Use given script(s) for preprocessing (request)")

        general.add_argument("--postprocess", dest="postprocess",
            help="Use given script(s) for postprocessing (response)")

        general.add_argument("--repair", dest="repair", action="store_true",
            help="Redump entries having unknown character marker (%s)" % INFERENCE_UNKNOWN_CHAR)

        general.add_argument("--save", dest="saveConfig",
            help="Save options to a configuration INI file")

        general.add_argument("--scope", dest="scope",
            help="Regexp for filtering targets")

        general.add_argument("--skip-heuristics", dest="skipHeuristics", action="store_true",
            help="Skip heuristic detection of vulnerabilities")

        general.add_argument("--skip-waf", dest="skipWaf", action="store_true",
            help="Skip heuristic detection of WAF/IPS protection")

        general.add_argument("--table-prefix", dest="tablePrefix",
            help="Prefix used for temporary tables (default: \"%s\")" % defaults.tablePrefix)

        general.add_argument("--test-filter", dest="testFilter",
            help="Select tests by payloads and/or titles (e.g. ROW)")

        general.add_argument("--test-skip", dest="testSkip",
            help="Skip tests by payloads and/or titles (e.g. BENCHMARK)")

        general.add_argument("--web-root", dest="webRoot",
            help="Web server document root directory (e.g. \"/var/www\")")

        # Miscellaneous options
        miscellaneous = parser.add_argument_group("Miscellaneous", "These options do not fit into any other category")

        miscellaneous.add_argument("-z", dest="mnemonics",
            help="Use short mnemonics (e.g. \"flu,bat,ban,tec=EU\")")

        miscellaneous.add_argument("--alert", dest="alert",
            help="Run host OS command(s) when SQL injection is found")

        miscellaneous.add_argument("--beep", dest="beep", action="store_true",
            help="Beep on question and/or when vulnerability is found")

        miscellaneous.add_argument("--dependencies", dest="dependencies", action="store_true",
            help="Check for missing (optional) sqlmap dependencies")

        miscellaneous.add_argument("--disable-coloring", dest="disableColoring", action="store_true",
            help="Disable console output coloring")

        miscellaneous.add_argument("--list-tampers", dest="listTampers", action="store_true",
            help="Display list of available tamper scripts")

        miscellaneous.add_argument("--no-logging", dest="noLogging", action="store_true",
            help="Disable logging to a file")

        miscellaneous.add_argument("--offline", dest="offline", action="store_true",
            help="Work in offline mode (only use session data)")

        miscellaneous.add_argument("--purge", dest="purge", action="store_true",
            help="Safely remove all content from sqlmap data directory")

        miscellaneous.add_argument("--results-file", dest="resultsFile",
            help="Location of CSV results file in multiple targets mode")

        miscellaneous.add_argument("--shell", dest="shell", action="store_true",
            help="Prompt for an interactive sqlmap shell")

        miscellaneous.add_argument("--tmp-dir", dest="tmpDir",
            help="Local directory for storing temporary files")

        miscellaneous.add_argument("--unstable", dest="unstable", action="store_true",
            help="Adjust options for unstable connections")

        miscellaneous.add_argument("--update", dest="updateAll", action="store_true",
            help="Update sqlmap")

        miscellaneous.add_argument("--wizard", dest="wizard", action="store_true",
            help="Simple wizard interface for beginner users")

        # Hidden and/or experimental options
        parser.add_argument("--crack", dest="hashFile",
            help=SUPPRESS)  # "Load and crack hashes from a file (standalone)"

        parser.add_argument("--dummy", dest="dummy", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--yuge", dest="yuge", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--murphy-rate", dest="murphyRate", type=int,
            help=SUPPRESS)

        parser.add_argument("--debug", dest="debug", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--deprecations", dest="deprecations", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-multi", dest="disableMulti", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-precon", dest="disablePrecon", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-stats", dest="disableStats", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--profile", dest="profile", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--localhost", dest="localhost", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-dbms", dest="forceDbms",
            help=SUPPRESS)

        parser.add_argument("--force-dns", dest="forceDns", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-partial", dest="forcePartial", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-pivoting", dest="forcePivoting", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--ignore-stdin", dest="ignoreStdin", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--non-interactive", dest="nonInteractive", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--gui", dest="gui", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--smoke-test", dest="smokeTest", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--vuln-test", dest="vulnTest", action="store_true",
            help=SUPPRESS)

        # API options
        parser.add_argument("--api", dest="api", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--taskid", dest="taskid",
            help=SUPPRESS)

        parser.add_argument("--database", dest="database",
            help=SUPPRESS)

        # Dirty hack to display longer options without breaking into two lines
        if hasattr(parser, "formatter"):
            def _(self, *args):
                retVal = parser.formatter._format_option_strings(*args)
                if len(retVal) > MAX_HELP_OPTION_LENGTH:
                    retVal = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - parser.formatter.indent_increment)) % retVal
                return retVal

            parser.formatter._format_option_strings = parser.formatter.format_option_strings
            parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser)
        else:
            def _format_action_invocation(self, action):
                retVal = self.__format_action_invocation(action)
                if len(retVal) > MAX_HELP_OPTION_LENGTH:
                    retVal = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - self._indent_increment)) % retVal
                return retVal

            parser.formatter_class.__format_action_invocation = parser.formatter_class._format_action_invocation
            parser.formatter_class._format_action_invocation = _format_action_invocation

        # Dirty hack for making a short option '-hh'
        if hasattr(parser, "get_option"):
            option = parser.get_option("--hh")
            option._short_opts = ["-hh"]
            option._long_opts = []
        else:
            for action in get_actions(parser):
                if action.option_strings == ["--hh"]:
                    action.option_strings = ["-hh"]
                    break

        # Dirty hack for inherent help message of switch '-h'
        if hasattr(parser, "get_option"):
            option = parser.get_option("-h")
            option.help = option.help.capitalize().replace("this help", "basic help")
        else:
            for action in get_actions(parser):
                if action.option_strings == ["-h", "--help"]:
                    action.help = action.help.capitalize().replace("this help", "basic help")
                    break

        _ = []
        advancedHelp = True
        extraHeaders = []
        auxIndexes = {}

        # Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
        for arg in argv:
            _.append(getUnicode(arg, encoding=sys.stdin.encoding))

        argv = _
        checkOldOptions(argv)

        if "--gui" in argv:
            from lib.core.gui import runGui

            runGui(parser)

            raise SqlmapSilentQuitException

        elif "--shell" in argv:
            _createHomeDirectories()

            parser.usage = ""
            cmdLineOptions.sqlmapShell = True

            commands = set(("x", "q", "exit", "quit", "clear"))
            commands.update(get_all_options(parser))

            autoCompletion(AUTOCOMPLETE_TYPE.SQLMAP, commands=commands)

            while True:
                command = None
                prompt = "sqlmap > "

                try:
                    # Note: in Python2 command should not be converted to Unicode before passing to shlex (Reference: https://bugs.python.org/issue1170)
                    command = _input(prompt).strip()
                except (KeyboardInterrupt, EOFError):
                    print()
                    raise SqlmapShellQuitException

                command = re.sub(r"(?i)\Anew\s+", "", command or "")

                if not command:
                    continue
                elif command.lower() == "clear":
                    clearHistory()
                    dataToStdout("[i] history cleared\n")
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                elif command.lower() in ("x", "q", "exit", "quit"):
                    raise SqlmapShellQuitException
                elif command[0] != '-':
                    if not re.search(r"(?i)\A(\?|help)\Z", command):
                        dataToStdout("[!] invalid option(s) provided\n")
                    dataToStdout("[i] valid example: '-u http://www.site.com/vuln.php?id=1 --banner'\n")
                else:
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    loadHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    break

            try:
                for arg in shlex.split(command):
                    argv.append(getUnicode(arg, encoding=sys.stdin.encoding))
            except ValueError as ex:
                raise SqlmapSyntaxException("something went wrong during command line parsing ('%s')" % getSafeExString(ex))

        longOptions = set(re.findall(r"\-\-([^= ]+?)=", parser.format_help()))
        longSwitches = set(re.findall(r"\-\-([^= ]+?)\s", parser.format_help()))

        for i in xrange(len(argv)):
            # Reference: https://en.wiktionary.org/wiki/-
            argv[i] = re.sub(u"\\A(\u2010|\u2013|\u2212|\u2014|\u4e00|\u1680|\uFE63|\uFF0D)+", lambda match: '-' * len(match.group(0)), argv[i])

            # Reference: https://unicode-table.com/en/sets/quotation-marks/
            argv[i] = argv[i].strip(u"\u00AB\u2039\u00BB\u203A\u201E\u201C\u201F\u201D\u2019\u275D\u275E\u276E\u276F\u2E42\u301D\u301E\u301F\uFF02\u201A\u2018\u201B\u275B\u275C")

            if argv[i] == "-hh":
                argv[i] = "-h"
            elif i == 1 and re.search(r"\A(http|www\.|\w[\w.-]+\.\w{2,})", argv[i]) is not None:
                argv[i] = "--url=%s" % argv[i]
            elif len(argv[i]) > 1 and all(ord(_) in xrange(0x2018, 0x2020) for _ in ((argv[i].split('=', 1)[-1].strip() or ' ')[0], argv[i][-1])):
                dataToStdout("[!] copy-pasting illegal (non-console) quote characters from Internet is illegal (%s)\n" % argv[i])
                raise SystemExit
            elif len(argv[i]) > 1 and u"\uff0c" in argv[i].split('=', 1)[-1]:
                dataToStdout("[!] copy-pasting illegal (non-console) comma characters from Internet is illegal (%s)\n" % argv[i])
                raise SystemExit
            elif re.search(r"\A-\w=.+", argv[i]):
                dataToStdout("[!] potentially miswritten (illegal '=') short option detected ('%s')\n" % argv[i])
                raise SystemExit
            elif re.search(r"\A-\w{3,}", argv[i]):
                if argv[i].strip('-').split('=')[0] in (longOptions | longSwitches):
                    argv[i] = "-%s" % argv[i]
            elif argv[i] in IGNORED_OPTIONS:
                argv[i] = ""
            elif argv[i] in DEPRECATED_OPTIONS:
                argv[i] = ""
            elif argv[i].startswith("--data-raw"):
                argv[i] = argv[i].replace("--data-raw", "--data", 1)
            elif argv[i].startswith("--auth-creds"):
                argv[i] = argv[i].replace("--auth-creds", "--auth-cred", 1)
            elif argv[i].startswith("--drop-cookie"):
                argv[i] = argv[i].replace("--drop-cookie", "--drop-set-cookie", 1)
            elif any(argv[i].startswith(_) for _ in ("--tamper", "--ignore-code", "--skip")):
                key = re.search(r"\-?\-(\w+)\b", argv[i]).group(1)
                index = auxIndexes.get(key, None)
                if index is None:
                    index = i if '=' in argv[i] else (i + 1 if i + 1 < len(argv) and not argv[i + 1].startswith('-') else None)
                    auxIndexes[key] = index
                else:
                    delimiter = ','
                    argv[index] = "%s%s%s" % (argv[index], delimiter, argv[i].split('=')[1] if '=' in argv[i] else (argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith('-') else ""))
                    argv[i] = ""
            elif argv[i] in ("-H", "--header") or any(argv[i].startswith("%s=" % _) for _ in ("-H", "--header")):
                if '=' in argv[i]:
                    extraHeaders.append(argv[i].split('=', 1)[1])
                elif i + 1 < len(argv):
                    extraHeaders.append(argv[i + 1])
            elif argv[i] == "--deps":
                argv[i] = "--dependencies"
            elif argv[i] == "--disable-colouring":
                argv[i] = "--disable-coloring"
            elif argv[i] == "-r":
                for j in xrange(i + 2, len(argv)):
                    value = argv[j]
                    if os.path.isfile(value):
                        argv[i + 1] += ",%s" % value
                        argv[j] = ''
                    else:
                        break
            elif re.match(r"\A\d+!\Z", argv[i]) and argv[max(0, i - 1)] == "--threads" or re.match(r"\A--threads.+\d+!\Z", argv[i]):
                argv[i] = argv[i][:-1]
                conf.skipThreadCheck = True
            elif argv[i] == "--version":
                print(VERSION_STRING.split('/')[-1])
                raise SystemExit
            elif argv[i] in ("-h", "--help"):
                advancedHelp = False
                for group in get_groups(parser)[:]:
                    found = False
                    for option in get_actions(group):
                        if option.dest not in BASIC_HELP_ITEMS:
                            option.help = SUPPRESS
                        else:
                            found = True
                    if not found:
                        get_groups(parser).remove(group)
            elif '=' in argv[i] and not argv[i].startswith('-') and argv[i].split('=')[0] in longOptions and re.search(r"\A-{1,2}\w", argv[i - 1]) is None:
                dataToStdout("[!] detected usage of long-option without a starting hyphen ('%s')\n" % argv[i])
                raise SystemExit

        for verbosity in (_ for _ in argv if re.search(r"\A\-v+\Z", _)):
            try:
                if argv.index(verbosity) == len(argv) - 1 or not argv[argv.index(verbosity) + 1].isdigit():
                    conf.verbose = verbosity.count('v')
                    del argv[argv.index(verbosity)]
            except (IndexError, ValueError):
                pass

        try:
            (args, _) = parser.parse_known_args(argv) if hasattr(parser, "parse_known_args") else parser.parse_args(argv)
        except UnicodeEncodeError as ex:
            dataToStdout("\n[!] %s\n" % getUnicode(ex.object.encode("unicode-escape")))
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

        if hasattr(sys.stdin, "fileno") and not any((os.isatty(sys.stdin.fileno()), args.api, args.ignoreStdin, "GITHUB_ACTIONS" in os.environ)):
            args.stdinPipe = iter(sys.stdin.readline, None)
        else:
            args.stdinPipe = None

        if not any((args.direct, args.url, args.logFile, args.bulkFile, args.googleDork, args.configFile, args.requestFile, args.updateAll, args.smokeTest, args.vulnTest, args.wizard, args.dependencies, args.purge, args.listTampers, args.hashFile, args.stdinPipe)):
            errMsg = "missing a mandatory option (-d, -u, -l, -m, -r, -g, -c, --wizard, --shell, --update, --purge, --list-tampers or --dependencies). "
            errMsg += "Use -h for basic and -hh for advanced help\n"
            parser.error(errMsg)

        return args

    except (ArgumentError, TypeError) as ex:
        parser.error(ex)

    except SystemExit:
        # Protection against Windows dummy double clicking
        if IS_WIN and "--non-interactive" not in sys.argv:
            dataToStdout("\nPress Enter to continue...")
            _input()
        raise

    debugMsg = "parsing command line"
    logger.debug(debugMsg)
