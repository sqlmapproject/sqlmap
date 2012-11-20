#compdef sqlmap.py

# sqlmap completion commands. written by kost
# put this file in your zsh completion dir and restart your shell. Zsh completion dir is usually 
# located somewhere in /usr/share/zsh/ or /usr/local/share/zsh 

local curcontext="$curcontext" state line

_arguments -C -s \
  '(- *)'{--help,-h}'[Show basic help message and exit]' \
  '(- *)'-hh'[Show advanced help message and exit]' \
  '(-v)'-v+'[Verbosity level: 0-6 (default 1)]:Verbosity level (0-6) - default 1' \
  '(-d)'-d+'[Direct connection to the database]' \
  '(-u,--url)'{-u+,--url=-}'[Target url]' \
  '(-g)'-g+'[Process Google dork results as target urls]' \
  '(--data)'--data=-'[Data string to be sent through POST]' \
  '(-l)'-l+'[Parse targets from Burp or WebScarab proxy logs]:LOGFILE:_files' \
  '(-m)'-m+'[Scan multiple targets enlisted in a given textual file]:BULKFILE:_files' \
  '(-r)'-r+'[Load HTTP request from a file]:REQUESTFILE:_files' \
  '(-s)'-s+'[Load session from a stored (.sqlite) file]:SESSIONFILE:_files' \
  '(-c)'-c+'[Load options from a configuration INI file]:CONFIGFILE:_files' \
  '(--param-del)'--param-del=-'[Character used for splitting parameter values]:PDEL' \
  '(--cookie)'--cookie=-'[HTTP Cookie header]:COOKIE' \
  '(--load-cookies)'--load-cookies=-'[File containing cookies in Netscape/wget format]:COOKIEFILE:_files' \
  '(--drop-set-cookie)'--drop-set-cookie'[Ignore Set-Cookie header from response]' \
  '(--user-agent)'--user-agent=-'[HTTP User-Agent header]:HTTP User Agent' \
  '(--random-agent)'--random-agent'[Use randomly selected HTTP User-Agent header]' \
  '(--randomize)'--randomize=-'[Randomly change value for given parameter(s)]:RPARAM' \
  '(--force-ssl)'--force-ssl'[Force usage of SSL/HTTPS requests]' \
  '(--host)'--host=-'[HTTP Host header]:Host Header' \
  '(--referer)'--referer=-'[HTTP Referer header]:REFERER' \
  '(--headers)'--headers=-'[Extra headers (e.g. Accept-Language: fr\nETag: 123)]:HEADERS' \
  '(--auth-type)'--auth-type=-'[HTTP authentication type (Basic, Digest or NTLM)]:ATYPE' \
  '(--auth-cred)'--auth-cred=-'[HTTP authentication credentials (name:password)]:ACRED' \
  '(--auth-cert)'--auth-cert=-'[HTTP authentication certificate (key_file,cert_file)]:ACERT:_files' \
  '(--proxy)'--proxy=-'[Use a HTTP proxy to connect to the target url]:PROXY' \
  '(--proxy-cred)'--proxy-cred=-'[HTTP proxy authentication credentials (name:password)]:PCRED' \
  '(--ignore-proxy)'--ignore-proxy'[Ignore system default HTTP proxy]' \
  '(--delay)'--delay=-'[Delay in seconds between each HTTP request]:DELAY' \
  '(--timeout)'--timeout=-'[Seconds to wait before timeout connection (default 30)]:TIMEOUT' \
  '(--retries)'--retries=-'[Retries when the connection timeouts (default 3)]:RETRIES' \
  '(--scope)'--scope=-'[Regexp to filter targets from provided proxy log]:SCOPE' \
  '(--safe-url)'--safe-url=-'[Url address to visit frequently during testing]:SAFURL' \
  '(--safe-freq)'--safe-freq=-'[Test requests between two visits to a given safe url]:SAFREQ' \
  '(--skip-urlencode)'--skip-urlencode'[Skip URL encoding of payload data]' \
  '(--eval)'--eval=-'[Evaluate provided Python code before the request (e.g.]:EVALCODE' \
  '(-o)'-o'[Turn on all optimization switches]' \
  '(--predict-output)'--predict-output'[Predict common queries output]' \
  '(--keep-alive)'--keep-alive'[Use persistent HTTP(s) connections]' \
  '(--null-connection)'--null-connection'[Retrieve page length without actual HTTP response body]' \
  '(--threads)'--threads=-'[Max number of concurrent HTTP(s) requests (default 1)]:THREADS' \
  '(-p)'-p+'[Testable parameter(s)]:TESTPARAMETER' \
  '(--dbms)'--dbms=-'[Force back-end DBMS to this value]:DBMS:->list-dbms' \
  '(--os)'--os=-'[Force back-end DBMS operating system to this value]:OS:->list-os' \
  '(--invalid-bignum)'--invalid-bignum'[Use big numbers for invalidating values]' \
  '(--invalid-logical)'--invalid-logical'[Use logical operations for invalidating values]' \
  '(--no-cast)'--no-cast'[Turn off payload casting mechanism]' \
  '(--no-unescape)'--no-unescape'[Turn off string unescaping mechanism]' \
  '(--prefix)'--prefix=-'[Injection payload prefix string]:PREFIX' \
  '(--suffix)'--suffix=-'[Injection payload suffix string]:SUFFIX' \
  '(--skip)'--skip=-'[Skip testing for given parameter(s)]:SKIP' \
  '(--tamper)'--tamper=-'[Use given script(s) for tampering injection data]:TAMPER' \
  '(--level)'--level=-'[Level of tests to perform (1-5, default 1)]:LEVEL (1-5), default 1' \
  '(--risk)'--risk=-'[Risk of tests to perform (0-3, default 1)]:RISK (0-3), default 1' \
  '(--string)'--string=-'[String to match when query is evaluated to True]:STRING' \
  '(--not-string)'--not-string=-'[String to match when query is evaluated to False]:NOTSTRING' \
  '(--regexp)'--regexp=-'[Regexp to match when query is evaluated to True]:REGEXP' \
  '(--code)'--code=-'[HTTP code to match when query is evaluated to True]' \
  '(--text-only)'--text-only'[Compare pages based only on the textual content]' \
  '(--titles)'--titles'[Compare pages based only on their titles]' \
  '(--technique)'--technique=-'[SQL injection techniques to test for (default "BEUST")]:TECH:->list-techniques' \
  '(--time-sec)'--time-sec=-'[Seconds to delay the DBMS response (default 5)]:TIMESEC' \
  '(--union-cols)'--union-cols=-'[Range of columns to test for UNION query SQL injection]:UCOLS' \
  '(--union-char)'--union-char=-'[Character to use for bruteforcing number of columns]:UCHAR' \
  '(--dns-domain)'--dns-domain=-'[Domain name used for DNS exfiltration attack]:DNSDOMAIN' \
  '(--second-order)'--second-order=-'[Resulting page url searched for second-order response]:SECONDORDER' \
  '(-f,--fingerprint)'{-f,--fingerprint}'[Perform an extensive DBMS version fingerprint]' \
  '(-a,--all)'{-a,--all}'[Retrieve everything]' \
  '(-b,--banner)'{-b,--banner}'[Retrieve DBMS banner]' \
  '(--current-user)'--current-user'[Retrieve DBMS current user]' \
  '(--current-db)'--current-db'[Retrieve DBMS current database]' \
  '(--hostname)'--hostname'[Retrieve DBMS server hostname]' \
  '(--is-dba)'--is-dba'[Detect if the DBMS current user is DBA]' \
  '(--users)'--users'[Enumerate DBMS users]' \
  '(--passwords)'--passwords'[Enumerate DBMS users password hashes]' \
  '(--privileges)'--privileges'[Enumerate DBMS users privileges]' \
  '(--roles)'--roles'[Enumerate DBMS users roles]' \
  '(--dbs)'--dbs'[Enumerate DBMS databases]' \
  '(--tables)'--tables'[Enumerate DBMS database tables]' \
  '(--columns)'--columns'[Enumerate DBMS database table columns]' \
  '(--schema)'--schema'[Enumerate DBMS schema]' \
  '(--count)'--count'[Retrieve number of entries for table(s)]' \
  '(--dump)'--dump'[Dump DBMS database table entries]' \
  '(--dump-all)'--dump-all'[Dump all DBMS databases tables entries]' \
  '(--search)'--search'[Search column(s), table(s) and/or database name(s)]' \
  '(-D)'-D+'[DBMS database to enumerate]:DB' \
  '(-T)'-T+'[DBMS database table to enumerate]:TBL' \
  '(-C)'-C+'[DBMS database table column to enumerate]:COL' \
  '(-U)'-U+'[DBMS user to enumerate]:USER' \
  '(--exclude-sysdbs)'--exclude-sysdbs'[Exclude DBMS system databases when enumerating tables]' \
  '(--start)'--start=-'[First query output entry to retrieve]:LIMITSTART' \
  '(--stop)'--stop=-'[Last query output entry to retrieve]:LIMITSTOP' \
  '(--first)'--first=-'[First query output word character to retrieve]:FIRSTCHAR' \
  '(--last)'--last=-'[Last query output word character to retrieve]:LASTCHAR' \
  '(--sql-query)'--sql-query=-'[SQL statement to be executed]:QUERY' \
  '(--sql-shell)'--sql-shell'[Prompt for an interactive SQL shell]' \
  '(--sql-file)'--sql-file=-'[Execute SQL statements from given file(s)]:SQLFILE:_files' \
  '(--common-tables)'--common-tables'[Check existence of common tables]' \
  '(--common-columns)'--common-columns'[Check existence of common columns]' \
  '(--udf-inject)'--udf-inject'[Inject custom user-defined functions]' \
  '(--shared-lib)'--shared-lib=-'[Local path of the shared library]:SHLIB' \
  '(--file-read)'--file-read=-'[Read a file from the back-end DBMS file system]:RFILE' \
  '(--file-write)'--file-write=-'[Write a local file on the back-end DBMS file system]:WFILE' \
  '(--file-dest)'--file-dest=-'[Back-end DBMS absolute filepath to write to]:DFILE' \
  '(--os-cmd)'--os-cmd=-'[Execute an operating system command]:OSCMD' \
  '(--os-shell)'--os-shell'[Prompt for an interactive operating system shell]' \
  '(--os-pwn)'--os-pwn'[Prompt for an out-of-band shell, meterpreter or VNC]' \
  '(--os-smbrelay)'--os-smbrelay'[One click prompt for an OOB shell, meterpreter or VNC]' \
  '(--os-bof)'--os-bof'[Stored procedure buffer overflow exploitation]' \
  '(--priv-esc)'--priv-esc'[Database process user privilege escalation]' \
  '(--msf-path)'--msf-path=-'[Local path where Metasploit Framework is installed]:MSFPATH' \
  '(--tmp-path)'--tmp-path=-'[Remote absolute path of temporary files directory]:TMPPATH' \
  '(--reg-read)'--reg-read'[Read a Windows registry key value]' \
  '(--reg-add)'--reg-add'[Write a Windows registry key value data]' \
  '(--reg-del)'--reg-del'[Delete a Windows registry key value]' \
  '(--reg-key)'--reg-key=-'[Windows registry key]:REGKEY' \
  '(--reg-value)'--reg-value=-'[Windows registry key value]:REGVAL' \
  '(--reg-data)'--reg-data=-'[Windows registry key value data]:REGDATA' \
  '(--reg-type)'--reg-type=-'[Windows registry key value type]:REGTYPE' \
  '(-t)'-t+'[Log all HTTP traffic into a textual file]:TRAFFICFILE' \
  '(--batch)'--batch'[Never ask for user input, use the default behaviour]' \
  '(--charset)'--charset=-'[Force character encoding used for data retrieval]:CHARSET' \
  '(--check-tor)'--check-tor'[Check to see if Tor is used properly]' \
  '(--crawl)'--crawl=-'[Crawl the website starting from the target url]:CRAWLDEPTH' \
  '(--csv-del)'--csv-del=-'[Delimiting character used in CSV output (default is ,)]:CSVDEL' \
  '(--dbms-cred)'--dbms-cred=-'[DBMS authentication credentials (user:password)]:DBMS authentication credentials' \
  '(--eta)'--eta'[Display for each output the estimated time of arrival]' \
  '(--flush-session)'--flush-session'[Flush session files for current target]' \
  '(--forms)'--forms'[Parse and test forms on target url]' \
  '(--fresh-queries)'--fresh-queries'[Ignores query results stored in session file]' \
  '(--hex)'--hex'[Uses DBMS hex function(s) for data retrieval]' \
  '(--output-dir)'--output-dir=-'[Custom output directory path]:ODIR' \
  '(--parse-errors)'--parse-errors'[Parse and display DBMS error messages from responses]' \
  '(--replicate)'--replicate'[Replicate dumped data into a sqlite3 database]' \
  '(--save)'--save'[Save options to a configuration INI file]' \
  '(--tor)'--tor'[Use Tor anonymity network]' \
  '(--tor-port)'--tor-port=-'[Set Tor proxy port other than default]:TORPORT' \
  '(--tor-type)'--tor-type=-'[Set Tor proxy type (HTTP - default, SOCKS4 or SOCKS5)]:TORTYPE' \
  '(--update)'--update'[Update sqlmap]' \
  '(-z)'-z+'[Use short mnemonics (e.g. flu,bat,ban,tec=EU)]:MNEMONICS' \
  '(--check-payload)'--check-payload'[Offline WAF/IPS/IDS payload detection testing]' \
  '(--check-waf)'--check-waf'[Check for existence of WAF/IPS/IDS protection]' \
  '(--cleanup)'--cleanup'[Clean up the DBMS by sqlmap specific UDF and tables]' \
  '(--dependencies)'--dependencies'[Check for missing (non-core) sqlmap dependencies]' \
  '(--disable-coloring)'--disable-coloring'[Disable console output coloring]' \
  '(--gpage)'--gpage=-'[Use Google dork results from specified page number]:GOOGLEPAGE' \
  '(--mobile)'--mobile'[Imitate smartphone through HTTP User-Agent header]' \
  '(--page-rank)'--page-rank'[Display page rank (PR) for Google dork results]' \
  '(--purge-output)'--purge-output'[Safely remove all content from output directory]' \
  '(--smart)'--smart'[Conduct through tests only if positive heuristic(s)]' \
  '(--test-filter)'--test-filter=-'[Select tests by payloads and/or titles (e.g. ROW)]:test-filter' \
  '(--wizard)'--wizard'[Simple wizard interface for beginner users]' && return 0

case "$state" in
  list-dbms)
    _values -S : 'DBMS' 'access' 'db2' 'firebird' 'maxdb' 'mssqlserver' 'mysql' 'oracle' 'postgresql' \
		 'sqlite' 'sybase'
    ;;
  list-os)
    _values -S : 'os' 'Linux' 'Windows' 
    ;;
  list-techniques)
  	_values -S : 'technique' \
	'B[Boolean]' 'E[Error]'  'U[Union]' 'S[Stacked]' 'T[Time]'
  ;;
esac

return 0
