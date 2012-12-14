<br>
<br>
<br>
<br>
<br>
<br>
<h2 id="thirdparty">Libraries in thirdparty/ directory</h2>

| Library | License | Notes | Switch |
| ------------ | ----------- | ----------- | ----------- |
| [thirdparty/ansistrm/](http://plumberjack.blogspot.co.uk/2010/12/colorizing-logging-output-in-terminals.html) | BSD | Used to colourize logging messages | - |
| [thirdparty/beautifulsoup/](http://www.crummy.com/software/BeautifulSoup/) | BSD | Used to crawl the target site | --crawl |
| [thirdparty/chardet/](http://pypi.python.org/pypi/chardet) | LGPL | Used to heuristically detect the HTTP response body charset | - |
| [thirdparty/clientform/](http://wwwsearch.sourceforge.net/old/ClientForm/) | BSD | Used to parse HTML forms | --forms |
| [thirdparty/colorama/](http://pypi.python.org/pypi/colorama) | BSD | Used to make output colouring cross-platform | - |
| [thirdparty/fcrypt/](http://carey.geek.nz/code/python-fcrypt/) | BSD | Used to crack a generic password hash | --passwords |
| [thirdparty/gprof2dot/](http://code.google.com/p/jrfonseca/wiki/Gprof2Dot) | LGPL | Used for internal debug purposes | --profile |
| [thirdparty/keepalive/](http://urlgrabber.baseurl.org/) | LGPL | Used for persistent HTTP(s) requests | --keep-alive and -o |
| [thirdparty/magic/](http://pypi.python.org/pypi/python-magic/) | PSF | Used to identify and show the file type in log messages | --file-write |
| [thirdparty/multipartpost/](http://pipe.scs.fsu.edu/PostHandler/MultipartPostHandler.py) | LGPL | Used to upload files via web file stager | --os-cmd, --os-shell, --os-pwn |
| [thirdparty/odict/](http://www.voidspace.org.uk/python/odict.html) | BSD | Used internally | - |
| [thirdparty/oset/](http://pypi.python.org/pypi/oset/0.1.1) | BSD | Used to keep multiple targets sorted as they are provided | -l, -m and -g |
| [thirdparty/pagerank/](http://code.google.com/p/corey-projects/) | MIT | Used to display page rank for Google dork results | -g |
| [thirdparty/prettyprint/](http://code.google.com/p/python-httpclient-gui/) | MIT | Used to generate XML output | --xml, to be replaced by --report (#14) |
| [thirdparty/pydes/](http://twhiteman.netfirms.com/des.html) | Free, public domain | Used to crack the Oracle old password format | --passwords |
| [thirdparty/socks/](http://socksipy.sourceforge.net/) | BSD | Used to tunnel your requests over Tor SOCKS proxy | --tor-type and --proxy |
| [thirdparty/termcolor/](http://pypi.python.org/pypi/termcolor) | MIT | Used to colourize output | - |
| [thirdparty/xdot/](http://code.google.com/p/jrfonseca/wiki/XDot) | LGPL | Used for internal debug purposes | --profile |

<h2 id="extra">Libraries and tools in extra/ directory</h2>

These listed are libraries and tools not entirely developed by sqlmap developers only.

| Library / tool | License | Notes | Switch |
| ------------ | ----------- | ----------- | ----------- |
| [extra/icmpsh/](https://github.com/inquisb/icmpsh) | LGPL | Used for OS takeover feature via ICMP | --os-pwn |
| [extra/bottle/](http://bottlepy.org/) | MIT | Used as micro web server for the RESTful API | --restapi and --restapi-port |

<h2 id="notbundled">Dependencies not bundled</h2>

| Library / tool | License | Notes | Switch |
| ------------ | ----------- | ----------- | ----------- |
| [Metasploit Framework](http://www.metasploit.com) | BSD | Used for OS takeover features | --os-pwn, --os-bof, --os-smbshell |
| [PyReadline](http://ipython.scipy.org/moin/PyReadline/Intro) | BSD | Used for TAB autocomplete and history | --os-shell and --sql-shell |
| [python cx_Oracle](http://cx-oracle.sourceforge.net/) | BSD | Connector for Oracle | -d |
| [python-impacket](http://code.google.com/p/impacket/) | BSD | Used for OS takeover feature via icmpsh | --os-pwn |
| [python-kinterbasdb](http://kinterbasdb.sourceforge.net/) | BSD | Connector for Firebird | -d |
| [python-ntlm](http://code.google.com/p/python-ntlm/) | LGPL | Used when the site requires NTLM authentication | --auth-type |
| [python-psycopg2](http://initd.org/psycopg/) | LGPL | Connector for PostgreSQL | -d |
| [python-pyodbc](http://pyodbc.googlecode.com/) | MIT | Connector for Microsoft Access | -d |
| [python-pymssql](http://pymssql.sourceforge.net/) | LGPL | Connector for MS SQL Server | -d |
| [python pymysql](http://code.google.com/p/pymysql/) | MIT | Connector for MySQL | -d |
| [python-pysqlite2](http://pysqlite.googlecode.com/) | MIT | Connector for SQLite 2 | -d |