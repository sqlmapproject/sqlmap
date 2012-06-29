by [Bernardo Damele A. G.](mailto:bernardo@sqlmap.org) and [Miroslav Stampar](mailto:miroslav@sqlmap.org)

version 1.0-dev, XXX XX, 2012

# Abstract
This document is the user's manual for [sqlmap](http://www.sqlmap.org).

# Introduction
sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.

## Requirements
sqlmap is developed in [python](http://www.python.org), a dynamic, object-oriented, interpreted programming language freely available from [http://python.org/download/](http://python.org/download/). This makes sqlmap a cross-platform application which is independant of the operating system. sqlmap requires Python version **2.6** or above. To make it even easier, many GNU/Linux distributions come out of the box with Python installed. Other Unixes and Mac OSX also provide Python packaged and ready to be installed. Windows users can download and install the Python installer for x86, AMD64 and Itanium.

sqlmap relies on the [Metasploit Framework](http://metasploit.com) for some of its post-exploitation takeover features. You need to grab a copy of the framework from the [download](http://metasploit.com/download/) page - the required version is **3.5** or higher. For the ICMP tunneling out-of-band takeover technique, sqlmap requires the [Impacket](http://corelabs.coresecurity.com/index.php?module=Wiki&amp;action=view&amp;type=tool&amp;name=Impacket) library too.

If you are willing to connect directly to a database server (switch `-d`), without passing through the web application, you need to install Python bindings for the database management system that you are going to attack:

* Firebird: [python-kinterbasdb](http://kinterbasdb.sourceforge.net/)
* Microsoft Access: [python-pyodbc](http://pyodbc.googlecode.com/)
* Microsoft SQL Server: [python-pymssql](http://pymssql.sourceforge.net/)
* MySQL: [python pymysql](http://code.google.com/p/pymysql/)
* Oracle: [python cx_Oracle](http://cx-oracle.sourceforge.net/)
* PostgreSQL: [python-psycopg2](http://initd.org/psycopg/)
* SQLite: [python-pysqlite2](http://pysqlite.googlecode.com/)
* Sybase: [python-pymssql](http://pymssql.sourceforge.net/)

If you plan to attack a web application behind NTLM authentication or use the sqlmap update functionality (switch `--update`) you need to install respectively [python-ntlm](http://code.google.com/p/python-ntlm/) and [python-svn](http://pysvn.tigris.org/) libraries respectively.

Optionally, if you are running sqlmap on Windows, you may wish to install the [PyReadline](http://ipython.scipy.org/moin/PyReadline/Intro) library in order to take advantage of the sqlmap TAB completion and history support features in the SQL shell and OS shell. Note that these functionalities are available natively via the standard Python [readline](http://docs.python.org/library/readline.html) library on other operating systems.

## Scenario

### Detect and exploit a SQL injection
Let's say that you are auditing a web application and found a web page that accepts dynamic user-provided values via `GET`, `POST` or `Cookie` parameters or via the HTTP `User-Agent` request header.
You now want to test if these are affected by a SQL injection vulnerability, and if so, exploit them to retrieve as much information as possible from the back-end database management system, or even be able to access the underlying file system and operating system.

In a simple world, consider that the target url is:
`http://192.168.136.131/sqlmap/mysql/get_int.php?id=1`

Assume that:
`http://192.168.136.131/sqlmap/mysql/get_int.php?id=1+AND+1=1`

is the same page as the original one and (the condition evaluates to **True**):
`http://192.168.136.131/sqlmap/mysql/get_int.php?id=1+AND+1=2`

differs from the original one (the condition evaluates to **False**). This likely means that you are in front of a SQL injection vulnerability in the `id` `GET` parameter of the `index.php` page. Additionally, no sanitisation of user's supplied input is taking place before the SQL statement is sent to the back-end database management system.

This is quite a common flaw in dynamic content web applications and it does not depend upon the back-end database management system nor on the web application programming language; it is a flaw within the application code. The [Open Web Application Security Project](http://www.owasp.org) rated this class of vulnerability as the [most common](http://owasptop10.googlecode.com/files/OWASP%20Top%2010%20-%202010.pdf) and serious web application vulnerability in their [Top Ten](http://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project) list from 2010.

Now that you have found the vulnerable parameter, you can exploit it by manipulating the `id` parameter value in the HTTP request.

Back to the scenario, we can make an educated guess about the probable syntax of the SQL `SELECT` statement where the user supplied value is being used in the `get_int.php` web page. In pseudo PHP code:

`$query = "SELECT [column name(s)] FROM [table name] WHERE id=" . $_REQUEST['id'];`

As you can see, appending a syntactically valid SQL statement that will evaluate to a **True** condition after the value for the `id` parameter (such as `id=1 AND 1=1`) will result in the web application returning the same web page as in the original request (where no SQL statement is added).
This is because the back-end database management system has evaluated the
injected SQL statement. The previous example describes a simple boolean-based blind SQL injection
vulnerability.  However, sqlmap is able to detect any type of SQL injection flaw and adapt
its work-flow accordingly. 

In this simple scenario it would also be possible to append, not just one or more valid SQL conditions, but also (depending on the DBMS) stacked SQL queries. For instance:  `[...]&id=1;ANOTHER SQL QUERY#`.

sqlmap can automate the process of identifying and exploiting this type of vulnerability. Passing the original address, `http://192.168.136.131/sqlmap/mysql/get_int.php?id=1` to sqlmap, the tool will automatically:

* Identify the vulnerable parameter(s) (`id` in this example)
* Identify which SQL injection techniques can be used to exploit the
vulnerable parameter(s)
* Fingerprint the back-end database management system
* Depending on the user's options, it will extensively fingerprint,
enumerate data or takeover the database server as a whole

...and depending on supplied options, it will enumerate data or takeover the
database server entirely.

There exist many [resources](http://delicious.com/inquis/sqlinjection) on the web explaining in depth how to detect, exploit and prevent SQL injection vulnerabilities in web applications. It is recommendeded that you read them before going much further with sqlmap.

### Direct connection to the database management system
Up until sqlmap version **0.8**, the tool has been **yet another SQL injection tool**, used by web application penetration testers/newbies/curious teens/computer addicted/punks and so on. Things move on
and as they evolve, we do as well. Now it supports this new switch, `-d`, that allows you to connect from your machine to the database server's TCP port where the database management system daemon is listening
on and perform any operation you would do while using it to attack a database via a SQL injection vulnerability.

## Techniques

sqlmap is able to detect and exploit five different SQL injection **types**:

* **Boolean-based blind SQL injection**, also known as **inferential SQL injection**: sqlmap replaces or appends to the affected parameter in the HTTP request, a syntatically valid SQL statement string containing a `SELECT` sub-statement, or any other SQL statement whose the user want to retrieve the output. For each HTTP response, by making a comparison between the HTTP response headers/body with the original request, the tool inference the output of the injected statement character by character. Alternatively, the user can provide a string or regular expression to match on True pages. The bisection algorithm implemented in sqlmap to perform this technique is able to fetch each character of the output with a maximum of seven HTTP requests. Where the output is not within the clear-text plain charset, sqlmap will adapt the algorithm with bigger ranges to detect the output.
* **Time-based blind SQL injection**, also known as **full blind SQL injection**: sqlmap replaces or appends to the affected parameter in the HTTP request, a syntatically valid SQL statement string containing a query which put on hold the back-end DBMS to return for a certain number of seconds. For each HTTP response, by making a comparison between the HTTP response time with the original request, the tool inference the output of the injected statement character by character. Like for boolean-based technique, the bisection algorithm is applied.
* **Error-based SQL injection**: sqlmap replaces or appends to the affected parameter a database-specific error message provoking statement and parses the HTTP response headers and body in search of DBMS error messages containing the injected pre-defined chain of characters and the subquery statement output within. This technique works only when the web application has been configured to disclose back-end database management system error messages.
* **UNION query SQL injection**, also known as **inband SQL injection**: sqlmap appends to the affected parameter a syntactically valid SQL statement starting with an `UNION ALL SELECT`. This techique works when the web application page passes directly the output of the `SELECT` statement within a `for` loop, or similar, so that each line of the query output is printed on the page content. sqlmap is also able to exploit **partial (single entry) UNION query SQL injection** vulnerabilities which occur when the output of the statement is not cycled in a `for` construct, whereas only the first entry of the query output is displayed.
* **Stacked queries SQL injection**, also known as **multiple statements SQL injection**: sqlmap tests if the web application supports stacked queries and then, in case it does support, it appends to the affected
parameter in the HTTP request, a semi-colon (`;`) followed by the SQL statement to be executed. This technique is useful to run SQL statements other than `SELECT`, like for instance, **data definition** or **data manipulation** statements, possibly leading to file system read and write access and operating system command execution depending on the underlying back-end database management system and the session user privileges.

## Demo
You can watch several demo videos, they are hosted on [YouTube](http://www.youtube.com/user/inquisb).

# Features
Features implemented in sqlmap include:
## Generic features
* Full support for **MySQL**, **Oracle**, **PostgreSQL**, **Microsoft SQL Server**, **Microsoft Access**, **SQLite**, **Firebird**, **Sybase** and **SAP MaxDB** database management systems.
* Full support for five SQL injection techniques: **boolean-based blind**, **time-based blind**, **error-based**, **UNION query** and **stacked queries**.
* Support to **directly connect to the database** without passing via a SQL injection, by providing DBMS credentials, IP address, port and database name.
* It is possible to provide a single target URL, get the list of targets from [Burp proxy](http://portswigger.net/suite/) or [WebScarab proxy](http://www.owasp.org/index.php/Category:OWASP_WebScarab_Project) requests log files, get the whole HTTP request from a text file or get the list of targets by providing sqlmap with a Google dork which queries [Google](http://www.google.com) search engine and parses its results page. You can also define a regular-expression based scope that is used to identify which of the parsed addresses to test.
* Tests provided **GET** parameters, **POST** parameters, HTTP **Cookie** header values, HTTP **User-Agent** header value and HTTP **Referer** header value to identify and exploit SQL injection vulnerabilities. It is also possible to specify a comma-separated list of specific parameter(s) to test.
* Option to specify the **maximum number of concurrent HTTP(S) requests (multi-threading)** to speed up the blind SQL injection techniques. Vice versa, it is also possible to specify the number of seconds to hold between each HTTP(S) request. Others optimization switches to speed up the exploitation are implemented too.
* **HTTP `Cookie` header** string support, useful when the web application requires authentication based upon cookies and you have such data or in case you just want to test for and exploit SQL injection on such header values. You can also specify to always URL-encode the Cookie.
* Automatically handles **HTTP `Set-Cookie` header** from the application, re-establishing of the session if it expires. Test and exploit on these values is supported too. Vice versa, you can also force to ignore any `Set-Cookie` header.
* HTTP protocol **Basic, Digest, NTLM and Certificate authentications** support.
* **HTTP(S) proxy** support to pass by the requests to the target application that works also with HTTPS requests and with authenticated proxy servers.
* Options to fake the **HTTP `Referer` header** value and the **HTTP `User-Agent` header** value specified by user or randomly selected from a textual file.
* Support to increase the **verbosity level of output messages**: there exist **seven levels** of verbosity.
* Support to **parse HTML forms** from the target URL and forge HTTP(S) requests against those pages to test the form parameters against vulnerabilities.
* **Granularity and flexibility** in terms of both user's switches and features.
* **Estimated time of arrival** support for each query, updated in real time, to provide the user with an overview on how long it will take to retrieve the queries' output.
* Automatically saves the session (queries and their output, even if partially retrieved) on a textual file in real time while fetching the data and **resumes the injection** by parsing the session file.
* Support to read options from a configuration INI file rather than specify each time all of the switches on the command line. Support also to generate a configuration file based on the command line switches provided.
* Support to **replicate the back-end database tables structure and entries** on a local SQLite 3 database.
* Option to update sqlmap to the latest development version from the subversion repository.
* Support to parse HTTP(S) responses and display any DBMS error message to the user.
* Integration with other IT security open source projects, (http://metasploit.com "Metasploit) and [w3af](http://w3af.sourceforge.net/).

## Fingerprint and enumeration features
* **Extensive back-end database software version and underlying operating system fingerprint** based upon
[error messages](http://bernardodamele.blogspot.com/2007/06/database-management-system-fingerprint.html),
[banner parsing](http://bernardodamele.blogspot.com/2007/06/database-management-system-fingerprint.html),
[functions output comparison](http://bernardodamele.blogspot.com/2007/07/more-on-database-management-system.html) and [specific features](http://bernardodamele.blogspot.com/2007/07/more-on-database-management-system.html) such as MySQL comment injection. It is also possible to force the back-end database management system name if you already know it.
* Basic web server software and web application technology fingerprint.
* Support to retrieve the DBMS **banner**, **session user** and **current database** information. The tool can also check if the session user is a **database administrator** (DBA).
* Support to enumerate **database users**, **users' password hashes**, **users' privileges**, **users' roles**, **databases**, **tables** and **columns**.
* Automatic recognition of password hashes format and support to **crack them with a dictionary-based attack**.
* Support to **brute-force tables and columns name**. This is useful when the session user has no read access over the system table containing schema information or when the database management system does
not store this information anywhere (e.g. MySQL < 5.0).
* Support to **dump database tables** entirely, a range of entries or specific columns as per user's choice. The user can also choose to dump only a range of characters from each column's entry.
* Support to automatically **dump all databases**' schemas and entries. It is possibly to exclude from the dump the system databases.
* Support to **search for specific database names, specific tables across all databases or specific columns across all databases' tables**. This is useful, for instance, to identify tables containing custom application credentials where relevant columns' names contain string like **name** and **pass**.
* Support to **run custom SQL statement(s)** as in an interactive SQL client connecting to the back-end database. sqlmap automatically dissects the provided statement, determines which technique fits best to inject it and how to pack the SQL payload accordingly.

## Takeover features
Some of these techniques are detailed in the white paper
[Advanced SQL injection to operating system full control](http://www.slideshare.net/inquis/advanced-sql-injection-to-operating-system-full-control-whitepaper-4633857) and in the
slide deck [Expanding the control over the operating system from the database](http://www.slideshare.net/inquis/expanding-the-control-over-the-operating-system-from-the-database).
* Support to **inject custom user-defined functions**: the user can compile a shared library then use sqlmap to create within the back-end DBMS user-defined functions out of the compiled shared library file. These
UDFs can then be executed, and optionally removed, via sqlmap. This is supported when the database software is MySQL or PostgreSQL.
* Support to **download and upload any file** from the database server underlying file system when the database software is MySQL, PostgreSQL or Microsoft SQL Server.
* Support to **execute arbitrary commands and retrieve their standard output** on the database server underlying operating system when the database software is MySQL, PostgreSQL or Microsoft SQL Server.
* On MySQL and PostgreSQL via user-defined function injection and execution.
* On Microsoft SQL Server via `xp_cmdshell()` stored procedure.
Also, the stored procedure is re-enabled if disabled or created from scratch if removed by the DBA.
* Support to **establish an out-of-band stateful TCP connection between the attacker machine and the database server** underlying operating system. This channel can be an interactive command prompt, a Meterpreter session or a graphical user interface (VNC) session as per user's choice.
sqlmap relies on Metasploit to create the shellcode and implements four different techniques to execute it on the database server. These techniques are:
* Database **in-memory execution of the Metasploit's shellcode** via sqlmap own user-defined function `sys_bineval()`. Supported on MySQL and PostgreSQL.
* Upload and execution of a Metasploit's **stand-alone payload stager** via sqlmap own user-defined function `sys_exec()` on MySQL and PostgreSQL or via `xp_cmdshell()` on Microsoft SQL Server.
* Execution of Metasploit's shellcode by performing a **SMB reflection attack** ([MS08-068](http://www.microsoft.com/technet/security/Bulletin/MS08-068.mspx) with a UNC path request from the database server to the attacker's machine where the Metasploit `smb_relay` server exploit listens. Supported when running sqlmap with high privileges (`uid=0`) on Linux/Unix and the target DBMS runs as Administrator on Windows.
* Database in-memory execution of the Metasploit's shellcode by exploiting **Microsoft SQL Server 2000 and 2005 `sp_replwritetovarbin` stored procedure heap-based buffer overflow** ([MS09-004](http://www.microsoft.com/technet/security/bulletin/ms09-004.mspx)). sqlmap has its own exploit to trigger the vulnerability with automatic DEP memory protection bypass, but it relies on Metasploit to generate the shellcode to get executed upon successful exploitation.
* Support for **database process' user privilege escalation** via Metasploit's `getsystem` command which include, among others, the 
[kitrap0d](http://archives.neohapsis.com/archives/fulldisclosure/2010-01/0346.html) technique ([MS10-015](http://www.microsoft.com/technet/security/bulletin/ms10-015.mspx)).
* Support to access (read/add/delete) Windows registry hives.

# History

## 2012
* **May 31**, Miroslav [presents](http://phdays.com/program/conference/) his research **DNS exfiltration using sqlmap** ([slides](http://www.slideshare.net/stamparm/dns-exfiltration-using-sqlmap-13163281)) with accompanying [whitepaper](http://www.slideshare.net/stamparm/ph-days-2012miroslavstampardataretrievaloverdnsinsqlinjectionattackspaper) **Data Retrieval over DNS in SQL Injection Attacks** at PHDays 2012 in Moscow, Russia.

## 2011
* **September 23**, Miroslav [presents](http://fsec.foi.hr/index.php/Miroslav_Stampar_-_It_all_starts_with_the_%27_-_SQL_injection_from_attackers_point_of_view) **It all starts with the ' (SQL injection from attacker's point of view)** ([slides](http://www.slideshare.net/stamparm/f-sec-2011miroslavstamparitallstartswiththesinglequote-9311238)) talking about methods attackers use in SQL injection attacks at FSec - FOI Security Symposium in Varazdin, Croatia.
* **June 23**, Miroslav [presents](https://ep2012.europython.eu/conference/talks/sqlmap-security-developing-in-python) **sqlmap - security development in Python** ([slides](http://www.slideshare.net/stamparm/euro-python-2011miroslavstamparsqlmapsecuritydevelopmentinpython)) talking about sqlmap internals at EuroPython 2011 in Firenze, Italy.
* **April 10**, [Bernardo and Miroslav](http://www.sqlmap.org/#developers) release sqlmap **0.9** featuring a totally rewritten and powerful SQL injection detection engine, the possibility to connect directly to a database server, support for time-based blind SQL injection and error-based SQL injection, support for four new database management systems and much more.

## 2010
* **December**, [Bernardo and Miroslav](http://www.sqlmap.org/#developers) have enhanced sqlmap a lot during the whole year and prepare to release sqlmap **0.9** within the first quarter of 2011.
* **June 3**, Bernardo [presents](http://www.slideshare.net/inquis/ath-con-2010bernardodamelegotdbownnet)
a talk titled **Got database access? Own the network!** at AthCon 2010 in Athens (Greece).
* **March 14**, [Bernardo and Miroslav](http://www.sqlmap.org/#developers) release stable version of 
sqlmap **0.8** featuring many features. Amongst these, support to enumerate and dump all databases' tables containing user provided column(s), stabilization and enhancements to the takeover functionalities, updated integration with Metasploit 3.3.3 and a lot of minor features and bug fixes.
* **March**, sqlmap demo videos have been [published](http://www.youtube.com/inquisb).
* **January**, Bernardo is [invited](http://www.athcon.org/speakers/) to present at [AthCon](http://www.athcon.org/archives/2010-2/) conference in Greece on June 2010.

## 2009
* **December 18**, [Miroslav Stampar](http://unconciousmind.blogspot.com/) replies to the call for developers. Along with Bernardo, he actively develops sqlmap from version **0.8 release candidate 2**.
* **December 12**, Bernardo writes to the mailing list a post titled [sqlmap state of art - 3 years later](http://bernardodamele.blogspot.com/2009/12/sqlmap-state-of-art-3-years-later.html) highlighting the goals
achieved during these first three years of the project and launches a call for developers.
* **December 4**, sqlmap-devel mailing list has been merged into sqlmap-users [mailing list](http://www.sqlmap.org/#ml).
* **November 20**, Bernardo and Guido present again their research on stealth database server takeover at CONfidence 2009 in Warsaw, Poland.
* **September 26**, sqlmap version **0.8 release candidate 1** goes public on the [subversion repository]
(https://svn.sqlmap.org/sqlmap/trunk/sqlmap/), with all the attack vectors unveiled at SOURCE Barcelona 2009 Conference. These include an enhanced version of the Microsoft SQL Server buffer overflow exploit to automatically bypass DEP memory protection, support to establish the out-of-band connection with the database server by executing in-memory the Metasploit shellcode via UDF **sys_bineval()** (anti-forensics technique), support to access the Windows registry hives and support to inject custom user-defined functions.
* **September 21**, Bernardo and [Guido Landi](http://www.pornosecurity.org) [present](http://www.sourceconference.com/index.php/pastevents/source-barcelona-2009/schedule) their research ([slides](http://www.slideshare.net/inquis/expanding-the-control-over-the-operating-system-from-the-database)) at SOURCE Conference 2009 in Barcelona, Spain.
* **August**, Bernardo is accepted as a speaker at two others IT security conferences, [SOURCE Barcelona 2009](http://www.sourceconference.com/index.php/pastevents/source-barcelona-2009) and [CONfidence 2009 Warsaw](http://200902.confidence.org.pl/).
This new research is titled **Expanding the control over the operating system from the database**.
* **July 25**, stable version of sqlmap **0.7** is out!
* **June 27**, Bernardo [presents](http://www.slideshare.net/inquis/sql-injection-not-only-and-11-updated)
an updated version of his **SQL injection: Not only AND 1=1** slides at [2nd Digital Security Forum](http://www.digitalsecurityforum.eu/) in Lisbon, Portugal.
* **June 2**, sqlmap version **0.6.4** has made its way to the official Ubuntu repository too.
* **May**, Bernardo presents again his research on operating system takeover via SQL injection at [OWASP AppSec Europe 2009](http://www.owasp.org/index.php/OWASP_AppSec_Europe_2009_-_Poland) in Warsaw, Poland and at [EUSecWest 2009](http://eusecwest.com/) in London, UK.
* **May 8**, sqlmap version **0.6.4** has been officially accepted in Debian repository. Details on 
[this blog post](http://bernardodamele.blogspot.com/2009/05/sqlmap-in-debian-package-repository.html).
* **April 22**, sqlmap version **0.7 release candidate 1** goes public, with all the attack vectors unveiled at Black Hat Europe 2009 Conference. These include execution of arbitrary commands on the underlying operating system, full integration with Metasploit to establish an out-of-band TCP connection, first publicly available exploit for Microsoft Security Bulletin [MS09-004](http://www.microsoft.com/technet/security/Bulletin/MS09-004.mspx) against Microsoft SQL Server 2000 and 2005 and others attacks to takeover the database server as a whole, not only the data from the database.
* **April 16**, Bernardo [presents](http://www.blackhat.com/html/bh-europe-09/bh-eu-09-archives.html#Damele") his research ([slides](http://www.slideshare.net/inquis/advanced-sql-injection-to-operating-system-full-control-slides), 
[whitepaper](http://www.slideshare.net/inquis/advanced-sql-injection-to-operating-system-full-control-whitepaper-4633857)) at Black Hat Europe 2009 in Amsterdam, The Netherlands. The feedback from the audience is good and there has been some [media coverage](http://bernardodamele.blogspot.com/2009/03/black-hat-europe-2009.html) too.
* **March 5**, Bernardo [presents](http://www.slideshare.net/inquis/sql-injection-not-only-and-11) for the first time some of the sqlmap recent features and upcoming enhancements at an international event, 
[Front Range OWASP Conference 2009](http://www.owasp.org/index.php/Front_Range_OWASP_Conference_2009) in Denver, USA. The presentation is titled **SQL injection: Not only AND 1=1**.
* **February 24**, Bernardo is accepted as a [speaker](http://www.blackhat.com/html/bh-europe-09/bh-eu-09-speakers.html#Damele) at [Black Hat Europe 2009](http://www.blackhat.com/html/bh-europe-09/bh-eu-09-main.html) with a presentation titled **Advanced SQL injection exploitation to operating system full control**.
* **February 3**, sqlmap **0.6.4** is the last point release for 0.6: taking advantage of the stacked queries test implemented in 0.6.3, sqlmap can now be used to execute any arbitrary SQL statement, not only
**SELECT** anymore. Also, many features have been stabilized, tweaked and improved in terms of speed in this release.
* **January 9**, Bernardo [presents](http://www.slideshare.net/inquis/sql-injection-exploitation-internals-presentation) **SQL injection exploitation internals** at a private event in London, UK.

## 2008
* **December 18**, sqlmap **0.6.3** is released featuring support to retrieve targets from Burp and WebScarab proxies log files, support to test for stacked queries ant time-based blind SQL injection, rough fingerprint of the web server and web application technologies in use and more options to customize the HTTP requests and enumerate more information from the database.
* **November 2**, sqlmap version **0.6.2** is a "bug fixes" release only.
* **October 20**, sqlmap first point release, **0.6.1**, goes public. This includes minor bug fixes and the first contact between the tool and [Metasploit](http://metasploit.com): an auxiliary module to launch sqlmap from within Metasploit Framework. The [subversion development repository](https://svn.sqlmap.org/sqlmap/trunk/sqlmap/) goes public again.
* **September 1**, nearly one year after the previous release, sqlmap **0.6** comes to life featuring a complete code refactoring, support to execute arbitrary SQL **SELECT** statements, more options to enumerate and dump specific information are added, brand new installation packages for Debian, Red Hat, Windows and much more.
* **August**, two public [mailing lists](http://www.sqlmap.org/#ml) are created on SourceForge.
* **January**, sqlmap subversion development repository is moved away from SourceForge and goes private for a while.

## 2007
* **November 4**, release **0.5** marks the end of the OWASP Spring of Code 2007 contest participation. Bernardo has [accomplished](http://www.owasp.org/index.php/SpoC_007_-_SQLMap_-_Progress_Page) all the proposed objects which include also initial support for Oracle, enhanced support for UNION query SQL injection and support to test and exploit SQL injections in HTTP Cookie and User-Agent headers.
* **June 15**, Bernardo releases version **0.4** as a result of the first OWASP Spring of Code 2007 milestone. This release features, amongst others, improvements to the DBMS fingerprint engine, support to calculate the estimated time of arrival, options to enumerate specific data from the database server and brand new logging system.
* **April**, even though sqlmap was **not** and is **not** an OWASP project, it gets [accepted](http://www.owasp.org/index.php/SpoC_007_-_SqlMap), amongst many other open source projects to OWASP Spring
of Code 2007.
* **March 30**, Bernardo applies to OWASP [Spring of Code 2007](http://www.owasp.org/index.php/OWASP_Spring_Of_Code_2007_Applications#Bernardo_-_sqlmap).
* **January 20**, sqlmap version **0.3** is released, featuring initial support for Microsoft SQL Server, support to test and exploit UNION query SQL injections and injection points in POST parameters.

## 2006
* **December 13**, Bernardo releases version **0.2** with major enhancements to the DBMS fingerprint functionalities and replacement of the old inference algorithm with the bisection algorithm.
* **September**, Daniele leaves the project, [Bernardo Damele A. G.](http://bernardodamele.blogspot.com)
takes it over.
* **August**, Daniele adds initial support for PostgreSQL and releases version **0.1**.
* **July 25**, [Daniele Bellucci](http://dbellucci.blogspot.com) registers the sqlmap project on SourceForge and develops it on the [SourceForge subversion repository](http://sqlmap.svn.sourceforge.net/viewvc/sqlmap/). The skeleton is implemented and
limited support for MySQL added.


# Download and update
sqlmap can be downloaded from its (http://sourceforge.net/projects/sqlmap/files/ "SourceForge File List page). It is available in two formats:
* (http://downloads.sourceforge.net/sqlmap/sqlmap-0.9.tar.gz"
name="Source gzip compressed).
* (http://downloads.sourceforge.net/sqlmap/sqlmap-0.9.zip"
name="Source zip compressed).

You can also checkout the latest development version from the (https://github.com/sqlmapproject/sqlmap "git)
repository:
```$ git clone https://github.com/sqlmapproject/sqlmap.git sqlmap-dev```

You can update it at any time to the latest development version by running:
```$ python sqlmap.py --update```

Or:
```$ git pull```

This is strongly recommended **before** reporting any bug to the [mailing list](http://www.sqlmap.org/#ml).

# Usage

```
$ python sqlmap.py -h


    sqlmap/1.0-dev - automatic SQL injection and database takeover tool
    http://www.sqlmap.org

[!] legal disclaimer: usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Authors assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting at 16:38:25

Usage: python sqlmap.py [options]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -v VERBOSE            Verbosity level: 0-6 (default 1)

  Target:
    At least one of these options has to be specified to set the source to get target urls from

    -d DIRECT           Direct connection to the database
    -u URL, --url=URL   Target url
    -l LOGFILE          Parse targets from Burp or WebScarab proxy logs
    -m BULKFILE         Scan multiple targets enlisted in a given textual file
    -r REQUESTFILE      Load HTTP request from a file
    -g GOOGLEDORK       Process Google dork results as target urls
    -c CONFIGFILE       Load options from a configuration INI file

  Request:
    These options can be used to specify how to connect to the target url

    --data=DATA         Data string to be sent through POST
    --param-del=PDEL    Character used for splitting parameter values
    --cookie=COOKIE     HTTP Cookie header
    --load-cookies=LOC  File containing cookies in Netscape/wget format
    --cookie-urlencode  URL Encode generated cookie injections
    --drop-set-cookie   Ignore Set-Cookie header from response
    --user-agent=AGENT  HTTP User-Agent header
    --random-agent      Use randomly selected HTTP User-Agent header
    --randomize=RPARAM  Randomly change value for given parameter(s)
    --force-ssl         Force usage of SSL/HTTPS requests
    --host=HOST         HTTP Host header
    --referer=REFERER   HTTP Referer header
    --headers=HEADERS   Extra headers (e.g. "Accept-Language: fr\nETag: 123")
    --auth-type=ATYPE   HTTP authentication type (Basic, Digest or NTLM)
    --auth-cred=ACRED   HTTP authentication credentials (name:password)
    --auth-cert=ACERT   HTTP authentication certificate (key_file,cert_file)
    --proxy=PROXY       Use a HTTP proxy to connect to the target url
    --proxy-cred=PCRED  HTTP proxy authentication credentials (name:password)
    --ignore-proxy      Ignore system default HTTP proxy
    --delay=DELAY       Delay in seconds between each HTTP request
    --timeout=TIMEOUT   Seconds to wait before timeout connection (default 30)
    --retries=RETRIES   Retries when the connection timeouts (default 3)
    --scope=SCOPE       Regexp to filter targets from provided proxy log
    --safe-url=SAFURL   Url address to visit frequently during testing
    --safe-freq=SAFREQ  Test requests between two visits to a given safe url
    --skip-urlencode    Skip URL encoding of POST data
    --eval=EVALCODE     Evaluate provided Python code before the request (e.g. "import hashlib;id2=hashlib.md5(id).hexdigest()")

  Optimization:
    These options can be used to optimize the performance of sqlmap

    -o                  Turn on all optimization switches
    --predict-output    Predict common queries output
    --keep-alive        Use persistent HTTP(s) connections
    --null-connection   Retrieve page length without actual HTTP response body
    --threads=THREADS   Max number of concurrent HTTP(s) requests (default 1)

  Injection:
    These options can be used to specify which parameters to test for, provide custom injection payloads and optional tampering scripts

    -p TESTPARAMETER    Testable parameter(s)
    --dbms=DBMS         Force back-end DBMS to this value
    --os=OS             Force back-end DBMS operating system to this value
    --invalid-bignum    Use big numbers for invalidating values
    --invalid-logical   Use logical operations for invalidating values
    --no-cast           Turn off payload casting mechanism
    --prefix=PREFIX     Injection payload prefix string
    --suffix=SUFFIX     Injection payload suffix string
    --skip=SKIP         Skip testing for given parameter(s)
    --tamper=TAMPER     Use given script(s) for tampering injection data

  Detection:
    These options can be used to specify how to parse and compare page content from HTTP responses when using blind SQL injection technique

    --level=LEVEL       Level of tests to perform (1-5, default 1)
    --risk=RISK         Risk of tests to perform (0-3, default 1)
    --string=STRING     String to match in the response when query is valid
    --regexp=REGEXP     Regexp to match in the response when query is valid
    --code=CODE         HTTP response code to match when the query is valid
    --text-only         Compare pages based only on the textual content
    --titles            Compare pages based only on their titles

  Techniques:
    These options can be used to tweak testing of specific SQL injection techniques

    --technique=TECH    SQL injection techniques to test for (default "BEUST")
    --time-sec=TIMESEC  Seconds to delay the DBMS response (default 5)
    --union-cols=UCOLS  Range of columns to test for UNION query SQL injection
    --union-char=UCHAR  Character to use for bruteforcing number of columns
    --dns-domain=DNAME  Domain name used for DNS exfiltration attack

  Fingerprint:
    -f, --fingerprint   Perform an extensive DBMS version fingerprint

  Enumeration:
    These options can be used to enumerate the back-end database management system information, structure and data contained in the tables. Moreover you can run your own SQL statements

    -b, --banner        Retrieve DBMS banner
    --current-user      Retrieve DBMS current user
    --current-db        Retrieve DBMS current database
    --is-dba            Detect if the DBMS current user is DBA
    --users             Enumerate DBMS users
    --passwords         Enumerate DBMS users password hashes
    --privileges        Enumerate DBMS users privileges
    --roles             Enumerate DBMS users roles
    --dbs               Enumerate DBMS databases
    --tables            Enumerate DBMS database tables
    --columns           Enumerate DBMS database table columns
    --schema            Enumerate DBMS schema
    --count             Retrieve number of entries for table(s)
    --dump              Dump DBMS database table entries
    --dump-all          Dump all DBMS databases tables entries
    --search            Search column(s), table(s) and/or database name(s)
    -D DB               DBMS database to enumerate
    -T TBL              DBMS database table to enumerate
    -C COL              DBMS database table column to enumerate
    -U USER             DBMS user to enumerate
    --exclude-sysdbs    Exclude DBMS system databases when enumerating tables
    --start=LIMITSTART  First query output entry to retrieve
    --stop=LIMITSTOP    Last query output entry to retrieve
    --first=FIRSTCHAR   First query output word character to retrieve
    --last=LASTCHAR     Last query output word character to retrieve
    --sql-query=QUERY   SQL statement to be executed
    --sql-shell         Prompt for an interactive SQL shell

  Brute force:
    These options can be used to run brute force checks

    --common-tables     Check existence of common tables
    --common-columns    Check existence of common columns

  User-defined function injection:
    These options can be used to create custom user-defined functions

    --udf-inject        Inject custom user-defined functions
    --shared-lib=SHLIB  Local path of the shared library

  File system access:
    These options can be used to access the back-end database management system underlying file system

    --file-read=RFILE   Read a file from the back-end DBMS file system
    --file-write=WFILE  Write a local file on the back-end DBMS file system
    --file-dest=DFILE   Back-end DBMS absolute filepath to write to

  Operating system access:
    These options can be used to access the back-end database management system underlying operating system

    --os-cmd=OSCMD      Execute an operating system command
    --os-shell          Prompt for an interactive operating system shell
    --os-pwn            Prompt for an out-of-band shell, meterpreter or VNC
    --os-smbrelay       One click prompt for an OOB shell, meterpreter or VNC
    --os-bof            Stored procedure buffer overflow exploitation
    --priv-esc          Database process' user privilege escalation
    --msf-path=MSFPATH  Local path where Metasploit Framework is installed
    --tmp-path=TMPPATH  Remote absolute path of temporary files directory

  Windows registry access:
    These options can be used to access the back-end database management system Windows registry

    --reg-read          Read a Windows registry key value
    --reg-add           Write a Windows registry key value data
    --reg-del           Delete a Windows registry key value
    --reg-key=REGKEY    Windows registry key
    --reg-value=REGVAL  Windows registry key value
    --reg-data=REGDATA  Windows registry key value data
    --reg-type=REGTYPE  Windows registry key value type

  General:
    These options can be used to set some general working parameters

    -t TRAFFICFILE      Log all HTTP traffic into a textual file
    --batch             Never ask for user input, use the default behaviour
    --charset=CHARSET   Force character encoding used for data retrieval
    --check-tor         Check to see if Tor is used properly
    --crawl=CRAWLDEPTH  Crawl the website starting from the target url
    --csv-del=CSVDEL    Delimiting character used in CSV output (default ",")
    --eta               Display for each output the estimated time of arrival
    --flush-session     Flush session file for current target
    --forms             Parse and test forms on target url
    --fresh-queries     Ignores query results stored in session file
    --hex               Uses DBMS hex function(s) for data retrieval
    --parse-errors      Parse and display DBMS error messages from responses
    --replicate         Replicate dumped data into a sqlite3 database
    --save              Save options to a configuration INI file
    --tor               Use Tor anonymity network
    --tor-port=TORPORT  Set Tor proxy port other than default
    --tor-type=TORTYPE  Set Tor proxy type (HTTP - default, SOCKS4 or SOCKS5)
    --update            Update sqlmap

  Miscellaneous:
    -z MNEMONICS        Use short mnemonics (e.g. "flu,bat,ban,tec=EU")
    --beep              Sound alert when SQL injection found
    --check-payload     Offline WAF/IPS/IDS payload detection testing
    --check-waf         Check for existence of WAF/IPS/IDS protection
    --cleanup           Clean up the DBMS by sqlmap specific UDF and tables
    --dependencies      Check for missing sqlmap dependencies
    --disable-hash      Disable password hash cracking mechanism
    --disable-like      Disable LIKE search of identificator names
    --gpage=GOOGLEPAGE  Use Google dork results from specified page number
    --mobile            Imitate smartphone through HTTP User-Agent header
    --page-rank         Display page rank (PR) for Google dork results
    --purge-output      Safely remove all content from output directory
    --smart             Conduct through tests only if positive heuristic(s)
    --test-filter=TSTF  Select tests by payloads and/or titles (e.g. ROW)
    --wizard            Simple wizard interface for beginner users
```