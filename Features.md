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
* Integration with other IT security open source projects, [Metasploit](http://metasploit.com) and [w3af](http://w3af.sourceforge.net).

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
[Advanced SQL injection to operating system full control](http://www.slideshare.net/inquis/advanced-sql-injection-to-operating-system-full-control-whitepaper-4633857) and in the slide deck [Expanding the control over the operating system from the database](http://www.slideshare.net/inquis/expanding-the-control-over-the-operating-system-from-the-database).

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

## Demo

You can watch demo videos on [Bernardo](http://www.youtube.com/user/inquisb/videos) and [Miroslav](http://www.youtube.com/user/stamparm/videos) YouTube pages. Also, you can find lots of examples against publicly available vulnerable web applications made for legal web assessment [here](http://unconciousmind.blogspot.com/search/label/sqlmap).
