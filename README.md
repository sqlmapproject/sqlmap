# Introduction

sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.

# Features

* Full support for **MySQL, Oracle, PostgreSQL, Microsoft SQL Server, Microsoft Access, SQLite, Firebird, Sybase and SAP MaxDB** database management systems.
* Full support for six SQL injection techniques: **boolean-based blind, time-based blind, error-based, UNION query, stacked queries and out-of-band**.
* Support to **directly connect to the database** without passing via a SQL injection, by providing DBMS credentials, IP address, port and database name.
* Support to enumerate **database users, users' password hashes, users' privileges, users' roles, databases, tables and columns**.
* Automatic recognition of password hashes format and support to **crack them with a dictionary-based attack**.
* Support to **dump database tables** entirely, a range of entries or specific columns as per user's choice. The user can also choose to dump only a range of characters from each column's entry.
* Support to **search for specific database names, specific tables across all databases or specific columns across all databases' tables**. This is useful, for instance, to identify tables containing custom application credentials where relevant columns' names contain string like name and pass.
* Support to **download and upload any file** from the database server underlying file system when the database software is MySQL, PostgreSQL or Microsoft SQL Server.
* Support to **execute arbitrary commands and retrieve their standard output** on the database server underlying operating system when the database software is MySQL, PostgreSQL or Microsoft SQL Server.
* Support to **establish an out-of-band stateful TCP connection between the attacker machine and the database server** underlying operating system. This channel can be an interactive command prompt, a Meterpreter session or a graphical user interface (VNC) session as per user's choice.
* Support for **database process' user privilege escalation** via Metasploit's Meterpreter `getsystem` command.

# Mailing list

The **sqlmap-users@lists.sourceforge.net** mailing list is the preferred way to ask questions, report bugs, suggest new features and discuss with other users, [contributors](https://github.com/sqlmapproject/sqlmap/blob/master/doc/THANKS) and the [developers](#developers). To subscribe use the [online web form](https://lists.sourceforge.net/lists/listinfo/sqlmap-users).
The mailing list is archived online on [SourceForge](http://sourceforge.net/mailarchive/forum.php?forum_name=sqlmap-users), [Gmane](http://news.gmane.org/gmane.comp.security.sqlmap) and is available also via Gmane [RSS feed](http://rss.gmane.org/messages/complete/gmane.comp.security.sqlmap).

# Developers

[Bernardo Damele A. G.](bernardo@sqlmap.org) - [@inquisb](https://twitter.com/inquisb)<BR>
[Miroslav Stampar](miroslav@sqlmap.org) - [@stamparm](https://twitter.com/stamparm)

You can contact the development team by writing to dev@sqlmap.org.

# License

sqlmap is released under the terms of the [General Public License v2](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html).<BR>
sqlmap is copyrighted by its [developers](#developers).
