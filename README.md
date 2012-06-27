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

# Documentation

* sqlmap [user's manual](https://github.com/sqlmapproject/sqlmap/raw/master/doc/README.pdf).
* sqlmap [ChangeLog](https://raw.github.com/sqlmapproject/sqlmap/master/doc/ChangeLog).
* *SQL injection: Not only AND 1=1* [slides](http://www.slideshare.net/inquis/sql-injection-not-only-and-11-updated) presented by Bernardo at the 2nd Digital Security Forum in Lisbon (Portugal) on June 27, 2009.
* **Advanced SQL injection to operating system full control** [whitepaper](http://www.slideshare.net/inquis/advanced-sql-injection-to-operating-system-full-control-whitepaper-4633857) and [slides](http://www.slideshare.net/inquis/advanced-sql-injection-to-operating-system-full-control-slides) presented by Bernardo at [Black Hat Europe 2009](https://www.blackhat.com/html/bh-europe-09/bh-eu-09-main.html) in Amsterdam (The Netherlands) on April 16, 2009.
* **Expanding the control over the operating system from the database** [slides](http://www.slideshare.net/inquis/expanding-the-control-over-the-operating-system-from-the-database) presented by Bernardo at [SOURCE Conference](http://www.sourceconference.com/archive/) 2009 in Barcelona (Spain) on September 21, 2009.
* **Got database access? Own the network!** [slides](http://www.slideshare.net/inquis/ath-con-2010bernardodamelegotdbownnet) presented by Bernardo at [AthCon 2010](http://www.athcon.org/archive.php) in Athens (Greece) on June 3, 2010.
* **sqlmap - security development in python** [slides](http://www.slideshare.net/stamparm/euro-python-2011miroslavstamparsqlmapsecuritydevelopmentinpython) presented by Miroslav at [EuroPython 2011](http://ep2011.europython.eu/) in Firenze (Italy) on June 23, 2011.
* **It all starts with the ' (SQL injection from attacker's point of view)** [slides](http://www.slideshare.net/stamparm/f-sec-2011miroslavstamparitallstartswiththesinglequote-9311238) presented by Miroslav at [FSec - FOI Security Symposium](http://fsec.foi.hr/) in Varazdin (Croatia) on September 23, 2011.
* **DNS exfiltration using sqlmap** [slides](http://www.slideshare.net/stamparm/dns-exfiltration-using-sqlmap-13163281) and accompaining [whitepaper](http://www.slideshare.net/stamparm/ph-days-2012miroslavstampardataretrievaloverdnsinsqlinjectionattackspaper) titled **Data Retrieval over DNS in SQL Injection Attacks** presented by Miroslav at [PHDays 2012](http://www.phdays.com/) in Moscow (Russia) on May 31, 2012.

# Download

You can download the latest tarball by clicking [here](https://github.com/sqlmapproject/sqlmap/tarball/master).

Preferably, you can download sqlmap by cloning the [Git](https://github.com/sqlmapproject/sqlmap) repository:
```
git clone https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

This is strongly recommended before reporting any bug to the [mailing list](#mailing-list).

# Mailing list

The **sqlmap-users@lists.sourceforge.net** mailing list is the preferred way to ask questions, report bugs, suggest new features and discuss with other users, [contributors](https://github.com/sqlmapproject/sqlmap/blob/master/doc/THANKS) and the [developers](#developers). To subscribe use the [online web form](https://lists.sourceforge.net/lists/listinfo/sqlmap-users).
The mailing list is archived online on [SourceForge](http://sourceforge.net/mailarchive/forum.php?forum_name=sqlmap-users), [Gmane](http://news.gmane.org/gmane.comp.security.sqlmap) and is available also via Gmane [RSS feed](http://rss.gmane.org/messages/complete/gmane.comp.security.sqlmap).

# Developers

[Bernardo Damele A. G.](bernardo@sqlmap.org) - [@inquisb](https://twitter.com/inquisb)<BR>
[Miroslav Stampar](miroslav@sqlmap.org) - [@stamparm](https://twitter.com/stamparm)

You can contact the development team by writing to dev@sqlmap.org.

# Contribute

We are constantly seeking for people who can write some clean Python code, are up to do security research, know about web application security, database assessment and takeover, software refactoring and are motivated to join the development team.

If this sounds interesting to you, send us your (pull requests](https://github.com/sqlmapproject/sqlmap/pulls]!

# Donate

sqlmap is the result of numerous hours of passionated work from a small team of computer security enthusiasts. If you appreciated our work and you want to see sqlmap kept being developed, please consider making a small donation to our efforts.

# License

sqlmap is released under the terms of the [General Public License v2](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html).<BR>
sqlmap is copyrighted by its [developers](#developers).
