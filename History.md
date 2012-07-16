# History

## 2012

* **June 26**, sqlmap development is [relocated](http://article.gmane.org/gmane.comp.security.sqlmap/2247) on [GitHub](https://github.com/sqlmapproject/sqlmap). A new [homepage](http://sqlmap.org) is deployed. The issue tracker goes [public](https://github.com/sqlmapproject/sqlmap/issues). The Subversion repository is dismissed as is the project hosting on SourceForge.
* **May 31**, Miroslav [presents](http://phdays.com/program/conference/) his research **DNS exfiltration using sqlmap** ([slides](http://www.slideshare.net/stamparm/dns-exfiltration-using-sqlmap-13163281)) with accompanying [whitepaper](http://www.slideshare.net/stamparm/ph-days-2012miroslavstampardataretrievaloverdnsinsqlinjectionattackspaper) **Data Retrieval over DNS in SQL Injection Attacks** at PHDays 2012 in Moscow, Russia.

## 2011

* **December**, Throughout the year dozen of new features have been developed and hundreds of bugs have been fixed.
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
