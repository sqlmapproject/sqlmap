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

* Firebird: <htmlurl name="python-kinterbasdb" url="http://kinterbasdb.sourceforge.net/">
* Microsoft Access: <htmlurl name="python-pyodbc" url="http://pyodbc.googlecode.com/">
* Microsoft SQL Server: <htmlurl name="python-pymssql" url="http://pymssql.sourceforge.net/">
* MySQL: <htmlurl name="python pymysql" url="http://code.google.com/p/pymysql/">
* Oracle: <htmlurl name="python cx_Oracle" url="http://cx-oracle.sourceforge.net/">
* PostgreSQL: <htmlurl name="python-psycopg2" url="http://initd.org/psycopg/">
* SQLite: <htmlurl name="python-pysqlite2" url="http://pysqlite.googlecode.com/">
* Sybase: <htmlurl name="python-pymssql" url="http://pymssql.sourceforge.net/">

If you plan to attack a web application behind NTLM authentication or use the sqlmap update functionality (`--update` switch) you need to install respectively (http://code.google.com/p/python-ntlm/"
name="python-ntlm"> and (http://pysvn.tigris.org/" name="python-svn"> libraries respectively.

Optionally, if you are running sqlmap on Windows, you may wish to install the [PyReadline](http://ipython.scipy.org/moin/PyReadline/Intro) library in order to take advantage of the sqlmap TAB completion and history support features in the SQL shell and OS shell. Note that these functionalities are available natively via the standard Python [readline](http://docs.python.org/library/readline.html) library on other operating systems.

[TODO]