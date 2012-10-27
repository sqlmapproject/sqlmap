# Dependencies

sqlmap is developed in [python](http://www.python.org), a dynamic, object-oriented, interpreted programming language freely available from [http://python.org/download/](http://python.org/download/). This makes sqlmap a cross-platform application which is independant of the operating system. sqlmap requires Python version **2.6.x** or **2.7.x**. To make it even easier, many GNU/Linux distributions come out of the box with Python installed. Other Unixes and Mac OSX also provide Python packaged and ready to be installed. Windows users can download and install the Python installer for x86, AMD64 and Itanium.

sqlmap relies on the [Metasploit Framework](http://metasploit.com) for some of its post-exploitation takeover features. You can grab a copy of the framework from the [download](http://metasploit.com/download/) page - the required version is **3.5** or higher. For the ICMP tunneling out-of-band takeover technique, sqlmap requires the [Impacket](http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Impacket) library too.

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