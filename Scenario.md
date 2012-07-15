# Scenario

## Detect and exploit a SQL injection

Let's say that you are auditing a web application and found a web page that accepts dynamic user-provided values via `GET`, `POST` or `Cookie` parameters or via the HTTP `User-Agent` request header.
You now want to test if these are affected by a SQL injection vulnerability, and if so, exploit them to retrieve as much information as possible from the back-end database management system, or even be able to access the underlying file system and operating system.

In a simple world, consider that the target url is:

    http://192.168.136.131/sqlmap/mysql/get_int.php?id=1

Assume that:

    http://192.168.136.131/sqlmap/mysql/get_int.php?id=1+AND+1=1

is the same page as the original one and (the condition evaluates to **True**):

    http://192.168.136.131/sqlmap/mysql/get_int.php?id=1+AND+1=2

differs from the original one (the condition evaluates to **False**). This likely means that you are in front of a SQL injection vulnerability in the `id` `GET` parameter of the `index.php` page. Additionally, no sanitisation of user's supplied input is taking place before the SQL statement is sent to the back-end database management system.

This is quite a common flaw in dynamic content web applications and it does not depend upon the back-end database management system nor on the web application programming language; it is a flaw within the application code. The [Open Web Application Security Project](http://www.owasp.org) rated this class of vulnerability as the [most common](http://owasptop10.googlecode.com/files/OWASP%20Top%2010%20-%202010.pdf) and serious web application vulnerability in their [Top Ten](http://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project) list from 2010.

Now that you have found the vulnerable parameter, you can exploit it by manipulating the `id` parameter value in the HTTP request.

Back to the scenario, we can make an educated guess about the probable syntax of the SQL `SELECT` statement where the user supplied value is being used in the `get_int.php` web page. In pseudo PHP code:

    $query = "SELECT [column name(s)] FROM [table name] WHERE id=" . $_REQUEST['id'];

As you can see, appending a syntactically valid SQL statement that will evaluate to a **True** condition after the value for the `id` parameter (such as `id=1 AND 1=1`) will result in the web application returning the same web page as in the original request (where no SQL statement is added). This is because the back-end database management system has evaluated the injected SQL statement. The previous example describes a simple boolean-based blind SQL injection vulnerability.  However, sqlmap is able to detect any type of SQL injection flaw and adapt its work-flow accordingly.

In this simple scenario it would also be possible to append, not just one or more valid SQL conditions, but also (depending on the DBMS) stacked SQL queries. For instance:  `[...]&id=1;ANOTHER SQL QUERY#`.

sqlmap can automate the process of identifying and exploiting this type of vulnerability. Passing the original address, `http://192.168.136.131/sqlmap/mysql/get_int.php?id=1` to sqlmap, the tool will automatically:

* Identify the vulnerable parameter(s) (`id` in this example)
* Identify which SQL injection techniques can be used to exploit the vulnerable parameter(s)
* Fingerprint the back-end database management system
* Depending on the user's options, it will extensively fingerprint, enumerate data or takeover the database server as a whole

...and depending on supplied options, it will enumerate data or takeover the database server entirely.

There exist many [resources](http://delicious.com/inquis/sqlinjection) on the web explaining in depth how to detect, exploit and prevent SQL injection vulnerabilities in web applications. It is recommendeded that you read them before going much further with sqlmap.

## Direct connection to the database management system
Up until sqlmap version **0.8**, the tool has been **yet another SQL injection tool**, used by web application penetration testers/newbies/curious teens/computer addicted/punks and so on. Things move on
and as they evolve, we do as well. Now it supports this new switch, `-d`, that allows you to connect from your machine to the database server's TCP port where the database management system daemon is listening
on and perform any operation you would do while using it to attack a database via a SQL injection vulnerability.
