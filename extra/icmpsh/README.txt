icmpsh - simple reverse ICMP shell

icmpsh is a simple reverse ICMP shell with a win32 slave and a POSIX compatible master in C or Perl.


--- Running the Master ---

The master is straight forward to use. There are no extra libraries required for the C version. 
The Perl master however has the following dependencies:

    * IO::Socket
    * NetPacket::IP
    * NetPacket::ICMP


When running the master, don't forget to disable ICMP replies by the OS. For example:

    sysctl -w net.ipv4.icmp_echo_ignore_all=1

If you miss doing that, you will receive information from the slave, but the slave is unlikely to receive
commands send from the master.


--- Running the Slave ---

The slave comes with a few command line options as outlined below:


-t host            host ip address to send ping requests to. This option is mandatory!

-r                 send a single test icmp request containing the string "Test1234" and then quit. 
                   This is for testing the connection.

-d milliseconds    delay between requests in milliseconds 

-o milliseconds    timeout of responses in milliseconds. If a response has not received in time, 
                   the slave will increase a counter of blanks. If that counter reaches a limit, the slave will quit.
                   The counter is set back to 0 if a response was received.

-b num             limit of blanks (unanswered icmp requests before quitting

-s bytes           maximal data buffer size in bytes


In order to improve the speed, lower the delay (-d) between requests or increase the size (-s) of the data buffer.
