Before compiling, you need to adapt the following to your environment:

Variables in install.sh script:
--------------------------------------------------------------------------
Variable name			Variable description
--------------------------------------------------------------------------
USER                    Database management system administrative username
PORT                    Database management system port
VERSION                 Database management system version (PostgreSQL only)

Variables in Makefile:
--------------------------------------------------------------------------
Variable name			Variable description
--------------------------------------------------------------------------
LIBDIR                  Database management system absolute file system
                        path for third party libraries (MySQL only)

Then you can launch './install.sh' if you want to compile the shared
object from the source code and create the user-defined functions on the
database management system.
If you only want to compile the shared object, you need to call only the
'make' command.


Notes:

To get as small shared libraries as possible compile with GCC 4.3 on
both 32-bit and 64-bit architecture and strip the libraries with 'strip'
command.
