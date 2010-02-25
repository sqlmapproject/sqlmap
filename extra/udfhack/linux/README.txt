Before compiling, you need to adapt the following to your environment:

Variables in install.sh script:
--------------------------------------------------------------------------
Variable name			Variable description
--------------------------------------------------------------------------
USER                    Database management system administrative username
PORT                    Database management system port
VERSION                 Database management system version (PostgreSQL only)

Variable in Makefile (MySQL only):
--------------------------------------------------------------------------
Variable name			Variable description
--------------------------------------------------------------------------
LIBDIR                  Database management system absolute file system
                        path for third party libraries

Then you can launch './install.sh' if you want to compile the shared
object from the source code and create the user-defined functions on the
database management system.
If you only want to compile the shared object, you need to call only the
'make' command.
