Before compiling, certain enviroment variables have to be set,
depending on the project used. For project lib_mysqludf_sys variables
PLATFORM_SDK_DIR and MYSQL_SERVER_DIR have to be set, while for project
lib_postgresqludf_sys variables PLATFORM_SDK_DIR and
POSTGRESQL_SERVER_DIR.

Variables:
--------------------------------------------------------------------------
Variable name			Variable description
--------------------------------------------------------------------------
PLATFORM_SDK_DIR		Directory where the Platform SDK is installed
MYSQL_SERVER_DIR		Directory where the MySQL is installed
POSTGRESQL_SERVER_DIR	Directory where the PostgreSQL is installed

Procedure for setting environment variables:
My Computer -> Properties -> Advanced -> Environment Variables
User variables -> New

Sample values:
--------------------------------------------------------------------------
Variable name			Variable value
--------------------------------------------------------------------------
PLATFORM_SDK_DIR		C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2
MYSQL_SERVER_DIR		C:\Program Files\MySQL\MySQL Server 5.1
POSTGRESQL_SERVER_DIR	C:\Program Files\PostgreSQL\8.4


Notes:

To get as small shared libraries as possible compile as follows:
* MySQL Windows 32-bit DLL: use Visual C++ 2005 and strip the library with UPX
* TODO
