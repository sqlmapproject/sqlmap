1. Before compiling, certain enviroment variables have to be set, depending on the project used. for project lib_mysqludf_sys variables PLATFORM_SDK_DIR and MYSQL_SERVER_DIR have to be set, while for lib_postgresqludf_sys PLATFORM_SDK_DIR and POSTGRESQL_SERVER_DIR.
--------------------------------------------------------------------------
Variable name			Variable description
--------------------------------------------------------------------------
PLATFORM_SDK_DIR		directory where the Platform SDK is installed
MYSQL_SERVER_DIR		directory where the MySQL is installed
POSTGRESQL_SERVER_DIR	directory where the PostgreSQL is installed

2. Procedure for setting environment variables:
My Computer -> Properties -> Advanced -> Environment Variables
User variables -> New

3. Sample values:
--------------------------------------------------------------------------
Variable name			Variable value 
--------------------------------------------------------------------------
PLATFORM_SDK_DIR		C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2
MYSQL_SERVER_DIR		C:\Program Files\MySQL\MySQL Server 5.1
POSTGRESQL_SERVER_DIR	C:\Program Files\PostgreSQL\8.3
