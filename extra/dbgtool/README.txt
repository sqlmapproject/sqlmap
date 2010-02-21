To use dbgtool.py you need to pass it the MS-DOS executable binary file,
and optionally the output debug.exe script file name.

Example:

$ python ./dbgtool.py -i ./nc.exe -o nc.scr

This will create a ASCII text file with CRLF line terminators called
nc.scr.

Such file can then be converted to its original portable executable with
the Windows native debug.exe, that is installed by default in all Windows
systems:

> debug.exe < nc.scr

To be able to execute it on Windows you have to rename it to end with
'.com' or '.exe':

> ren nc_exe nc.exe
