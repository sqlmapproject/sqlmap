LIBDIR=/tmp

9.0:
	gcc -Wall -I/usr/include/postgresql/9.0/server -Os -shared lib_postgresqludf_sys.c -fPIC -o lib_postgresqludf_sys.so
	strip -sx lib_postgresqludf_sys.so
	cp -f lib_postgresqludf_sys.so $(LIBDIR)/lib_postgresqludf_sys.so

8.4:
	gcc-4.3 -Wall -I/usr/include/postgresql/8.4/server -Os -shared lib_postgresqludf_sys.c -o lib_postgresqludf_sys.so
	strip -sx lib_postgresqludf_sys.so
	cp -f lib_postgresqludf_sys.so $(LIBDIR)/lib_postgresqludf_sys.so

8.3:
	gcc-4.3 -Wall -I/usr/include/postgresql/8.3/server -Os -shared lib_postgresqludf_sys.c -o lib_postgresqludf_sys.so
	strip -sx lib_postgresqludf_sys.so
	cp -f lib_postgresqludf_sys.so $(LIBDIR)/lib_postgresqludf_sys.so

8.2:
	gcc-4.3 -Wall -I/usr/include/postgresql/8.2/server -Os -shared lib_postgresqludf_sys.c -o lib_postgresqludf_sys.so
	strip -sx lib_postgresqludf_sys.so
	cp -f lib_postgresqludf_sys.so $(LIBDIR)/lib_postgresqludf_sys.so
