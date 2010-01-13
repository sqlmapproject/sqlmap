LIBDIR=/tmp

8.2:
	gcc -Wall -I/usr/include/postgresql/8.2/server -O1 -shared src/8.2/lib_postgresqludf_sys.c -o so/8.2/lib_postgresqludf_sys.so
	strip -sx so/8.2/lib_postgresqludf_sys.so
	cp -f so/8.2/lib_postgresqludf_sys.so $(LIBDIR)/lib_postgresqludf_sys.so

8.3:
	gcc -Wall -I/usr/include/postgresql/8.3/server -O1 -shared src/8.3/lib_postgresqludf_sys.c -o so/8.3/lib_postgresqludf_sys.so
	strip -sx so/8.3/lib_postgresqludf_sys.so
	cp -f so/8.3/lib_postgresqludf_sys.so $(LIBDIR)/lib_postgresqludf_sys.so
