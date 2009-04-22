LIBDIR=/usr/lib

install:
	gcc -Wall -I/usr/include/mysql -O1 -shared src/lib_mysqludf_sys.c -o so/lib_mysqludf_sys.so
	strip -sx so/lib_mysqludf_sys.so
	cp -f so/lib_mysqludf_sys.so $(LIBDIR)/lib_mysqludf_sys.so
