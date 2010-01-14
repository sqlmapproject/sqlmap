LIBDIR=/usr/lib

install:
	gcc -Wall -I/usr/include/mysql -O1 -shared lib_mysqludf_sys.c -o lib_mysqludf_sys.so
	strip -sx lib_mysqludf_sys.so
	sudo cp -f lib_mysqludf_sys.so $(LIBDIR)/lib_mysqludf_sys.so
