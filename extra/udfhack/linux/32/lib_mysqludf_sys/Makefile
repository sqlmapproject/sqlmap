# For MySQL < 5.1
LIBDIR=/usr/lib
# For MySQL >= 5.1
#LIBDIR=/usr/lib/mysql/plugin

install:
	gcc-4.3 -Wall -I/usr/include/mysql -Os -shared lib_mysqludf_sys.c -o lib_mysqludf_sys.so
	strip -sx lib_mysqludf_sys.so
	cp -f lib_mysqludf_sys.so $(LIBDIR)/lib_mysqludf_sys.so
