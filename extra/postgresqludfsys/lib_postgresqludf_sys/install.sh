#!/bin/bash
# lib_postgresqludf_sys - a library with miscellaneous (operating) system level functions
# Copyright (C) 2009  Bernardo Damele A. G.
# web: http://bernardodamele.blogspot.com/
# email: bernardo.damele@gmail.com
# 
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

echo "Compiling the PostgreSQL UDF"
make

if test $? -ne 0; then
	echo "ERROR: You need postgresql-server development software installed "
	echo "to be able to compile this UDF, on Debian/Ubuntu just run:"
	echo "apt-get install postgresql-server-dev-8.3"
	exit 1
else
	echo "PostgreSQL UDF compiled successfully"
fi

echo -e "\nPlease provide your PostgreSQL 'postgres' user's password"

/usr/lib/postgresql/8.3/bin/psql -h 127.0.0.1 -p 5432 -U postgres -q template1 < lib_postgresqludf_sys.sql
#psql -h 127.0.0.1 -p 5432 -U postgres -q template1 < lib_postgresqludf_sys.sql

if test $? -ne 0; then
	echo "ERROR: unable to install the UDF"
	exit 1
else
	echo "PostgreSQL UDF installed successfully"
fi
