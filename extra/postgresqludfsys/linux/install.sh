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

# Adapt the following settings to your environment
USER="postgres"
PORT="5434"
VERSION="8.4"
#PORT="5433"
#VERSION="8.3"
#PORT="5432"
#VERSION="8.2"

echo "Compiling the PostgreSQL UDF"
make ${VERSION}

if test $? -ne 0; then
	echo "ERROR: You need postgresql-server development software installed"
	echo "to be able to compile this UDF, on Debian/Ubuntu just run:"

	if test "${VERSION}" == "8.2"; then
		echo "apt-get install postgresql-server-dev-8.2"
	else if test "${VERSION}" == "8.3"; then
		echo "apt-get install postgresql-server-dev-8.3"
	else if test "${VERSION}" == "8.4"; then
		echo "apt-get install postgresql-server-dev-8.4"
	fi

	exit 1
else
	echo "PostgreSQL UDF compiled successfully"
fi

echo -e "\nPlease provide your PostgreSQL 'postgres' user's password"

psql -h 127.0.0.1 -p ${PORT} -U ${USER} -q template1 < lib_postgresqludf_sys.sql

if test $? -ne 0; then
	echo "ERROR: unable to install the UDF"
	exit 1
else
	echo "PostgreSQL UDF installed successfully"
fi
