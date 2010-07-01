#!/bin/bash
# lib_mysqludf_sys - a library with miscellaneous (operating) system level functions
# Copyright (C) 2007  Roland Bouman 
# Copyright (C) 2008-2010  Roland Bouman and Bernardo Damele A. G.
# web: http://www.mysqludf.org/
# email: mysqludfs@gmail.com, bernardo.damele@gmail.com
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
USER="root"
PORT="3306"

echo "Compiling the MySQL UDF"
make

if test $? -ne 0; then
	echo "ERROR: You need libmysqlclient development software installed"
	echo "to be able to compile this UDF, on Debian/Ubuntu just run:"
	echo "apt-get install libmysqlclient-dev"
	exit 1
else
	echo "MySQL UDF compiled successfully"
fi

echo -e "\nPlease provide your MySQL root password"

mysql -h 127.0.0.1 -P ${PORT} -u ${USER} -p mysql < lib_mysqludf_sys.sql

if test $? -ne 0; then
	echo "ERROR: unable to install the UDF"
	exit 1
else
	echo "MySQL UDF installed successfully"
fi
