/* 
	lib_postgresqludf_sys - a library with miscellaneous (operating) system level functions
	Copyright (C) 2009  Bernardo Damele A. G.
	web: http://bernardodamele.blogspot.com/
	email: bernardo.damele@gmail.com
	
	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.
	
	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
	
	You should have received a copy of the GNU Lesser General Public
	License along with this library; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

CREATE OR REPLACE FUNCTION sys_exec(text) RETURNS int4 AS '/tmp/lib_postgresqludf_sys.so', 'sys_exec' LANGUAGE C RETURNS NULL ON NULL INPUT IMMUTABLE;
CREATE OR REPLACE FUNCTION sys_eval(text) RETURNS text AS '/tmp/lib_postgresqludf_sys.so', 'sys_eval' LANGUAGE C RETURNS NULL ON NULL INPUT IMMUTABLE;
CREATE OR REPLACE FUNCTION sys_bineval(text) RETURNS int4 AS '/tmp/lib_postgresqludf_sys.so', 'sys_bineval' LANGUAGE C RETURNS NULL ON NULL INPUT IMMUTABLE;
CREATE OR REPLACE FUNCTION sys_fileread(text) RETURNS text AS '/tmp/lib_postgresqludf_sys.so', 'sys_fileread' LANGUAGE C RETURNS NULL ON NULL INPUT IMMUTABLE;
