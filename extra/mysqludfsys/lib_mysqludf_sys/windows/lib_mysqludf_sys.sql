/*
        lib_mysqludf_sys - a library with miscellaneous (operating) system level functions
        Copyright (C) 2007  Roland Bouman
        Copyright (C) 2008-2009  Roland Bouman and Bernardo Damele A. G.
        web: http://www.mysqludf.org/
        email: roland.bouman@gmail.com, bernardo.damele@gmail.com

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

DROP FUNCTION IF EXISTS lib_mysqludf_sys_info;
DROP FUNCTION IF EXISTS sys_get;
DROP FUNCTION IF EXISTS sys_set;
DROP FUNCTION IF EXISTS sys_exec;
DROP FUNCTION IF EXISTS sys_eval;
DROP FUNCTION IF EXISTS sys_bineval;

CREATE FUNCTION lib_mysqludf_sys_info RETURNS string SONAME 'lib_mysqludf_sys.dll';
CREATE FUNCTION sys_get RETURNS string SONAME 'lib_mysqludf_sys.dll';
CREATE FUNCTION sys_set RETURNS int SONAME 'lib_mysqludf_sys.dll';
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.dll';
CREATE FUNCTION sys_eval RETURNS string SONAME 'lib_mysqludf_sys.dll';
CREATE FUNCTION sys_bineval RETURNS int SONAME 'lib_mysqludf_sys.dll';
