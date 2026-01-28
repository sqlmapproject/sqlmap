/* 
	runcmd - a program for running command prompt commands
	Copyright (C) 2010 Miroslav Stampar
	email: miroslav.stampar@gmail.com
	
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

#include <stdio.h>
#include <windows.h>
#include <use_ansi.h>
#include "stdafx.h"
#include <string>

using namespace std;
int main(int argc, char* argv[])
{
  FILE *fp;
  string cmd;

  for( int count = 1; count < argc; count++ )
	cmd += " " + string(argv[count]);

  fp = _popen(cmd.c_str(), "r");

  if (fp != NULL) {
    char buffer[BUFSIZ];

    while (fgets(buffer, sizeof buffer, fp) != NULL)
      fputs(buffer, stdout);
  }

  return 0;
}
