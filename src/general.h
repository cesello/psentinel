/*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * general.h
 * Copyright (C) Damiano Scaramuzza 2012 <dscaramuzza@daimonlab.it>
 *
 * pgsentinel is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * pgsentinel is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _PGGENERAL_
#define _PGGENERAL_

#ifdef __cplusplus
extern "C" {
#endif


#include "psentinel.h"

int init(int argc ,char **argv,configuration * connections);
int clean_all(configuration * connections);
void print_help(int argc ,char **argv);
int execute_command(configuration * connections);
int update_datafile(const configuration * connections,int slot);
int init_datafile(configuration * connections);

#ifdef __cplusplus
}
#endif

#endif //_PGGENERAL_
