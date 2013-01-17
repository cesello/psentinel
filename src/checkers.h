/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * checkers.h
 * Copyright (C) Damiano Scaramuzza 2012 <dscaramuzza@daimonlab.it>
 *
 * psentinel is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * psentinel is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _PGCHECKERS_
#define _PGCHECKERS_

#ifdef __cplusplus
extern "C" {
#endif

#include <signal.h>
#include "psentinel.h"


typedef struct shell_args
{
	char * script_name;
	char ** script_args;
} shell_args_t;

unsigned short int call_script(sigval_t args);


#ifdef __cplusplus
}
#endif

#endif //_PGCHECKERS_
