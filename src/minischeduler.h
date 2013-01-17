/*
 * minischeduler.h
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

#ifndef MINISCHEDULER_H_
#define MINISCHEDULER_H_

#ifdef __cplusplus
extern "C" {
#endif


#include "psentinel.h"

//utility function for making a timer
int make_timer(struct single_connection * connection);


//very simple thread function that calls a check

#ifdef __cplusplus
}
#endif

#endif /* MINISCHEDULER_H_ */
