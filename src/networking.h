/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * networking.h
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

#ifndef _PGNETWORKING_
#define _PGNETWORKING_

#ifdef __cplusplus
extern "C" {
#endif

#include "psentinel.h"


int sock_read(int sockfd, char *buf, size_t count);
int sock_write(int sockfd, char *buf, size_t count);
int sock_puts(int sockfd, char *str);
int initialize_network(configuration * connections);
void rebuild_connection_set(configuration * connections);
void handle_new_connection(configuration * connections,int socket_index);
void read_send_data(configuration * connections,int port_index,int socket_index);
void read_sockets(configuration * connections);
void setnonblocking(int sock);

#ifdef __cplusplus
}
#endif

#endif //_PGNETWORKING_
