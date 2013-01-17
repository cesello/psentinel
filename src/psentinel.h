/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * psentinel.h
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

#ifndef _PSENTINEL_
#define _PSENTINEL_

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>

/* Module constants */

#define INIT_FAILURE -2
#define INIT_SUCCESS 2
#define DAEMONIZE_FAILURE -1
#define DAEMONIZE_SUCCESS 0
#define DAEMONIZE_INDAEMON 1
#define NETWORKING_SUCCESS 3

#define MAX_LINE 4096
#define LISTENQ  10
#define MAX_CLIENTS 3
#define LISTENING_PORTS 20
#define PROGRAM_NAME "psentinel"
#define GENERAL_SETUP_ENTRY "general"
#define DEFAULT_CONFIG_FILE "/etc/" PROGRAM_NAME "/" PROGRAM_NAME ".cfg"


#define MSG_OK	 	 	 		200
#define MSG_OK_S 	 	 		"OK"
#define MSG_DOWN 	 	 		500
#define MSG_DOWN_S 	 	 		"System error"
#define MSG_DOWN_TOOMANY_S 		"Too many clients"
#define MSG_DOWN_TEST_FAILED 	"Application Test Failed"
#define MSG_SERVICE_UNVL 		503
#define MSG_SERVICE_UNVL_S 		"User disabled"
#define VERSION					"0.2.0 Rev.142"
#define ECHOMSG					"HTTP/1.0 %d %s - " PROGRAM_NAME " Ver." VERSION "\r\n"




typedef unsigned short int (*pf_timer_func_t)(sigval_t args);

struct timer_action
{
	timer_t 			timerid;
	time_t 				last_call;
	int					counter;
	int 				inqueue;
	int 				check_interval;
	pf_timer_func_t		chk_function;
	sigval_t			chk_arguments;
	pthread_mutex_t		chk_mutex;
	unsigned short int  chk_status;
};



struct single_connection
{
	char				* service_name;
	struct timer_action timer;
	int 				listening_socket;
	struct	sockaddr_in servaddr;  /*  socket address structure  */
	struct	sockaddr_un servaddr_un;  /*  socket AF_UNIX address structure  */
	in_port_t	  	 	port;
	unsigned short int 	pausable;
	unsigned short int 	disabled;
	unsigned int		counter;
	int  				running_sockets[MAX_CLIENTS];
	char 				buffer[MAX_CLIENTS][MAX_LINE];
	unsigned short int (* reply_function)(void *,int ,int );



};


struct all_connections
{
	int 	max_socket;
	pid_t 	running_pid;
	int 	last_slot;
	fd_set 	socket_set;
	char 	command_line[MAX_LINE];		//Command line for AF_UNIX socket client-mode
	struct single_connection single_conn[LISTENING_PORTS];

};

typedef struct all_connections configuration;

#ifdef __cplusplus
}
#endif

#endif //_PSENTINEL_
