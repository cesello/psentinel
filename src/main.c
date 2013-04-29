/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * main.c
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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include "psentinel.h"
#include "networking.h"
#include "checkers.h"
#include "general.h"
#include "minischeduler.h"

/*Global settings */

unsigned char to_demonize = 0;
unsigned char to_disable = 0;
unsigned char to_command_mode = 0;
unsigned char to_printhelp = 1;
char * config_file = NULL;
char * pid_file = NULL;
char * socket_file = NULL;

/* When a SIGUSR1 signal arrives, set this variable.   */
volatile sig_atomic_t sleep_status = 1;

unsigned short int pausable_chk_port = 0;
unsigned short int chk_port = 0;
int log_level = LOG_ERR;
configuration connections;

/*
 This function is called for daemonize the proces only
 (option -D)
 */

int daemonize(configuration * connections)
{
	FILE * file;
	char saved_pid[11];
	int status;
	/* Our process ID and Session ID */
	pid_t pid, sid;

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0)
	{
		return (DAEMONIZE_FAILURE);
	}
	/* If we got a good PID, then
	 we can exit the parent process. */
	if (pid > 0)
	{
		return (DAEMONIZE_SUCCESS);
	}

	/* Change the file mode mask */
	umask(0);

	// ok we save child pid
	connections->running_pid = getpid();

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0)
	{
		/* Log the failure */
		return (DAEMONIZE_FAILURE);
	}

	/* Change the current working directory */
	if ((chdir("/")) < 0)
	{
		/* Log the failure */
		return (DAEMONIZE_FAILURE);
	}

	//update pid value in pid file
	if (pid_file)
	{
		file = fopen(pid_file, "w+");
		if (!file)
		{
			printf("ERROR: Cannot open %s file.Check permission \n", pid_file);
			return (DAEMONIZE_FAILURE);
		}
		sprintf(saved_pid, "%d", connections->running_pid);
		status = fputs(saved_pid, file);
		if (status == EOF)
		{
			printf("ERROR: Cannot write on %s file.Check permission \n", pid_file);
			return (DAEMONIZE_FAILURE);
		}
		fclose(file);
	}
	else
	{
		printf("ERROR: You have to specify a pid file.Check configuration \n");
		return (DAEMONIZE_FAILURE);
	}

	/* Close out the standard file descriptors but we reopen toward /dev/null
	 * to avoid that exec command without stdio/stdin/stderr could be problematic
	 * often commands complains without stdout/stdin/stderr */
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);

	/* Ok we are in daemon */
	return (DAEMONIZE_INDAEMON);
}

/*General log function to abstract the log facility pointing to syslog or
 * printf depending on to_demonize setting
 */

void Log(int priority, char * format, ...)
{
	va_list ap;

	va_start (ap, format);
	if (to_demonize == 0)
		vprintf(format, ap);
	else
		vsyslog(priority, format, ap);
	va_end (ap);

}
void sleep_signal(int sig)
{
	sleep_status = !sleep_status;
	if (sleep_status)
		Log(LOG_DEBUG, "Sleep enabled\n");
	else
		Log(LOG_DEBUG, "Sleep disabled\n");

}

//function used to clear resources
void term_signal(int sig)
{
	int status;

	Log(LOG_DEBUG, "SIGTERM trapped.Clean all things\n");
	status = clean_all(&connections);
	status = remove(pid_file);
	if (status)
	{
		status = errno;
		Log(LOG_ERR, "Error removing PID file %s, Err(%s)", pid_file, strerror(status));
	}
	status = remove(socket_file);
	if (status)
	{
		status = errno;
		Log(LOG_ERR, "Error removing Socket file %s, Err(%s)", socket_file, strerror(status));
	}
	exit(status);
}

void pipe_signal(int sig)
{
	Log(LOG_DEBUG, "SIGPIPE trapped.Ignore it\n");
}

int initialize_timers(configuration * connections)
{
	int configured_ports = connections->last_slot;
	int i;
	int status = 0;

	for (i = 0; i <= configured_ports; i++)
	{

		if (connections->single_conn[i].timer.chk_function)
		{
			status = make_timer(&(connections->single_conn[i]));
			if (status)
			{
				Log(LOG_ERR, "Error creating timer for service %s", connections->single_conn[i].service_name);

			}
		}
	}

	return status;
}

int main(int argc, char **argv)
{

	int status;
	struct sigaction usr_action;
	struct sigaction term_action;
	struct sigaction pipe_action;
	sigset_t block_mask;

	int socks_status;

	connections.last_slot = -1;
	connections.running_pid = getpid();

	status = init(argc, argv, &connections);

	if (status == INIT_FAILURE)
	{
		if (to_printhelp == 1)
			print_help(argc, argv);
		exit(EXIT_FAILURE);
	}

	if (status == INIT_SUCCESS && to_printhelp == 1)
	{
		print_help(argc, argv);
		exit(EXIT_SUCCESS);
	}

	if (to_command_mode)
	{
		status = execute_command(&connections);
		exit(status);
	}

	Log(LOG_NOTICE, "Program started by User %d \n", getuid());
	/* Daemon-specific initialization */

	if (to_demonize)
	{

		status = daemonize(&connections);
		switch (status)
		{
			case DAEMONIZE_FAILURE:
				/*something gone wrong exit from parent */
				printf("Failed to daemonize.Check permissions\n");
				exit(EXIT_FAILURE);
				break;
			case DAEMONIZE_SUCCESS:
				/*ok we are the parent, we can exit gracefully */
				Log(LOG_INFO, "Starting as a daemon.Parent exit\n");
				printf("Starting as a daemon.Parent exit\n");
				exit(EXIT_SUCCESS);
				break;
		}

	}

	/* Establish the signal handler.  */
	sigfillset(&block_mask);
	usr_action.sa_handler = sleep_signal;
	usr_action.sa_mask = block_mask;
	usr_action.sa_flags = 0;
	sigaction(SIGUSR1, &usr_action, NULL);
	term_action.sa_handler = term_signal;
	term_action.sa_mask = block_mask;
	term_action.sa_flags = 0;
	sigaction(SIGTERM, &term_action, NULL);
	pipe_action.sa_handler = pipe_signal;
	pipe_action.sa_mask = block_mask;
	pipe_action.sa_flags = 0;
	sigaction(SIGPIPE, &pipe_action, NULL);

	Log(LOG_INFO, "Init networking\n");

	status = initialize_network(&connections);

	Log(LOG_INFO, "Init timers\n");
	status = initialize_timers(&connections);

	/* The Big Loop */
	while (1)
	{
		Log(LOG_DEBUG, "Main loop\n");
		rebuild_connection_set(&connections);
		socks_status = select(connections.max_socket + 1, &connections.socket_set, NULL, NULL, NULL);
		if (socks_status < 0)
		{
			status = errno;
			/* We had an error, signal it */
			if (status != EINTR)
			{
				Log(LOG_ERR, "Error in select socket (%s) \n", strerror(status));
				exit(EXIT_FAILURE);
			}
		}
		else
			if (socks_status == 0)
			{
				/* Nothing to do probably a staying alive msg in debug mode */
			}
			else
			{
				read_sockets(&connections);
			}
	}
	closelog();
	exit(EXIT_SUCCESS);
}
