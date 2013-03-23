/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * general.c
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
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "general.h"
#include "ini.h"
#include "checkers.h"
#include "networking.h"

extern unsigned char to_demonize;
extern unsigned char to_printhelp;
extern unsigned char to_command_mode;
extern char * config_file;

extern char * pid_file;
extern char * socket_file;
extern volatile sig_atomic_t sleep_status;

extern void Log(int priority, char * format, ...);
extern int log_level;

#define ARG_NULL   0
#define ARG_NAME   1
#define ARG_NUMBER 2
#define ARG_EASTER 3

#define COMMAND_BUFFER_SIZE  201

struct shell_commands
{
	char * token;
	int arg1_type; //ARG_XXX defines
	int arg2_type; //ARG_XXX defines
	char help_string[COMMAND_BUFFER_SIZE]; //help string for the command
	int (*pfunc_command)(configuration *, char *, struct shell_commands *, ...); //function pointer to the real cmd_shell function
};

void print_help(int argc, char **argv)
{
	printf("PortSentinel - HAProxy responder Ver: %s, (C) 2012 Daimonlab \n", VERSION);
	printf("Usage:\n");
	printf("%s [options] -f <configuration_file> \n", argv[0]);
	printf("       -?  Help screen \n");
	printf("       -D  run Detached \n");
	printf("       -d  run demonized \n");
	printf("       -c <command> Invoke a command in client mode (type -c help for the list) \n");
	printf("       -f <configuration_file>  config INI file \n");
	printf("\nNOTE:To ckeck pausable status telnet to pausable port \n");
	printf("     %s sends a 503 to callers notifying paused activity \n", PROGRAM_NAME);
	printf("                sends a 200 to callers in normal behaviour \n");

}

char ** split(const char * string)
{
	char * SPLIT_TOKEN_SEPARATORS = " ";
	int BUFFERSIZE = 1024;
	int iter = 0;
	char * saveptr;
	char * token;
	char ** splitted;
	char * buffer;

	if (string)
	{
		buffer = strdup(string);
		splitted = malloc(BUFFERSIZE * sizeof(char *));
		memset(splitted, 0, BUFFERSIZE * sizeof(char *));
		token = strtok_r(buffer, SPLIT_TOKEN_SEPARATORS, &saveptr);
		if (token)
		{
			do
			{
				splitted[iter++] = strdup(token);
				token = strtok_r(NULL, SPLIT_TOKEN_SEPARATORS, &saveptr);

			} while (token && iter < 1024);
			free(buffer);
			return splitted;
		}
		else
		{
			free(buffer);
			return NULL;
		}
	}
	else
		return NULL;

}

unsigned short int reply_simple(void * conn, int port_index, int socket_index)
{
	char * temp_buffer;
	int chk_status;

	configuration * connections = (configuration *) conn;

	temp_buffer = &(connections->single_conn[port_index].buffer[socket_index][0]);

	sprintf(temp_buffer, ECHOMSG, MSG_OK, MSG_OK_S);

	if (connections->single_conn[port_index].disabled)
	{
		sprintf(temp_buffer, ECHOMSG, MSG_SERVICE_UNVL, MSG_SERVICE_UNVL_S);
		return 0;
	}

	if (connections->single_conn[port_index].pausable)
	{
		if (sleep_status)
		{
			sprintf(temp_buffer, ECHOMSG, MSG_SERVICE_UNVL, MSG_SERVICE_UNVL_S);
			return 0;
		}
	}

	chk_status=connections->single_conn[port_index].timer.chk_status;

	if (chk_status != CHKSTATUS_OK)
	{
		switch (chk_status)
		{
			case CHKSTATUS_SERVICE_DOWN:
				sprintf(temp_buffer, ECHOMSG, MSG_DOWN, MSG_DOWN_SERVICE_DOWN_S);
			break;
			case CHKSTATUS_CHECK_FAILS:
				sprintf(temp_buffer, ECHOMSG, MSG_DOWN, MSG_DOWN_TEST_FAILED_S);
			break;
			case CHKSTATUS_SERVICE_PAUSING:
				sprintf(temp_buffer, ECHOMSG, MSG_APPLICTION_SLEEP, MSG_APPLICTION_SLEEP_S);
			break;
			default:
				sprintf(temp_buffer, ECHOMSG, MSG_DOWN, MSG_DOWN_UNKNOWN_S);

		}
	}

	return 0;

}

int cmd_shell_version(configuration * connections, char * buffer, struct shell_commands * valid_commands, ...)
{
#define VERSION_MSG		" " PROGRAM_NAME " Version: " VERSION "\r\n"

	sprintf(buffer, VERSION_MSG);
	return 0;
}

int cmd_shell_help(configuration * connections, char * buffer, struct shell_commands * valid_commands, ...)
{
#define HELP_HEADER "-- "PROGRAM_NAME " Help -- \n\n"
#define COMMAND_NOTFOUND "Sorry. Command not found in help"

	va_list ap;
	char arg_command[COMMAND_BUFFER_SIZE], *parg;
	struct shell_commands * valid_command;
	int pos, num;

	valid_command = valid_commands;
	va_start (ap, valid_commands);
	parg = va_arg(ap,char *);
	if (parg)
		strncpy(arg_command, parg, COMMAND_BUFFER_SIZE);
	else
		arg_command[0] = '\0';
	pos = num = 0;

	num = sprintf(buffer + pos, HELP_HEADER);
	pos = pos + num;

	do
	{
		if (strlen(arg_command))
		{
			if ((strcmp(valid_command->token, arg_command) == 0) && (valid_command->arg1_type != ARG_EASTER))
			{
				sprintf(buffer + pos, valid_command->help_string);
				va_end(ap);
				return 0;
			}
		}
		else
		{
			if (valid_command->arg1_type != ARG_EASTER)
			{
				num = sprintf(buffer + pos, valid_command->help_string);
				pos = pos + num;
			}

		}
		valid_command++;
	} while (valid_command->token != NULL);

	if (strlen(arg_command))
	{
		//asked a command that does not exists
		sprintf(buffer + pos, COMMAND_NOTFOUND);
	}

	va_end(ap);

	return 0;
}

int cmd_shell_enable(configuration * connections, char * buffer, struct shell_commands * valid_commands, ...)
{

#define ENABLE_ERROR 		"Error enabling. Please specify service name to enable\n\n"
#define SERVICE_NOT_FOUND   "Error enabling. Service name not found in configuration file\n\n"
#define ENABLE_OK 			"Service [%s] enabled.\n\n"

	va_list ap;
	char arg_command[COMMAND_BUFFER_SIZE], *parg;
	struct shell_commands * valid_command;

	valid_command = valid_commands;
	va_start (ap, valid_commands);

	parg = va_arg(ap,char *);

	if (parg)
	{
		strncpy(arg_command, parg, COMMAND_BUFFER_SIZE);
	}
	else
	{

		sprintf(buffer, ENABLE_ERROR);
		va_end(ap);
		return 0;
	}

	do
	{
		if (strlen(arg_command))
		{
			int i = 0;
			while (connections->single_conn[i].service_name != NULL && i < LISTENING_PORTS)
			{
				if (strcmp(connections->single_conn[i].service_name, arg_command) == 0)
				{
					connections->single_conn[i].disabled = 0;
					sprintf(buffer, ENABLE_OK, arg_command);
					va_end(ap);
					return 0;
				}
				i++;
			}
		}
		else
		{
			sprintf(buffer, ENABLE_ERROR);
			va_end(ap);
			return 0;

		}
		valid_command++;
	} while (valid_command->token != NULL);

	if (strlen(arg_command))
	{
		//asked a service that does not exists
		sprintf(buffer, SERVICE_NOT_FOUND);
	}

	va_end(ap);

	return 0;
}

int cmd_shell_disable(configuration * connections, char * buffer, struct shell_commands * valid_commands, ...)
{
#define DISABLE_ERROR 			"Error disabling. Please specify service name to disable\n\n"
#define DIS_SERVICE_NOT_FOUND   "Error disabling. Service name not found in configuration file\n\n"
#define DISABLE_OK 				"Service [%s] disabled.\n\n"

	va_list ap;
	char arg_command[COMMAND_BUFFER_SIZE], *parg;
	struct shell_commands * valid_command;

	valid_command = valid_commands;
	va_start (ap, valid_commands);

	parg = va_arg(ap,char *);

	if (parg)
	{
		strncpy(arg_command, parg, COMMAND_BUFFER_SIZE);
	}
	else
	{

		sprintf(buffer, DISABLE_ERROR);
		va_end(ap);
		return 0;
	}

	do
	{
		if (strlen(arg_command))
		{
			int i = 0;
			while (connections->single_conn[i].service_name != NULL && i < LISTENING_PORTS)
			{
				if (strcmp(connections->single_conn[i].service_name, arg_command) == 0)
				{
					connections->single_conn[i].disabled = 1;
					sprintf(buffer, DISABLE_OK, arg_command);
					va_end(ap);
					return 0;
				}
				i++;
			}
		}
		else
		{
			sprintf(buffer, DISABLE_ERROR);
			va_end(ap);
			return 0;

		}
		valid_command++;
	} while (valid_command->token != NULL);

	if (strlen(arg_command))
	{
		//asked a service that does not exists
		sprintf(buffer, DIS_SERVICE_NOT_FOUND);
	}

	va_end(ap);

	return 0;
}

int cmd_shell_status(configuration * connections, char * buffer, struct shell_commands * valid_commands, ...)
{
#define LIST_PID          PROGRAM_NAME " process ID: %d \n"
#define LIST_FLAG         "Pausing state: %s \n\n"
#define LIST_STATUS       "Service [%s]\n Listening port: %d\n Port type: %s\n Port status: %s\n Active connections: %d\n Connections counter: %d \n Check timer params\n ------------------\n  CheckTest status: %s\n  Command: %s\n  Check interval: %d sec\n  Last check return status: %d\n  Last time call  %02d/%02d/%d %02d:%02d:%02d\n  Checks count: %d\n  Calls in queue: %d\n\n"
#define LIST_STATUS_WT    "Service [%s]\n Listening port: %d\n Port type: %s\n Port status: %s\n Active connections: %d\n Connections counter: %d \n\n"
#define LIST_ENABLED      "ENABLED"
#define LIST_DISABLED     "DISABLED"
#define LIST_PAUSABLE     "pausable"
#define LIST_NON_PAUSABLE "not pausable"
#define CHECK_ENABLED      "ENABLED"
#define CHECK_DISABLED     "DISABLED"

	va_list ap;
	int num_connections = 0;
	int pid = 0;
	int port = 0;
	char port_type[100];
	char port_status[100];
	char check_status[100];
	char pause_status[100];
	int pos, num;
	struct tm *tm;
	shell_args_t * args;

	char arg_command[COMMAND_BUFFER_SIZE], *parg;
	struct shell_commands * valid_command;
	int i = 0;

	valid_command = valid_commands;
	va_start (ap, valid_commands);
	parg = va_arg(ap,char *);

	arg_command[0]='\0';

	if (parg)
	{
		strncpy(arg_command, parg, COMMAND_BUFFER_SIZE-1);
	}


	pos = num = 0;

	pid = connections->running_pid;
	num = sprintf(buffer, LIST_PID, pid);
	pos = pos + num;
	if (sleep_status)
		strcpy(pause_status, LIST_ENABLED);
	else
		strcpy(pause_status, LIST_DISABLED);
	num = sprintf(buffer + pos, LIST_FLAG, pause_status);
	pos = pos + num;

	if (connections)
		while (connections->single_conn[i].service_name != NULL && i < LISTENING_PORTS)
		{
			int j = 0;
			while (connections->single_conn[i].running_sockets[j] != 0 && j < MAX_CLIENTS)
			{
				j++;
			}
			num_connections = j;

			port = connections->single_conn[i].port;
			if (connections->single_conn[i].pausable)
				strcpy(port_type, LIST_PAUSABLE);
			else
				strcpy(port_type, LIST_NON_PAUSABLE);

			if (connections->single_conn[i].disabled)
				strcpy(port_status, LIST_DISABLED);
			else
				strcpy(port_status, LIST_ENABLED);

			if (connections->single_conn[i].timer.disabled)
				strcpy(check_status, CHECK_DISABLED);
			else
				strcpy(check_status, CHECK_ENABLED);



			if ((strlen(arg_command)==0) || (strcmp(arg_command,connections->single_conn[i].service_name)==0))
			{

				if (connections->single_conn[i].timer.chk_function)
				{
					tm = localtime(&(connections->single_conn[i].timer.last_call));
					args = (shell_args_t *) connections->single_conn[i].timer.chk_arguments.sival_ptr;
					num = sprintf(buffer + pos, LIST_STATUS, connections->single_conn[i].service_name, port, port_type,
						port_status, num_connections, connections->single_conn[i].counter, check_status,args->script_name,
						connections->single_conn[i].timer.check_interval, connections->single_conn[i].timer.chk_status,
						tm->tm_mday,tm->tm_mon,tm->tm_year+1900,tm->tm_hour, tm->tm_min, tm->tm_sec, connections->single_conn[i].timer.counter,
						connections->single_conn[i].timer.inqueue);
				}
				else
				{

					num = sprintf(buffer + pos, LIST_STATUS_WT, connections->single_conn[i].service_name, port, port_type,
							port_status, num_connections, connections->single_conn[i].counter);
				}

				pos = pos + num;
			}

			i++;
		}

	va_end(ap);
	return 0;
}

int cmd_shell_pause_all(configuration * connections, char * buffer, struct shell_commands * valid_commands, ...)
{
	#define PAUSE_OK	"All pausable ports are now in pause state.\n\n"
	sleep_status = 1;
	Log(LOG_DEBUG, "Sleep enabled by shell\n");
	sprintf(buffer,PAUSE_OK);
	return 0;
}
int cmd_shell_unpause_all(configuration * connections, char * buffer, struct shell_commands * valid_commands, ...)
{
	#define UNPAUSE_OK	"All pausable ports are now in active state.\n\n"
	sleep_status = 0;
	Log(LOG_DEBUG, "Sleep disabled by shell\n");
	sprintf(buffer,UNPAUSE_OK);
	return 0;

}
int cmd_shell_kill(configuration * connections, char * buffer, struct shell_commands * valid_commands, ...)
{
	kill(connections->running_pid,SIGTERM);
	return 0;
}
int cmd_shell_dobby(configuration * connections, char * buffer, struct shell_commands * valid_commands, ...)
{
	#define DOBBY "Dobby has got a sock\nMaster threw it, and Dobby caught it\nand Dobby.. Dobby is free.\n\n"
	sprintf(buffer,DOBBY);
	return 0;
}

int cmd_shell_test(configuration * connections, char * buffer, struct shell_commands * valid_commands, ...)
{
	return 0;
}
int cmd_shell_disable_test(configuration * connections, char * buffer, struct shell_commands * valid_commands, ...)
{
#define TEST_DISABLE_ERROR 			 "Error disabling test. Please specify service name to disable\n\n"
#define TEST_DIS_SERVICE_NOT_FOUND   "Error disabling test . Service name not found in configuration file\n\n"
#define TEST_DIS_SERVICE_NO_FUNCTION "Error disabling. Service [%s] do not have check function\n\n"
#define TEST_DISABLE_OK 				"Test check for  [%s] disabled.\n\n"

	va_list ap;
	char arg_command[COMMAND_BUFFER_SIZE], *parg;
	struct shell_commands * valid_command;

	valid_command = valid_commands;
	va_start (ap, valid_commands);

	parg = va_arg(ap,char *);

	if (parg)
	{
		strncpy(arg_command, parg, COMMAND_BUFFER_SIZE);
	}
	else
	{

		sprintf(buffer, TEST_DISABLE_ERROR);
		va_end(ap);
		return 0;
	}

	do
	{
		if (strlen(arg_command))
		{
			int i = 0;
			while (connections->single_conn[i].service_name != NULL && i < LISTENING_PORTS)
			{
				if (strcmp(connections->single_conn[i].service_name, arg_command) == 0)
				{
					if (connections->single_conn[i].timer.chk_function)
					{
						pthread_mutex_lock(&(connections->single_conn[i].timer.chk_mutex));
						connections->single_conn[i].timer.disabled = 1;
						connections->single_conn[i].timer.chk_status=0;
						pthread_mutex_unlock(&(connections->single_conn[i].timer.chk_mutex));
						sprintf(buffer, TEST_DISABLE_OK, arg_command);
						va_end(ap);
						return 0;
					}
					else
					{
						sprintf(buffer, TEST_DIS_SERVICE_NO_FUNCTION, arg_command);
						va_end(ap);
						return 0;
					}
				}
				i++;
			}
		}
		else
		{
			sprintf(buffer, TEST_DISABLE_ERROR);
			va_end(ap);
			return 0;

		}
		valid_command++;
	} while (valid_command->token != NULL);

	if (strlen(arg_command))
	{
		//asked a service that does not exists
		sprintf(buffer, TEST_DIS_SERVICE_NOT_FOUND);
	}

	va_end(ap);

	return 0;
}
int cmd_shell_enable_test(configuration * connections, char * buffer, struct shell_commands * valid_commands, ...)
{
#define TEST_ENABLE_ERROR 		"Error enabling test. Please specify service name to enable\n\n"
#define TEST_SERVICE_NOT_FOUND   "Error enabling test. Service name not found in configuration file\n\n"
#define TEST_SERVICE_NO_FUNCTION "Error enabling. Service [%s] do not have check function\n\n"
#define TEST_ENABLE_OK 			"Check test for [%s] enabled.\n\n"

	va_list ap;
	char arg_command[COMMAND_BUFFER_SIZE], *parg;
	struct shell_commands * valid_command;

	valid_command = valid_commands;
	va_start (ap, valid_commands);

	parg = va_arg(ap,char *);

	if (parg)
	{
		strncpy(arg_command, parg, COMMAND_BUFFER_SIZE);
	}
	else
	{

		sprintf(buffer, TEST_ENABLE_ERROR);
		va_end(ap);
		return 0;
	}

	do
	{
		if (strlen(arg_command))
		{
			int i = 0;
			while (connections->single_conn[i].service_name != NULL && i < LISTENING_PORTS)
			{
				if (strcmp(connections->single_conn[i].service_name, arg_command) == 0)
				{
					if (connections->single_conn[i].timer.chk_function)
					{
						pthread_mutex_lock(&(connections->single_conn[i].timer.chk_mutex));
						connections->single_conn[i].timer.disabled = 0;
						pthread_mutex_unlock(&(connections->single_conn[i].timer.chk_mutex));
						sprintf(buffer, TEST_ENABLE_OK, arg_command);
						va_end(ap);
						return 0;
					}
					else
					{
						sprintf(buffer, TEST_SERVICE_NO_FUNCTION, arg_command);
						va_end(ap);
						return 0;
					}
				}
				i++;
			}
		}
		else
		{
			sprintf(buffer, TEST_ENABLE_ERROR);
			va_end(ap);
			return 0;

		}
		valid_command++;
	} while (valid_command->token != NULL);

	if (strlen(arg_command))
	{
		//asked a service that does not exists
		sprintf(buffer, TEST_SERVICE_NOT_FOUND);
	}

	va_end(ap);

	return 0;

}
//reply function used to set advanced parameters and future exensions
//using unix socket
unsigned short int single_command_shell(void * conn, int port_index, int socket_index)
{

	//AF_UNIX shell messages
#define NOTFOUND_ERROR_MSG	"Command not found \r\n"
#define SYNTAX_ERROR_MSG	"Syntax error \r\n"
#define TOKEN_SEPARATORS 	" \n\r\t"

	struct shell_commands valid_commands[] =
	{
			{ "version",
			  ARG_NULL,
			  ARG_NULL,
			  "version \nPrint the version of " PROGRAM_NAME "\n\n",
			  cmd_shell_version },
			{ "help",
			  ARG_NAME,
			  ARG_NULL,
			  "help [command] \nPrint help for [command] or full help list.\n\n",
			  cmd_shell_help },
			{ "pause",
			  ARG_NULL,
			  ARG_NULL,
			  "pause \nPause all ports declared as pausable.\n\n",
			  cmd_shell_pause_all },
			{ "run",
			  ARG_NULL,
			  ARG_NULL,
			  "run \nUnpause all ports declared as pausable.\n\n",
			  cmd_shell_unpause_all },
			{ "enable",
			  ARG_NAME,
			  ARG_NULL,
			  "enable <INI service name> \nManually enable the service name specified in INI section\n\n",
			  cmd_shell_enable },
			{ "disable",
			  ARG_NAME,
			  ARG_NULL,
			  "disable <INI service name> \nManually disable the service name specified in INI section\n\n",
			  cmd_shell_disable },
			  { "stop_server",
				ARG_NAME,
			    ARG_NULL,
			    "stop_server\nStop gracefully the server part of "PROGRAM_NAME "\n\n",
			   cmd_shell_kill },
			{ "status",
			  ARG_NAME,
			  ARG_NULL,
			  "status [INI service name] \nList information about service \n\n",
			  cmd_shell_status },
			{ "test",
			  ARG_NAME,
			  ARG_NULL,
			  "test <INI service name> \n Force a test execution for a specific service \n\n",
			  cmd_shell_test },
			{ "disable_test",
			  ARG_NAME,
			  ARG_NULL,
			  "disable_test <INI service name> \n Disable the check test execution for a specific service  \n\n",
			  cmd_shell_disable_test },
		    { "enable_test",
			  ARG_NAME,
			  ARG_NULL,
			  "enable_test <INI service name> \n Enable the check test execution for a specific service \n\n",
			  cmd_shell_enable_test },
			{
				"dobby",
				ARG_EASTER,
				ARG_EASTER,
				"***",
				cmd_shell_dobby
			},
			{ NULL, ARG_NULL,ARG_NULL, "", NULL } };

#define NUM_COMMANDS  (sizeof(valid_commands)/sizeof(struct shell_commands))
	char buffer[COMMAND_BUFFER_SIZE * NUM_COMMANDS];

	char * command, *token, *arg1, *arg2;
	char * saveptr;
	struct shell_commands * valid_command;
	int iter;
	int value1, value2;

	configuration * connections = (configuration *) conn;
	buffer[0]='\0';
	strncpy(buffer, &(connections->single_conn[port_index].buffer[socket_index][0]), COMMAND_BUFFER_SIZE * NUM_COMMANDS);
	buffer[COMMAND_BUFFER_SIZE * NUM_COMMANDS - 1] = '\0';
	command = buffer;
	token = strtok_r(command, TOKEN_SEPARATORS, &saveptr);
	if (token)
	{
		//search token in valid token array
		iter = 0;
		valid_command = valid_commands;
		do
		{
			if (strcmp(token, valid_command->token) == 0)
			{
				switch (valid_command->arg1_type)
				{
					case ARG_NULL:
					case ARG_EASTER:
						//no arguments. We call directly the function
						valid_command->pfunc_command(connections, buffer, valid_commands);
						strncpy(&(connections->single_conn[port_index].buffer[socket_index][0]), buffer, MAX_LINE);
						connections->single_conn[port_index].buffer[socket_index][MAX_LINE - 1] = '\0';
						return 0;
						break;
					case ARG_NAME:
						//take first arg
						arg1 = strtok_r(NULL, TOKEN_SEPARATORS, &saveptr);
						//check the second arg
						switch (valid_command->arg2_type)
						{
							case ARG_NULL:
								valid_command->pfunc_command(connections, buffer, valid_commands, arg1);
								strncpy(&(connections->single_conn[port_index].buffer[socket_index][0]), buffer,
										MAX_LINE);
								connections->single_conn[port_index].buffer[socket_index][MAX_LINE - 1] = '\0';
								return 0;

								break;
							case ARG_NAME:
								//take econd arg
								arg2 = strtok_r(NULL, TOKEN_SEPARATORS, &saveptr);
								valid_command->pfunc_command(connections, buffer, valid_commands, arg1, arg2);
								strncpy(&(connections->single_conn[port_index].buffer[socket_index][0]), buffer,
										MAX_LINE);
								connections->single_conn[port_index].buffer[socket_index][MAX_LINE - 1] = '\0';
								return 0;
								break;
							case ARG_NUMBER:
								arg2 = strtok_r(NULL, TOKEN_SEPARATORS, &saveptr);
								value2 = atoi(arg2);
								valid_command->pfunc_command(connections, buffer, valid_commands, arg1, value2);
								strncpy(&(connections->single_conn[port_index].buffer[socket_index][0]), buffer,
										MAX_LINE);
								connections->single_conn[port_index].buffer[socket_index][MAX_LINE - 1] = '\0';
								return 0;
								break;
						}
						break;
					case ARG_NUMBER:
						//take first arg
						arg1 = strtok_r(NULL, TOKEN_SEPARATORS, &saveptr);
						value1 = atoi(arg1);
						//check the second arg
						switch (valid_command->arg2_type)
						{
							case ARG_NULL:
								valid_command->pfunc_command(connections, buffer, valid_commands, value1);
								strncpy(&(connections->single_conn[port_index].buffer[socket_index][0]), buffer,
										MAX_LINE);
								connections->single_conn[port_index].buffer[socket_index][MAX_LINE - 1] = '\0';
								return 0;

								break;
							case ARG_NAME:
								//take econd arg
								arg2 = strtok_r(NULL, TOKEN_SEPARATORS, &saveptr);
								valid_command->pfunc_command(connections, buffer, valid_commands, value1, arg2);
								strncpy(&(connections->single_conn[port_index].buffer[socket_index][0]), buffer,
										MAX_LINE);
								connections->single_conn[port_index].buffer[socket_index][MAX_LINE - 1] = '\0';
								return 0;
								break;
							case ARG_NUMBER:
								arg2 = strtok_r(NULL, TOKEN_SEPARATORS, &saveptr);
								value2 = atoi(arg2);
								valid_command->pfunc_command(connections, buffer, valid_commands, value1, value2);
								strncpy(&(connections->single_conn[port_index].buffer[socket_index][0]), buffer,
										MAX_LINE);
								connections->single_conn[port_index].buffer[socket_index][MAX_LINE - 1] = '\0';
								return 0;
								break;
						}
						break;

				}
			}
			valid_command++;
			iter++;
		} while (valid_command->token != NULL);
	}

	sprintf(buffer, NOTFOUND_ERROR_MSG);
	strncpy(&(connections->single_conn[port_index].buffer[socket_index][0]), buffer, MAX_LINE);
	connections->single_conn[port_index].buffer[socket_index][MAX_LINE - 1] = '\0';

	return 0;

}
int search_slot(const char * section, const configuration * connections)
{
	int i;
	int last = connections->last_slot;

	for (i = 0; i <= last; i++)
	{
		if (connections->single_conn[i].service_name != NULL)
		{
			if (strcmp(section, connections->single_conn[i].service_name) == 0)
				break;
		}

	}

	return i;

}

static int handler(void* user, const char* section, const char* name, const char* value)
{
	int slot;

	configuration * connections = (configuration *) user;

	slot = search_slot(section, connections);

	if (slot > connections->last_slot)
	{
		if (slot < LISTENING_PORTS)
		{
			connections->last_slot = slot;
			connections->single_conn[slot].service_name = strdup(section);

			if (strcmp(section, GENERAL_SETUP_ENTRY) == 0)
			{
				//set reply function for socket AF_UNIX
				connections->single_conn[slot].reply_function = single_command_shell;

			}
			else
			{
				//set a simple reply function for haproxy
				connections->single_conn[slot].reply_function = reply_simple;
			}

		}
		else
		{
			printf("ERROR: Too many ports. The max is set to %d", LISTENING_PORTS);
			return 0;
		}
	}
	if (strcmp(name, "port") == 0)
	{

		in_port_t port = atoi(value);
		if (port < USHRT_MAX)
		{
			connections->single_conn[slot].port = port;
		}
		else
		{
			printf("IP port specified is out of range \n");
			return 0;
		}
	}
	if (strcmp(name, "pausable") == 0)
	{
		if (strcmp(value, "yes") == 0 || strcmp(value, "YES") == 0 || strcmp(value, "1") == 0)
		{
			connections->single_conn[slot].pausable = 1;
		}
		else
			if (strcmp(value, "no") == 0 || strcmp(value, "NO") == 0 || strcmp(value, "0") == 0)
			{
				connections->single_conn[slot].pausable = 0;
			}
			else
			{
				printf("Pausable attribute accepts yes,YES,no,NO,0,1 only \n");
				return 0;
			}
	}
	if (strcmp(name, "start_paused") == 0)
	{
		if (strcmp(value, "yes") == 0 || strcmp(value, "YES") == 0 || strcmp(value, "1") == 0)
		{
			sleep_status = 1;
		}
		else
			if (strcmp(value, "no") == 0 || strcmp(value, "NO") == 0 || strcmp(value, "0") == 0)
			{
				sleep_status = 0;
			}
			else
			{
				printf("Start paused attribute accepts yes,YES,no,NO,0,1 only \n");
				return 0;
			}
	}
	if (strcmp(name, "check_script") == 0)
	{
		if (strcmp(value, "none"))
		{
			char ** args;
			shell_args_t * shell_args;

			//for now only external scripts are supported. In future if we expose special check functions
			//we have to switch/case and substitute the right pointer
			connections->single_conn[slot].timer.chk_function = call_script;
			//argument extraction

			args = split(value);
			shell_args = (shell_args_t *) malloc(sizeof(shell_args_t));
			//tipically the first one is the fullpath name of script
			shell_args->script_name = strdup(args[0]);
			shell_args->script_args = args;
			connections->single_conn[slot].timer.chk_arguments.sival_ptr = shell_args;
			//if for some reason the check interbval is 0 (because forgot or wrong) we default to 10
			connections->single_conn[slot].timer.check_interval = 10;
		}
		else
		{
			connections->single_conn[slot].timer.chk_function
					= connections->single_conn[slot].timer.chk_arguments.sival_ptr = NULL;
		}
	}
	if (strcmp(name, "check_script_interval") == 0)
	{
		int seconds;
		seconds = atoi(value);
		if (seconds)
		{
			connections->single_conn[slot].timer.check_interval = seconds;
		}
		else
		{
			printf("Please specify a number in check_script_interval \n");
			return 0;
		}

	}
	if (strcmp(name, "pid_file") == 0)
	{
		FILE* file;
		char saved_pid[11];
		pid_t read_pid;
		int status;

		if (!to_command_mode)
		{
			file = fopen(value, "r+");
			if (file)
			{

				if (fgets(saved_pid, sizeof(saved_pid), file) != NULL)
				{
					read_pid = atoi(saved_pid);
					if (read_pid != connections->running_pid)
					{
						printf(
								"ERROR: File %s already exists with different PID file.Check if other hang copy of " PROGRAM_NAME " still running \n",
								value);
						fclose(file);
						return 0;
					}
				}
				fclose(file);
			}

			file = fopen(value, "w+");
			if (!file)
			{
				printf("ERROR: Cannot open %s file.Check permission \n", value);
				return 0;
			}
			sprintf(saved_pid, "%d", connections->running_pid);
			status = fputs(saved_pid, file);
			if (status == EOF)
			{
				printf("ERROR: Cannot write on %s file.Check permission \n", value);
				return 0;
			}
			fclose(file);

			pid_file = strdup(value);
		}

	}
	if (strcmp(name, "sock_file") == 0)
	{
		if (strlen(value) < 100)
		{
			socket_file = strdup(value);
		}
		else
		{
			printf("ERROR: Socket filename %s is too long. Please choose a short one \n", value);
			return 0;
		}
	}
	if (strcmp(name, "log_level") == 0)
	{
		int level;
		level = atoi(value);
		switch (level)
		{
			case 0:
				log_level = LOG_ERR;
				break;
			case 1:
				log_level = LOG_WARNING;
				break;
			case 2:
				log_level = LOG_NOTICE;
				break;
			case 3:
				log_level = LOG_INFO;
				break;
			case 4:
				log_level = LOG_DEBUG;
				break;
			default:
				printf("Warning: Log level given (%d)  out of range [0,4]. Default to 0 \n", level);
				log_level = LOG_ERR;
				break;

		}

	}

	return 1;

}

/*very simple function for reading from a socket
 * is quite basic but I've no time to improve it.
 * Probably in a next release
 */

int execute_command(configuration * connections)
{
	int temp_socket;
	struct sockaddr_un temp_servaddr_un; /*  AF_UNIX socket address structure  */
	int i;
	int nbytes,count;
	struct timespec tm;

	int configured_ports = connections->last_slot;

	for (i = 0; i <= configured_ports; i++)
	{
		//choose "general"  for unix socket
		if (strcmp(connections->single_conn[i].service_name, GENERAL_SETUP_ENTRY) == 0)
		{
			if ((temp_socket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			{
				Log(LOG_ERR, "Error creating listening AF_UNIX socket.\n");
				return (EXIT_FAILURE);
			}
			connections->single_conn[i].listening_socket = temp_socket;
			if (temp_socket > connections->max_socket)
				connections->max_socket = temp_socket;

			memset(&temp_servaddr_un, 0, sizeof(temp_servaddr_un));
			temp_servaddr_un.sun_family = AF_UNIX;
			strcpy(temp_servaddr_un.sun_path, socket_file);

			connections->single_conn[i].servaddr_un = temp_servaddr_un;

			if (connect(temp_socket, (struct sockaddr*) &temp_servaddr_un, SUN_LEN(&temp_servaddr_un)) < 0)
			{
				Log(LOG_ERR, "Error calling connect AF_UNIX (%s)\n", strerror(errno));
				return (EXIT_FAILURE);
			}

			break;
		}
	}
	if (i > configured_ports)
	{
		//general socket not found exit with error
		Log(LOG_ERR, "[general] section not found in config file.Please check the manual\n");
		return (EXIT_FAILURE);
	}

	setnonblocking(connections->single_conn[i].listening_socket);
	nbytes = sock_puts(connections->single_conn[i].listening_socket, connections->command_line);
	if (nbytes == -1)
	{
		//writing error
		Log(LOG_ERR, "Connection with server closed unexpectedly\n");
		return (EXIT_FAILURE);
	}
	nbytes = 0;
	count=0;
	tm.tv_sec = 0;
	tm.tv_nsec = 1000000;
	while (!nbytes && count < 2000 && ioctl(connections->single_conn[i].listening_socket, FIONREAD, &nbytes) >= 0)
	{
		nanosleep(&tm, NULL);
		count++;
	}
	nbytes = sock_read(connections->single_conn[i].listening_socket, connections->command_line, nbytes);
	connections->command_line[nbytes] = 0;

	printf("%s", connections->command_line);

	close(connections->single_conn[i].listening_socket);

	return 0;
}

int init(int argc, char **argv, configuration * connections)
{
	char option;
	int status;

	while ((option = getopt(argc, argv, "Ddf:c:")) != -1)
		switch (option)
		{
			case 'd':
				if (to_command_mode)
				{
					printf("Sorry. the option daemonize (-d) and command (-c) are mutually exclusive\n");
					return INIT_FAILURE;
				}
				to_demonize = 1;
				to_printhelp = 0;
				break;
			case 'D':
				to_demonize = 0;
				to_printhelp = 0;
				break;
			case 'f':
				config_file = optarg;
				if (config_file)
				{
					status = ini_parse(config_file, handler, connections);
					if (status < 0)
					{
						printf("ERROR: Cannot open %s file \n", config_file);
						return INIT_FAILURE;
					}
					else
						if (status > 0)
						{
							printf("------ Check line %d in config file \n", status);
							return INIT_FAILURE;
						}
				}
				else
					return INIT_FAILURE;
				break;
			case 'c':
				//command line mode
				if (to_demonize)
				{
					printf("Sorry. the option daemonize (-d) and command (-c) are mutually exclusive\n");
					return INIT_FAILURE;
				}
				strncpy(connections->command_line, optarg, MAX_LINE);
				if ((optind < argc) && (*argv[optind] != '-'))
				{
					strcat(connections->command_line, " ");
					strncat(connections->command_line, argv[optind], MAX_LINE - strlen(connections->command_line));
					optind++;
				}
				to_command_mode = 1;
				to_printhelp = 0;
				break;

			case '?':
				//print_help(argc, argv);

				break;
			default:
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
				return INIT_FAILURE;
		}

	if (to_demonize == 1)
	{
		setlogmask(LOG_UPTO (log_level));
		openlog(PROGRAM_NAME, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	}
	if (!config_file && !to_printhelp)
	{
		config_file=DEFAULT_CONFIG_FILE;
		status = ini_parse(config_file, handler, connections);
		if (status < 0)
		{
			printf("ERROR: Cannot open %s file \n", config_file);
			return INIT_FAILURE;
		}
		else
			if (status > 0)
			{
				printf("------ Check line %d in config file \n", status);
				return INIT_FAILURE;
			}
	}


	return INIT_SUCCESS;
}

int clean_all(configuration * connections)
{
	//clean all allocated objects and pid files
	int i, j;
	int running_socket;

	for (i = 0; i <= connections->last_slot; i++)
	{
		for (j = 0; j < MAX_CLIENTS; j++)
		{
			running_socket = connections->single_conn[i].running_sockets[j];
			if (running_socket)
			{
				shutdown(running_socket, 2);
			}
		}
		shutdown(connections->single_conn[i].listening_socket, 2);
		free(connections->single_conn[i].service_name);
		if (connections->single_conn[i].timer.chk_arguments.sival_ptr)
		{
			//this code is ugly because I blindly cast the pointer
			//without to know if type is right. For now it works because only oe type is permitted
			//but for future extensions of check functions this have to be improved
			shell_args_t * args = (shell_args_t *) connections->single_conn[i].timer.chk_arguments.sival_ptr;
			char * parg;
			int iarg = 0;

			for (parg = args->script_args[iarg]; parg != NULL; parg = args->script_args[++iarg])
			{
				if (parg)
					free(parg);
			}
			free(args->script_name);
			free(connections->single_conn[i].timer.chk_arguments.sival_ptr);
		}

	}

	return 0;

}

