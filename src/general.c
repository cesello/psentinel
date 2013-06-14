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

/*----------------------------------------------------------------------------
 *  CRC-32 routines are version 2.0.0 by Craig Bruce, 2006-04-29.
 *----------------------------------------------------------------------------
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
extern char * default_working_dir;

extern volatile sig_atomic_t sleep_status;

extern void Log(int priority, char * format, ...);
extern int log_level;

#define ARG_NULL   0
#define ARG_NAME   1
#define ARG_NUMBER 2
#define ARG_EASTER 3

#define COMMAND_BUFFER_SIZE  201

//General structure of psentinel shell command
struct shell_commands
{
	char * token;
	int arg1_type; //ARG_XXX defines
	int arg2_type; //ARG_XXX defines
	char help_string[COMMAND_BUFFER_SIZE]; //help string for the command
	int (*pfunc_command)(configuration *, char *, struct shell_commands *, ...); //function pointer to the real cmd_shell function
};

/*packed structures for store psentinel status on the disk
 * is composed by an header
 * and an array of couples port,service_status
 */

#define NAME_SIZE 		20
#define VERSION_SIZE 	10
#define PRGVERSION_SIZE 20
#define FILESIGNATURE		"DS-" PROGRAM_NAME
#define FILEVERSION			"1.0"
#define FILEPRGVERSION		VERSION
#define DATAFILE_NAME		"/rstatus.psl"
#define DATAFILE_EOF		0x0

struct file_header
{
	    uint8_t name[NAME_SIZE];
	    uint8_t version[VERSION_SIZE];
	    uint8_t prgversion[PRGVERSION_SIZE];
	    uint16_t nservices;
		uint32_t file_crc32;
		uint32_t future1;
		uint32_t future2;
} __attribute__((packed));

struct file_record
{
	    uint16_t service;
	    uint8_t  status;
		uint32_t future1;
		uint32_t future2;
} __attribute__((packed));

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
#define ENABLE_WARNING1		"Service [%s] enabled. BUT datafile error. Please check log\n\n"

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
					int status;

					connections->single_conn[i].disabled = 0;
					status=update_datafile(connections,i);
					if (status)
						sprintf(buffer, ENABLE_OK, arg_command);
					else
						sprintf(buffer,ENABLE_WARNING1,arg_command);
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
#define DISABLE_WARNING1		"Service [%s] disabled. BUT datafile error. Please check log\n\n"

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
					int status;

					connections->single_conn[i].disabled = 1;
					status=update_datafile(connections,i);
					if (status)
						sprintf(buffer, DISABLE_OK, arg_command);
					else
						sprintf(buffer, DISABLE_WARNING1, arg_command);
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
						tm->tm_mday,tm->tm_mon+1,tm->tm_year+1900,tm->tm_hour, tm->tm_min, tm->tm_sec, connections->single_conn[i].timer.counter,
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

int search_slot_byport(uint16_t port,const configuration * connections)
{
	int i;
	int last = connections->last_slot;

	for (i = 0; i <= last; i++)
	{
		if (connections->single_conn[i].service_name != NULL)
		{
			if (connections->single_conn[i].port==port)
				return i;
		}

	}

	return -1;
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
			//by default we set the chkstatus to error
			//in this way we avoid a proxy call during the psentinel startup *before* at least a check
			connections->single_conn[slot].timer.chk_status=CHKSTATUS_CHECK_FAILS;
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

/*----------------------------------------------------------------------------*\
 *  NAME:
 *     Crc32_ComputeBuf() - computes the CRC-32 value of a memory buffer
 *  DESCRIPTION:
 *     Computes or accumulates the CRC-32 value for a memory buffer.
 *     The 'inCrc32' gives a previously accumulated CRC-32 value to allow
 *     a CRC to be generated for multiple sequential buffer-fuls of data.
 *     The 'inCrc32' for the first buffer must be zero.
 *  ARGUMENTS:
 *     inCrc32 - accumulated CRC-32 value, must be 0 on first call
 *     buf     - buffer to compute CRC-32 value for
 *     bufLen  - number of bytes in buffer
 *  RETURNS:
 *     crc32 - computed CRC-32 value
 *  ERRORS:
 *     (no errors are possible)
\*----------------------------------------------------------------------------*/

static unsigned long Crc32_ComputeBuf( unsigned long inCrc32, const void *buf,
                                       size_t bufLen )
{
    static const unsigned long crcTable[256] = {
   0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,
   0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,
   0xE7B82D07,0x90BF1D91,0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,
   0x6DDDE4EB,0xF4D4B551,0x83D385C7,0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,
   0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,0x3B6E20C8,0x4C69105E,0xD56041E4,
   0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,0x35B5A8FA,0x42B2986C,
   0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,0x26D930AC,
   0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
   0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,
   0xB6662D3D,0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,
   0x9FBFE4A5,0xE8B8D433,0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,
   0x086D3D2D,0x91646C97,0xE6635C01,0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,
   0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,0x65B0D9C6,0x12B7E950,0x8BBEB8EA,
   0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,0x4DB26158,0x3AB551CE,
   0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,0x4369E96A,
   0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
   0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,
   0xCE61E49F,0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,
   0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,
   0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,
   0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,0xF00F9344,0x8708A3D2,0x1E01F268,
   0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,0xFED41B76,0x89D32BE0,
   0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,0xD6D6A3E8,
   0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
   0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,
   0x4669BE79,0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,
   0x220216B9,0x5505262F,0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,
   0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,
   0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,0x95BF4A82,0xE2B87A14,0x7BB12BAE,
   0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,0x86D3D2D4,0xF1D4E242,
   0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,0x88085AE6,
   0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
   0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,
   0x3E6E77DB,0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,
   0x47B2CF7F,0x30B5FFE9,0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,
   0xCDD70693,0x54DE5729,0x23D967BF,0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,
   0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D };
    unsigned long crc32;
    unsigned char *byteBuf;
    size_t i;

    /** accumulate crc32 for buffer **/
    crc32 = inCrc32 ^ 0xFFFFFFFF;
    byteBuf = (unsigned char*) buf;
    for (i=0; i < bufLen; i++) {
        crc32 = (crc32 >> 8) ^ crcTable[ (crc32 ^ byteBuf[i]) & 0xFF ];
    }
    return( crc32 ^ 0xFFFFFFFF );
}


/*----------------------------------------------------------------------------*\
 *  NAME:
 *     Crc32_ComputeFile() - compute CRC-32 value for a file
 *  DESCRIPTION:
 *     Computes the CRC-32 value for an opened file.
 *  ARGUMENTS:
 *     file - file pointer
 *     outCrc32 - (out) result CRC-32 value
 *  RETURNS:
 *     err - 0 on success or -1 on error
 *  ERRORS:
 *     - file errors
\*----------------------------------------------------------------------------*/

static int Crc32_ComputeFile( FILE *file, unsigned long *outCrc32 )
{
#   define CRC_BUFFER_SIZE  8192
    unsigned char buf[CRC_BUFFER_SIZE];
    size_t bufLen;

    /** accumulate crc32 from file **/
    *outCrc32 = 0;
    while (1) {
        bufLen = fread( buf, 1, CRC_BUFFER_SIZE, file );
        if (bufLen == 0) {
            if (ferror(file)) {
                fprintf( stderr, "error reading file\n" );
                goto ERR_EXIT;
            }
            break;
        }
        *outCrc32 = Crc32_ComputeBuf( *outCrc32, buf, bufLen );
    }
    return( 0 );

    /** error exit **/
ERR_EXIT:
    return( -1 );
}

int open_datafile(FILE * * fdata, const char * mode)
{

	char * fullpath;
	fullpath=(char *) malloc((strlen(default_working_dir)+strlen(DATAFILE_NAME)+2)*sizeof(char));
	fullpath[0]='\0';
	strcat(fullpath,default_working_dir);
	strcat(fullpath,DATAFILE_NAME);
	*fdata=fopen(fullpath,mode);
	free(fullpath);

	if (*fdata==NULL)
		return 0;

	return 1;


}

int close_datafile(FILE * fdata)
{
	int status=0;

	if (fdata !=NULL)
		status=fclose(fdata);

	return status;
}

int exists_datafile()
{
	int status;
	FILE * fdata=NULL;

	status=open_datafile(&fdata,"r");
	if (fdata==NULL)
		status=0;
	else
		status=1;

	close_datafile(fdata);

	return status;

}



int write_headerdatafile(FILE * fdata,const struct file_header * header)
{
	size_t writebytes;

	rewind(fdata);
	writebytes=fwrite(header,sizeof(struct file_header),1,fdata);
	if (writebytes != 1)
	{
		if (feof(fdata))
		{
			Log(LOG_ERR,"Warning unexpected EOF reached writing header. Please check code for some bug");
		}
		if (ferror(fdata))
		{
			Log(LOG_ERR,"Error on writing header . Please check code for some bug or file permissions");
		}
		clearerr(fdata);

		return 0;
	}
	return 1;

}


//Read the header.
//remember that the caller have to free memory allocated for the header read

struct file_header * read_headerdatafile(FILE * fdata)
{

	struct file_header * filehead=malloc(sizeof(struct file_header));
	size_t readbytes;

	rewind(fdata);
	readbytes=fread(filehead,sizeof(struct file_header),1,fdata);
	if (readbytes != 1)
	{
		if (feof(fdata))
		{
			memset(filehead,0,sizeof(struct file_header));
			filehead->nservices=DATAFILE_EOF;
		}
		if (ferror(fdata))
		{
			Log(LOG_ERR,"Error on reading header . Please check code for some bug or file permissions");
		}
		clearerr(fdata);
		free(filehead);
		return NULL;
	}
	return filehead;

}

int write_datafile(FILE * fdata,const struct file_record * filerec,int record)
{
	int status;

	size_t writebytes;

	status=fseek(fdata,record*sizeof(struct file_record)+sizeof(struct file_header),SEEK_SET);
	if (status !=-1)
	{
		writebytes=fwrite(filerec,sizeof(struct file_record),1,fdata);
		if (writebytes != 1)
		{
			if (feof(fdata))
			{
				Log(LOG_ERR,"Warning unexpected EOF reached writing file record. Please check code for some bug");
			}
			if (ferror(fdata))
			{
				Log(LOG_ERR,"Error on writing file record . Please check code for some bug or file permissions");
			}
			clearerr(fdata);

			return 0;
		}
		return 1;
	}
	else
	{
		Log(LOG_ERR,"Unable to move on record location for writing. Please check permissions or some bug");

		return 0;
	}

}


//Read a single record.
//remember that the caller have to free memory allocated for the record read

struct file_record * read_datafile(FILE * fdata,int record)
{
	int status;
	struct file_record * filerec=malloc(sizeof(struct file_record));
	size_t readbytes;

	status=fseek(fdata,record*sizeof(struct file_record)+sizeof(struct file_header),SEEK_SET);
	if (status !=-1)
	{
		readbytes=fread(filerec,sizeof(struct file_record),1,fdata);
		if (readbytes != 1)
		{
			if (feof(fdata))
			{
				memset(filerec,0,sizeof(struct file_record));
				filerec->service=DATAFILE_EOF;
			}
			if (ferror(fdata))
			{
				Log(LOG_ERR,"Error on reading file record . Please check code for some bug or file permissions");
			}
			clearerr(fdata);
			free(filerec);
			return NULL;
		}
		return filerec;


	}
	else
	{
		Log(LOG_ERR,"Unable to move on record location. Please check permissions or some bug");
		free(filerec);
		return NULL;
	}
}

int update_crc32_datafile(FILE * fdata)
{
	int status;
	struct file_header * pheader;

	pheader=read_headerdatafile(fdata);
	if (pheader != NULL)
	{
		pheader->file_crc32=0;
		status=write_headerdatafile(fdata,pheader);
		if (status == 0)
		{
			Log(LOG_ERR,"update_crc32:Unable to write header on datafile. Please check permissions");
			free(pheader);
			return 0;
		}
		rewind(fdata);
		status=Crc32_ComputeFile(fdata,(unsigned long *) &(pheader->file_crc32));
		if (status == -1)
		{
			Log(LOG_ERR,"update_crc32:Unable calculate CRC32 for datafile. Please check permissions");
			free(pheader);
			return 0;
		}
		status=write_headerdatafile(fdata,pheader);
		if (status == 0)
		{
			Log(LOG_ERR,"update_crc32:Unable to write header on datafile. Please check permissions");
			free(pheader);
			return 0;
		}
		free(pheader);
		return 1;
	}
	else
	{
		Log(LOG_ERR,"update_crc32:Unable to read header on datafile. Please check permissions");
		return 0;
	}

}

int check_crc32_datafile(FILE * fdata)
{
	int status;
	unsigned long crc32,crc32_computed;
	struct file_header * pheader;

	pheader=read_headerdatafile(fdata);
	if (pheader != NULL)
	{
		crc32=pheader->file_crc32;
		pheader->file_crc32=0;
		status=write_headerdatafile(fdata,pheader);


		if (status)
		{
			rewind(fdata);
			status=Crc32_ComputeFile(fdata, &crc32_computed);
			if (status == -1)
			{
				free(pheader);
				Log(LOG_ERR,"check_crc32:Unable calculate CRC32 for datafile. Please check permissions");
				return 0;
			}
			pheader->file_crc32=crc32;
			status=write_headerdatafile(fdata,pheader);
			free(pheader);

			if (crc32 == crc32_computed)
				return 1;
			else
				return 0;
		}
		else
		{
			Log(LOG_ERR,"check_crc32:Unable calculate CRC32 for datafile. Please check permissions");
			return 0;
		}
	}
	else
	{
		Log(LOG_ERR,"check_crc32:update_crc32:Unable to read header on datafile. Please check permissions");
		return 0;
	}

}


struct  file_record * find_datafile(FILE * fdata,uint16_t service_port, int * pos)
{
	struct file_header * pheader=NULL;
	struct file_record * filerec=NULL;

	int i;
	int count;

	pheader=read_headerdatafile(fdata);
	if (pheader != NULL)
	{
		count=pheader->nservices;
		free(pheader);

		for (i=0;i<count;i++)
		{

			filerec=read_datafile(fdata,i);
			if (filerec != NULL)
			{
				if (filerec->service !=DATAFILE_EOF)
				{
					if (filerec->service==service_port)
					{
						*pos=i;
						return filerec;
					}
					free(filerec);

				}
				else
				{
					free(filerec);
					return NULL;
				}
			}
			else
			{
				Log(LOG_ERR,"find_datafile:Unable to read datafile. Please check file permission");
				return NULL;
			}
		}
		Log(LOG_ERR,"find_datafile:Count into the header does not match the number of records. Please check your code for bugs");
		if (filerec!=NULL)
			free(filerec);
		return NULL;
	}
	else
	{
		Log(LOG_ERR,"find_datafile:Unable to read header. Please check file permission");
		return NULL;
	}

}

int update_datafile(const configuration * connections,int slot)
{
	int last = connections->last_slot;
	FILE * fdata=NULL;
	int status,pos;
	struct file_record * filerec;
	uint16_t service_port;

	if (slot<=last)
	{
		status=exists_datafile();
		if (status)
		{
			status=open_datafile(&fdata,"r+");
			if (status)
			{
				status=check_crc32_datafile(fdata);
				if (status==0)
					Log(LOG_DEBUG,"check crc32 do not match. Please see your code");
				service_port=connections->single_conn[slot].port;
				filerec=find_datafile(fdata,service_port,&pos);
				if (filerec != NULL)
				{
					//ok found it
					filerec->status=(uint8_t)connections->single_conn[slot].disabled;
					status=write_datafile(fdata,filerec,pos);
					update_crc32_datafile(fdata);
					free(filerec);
					close_datafile(fdata);
					return 1;
				}
				else
				{
					Log(LOG_DEBUG,"File record not found in update. Please check your code for a bug");
					close_datafile(fdata);
					return 0;
				}
			}
			else
			{
				Log(LOG_ERR,"update_datafile: Unable to open data file for update. Please check permissions");
				return 0;
			}
		}
		else
		{
			Log(LOG_ERR,"update_datafile: The data file does not exists or access error. Please check permissions");
			return 0;
		}
	}
	else
	{
		Log(LOG_ERR,"update_datafile: Record number is out of range in updating. Please check for bugs");
		return 0;
	}
}

int init_datafile(configuration * connections)
{
	struct file_header * pheader;
	struct file_record * precord;

	uint16_t count;
	int i;
	int last = connections->last_slot;
	FILE * fdata=NULL;
	int status,slot;

	status=exists_datafile();
	//if the file exists we try to merge with running config
	if (status)
	{
		status=open_datafile(&fdata,"r+");
		if (status)
		{
			status=check_crc32_datafile(fdata);
			if (status==0)
				Log(LOG_DEBUG,"check crc32 do not match. Please see your code");

			pheader=read_headerdatafile(fdata);
			if (pheader != NULL )
			{
				Log(LOG_DEBUG,"Header version: %s\n",pheader->version);
				Log(LOG_DEBUG,"psentinel writer version: %s\n",pheader->prgversion);
				Log(LOG_DEBUG,"Number of items: %d\n",pheader->nservices);
				Log(LOG_DEBUG,"crc32: %x\n",pheader->file_crc32);

				for(i=0; i< pheader->nservices;i++)
				{
					precord=read_datafile(fdata,i);
					if (precord != NULL)
					{
						if (precord->service != DATAFILE_EOF)
						{
							slot=search_slot_byport(precord->service,connections);
							if (slot != -1)
							{
								//found it we update the status with the status found on the file
								connections->single_conn[slot].disabled=precord->status;
							}
							free(precord);
						}
						else
						{
							free(precord);
							Log(LOG_ERR,"init_datafile:Number of records differs from nservices into the header. Check for bugs");
							break;
						}

					}
					else
					{
						free(pheader);
						Log(LOG_ERR,"Unable to read records from data file. Please check permissions");
						close_datafile(fdata);
						return 0;
					}
				}
				free(pheader);
				close_datafile(fdata);
			}
			else
			{
				Log(LOG_ERR,"Unable to read header from data file. Please check permissions");
				close_datafile(fdata);
				return 0;
			}
		}
		else
		{
			Log(LOG_ERR,"Unable to open data file. Please check permissions");
			return 0;
		}

	}

	//after merging (if a file exists) with in-memory config we create the new data file with new configurations

	status=open_datafile(&fdata,"w+");

	if (status)
	{
		pheader=(struct file_header *) malloc(sizeof(struct file_header));

		//better to zero-mem of structure
		memset(pheader,0,sizeof(struct file_header));

		strcpy(pheader->name,FILESIGNATURE);
		strcpy(pheader->prgversion,FILEPRGVERSION);
		strcpy(pheader->version,FILEVERSION);

		status=write_headerdatafile(fdata,pheader);

		if (status)
		{
			count=0;
			for (i = 0; i <= last; i++)
			{
				if (connections->single_conn[i].service_name != NULL)
				{
					if (strcmp(GENERAL_SETUP_ENTRY, connections->single_conn[i].service_name) != 0)
					{
						count++;
						precord=(struct file_record *) malloc(sizeof(struct file_record));
						memset(precord,0,sizeof(struct file_record));
						precord->service=connections->single_conn[i].port;
						precord->status=(uint8_t)connections->single_conn[i].disabled;
						status=write_datafile(fdata,precord,count-1);
						if (status)
						{
							free(precord);

						}
						else
						{
							free(precord);
							free(pheader);
							Log(LOG_ERR,"init_datafile:Unable to write a record. Please check permissions");
							close_datafile(fdata);
							return 0;
						}
					}
				}
			}
			//we are here without errors and with total number of records
			//so we update the header and crc32
			pheader->nservices=count;
			status=write_headerdatafile(fdata,pheader);
			if (status)
			{
				status=update_crc32_datafile(fdata);
				if (status)
				{
					free(pheader);
					close_datafile(fdata);
					return 1;
				}
				else
				{
					free(pheader);
					Log(LOG_ERR,"init_datafile:Unable to write crc32 into header. Please check permissions");
					close_datafile(fdata);
					return 0;
				}
			}
			else
			{
				free(pheader);
				Log(LOG_ERR,"init_datafile:Unable to write header. Please check permissions");
				close_datafile(fdata);
				return 0;
			}
		}
		else
		{
			free(pheader);
			Log(LOG_ERR,"init_datafile:Unable to write header. Please check permissions");
			close_datafile(fdata);
			return 0;
		}
	}
	else
	{
		Log(LOG_ERR,"init_datafile:Unable to open data file. Please check permissions");
		return 0;
	}


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

