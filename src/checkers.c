/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * checkers.c
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
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "checkers.h"

extern void Log(int priority, char * format,...);

//Support function to execute a process

int spawn (char* program, char** arg_list)
{
	int status;

	pid_t child_pid;
	/* Duplicate this process.  */
	child_pid = fork ();
	if (child_pid != 0)
		/* This is the parent process.  */
		return child_pid;
	else
	{
		/* Now execute PROGRAM, searching for it in the path.  */
		execvp (program, arg_list);
		/* The execvp function returns only if an error occurs.  */
		status=errno;
		Log (LOG_ERR,"Error in execvp, Err(%s)\n",strerror(status));
	}
	return 0;
}


//generic thread function for calling a system script


unsigned short int call_script(sigval_t args)
{
	pid_t child_pid;
	int child_status;
	unsigned short int exit_status;


	shell_args_t * shell_args =(shell_args_t * ) args.sival_ptr;
	//calling the script and wait for finish
	Log (LOG_DEBUG,"call_script: Executing %s\n",shell_args->script_name);
	child_pid = spawn(shell_args->script_name,shell_args->script_args);
	if (child_pid)
	{
		waitpid(child_pid,&child_status,0);
		if (WIFEXITED(child_status))
		{
			//exited normally we check error code
			exit_status=WEXITSTATUS(child_status);
			Log (LOG_DEBUG,"Script %s exited normally with code %d\n",shell_args->script_name,exit_status);
			return exit_status;
		}
		else
		if (WIFSIGNALED(child_status))
		{
			//exited by signal
			if (WTERMSIG(child_status))
			{
				Log (LOG_DEBUG,"Script %s exited by TERM signal\n",shell_args->script_name);
				return 255;
			}
			if (WIFSTOPPED(child_status))
			{
				Log (LOG_DEBUG,"Script %s exited by STOP signal\n",shell_args->script_name);
				return 255;
			}
			if (WCOREDUMP(child_status))
			{
				Log (LOG_DEBUG,"Script %s exited by CORE DUMP signal\n",shell_args->script_name);
				return 255;
			}
		}
		else
		{
			Log (LOG_ERR,"Script %s exited abnormally\n",shell_args->script_name);
			return 255;
		}
	}
	return 0;
}



