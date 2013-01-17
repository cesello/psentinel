/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * minischeduler.c
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

#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include "minischeduler.h"

extern void Log(int priority, char * format,...);

void timer_handler(sigval_t args)
{
	struct single_connection * connection = (struct single_connection *) args.sival_ptr;
	unsigned short int status;
	connection->timer.counter++;
	connection->timer.last_call=time(NULL);
	connection->timer.inqueue++;
	pthread_mutex_lock(&(connection->timer.chk_mutex));
	connection->timer.inqueue--;
	status=connection->timer.chk_function(connection->timer.chk_arguments);

	if (status)
	{
		Log (LOG_ERR,"chk_function returned an error state. Disabling service\n");

	}
	connection->timer.chk_status=status;
	pthread_mutex_unlock(&(connection->timer.chk_mutex));
}


int make_timer(struct single_connection * connection)
{
	pthread_attr_t attr;
	struct sigevent sig;
	struct itimerspec in, out;
	int status;


	pthread_attr_init( &attr );
	pthread_mutex_init(&(connection->timer.chk_mutex),NULL);

	sig.sigev_notify = SIGEV_THREAD;
	sig.sigev_notify_function = timer_handler;
	sig.sigev_value.sival_ptr=connection;
	sig.sigev_notify_attributes = &attr;

	//create a new timer.
	timer_t timerid;
	status= timer_create(CLOCK_REALTIME, &sig, &timerid);

	if (status)
	{
		status=errno;
		Log (LOG_ERR,"Error in timer creation, Err(%s)",strerror(status));
		return status;
	}

	connection->timer.timerid=timerid;
	in.it_value.tv_sec = connection->timer.check_interval;
	in.it_value.tv_nsec = 0;
	in.it_interval.tv_sec = connection->timer.check_interval;
	in.it_interval.tv_nsec = 0;
	//issue the periodic timer request here.
	status = timer_settime(timerid, 0, &in, &out);
	if (status)
	{
		status=errno;
		Log (LOG_ERR,"Error in setting timer, Err(%s)",strerror(status));
		return status;
	}

	return 0;

}
