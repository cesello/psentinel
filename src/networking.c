/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * networking.c
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
#include <stdio.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>

#include "networking.h"


extern void Log(int priority, char * format,...);
extern char * socket_file;

void setnonblocking(int sock)
{
	int opts;

	opts = fcntl(sock,F_GETFL);
	if (opts < 0)
	{

		Log(LOG_ERR,"Error in fcntl(F_GETFL) \n");

	}
	opts = (opts | O_NONBLOCK);
	if (fcntl(sock,F_SETFL,opts) < 0)
	{

		Log(LOG_ERR,"Error in fcntl(F_SETFL) \n");

	}
	return;
}

int sock_read(int sockfd, char *buf, size_t count)
{
  size_t bytes_read = 0;
  int this_read;

  while (bytes_read < count)
  {
    do
    {
      this_read = read(sockfd, buf, count - bytes_read);
    }
    while ( (this_read < 0) && (errno == EINTR) );

    if (this_read < 0)
    {
      return this_read;
    }
    else
    if (this_read == 0)
    {
      return bytes_read;
    }
    bytes_read += this_read;
    buf += this_read;
  }
  return count;
}

/* This is just like the write() system call, accept that it will
   make sure that all data is transmitted. */
int sock_write(int sockfd, char *buf, size_t count)
{
  size_t bytes_sent = 0;
  int this_write;

  while (bytes_sent < count)
  {
    do
    {
      this_write = write(sockfd, buf, count - bytes_sent);
    }
    while ( (this_write < 0) && (errno == EINTR) );

    if (this_write <= 0)
    {
      return this_write;
    }
    bytes_sent += this_write;
    buf += this_write;
  }
  return count;
}

/* This function writes a character string out to a socket.  It will
   return -1 if the connection is closed while it is trying to write. */
int sock_puts(int sockfd, char *str)
{
  return sock_write(sockfd, str, strlen(str));
}

int initialize_network(configuration * connections)
{

	int temp_socket;
	struct	sockaddr_in temp_servaddr;  /*  socket address structure  */
	struct	sockaddr_un temp_servaddr_un;  /*  AF_UNIX socket address structure  */
	int i;


	int configured_ports=connections->last_slot;

    for (i=0;i<=configured_ports;i++)
    {
    	//bypass "general"  is not a tcp/ip socket but a unix socket
    	if (strcmp(connections->single_conn[i].service_name,GENERAL_SETUP_ENTRY)==0)
    	{
    		if ( ( temp_socket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0 )
			{
				Log(LOG_ERR,"Error creating listening AF_UNIX socket.\n");
				exit(EXIT_FAILURE);
			}
    		connections->single_conn[i].listening_socket=temp_socket;
    		if (temp_socket > connections->max_socket)
    			connections->max_socket=temp_socket;

    		memset(&temp_servaddr_un, 0, sizeof(temp_servaddr_un));
    		temp_servaddr_un.sun_family      = AF_UNIX;
    		strcpy(temp_servaddr_un.sun_path,socket_file);

    		connections->single_conn[i].servaddr_un=temp_servaddr_un;

    		if ( bind(temp_socket, (struct sockaddr*) &temp_servaddr_un, SUN_LEN(&temp_servaddr_un)) < 0 )
			{
				Log(LOG_ERR,"Error calling bind AF_UNIX (%s)\n",strerror(errno));
				exit(EXIT_FAILURE);
			}
			if ( listen(temp_socket, LISTENQ) < 0 )
			{
				Log(LOG_ERR,"Error calling listen AF_UNIX (%s)\n",strerror(errno));
				exit(EXIT_FAILURE);
			}
    		continue;
    	}

        /*  Create the listening socket   */

        if ( ( temp_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    	{
    		Log(LOG_ERR,"Error creating listening socket.\n");
    		exit(EXIT_FAILURE);
    	}

        connections->single_conn[i].listening_socket=temp_socket;
        if (temp_socket > connections->max_socket)
        	connections->max_socket=temp_socket;

        /*  Set all bytes in socket address structure to
            zero, and fill in the relevant data members   */

        memset(&temp_servaddr, 0, sizeof(temp_servaddr));
        temp_servaddr.sin_family      = AF_INET;
        temp_servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        temp_servaddr.sin_port        = htons(connections->single_conn[i].port);
        connections->single_conn[i].servaddr=temp_servaddr;



    	if ( bind(temp_socket, (struct sockaddr *) &temp_servaddr, sizeof(temp_servaddr)) < 0 )
		{
			Log(LOG_ERR,"Error calling bind(%s)\n",strerror(errno));
			exit(EXIT_FAILURE);
		}
        if ( listen(temp_socket, LISTENQ) < 0 )
        {
        	Log(LOG_ERR,"ECHOSERV: Error calling listen(%s)\n",strerror(errno));
        	exit(EXIT_FAILURE);
        }


    }
    return NETWORKING_SUCCESS;
}

void rebuild_connection_set(configuration * connections)
{
	int i,j;
	int configured_connections=connections->last_slot;

	FD_ZERO(&(connections->socket_set));
	for (i=0;i<=configured_connections;i++)
	{
		FD_SET(connections->single_conn[i].listening_socket,&(connections->socket_set));
		for (j=0;j<MAX_CLIENTS;j++)
		{
			if (connections->single_conn[i].running_sockets[j]!=0)
			{
				FD_SET(connections->single_conn[i].running_sockets[j],&(connections->socket_set));
				if (connections->single_conn[i].running_sockets[j] > connections->max_socket)
				{
					connections->max_socket = connections->single_conn[i].running_sockets[j];
				}
			}
		}
	}
}

void handle_new_connection(configuration * connections,int socket_index)
{
	int connection;
	int i;
	char temp_buffer[MAX_LINE];

	connection = accept(connections->single_conn[socket_index].listening_socket,NULL,NULL);
	if (connection < 0 )
	{
		Log(LOG_ERR,"Error accepting new connections from port %d. Errno=%s\n", connections->single_conn[socket_index].port,strerror(errno));
	}
	for(i=0;(i<MAX_CLIENTS)&&(connection!=-1);i++)
	{
		if (connections->single_conn[socket_index].running_sockets[i]==0)
		{
			Log(LOG_DEBUG,"Connection from port (%d) Accepted: FD=%d,Slot=%d\n",connections->single_conn[socket_index].port,connection,i);
			connections->single_conn[socket_index].running_sockets[i]=connection;
            setnonblocking(connection);
            memset(&connections->single_conn[socket_index].buffer[i][0], 0, MAX_LINE);
			connection=-1;
		}
	}

	if (connection !=-1)
	{
		Log(LOG_DEBUG,"Too many connections. Increase room for clients..\n");
		sprintf(temp_buffer,ECHOMSG,MSG_DOWN,MSG_DOWN_TOOMANY_S);
		sock_puts(connection,temp_buffer);
		close(connection);
	}
}

void read_send_data(configuration * connections,int port_index,int socket_index)
{
	int connection;
	char * temp_buffer;

	connection=connections->single_conn[port_index].running_sockets[socket_index];
	temp_buffer=&(connections->single_conn[port_index].buffer[socket_index][0]);
	connections->single_conn[port_index].counter++;

	sock_read(connection,temp_buffer,MAX_LINE);

	(*connections->single_conn[port_index].reply_function)(connections,port_index,socket_index);

	sock_puts(connection,temp_buffer);

	close(connection);
	connections->single_conn[port_index].running_sockets[socket_index]=0;

}

void read_sockets(configuration * connections)
{
	int i,j;
	int running_socket;
	int configured_connections = connections->last_slot;


	for (i=0;i<=configured_connections;i++)
	{
		/* first we have to check for new connections */
		if (FD_ISSET(connections->single_conn[i].listening_socket,&(connections->socket_set)))
		{
			handle_new_connection(connections,i);
		}
		/* check if there are data from all other receiving sockets */
		for (j=0;j<MAX_CLIENTS;j++)
		{
			running_socket = connections->single_conn[i].running_sockets[j];
			if (running_socket)
			{
				if (FD_ISSET(running_socket,&(connections->socket_set)))
				{
					read_send_data(connections,i,j);
				}
			}
		}
	}
}
