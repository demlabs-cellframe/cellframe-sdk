/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/queue.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#else
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include "wrappers.h"
#include <wepoll.h>
#include <pthread.h>
#endif

#include "uthash.h"
#include "utlist.h"

#include "dap_common.h"
#include "dap_udp_client.h"
#include "dap_udp_server.h"

#define LOG_TAG "udp_client"

/**
 * @brief get_key Make key for hash table from host and port
 * @return 64 bit Key
 */
#define get_key( host, key ) (((uint64_t)host << 32) + (uint64_t)port)

/**
 * @brief udp_client_create Create new client and add it to hashmap
 * @param sh Server instance
 * @param host Client host address
 * @param w_client Clients event loop watcher
 * @param port Client port
 * @return Pointer to the new list's node
 */
dap_client_remote_t *dap_udp_client_create( dap_server_t *dap_srv, EPOLL_HANDLE efd, unsigned long host, unsigned short port )
{
  dap_udp_server_t *udp_server = DAP_UDP_SERVER( dap_srv );
  log_it( L_DEBUG, "Client structure create" );

  dap_udp_client_t *inh = DAP_NEW_Z( dap_udp_client_t );
  inh->host_key = get_key( host, port );

  dap_client_remote_t *ret = DAP_NEW_Z( dap_client_remote_t );
  inh->client = ret;

  ret->pevent.events = EPOLLIN | EPOLLERR;
  ret->pevent.data.fd = dap_srv->socket_listener;

  ret->server = dap_srv;
  ret->efd = efd;

  ret->flags = DAP_SOCK_READY_TO_READ;

//  ret->signal_close = false;
//  ret->_ready_to_read = true;
//  ret->_ready_to_write = false;

  ret->_inheritor = inh;

  pthread_mutex_init( &inh->mutex_on_client, NULL );

  pthread_mutex_lock( &udp_server->mutex_on_list );
  HASH_ADD_INT( udp_server->hclients, host_key, inh );
  pthread_mutex_unlock( &udp_server->mutex_on_list );

  if( dap_srv->client_new_callback )
    dap_srv->client_new_callback( ret, NULL ); // Init internal structure

  return ret;
}

/**
 * @brief udp_client_get_address Get host address and port of client
 * @param client Pointer to client structure
 * @param host Variable for host address
 * @param host Variable for port
 */
void dap_udp_client_get_address( dap_client_remote_t *client, unsigned int* host, unsigned short* port ) 
{
  dap_udp_client_t* udp_client = DAP_UDP_CLIENT( client );
  *host = udp_client->host_key >> 32;
  *port = (udp_client->host_key <<32) - *host;
}

/**
 * @brief udp_client_find Find client structure by host address and port
 * @param sh Server instance
 * @param host Source host address
 * @param port Source port
 * @return Pointer to client or NULL if not found
 */
dap_client_remote_t *dap_udp_client_find( dap_server_t *dap_srv, unsigned long host, unsigned short port )
{
  dap_udp_client_t *inh = NULL;
  dap_udp_server_t *udp_server = DAP_UDP_SERVER( dap_srv );

  uint64_t token = get_key( host, port );

  pthread_mutex_lock( &udp_server->mutex_on_list );
  HASH_FIND_INT( udp_server->hclients, &token, inh );    
  pthread_mutex_unlock( &udp_server->mutex_on_list );

  if( inh == NULL )
    return NULL;
  else
    return inh->client;
}

/**
 * @brief udp_client_ready_to_read Set ready_to_read flag
 * @param dap_rclient Client structure
 * @param is_ready Flag value
 */
void dap_udp_client_ready_to_read( dap_client_remote_t *sc, bool is_ready )
{
  if( is_ready == (bool)(sc->flags & DAP_SOCK_READY_TO_READ) )
    return;

  if ( is_ready )
    sc->flags |= DAP_SOCK_READY_TO_READ;
  else
    sc->flags ^= DAP_SOCK_READY_TO_READ;

  int events = EPOLLERR;

  if( sc->flags & DAP_SOCK_READY_TO_READ )
    events |= EPOLLIN;

  if( sc->flags & DAP_SOCK_READY_TO_WRITE )
    events |= EPOLLOUT;

  sc->pevent.events = events;

  if( epoll_ctl(sc->efd, EPOLL_CTL_MOD, sc->server->socket_listener, &sc->pevent) != 0 ) {
    log_it( L_ERROR, "epoll_ctl failed 002" );
  }
}

/**
 * @brief udp_client_ready_to_write Set ready_to_write flag
 * @param dap_rclient Client structure
 * @param is_ready Flag value
 */
void dap_udp_client_ready_to_write( dap_client_remote_t *sc, bool is_ready )
{
  if ( is_ready == (bool)(sc->flags & DAP_SOCK_READY_TO_WRITE) )
    return;

  if ( is_ready )
    sc->flags |= DAP_SOCK_READY_TO_WRITE;
  else
    sc->flags ^= DAP_SOCK_READY_TO_WRITE;

  int events = EPOLLERR;

  if( sc->flags & DAP_SOCK_READY_TO_READ )
    events |= EPOLLIN;

  if( sc->flags & DAP_SOCK_READY_TO_WRITE )
    events |= EPOLLOUT;

  sc->pevent.events = events;

  if ( epoll_ctl(sc->efd, EPOLL_CTL_MOD, sc->pevent.data.fd, &sc->pevent) != 0 ) {
    log_it( L_ERROR, "epoll_ctl failed 003" );
  }
}

/**
 * @brief add_waiting_client Add Client to write queue
 * @param client Client instance
 */
void add_waiting_client( dap_client_remote_t *dap_rclient )
{
    dap_udp_client_t* udp_cl, *tmp;

    dap_server_t *dap_srv = dap_rclient->server;
    dap_udp_server_t *udp_server = DAP_UDP_SERVER( dap_srv );
    dap_udp_client_t *udp_client = DAP_UDP_CLIENT( dap_rclient );

    pthread_mutex_lock( &udp_server->mutex_on_list );
    LL_FOREACH_SAFE( udp_server->waiting_clients, udp_cl, tmp ) {
        if( udp_cl == udp_client ) {
            pthread_mutex_unlock( &udp_server->mutex_on_list );
            return;
        }
    }
    LL_APPEND( udp_server->waiting_clients, udp_client );
    pthread_mutex_unlock( &udp_server->mutex_on_list );
}

size_t dap_udp_client_write( dap_client_remote_t *dap_rclient, const void *data, size_t data_size )
{
    size_t size = dap_client_remote_write( dap_rclient, data, data_size );
    add_waiting_client( dap_rclient );
    return size;
}

size_t dap_udp_client_write_f( dap_client_remote_t *dap_rclient, const char * a_format, ... )
{
    size_t size = 0;
    va_list va;

    va_start( va, a_format );
    size = dap_client_remote_write_f( dap_rclient, a_format, va );
    va_end( va );

    add_waiting_client( dap_rclient );
    return size;
}

