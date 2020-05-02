/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#endif

#include "dap_common.h"
#include "dap_server.h"
#include "dap_client_remote.h"

#define LOG_TAG "dap_client_remote"

/**
 * @brief dap_client_init Init clients module
 * @return Zero if ok others if no
 */
int dap_client_remote_init( )
{
  log_it( L_NOTICE, "Initialized socket client module" );

  return 0;
}

/**
 * @brief dap_client_deinit Deinit clients module
 */
void dap_client_remote_deinit( )
{

  return;
}

/**
 * @brief _save_ip_and_port
 * @param cl
 */
void _save_ip_and_port( dap_client_remote_t * cl )
{
  struct sockaddr_in ip_adr_get;
  socklen_t ip_adr_len;

  getpeername( cl->socket, (struct sockaddr * restrict)&ip_adr_get, &ip_adr_len );

  cl->port = ntohs( ip_adr_get.sin_port );
  strcpy( cl->s_ip, inet_ntoa(ip_adr_get.sin_addr) );
}

/**
 * @brief dap_client_remote_create Create new client and add it to the list
 * @param sh Server instance
 * @param s Client's socket
 * @return Pointer to the new list's node
 */
dap_client_remote_t *dap_client_remote_create( dap_server_t *sh, int s, dap_server_thread_t *t )
{
  dap_client_remote_t *dsc = DAP_NEW_Z( dap_client_remote_t );

  dap_random_string_fill( dsc->id, CLIENT_ID_SIZE );

  dsc->socket = s;
  dsc->server = sh;
  dsc->tn = t->thread_num;
  dsc->thread = t;
  dsc->efd = t->epoll_fd;
  dsc->time_connection = dsc->last_time_active = time( NULL) ;

  dsc->pevent.events = EPOLLIN | EPOLLOUT | EPOLLERR;
  dsc->pevent.data.ptr = dsc;

  dsc->flags = DAP_SOCK_READY_TO_READ;
  dsc->buf_out_offset = 0;

  _save_ip_and_port( dsc );

  pthread_mutex_lock( &t->mutex_on_hash );
  HASH_ADD_INT( t->hclients, socket, dsc );
  pthread_mutex_unlock( &t->mutex_on_hash );

  if ( sh->client_new_callback )
    sh->client_new_callback( dsc, NULL ); // Init internal structure

  log_it(L_DEBUG, "Create remote client: ip: %s port %d", dsc->s_ip, dsc->port );

    //log_it(L_DEBUG, "Create new client. ID: %s", dsc->id);
  return dsc;
}

/**
 * @brief safe_client_remove Removes the client from the list
 * @param sc Client instance
 */
void dap_client_remote_remove( dap_client_remote_t *sc )
{
  log_it(L_DEBUG, "dap_client_remote_remove [THREAD %u] efd %u", sc->tn , sc->efd );

  dap_server_thread_t *t = sc->thread;

  pthread_mutex_lock( &t->mutex_on_hash );
  HASH_DEL( t->hclients, sc );
  pthread_mutex_unlock( &t->mutex_on_hash );

  if( sc->server->client_delete_callback ) {
    sc->server->client_delete_callback( sc, NULL ); // Init internal structure
  }

  if( sc->_inheritor ) {
    free( sc->_inheritor );
  }

  if( sc->socket ) {
    log_it( L_INFO, "dap_client_remote_remove close( %d );", sc->socket );
#ifdef _WIN32
    closesocket( sc->socket );
#else
    close( sc->socket );
#endif
  }

  free( sc );
}

/**
 * @brief dap_server_client_find
 * @param sock
 * @param sh
 * @return
 */
dap_client_remote_t *dap_client_remote_find( int sock, dap_server_thread_t *t )
{
  dap_client_remote_t *ret = NULL;

  pthread_mutex_lock( &t->mutex_on_hash );
  HASH_FIND_INT( t->hclients, &sock, ret );
  pthread_mutex_unlock( &t->mutex_on_hash );

  return ret;
}

/**
 * @brief dap_client_remote_ready_to_read
 * @param sc
 * @param isReady
 */
void  dap_client_remote_ready_to_read( dap_client_remote_t *sc, bool is_ready )
{
  if( is_ready == (bool)(sc->flags & DAP_SOCK_READY_TO_READ) )
    return;

//  log_it( L_ERROR, "remote_ready_to_read() %u efd %X", sc->socket, sc->efd );

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

  if( epoll_ctl(sc->efd, EPOLL_CTL_MOD, sc->socket, &sc->pevent) != 0 )
    log_it( L_ERROR, "epoll_ctl failed 000" );
}

/**
 * @brief dap_client_remote_ready_to_write
 * @param sc
 * @param isReady
 */
void  dap_client_remote_ready_to_write( dap_client_remote_t *sc, bool is_ready )
{
  if ( is_ready == (bool)(sc->flags & DAP_SOCK_READY_TO_WRITE) )
    return;

//    log_it( L_ERROR, "remote_ready_to_write() %u efd %X", sc->socket, sc->efd );

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

  if( epoll_ctl(sc->efd, EPOLL_CTL_MOD, sc->socket, &sc->pevent) != 0 )
    log_it( L_ERROR, "epoll_ctl failed 001" );
}

/**
 * @brief dap_client_write Write data to the client
 * @param sc Client instance
 * @param data Pointer to data
 * @param data_size Size of data to write
 * @return Number of bytes that were placed into the buffer
 */
size_t dap_client_remote_write( dap_client_remote_t *sc, const void * data, size_t data_size )
{     
  if ( sc->buf_out_size + data_size > sizeof(sc->buf_out) ) {
    log_it( L_WARNING, "Client buffer overflow. Packet loosed" );
    return 0;
  }

  memcpy( sc->buf_out + sc->buf_out_size, data, data_size );
  sc->buf_out_size += data_size;
  return data_size;
}

/**
 * @brief dap_client_write_f Write formatted text to the client
 * @param a_client Client instance
 * @param a_format Format
 * @return Number of bytes that were placed into the buffer
 */
size_t dap_client_remote_write_f( dap_client_remote_t *a_client, const char * a_format, ... )
{
  size_t max_data_size = sizeof( a_client->buf_out ) - a_client->buf_out_size;

  va_list ap;
  va_start( ap, a_format );

  int ret = dap_vsnprintf( a_client->buf_out + a_client->buf_out_size, max_data_size, a_format, ap );

  va_end( ap );

  if( ret > 0 ) {
    a_client->buf_out_size += (unsigned long)ret;
    return (size_t)ret;
  } 
  else {
    log_it( L_ERROR, "Can't write out formatted data '%s'", a_format );
    return 0;
  }
}

/**
 * @brief dap_client_read Read data from input buffer
 * @param a_client Client instasnce
 * @param a_data Pointer to memory where to store the data
 * @param a_data_size Size of data to read
 * @return Actual bytes number that were read
 */
size_t dap_client_remote_read( dap_client_remote_t *a_client, void *a_data, size_t a_data_size )
{
  if ( a_data_size < a_client->buf_in_size ) {

    memcpy( a_data, a_client->buf_in, a_data_size );
    memmove( a_client->buf_in, a_client->buf_in + a_data_size, a_client->buf_in_size - a_data_size );
  } 
  else {
    if ( a_data_size > a_client->buf_in_size ) {
      a_data_size = a_client->buf_in_size;
    }
    memcpy( a_data, a_client->buf_in, a_data_size );
  }

  a_client->buf_in_size -= a_data_size;

  return a_data_size;
}


/**
 * @brief dap_client_remote_shrink_client_buf_in Shrink input buffer (shift it left)
 * @param a_client Client instance
 * @param a_shrink_size Size on wich we shrink the buffer with shifting it left
 */
void dap_client_remote_shrink_buf_in( dap_client_remote_t *a_client, size_t a_shrink_size )
{
#if 0
    if((a_shrink_size==0)||(a_client->buf_in_size==0) ){
        return;
    }else if(a_client->buf_in_size>a_shrink_size){
        size_t buf_size=a_client->buf_in_size-a_shrink_size;
        void * buf = malloc(buf_size);
        memcpy(buf,a_client->buf_in+ a_shrink_size,buf_size );
        memcpy(a_client->buf_in,buf,buf_size);
        a_client->buf_in_size=buf_size;
        free(buf);
    }else {
        a_client->buf_in_size=0;
    }
#endif

  if ( a_shrink_size == 0 || a_client->buf_in_size == 0 )
    return;

  if ( a_client->buf_in_size > a_shrink_size ) {

    size_t buf_size = a_client->buf_in_size - a_shrink_size;
    memmove( a_client->buf_in, a_client->buf_in + a_shrink_size, buf_size );
/**
    void *buf = malloc( buf_size );
    memcpy( buf, a_client->buf_in + a_shrink_size, buf_size );
    memcpy( a_client->buf_in, buf, buf_size );
    // holy shit
    a_client->buf_in_size = buf_size;
    free( buf );
**/
    a_client->buf_in_size = buf_size;
  }
  else {
    a_client->buf_in_size = 0;
  }
}
