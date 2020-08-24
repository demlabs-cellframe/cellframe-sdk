/*
 Copyright (c) 2017-2019 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
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
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
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
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#endif

#include "uthash.h"
#include "utlist.h"

#include "dap_common.h"
#include "dap_udp_server.h"

#define LOG_TAG "dap_udp_server"

#define BUFSIZE 1024

char buf[ BUFSIZE ]; /* message buf */
bool sb_payload_ready;
//struct ev_io w_read;
//struct ev_io w_write;

EPOLL_HANDLE efd_read  = (EPOLL_HANDLE)-1;

//static void write_cb( EPOLL_HANDLE efd, int revents );

int check_close( dap_events_socket_t *client );

/**
 */
static void error( char *msg ) {

  perror( msg );
  exit( 1 );
}

/**
 * @brief dap_udp_server_new Initialize server structure
 * @return Server pointer
 */
dap_server_t *dap_udp_server_new( )
{
  dap_udp_server_t *udp_server = (dap_udp_server_t *)calloc( 1, sizeof(dap_udp_server_t) );
  udp_server->waiting_clients = NULL;

  dap_server_t *sh = (dap_server_t *) calloc( 1, sizeof(dap_server_t) );
  sh->_inheritor = udp_server;

  udp_server->dap_server = sh;

  return sh;
}

/**
 * @brief dap_udp_server_delete Safe delete server structure
 * @param sh Server instance
 */
void dap_udp_server_delete( dap_server_t *sh )
{
  if ( !sh ) return;

//  dap_client_remote_t *client, *tmp;
//  dap_udp_server_t *udps = (dap_udp_server_t *)sh->_inheritor;

//  if ( !udps ) return;

  if( sh->address )
    free( sh->address );

//  HASH_ITER( hh, udps->hclients, client, tmp )
//    dap_client_remote_remove( client );

  if ( sh->delete_callback )
    sh->delete_callback( sh, NULL );

  if ( sh->_inheritor )
    free( sh->_inheritor );

  free( sh );
}

/**
 * @brief dap_udp_server_listen Create and bind server structure
 * @param port Binding port
 * @return Server instance
 */
dap_server_t *dap_udp_server_listen( uint16_t port ) {

  dap_server_t *sh = dap_udp_server_new( );

  sh->socket_listener = socket( AF_INET, SOCK_DGRAM, 0 );

  if ( sh->socket_listener < 0 ) {
    log_it ( L_ERROR, "Socket error %s", strerror(errno) );
    dap_udp_server_delete( sh );
    return NULL;
  }

  int optval = 1;
  if ( setsockopt( sh->socket_listener, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int)) < 0 )
    log_it( L_WARNING, "Can't set up REUSEADDR flag to the socket" );

  memset( (char *)&(sh->listener_addr), 0, sizeof(sh->listener_addr) );

  sh->listener_addr.sin_family = AF_INET;
  sh->listener_addr.sin_addr.s_addr = htonl( INADDR_ANY );
  sh->listener_addr.sin_port = htons( port );

  if ( bind(sh->socket_listener, (struct sockaddr *) &(sh->listener_addr), sizeof(sh->listener_addr)) < 0) {
    log_it( L_ERROR, "Bind error: %s", strerror(errno) );
    dap_udp_server_delete( sh );
    return NULL;
  }
  log_it(L_INFO, "UDP server listening port 0.0.0.0:%d", port);
  pthread_mutex_init( &DAP_UDP_SERVER(sh)->mutex_on_list, NULL );
  pthread_mutex_init( &DAP_UDP_SERVER(sh)->mutex_on_hash, NULL );

  return sh;
}

/**
 * @brief write_cb
 */
static void write_cb( EPOLL_HANDLE efd, int revents, dap_server_t *sh )
{
    UNUSED(revents);
  dap_udp_client_t *udp_client, *tmp;

//  dap_server_t *sh = watcher->data;
  dap_udp_server_t *udp = DAP_UDP_SERVER( sh );

  pthread_mutex_lock( &udp->mutex_on_list );

  LL_FOREACH_SAFE( udp->waiting_clients, udp_client, tmp ) {

        //log_it(L_INFO,"write_cb");
        //pthread_mutex_lock(&udp_client->mutex_on_client);

    dap_events_socket_t *client = udp_client->esocket;

    if( client != NULL && !check_close(client) && (client->flags & DAP_SOCK_READY_TO_WRITE) ) {

      if ( sh->client_callbacks.write_callback )
        sh->client_callbacks.write_callback( client, NULL );

      if ( client->buf_out_size > 0 ) {



        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        dap_udp_client_get_address( client, (unsigned int *)&addr.sin_addr.s_addr, &addr.sin_port );
        //log_it(L_INFO,"write_cb_client host = %x, port = %d, socket = %x", addr.sin_addr.s_addr, addr.sin_port, sh->socket_listener);
        for( size_t total_sent = 0; total_sent < client->buf_out_size; ) {

          int bytes_sent = sendto( sh->socket_listener, client->buf_out + total_sent,
                        client->buf_out_size - total_sent, 0, (struct sockaddr*) &addr, sizeof(addr) );

          if ( bytes_sent < 0 ) {
            log_it(L_ERROR,"Some error occured in send() function");
            break;
          }
          total_sent += bytes_sent;
        }
        client->buf_out_size = 0;
        memset( client->buf_out, 0, sizeof(client->buf_out) );
        client->flags &= ~DAP_SOCK_READY_TO_WRITE;
        sb_payload_ready = false;
      }
      LL_DELETE( udp->waiting_clients, udp_client );
    }
    else if( client == NULL ) {
      LL_DELETE( udp->waiting_clients, udp_client );
    }
    //pthread_mutex_unlock(&udp_client->mutex_on_client);

  } // for client
  pthread_mutex_unlock(&udp->mutex_on_list);
}

/**
 * @brief check_close Check if client need to close
 * @param client Client structure
 * @return 1 if client deleted, 0 if client is no need to delete
 */
int check_close( dap_events_socket_t *client )
{
    dap_udp_client_t *client_check, *tmp;

    if( !(client->flags & DAP_SOCK_SIGNAL_CLOSE) )
        return 0;

    dap_udp_client_t *udp_client = DAP_UDP_CLIENT( client );
    dap_server_t *sh = client->server;
    dap_udp_server_t *udp_server = DAP_UDP_SERVER( sh );

    LL_FOREACH_SAFE( udp_server->waiting_clients, client_check, tmp ) {

    if ( client_check->host_key == udp_client->host_key )
        LL_DELETE( udp_server->waiting_clients, client_check );
    }

    dap_events_socket_remove_and_delete_mt(client->worker, client );

    return 1;
}

/**
 * @brief read_cb
 */
static void read_cb( EPOLL_HANDLE efd, int revents, dap_server_t *sh )
{
    UNUSED(revents);
//    if ( !(revents & EV_READ) ) return;

    struct sockaddr_in clientaddr;
    socklen_t clientlen = sizeof(clientaddr);
//    dap_server_t *sh = watcher->data;

    memset( buf, 0, BUFSIZE );

    int32_t bytes = (int32_t) recvfrom( sh->socket_listener, buf, BUFSIZE, 0,(struct sockaddr *) &clientaddr, &clientlen );

    dap_events_socket_t *client = dap_udp_client_find( sh, clientaddr.sin_addr.s_addr, clientaddr.sin_port );

    if( client != NULL && check_close(client) != 0 )
            return;

    if ( bytes > 0 ) {

        char *hostaddrp = inet_ntoa( clientaddr.sin_addr );

        if ( hostaddrp == NULL ) {
            dap_udp_server_delete( sh );
            error("ERROR on inet_ntoa\n");
        }

        if ( client == NULL ) {
            client = dap_udp_client_create( sh, efd, clientaddr.sin_addr.s_addr, clientaddr.sin_port );
            if(client == NULL) {
                dap_udp_server_delete( sh );
                error("ERROR create client structure\n");
            }
        }

        dap_udp_client_t* udp_client = client->_inheritor;

        pthread_mutex_lock( &udp_client->mutex_on_client );

        size_t bytes_processed = 0;
        size_t bytes_recieved = bytes;

        while ( bytes_recieved > 0 ) {

            size_t bytes_to_transfer = 0;

            if ( bytes_recieved > UDP_CLIENT_BUF - client->buf_in_size )
                bytes_to_transfer = UDP_CLIENT_BUF - client->buf_in_size;
            else
                bytes_to_transfer = bytes_recieved;

            memcpy( client->buf_in + client->buf_in_size,buf + bytes_processed, bytes_to_transfer );
            client->buf_in_size += bytes_to_transfer;

            if ( sh->client_callbacks.read_callback )
                sh->client_callbacks.read_callback( client, NULL );

            bytes_processed += bytes_to_transfer;
            bytes_recieved -= bytes_to_transfer;
        }

        client->buf_in_size = 0;
        memset( client->buf_in, 0, sizeof(client->buf_out) );

        pthread_mutex_unlock( &udp_client->mutex_on_client );

    }
    else if ( bytes < 0 ) {

        log_it( L_ERROR, "Bytes read Error %s", strerror(errno) );
        if( client != NULL )
            client->flags |= DAP_SOCK_SIGNAL_CLOSE;
    }
    else if (bytes == 0) {
        if ( client != NULL )
            client->flags |= DAP_SOCK_SIGNAL_CLOSE;
    }
}

/**
 * @brief dap_udp_server_loop Start server event loop
 * @param sh Server instance
 */
void dap_udp_server_loop( dap_server_t *d_server )
{
  efd_read  = epoll_create1( 0 );

  if ( (intptr_t)efd_read == -1 ) {

    log_it( L_ERROR, "epoll_create1 failed" );
    goto udp_error;
  }

  sb_payload_ready = false;

  struct epoll_event  pev = {0, {0}};
  struct epoll_event  events[ 16 ] = {{0, {0}}};

  pev.events = EPOLLIN | EPOLLERR;
  pev.data.fd = d_server->socket_listener;

  if ( epoll_ctl( efd_read, EPOLL_CTL_ADD, d_server->socket_listener, &pev) != 0 ) {
    log_it( L_ERROR, "epoll_ctl failed 000" );
    goto udp_error;
  }

  while( 1 ) {

    int32_t n = epoll_wait( efd_read, &events[0], 16, -1 );

    if ( !n ) continue;

    if ( n < 0 ) {
      if ( errno == EINTR )
        continue;
      log_it( L_ERROR, "Server epoll error" );
      break;
    }

    for( int32_t i = 0; i < n; ++ i ) {

      if ( events[i].events & EPOLLIN ) {
        read_cb( efd_read, events[i].events, d_server );
      }
      if ( events[i].events & EPOLLOUT) {
        // Do nothing. It always true until socket eturn EAGAIN
      }
      if (sb_payload_ready) {
        write_cb( efd_read, events[i].events, d_server );
      }
      if( events[i].events & EPOLLERR ) {
        log_it( L_ERROR, "Server socket error event" );
        goto udp_error;
      }
    }

  }

udp_error:

  #ifndef _WIN32
    if ( efd_read != -1 )
      close( efd_read );
  #else
    if ( efd_read != INVALID_HANDLE_VALUE )
      epoll_close( efd_read );
  #endif

  return;
}

