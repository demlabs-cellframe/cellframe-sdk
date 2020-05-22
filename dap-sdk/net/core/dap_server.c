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

#define __USE_GNU

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

//#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
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

#include <sched.h>

#if 0
#define NI_NUMERICHOST  1 /* Don't try to look up hostname.  */
#define NI_NUMERICSERV  2 /* Don't convert port number to name.  */
#define NI_NOFQDN       4 /* Only return nodename portion.  */
#define NI_NAMEREQD     8 /* Don't return numeric addresses.  */
#define NI_DGRAM       16 /* Look up UDP service rather than TCP.  */
#endif

#include "dap_common.h"
#include "dap_server.h"
#include "dap_strfuncs.h"

#define LOG_TAG "server"

#define DAP_MAX_THREAD_EVENTS           8192
#define DAP_MAX_THREADS                 16

#define SOCKET_TIMEOUT_TIME             300
#define SOCKETS_TIMEOUT_CHECK_PERIOD    15

static uint32_t _count_threads = 0;
static uint32_t epoll_max_events = 0;
static bool bQuitSignal = false;
static bool moduleInit = false;

static struct epoll_event  *threads_epoll_events = NULL;
static dap_server_t *_current_run_server = NULL;

static void read_write_cb( dap_client_remote_t *dap_cur, int32_t revents );
void  *thread_loop( void *arg );

dap_server_thread_t dap_server_threads[ DAP_MAX_THREADS ];

/*
===============================================
  get_epoll_max_user_watches( )

  return max epoll() event watches
===============================================
*/
static uint32_t  get_epoll_max_user_watches( void )
{
  static const char *maxepollpath = "/proc/sys/fs/epoll/max_user_watches";
  uint32_t  v = 0, len;
  char  str[32];

  FILE *fp = fopen( maxepollpath, "r" );
  if ( !fp ) {
//    printf("can't open %s\n", maxepollpath );
    return v;
  }

  len = fread( &str[0], 1, 31, fp );
  if ( !len ) {
    return v;
  }

  str[ len ] = 0;
  v = atoi( str );

  return v;
}

/*
===============================================
  dap_server_init( )

  Init server module
  return Zero if ok others if no
===============================================
*/
int32_t dap_server_init( uint32_t count_threads )
{
  dap_server_thread_t *dap_thread;
  moduleInit = true;

  #ifndef _WIN32
    signal( SIGPIPE, SIG_IGN );
  #endif

  if ( count_threads > DAP_MAX_THREADS )
    count_threads = DAP_MAX_THREADS;

  _count_threads = count_threads;
  log_it( L_NOTICE, "dap_server_init() threads %u", count_threads );

  epoll_max_events = get_epoll_max_user_watches( );
  if ( epoll_max_events > DAP_MAX_THREAD_EVENTS )
    epoll_max_events = DAP_MAX_THREAD_EVENTS;

  threads_epoll_events = (struct epoll_event *)malloc( sizeof(struct epoll_event) * _count_threads * epoll_max_events );
  if ( !threads_epoll_events )
    goto err;

  memset( threads_epoll_events, 0, sizeof(struct epoll_event) * _count_threads * epoll_max_events );

  dap_thread = &dap_server_threads[0];
  memset( dap_thread, 0, sizeof(dap_server_thread_t) * DAP_MAX_THREADS );

  for ( uint32_t i = 0; i < _count_threads; ++i, ++dap_thread ) {
    #ifndef _WIN32
      dap_thread->epoll_fd = -1;
    #else
      dap_thread->epoll_fd = (void*)-1;
    #endif
    dap_thread->thread_num = i;
    dap_thread->epoll_events = &threads_epoll_events[ i * epoll_max_events ];

    pthread_mutex_init( &dap_thread->mutex_dlist_add_remove, NULL );
    pthread_mutex_init( &dap_thread->mutex_on_hash, NULL );
  }

  log_it( L_NOTICE, "Initialized socket server module" );

  dap_client_remote_init( );


  pthread_t thread_listener[ DAP_MAX_THREADS ];

  for( uint32_t i = 0; i < _count_threads; ++i ) {

    EPOLL_HANDLE efd = epoll_create1( 0 );
    if ( (intptr_t)efd == -1 ) {
      log_it( L_ERROR, "Can't create epoll instance" );
      goto err;
    }
    dap_server_threads[ i ].epoll_fd = efd;
    dap_server_threads[ i ].thread_num = i;
  }

  for( uint32_t i = 0; i < _count_threads; ++i ) {
    pthread_create( &thread_listener[i], NULL, thread_loop, &dap_server_threads[i] );
  }


  return 0;

err:;

  dap_server_deinit( );
  return 1;
}

void dap_server_loop_stop( void ){
    bQuitSignal = true;
}

/*
=========================================================
  dap_server_deinit( )

  Deinit server module
=========================================================
*/
void  dap_server_deinit( void )
{
    if (moduleInit) {
      dap_client_remote_t *dap_cur, *tmp;
      dap_server_thread_t *t = &dap_server_threads[0];

      dap_client_remote_deinit( );

      if ( threads_epoll_events ) {
        free( threads_epoll_events );

        for ( uint32_t i = 0; i < _count_threads; ++i, ++t ) {

          HASH_ITER( hh, t->hclients, dap_cur, tmp )
            dap_client_remote_remove( dap_cur );

          pthread_mutex_destroy( &dap_server_threads[i].mutex_on_hash );
          pthread_mutex_destroy( &dap_server_threads[i].mutex_dlist_add_remove );

          if ( (intptr_t)dap_server_threads[ i ].epoll_fd != -1 ) {
            #ifndef _WIN32
              close( dap_server_threads[ i ].epoll_fd );
            #else
              epoll_close( dap_server_threads[ i ].epoll_fd );
            #endif
          }
        }
      }
      moduleInit = false;
    }
}

/*
=========================================================
  dap_server_new( )

  Creates new empty instance of dap_server_t
=========================================================
*/
dap_server_t  *dap_server_new( void )
{
  return (dap_server_t *)calloc( 1, sizeof(dap_server_t) );
}

/*
=========================================================
  dap_server_new( )

  Delete server instance
=========================================================
*/
void dap_server_delete( dap_server_t *sh )
{
  if ( !sh ) return;

  if( sh->address )
    free( sh->address );

  if( sh->server_delete_callback )
    sh->server_delete_callback( sh, NULL );

  if ( sh->_inheritor )
    free( sh->_inheritor );

  free( sh );
}

/*
=========================================================
  set_nonblock_socket( )
=========================================================
*/
int32_t set_nonblock_socket( int32_t fd )
{
#ifdef _WIN32
  unsigned long arg = 1;
  return ioctlsocket( fd, FIONBIO, &arg );
#else
  int32_t flags;

  flags = fcntl( fd, F_GETFL );
  flags |= O_NONBLOCK;

  return fcntl( fd, F_SETFL, flags );
#endif
}


/*
=========================================================
  get_thread_min_connections( )

  return number thread which has minimum open connections
=========================================================
*/
static inline uint32_t get_thread_index_min_connections( )
{
  uint32_t min = 0;

  for( uint32_t i = 1; i < _count_threads; i ++ ) {
    if ( dap_server_threads[min].connections_count > dap_server_threads[i].connections_count ) {
      min = i;
    }
  }

  return min;
}

/*
=========================================================
  print_online( )

=========================================================
*/
static inline void print_online()
{
  for( uint32_t i = 0; i < _count_threads; i ++ )  {
    log_it( L_INFO, "Thread number: %u, count: %u", i, dap_server_threads[i].connections_count );
  }
}

void  dap_server_kill_socket( dap_client_remote_t *dcr )
{
  if ( !dcr ) {
    log_it( L_ERROR, "dap_server_kill_socket( NULL )" );
    return;
  }

  dap_server_thread_t *dsth = &dap_server_threads[ dcr->tn ];

  pthread_mutex_lock( &dsth->mutex_dlist_add_remove );

  if ( dcr->kill_signal ) {
    pthread_mutex_unlock( &dsth->mutex_dlist_add_remove );
    return;
  }

  log_it( L_DEBUG, "KILL %u socket! [ thread %u ]", dcr->socket, dcr->tn );

  dcr->kill_signal = true;

  DL_LIST_ADD_NODE_HEAD( dsth->dap_clients_to_kill, dcr, kprev, knext, dsth->to_kill_count );
  pthread_mutex_unlock( &dsth->mutex_dlist_add_remove );

  return;
}

/*
=========================================================
  dap_server_add_socket( )

=========================================================
*/
dap_client_remote_t  *dap_server_add_socket( int32_t fd, int32_t forced_thread_n )
{
  uint32_t tn = (forced_thread_n == -1) ? get_thread_index_min_connections( ) : forced_thread_n;
  dap_server_thread_t *dsth = &dap_server_threads[ tn ];
  dap_client_remote_t *dcr = dap_client_remote_create( _current_run_server, fd, dsth );

  if ( !dcr ) {
    log_it( L_ERROR, "accept %d dap_client_remote_create() == NULL", fd );
//    pthread_mutex_unlock( &dsth->mutex_dlist_add_remove );
    return dcr;
  }

  log_it( L_DEBUG, "accept %d Client, thread %d", fd, tn );

  pthread_mutex_lock( &dsth->mutex_dlist_add_remove );


  DL_APPEND( dsth->dap_remote_clients, dcr );
  dsth->connections_count ++;
  if ( epoll_ctl( dsth->epoll_fd, EPOLL_CTL_ADD, fd, &dcr->pevent) != 0 ) {
    log_it( L_ERROR, "epoll_ctl failed 005" );
  }
  pthread_mutex_unlock( &dsth->mutex_dlist_add_remove );

  return dcr;
}

/*
=========================================================
  dap_server_remove_socket( )

=========================================================
*/
void  dap_server_remove_socket( dap_client_remote_t *dcr )
{
  if ( !dcr ) {
    log_it( L_ERROR, "dap_server_remove_socket( NULL )" );
    return;
  }

  uint32_t tn = dcr->tn;
  log_it( L_DEBUG, "dap_server_remove_socket %u thread %u", dcr->socket, tn );

  dap_server_thread_t *dsth = &dap_server_threads[ tn ];

  if ( epoll_ctl( dcr->efd, EPOLL_CTL_DEL, dcr->socket, &dcr->pevent ) == -1 )
    log_it( L_ERROR,"Can't remove event socket's handler from the epoll_fd" );

//  pthread_mutex_lock( &dsth->mutex_dlist_add_remove );
  DL_DELETE( dsth->dap_remote_clients, dcr );
  dsth->connections_count --;

//  pthread_mutex_unlock( &dsth->mutex_dlist_add_remove );

//  log_it( L_DEBUG, "dcr = %X", dcr );
}

static void s_socket_all_check_activity( uint32_t tn, time_t cur_time )
{
  dap_client_remote_t *dcr, *tmp;
  dap_server_thread_t *dsth = &dap_server_threads[ tn ];

//  log_it( L_INFO,"s_socket_info_all_check_activity() on thread %u", tn );

  pthread_mutex_lock( &dsth->mutex_dlist_add_remove );

  DL_FOREACH_SAFE( dsth->dap_remote_clients, dcr, tmp ) {

    if ( !dcr->kill_signal && cur_time >= dcr->last_time_active + SOCKET_TIMEOUT_TIME && !dcr->no_close ) {

      log_it( L_INFO, "Socket %u timeout, closing...", dcr->socket );

      if ( epoll_ctl( dcr->efd, EPOLL_CTL_DEL, dcr->socket, &dcr->pevent ) == -1 )
        log_it( L_ERROR,"Can't remove event socket's handler from the epoll_fd" );

      DL_DELETE( dsth->dap_remote_clients, dcr );
      dsth->connections_count --;

      dap_client_remote_remove( dcr );
    }
  }
  pthread_mutex_unlock( &dsth->mutex_dlist_add_remove );
}

/*
=========================================================
  read_write_cb( )

=========================================================
*/
static void read_write_cb( dap_client_remote_t *dap_cur, int32_t revents )
{
//  log_it( L_NOTICE, "[THREAD %u] read_write_cb fd %u revents %u", dap_cur->tn, dap_cur->socket, revents );
//  sleep( 5 ); // ?????????

  if( !dap_cur ) {

    log_it( L_ERROR, "read_write_cb: dap_client_remote NULL" );
    return;
  }

  if ( revents & EPOLLIN ) {

//    log_it( L_DEBUG, "[THREAD %u] socket read %d ", dap_cur->tn, dap_cur->socket );

    int32_t bytes_read = recv( dap_cur->socket,
                                  dap_cur->buf_in + dap_cur->buf_in_size,
                                  sizeof(dap_cur->buf_in) - dap_cur->buf_in_size,
                                  0 );
    if ( bytes_read > 0 ) {
//      log_it( L_DEBUG, "[THREAD %u] read %u socket client said: %s", dap_cur->tn, bytes_read, dap_cur->buf_in + dap_cur->buf_in_size );

      dap_cur->buf_in_size += (size_t)bytes_read;
      dap_cur->upload_stat.buf_size_total += (size_t)bytes_read;

//      log_it( L_DEBUG, "[THREAD %u] read %u socket read callback()", dap_cur->tn, bytes_read );
      _current_run_server->client_read_callback( dap_cur ,NULL );
    }
    else if ( bytes_read < 0 ) {
      log_it( L_ERROR,"Bytes read Error %s",strerror(errno) );
      if ( strcmp(strerror(errno),"Resource temporarily unavailable") != 0 )
      dap_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
    }
    else { // bytes_read == 0
      dap_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
      log_it( L_DEBUG, "0 bytes read" );
    }
  }

  if( ( (revents & EPOLLOUT) || (dap_cur->flags & DAP_SOCK_READY_TO_WRITE) ) && !(dap_cur->flags & DAP_SOCK_SIGNAL_CLOSE) ) {

//    log_it(L_DEBUG, "[THREAD %u] socket write %d ", dap_cur->tn, dap_cur->socket );
    _current_run_server->client_write_callback( dap_cur, NULL ); // Call callback to process write event

    if( dap_cur->buf_out_size == 0 ) {
     //log_it(L_DEBUG, "dap_cur->buf_out_size = 0, set ev_read watcher " );

      dap_cur->pevent.events = EPOLLIN | EPOLLERR;
      if( epoll_ctl(dap_cur->efd, EPOLL_CTL_MOD, dap_cur->socket, &dap_cur->pevent) != 0 ) {
        log_it( L_ERROR, "epoll_ctl failed 003" );
      }
    }
    else {
//      log_it(L_DEBUG, "[THREAD %u] send dap_cur->buf_out_size = %u , %s", dap_cur->tn, dap_cur->buf_out_size, dap_cur->buf_out );

      size_t total_sent = dap_cur->buf_out_offset;

      while ( total_sent < dap_cur->buf_out_size ) {
        //log_it(DEBUG, "Output: %u from %u bytes are sent ", total_sent, dap_cur->buf_out_size);
        ssize_t bytes_sent = send( dap_cur->socket,
                                   dap_cur->buf_out + total_sent,
                                   dap_cur->buf_out_size - total_sent,
                                   MSG_DONTWAIT | MSG_NOSIGNAL );
        if( bytes_sent < 0 ) {
          log_it(L_ERROR,"[THREAD %u] Error occured in send() function %s", dap_cur->tn, strerror(errno) );
          dap_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
          break;
        }

        total_sent += (size_t)bytes_sent;
        dap_cur->download_stat.buf_size_total += (size_t)bytes_sent;
      }

//      log_it( L_ERROR, "check !" );

      if( total_sent == dap_cur->buf_out_size ) {
        dap_cur->buf_out_offset = dap_cur->buf_out_size  = 0;
      }
      else {
        dap_cur->buf_out_offset = total_sent;
      }
    } // else
  } // write


//  log_it(L_ERROR,"OPA !") ;
//  Sleep(200);

//  if ( (dap_cur->flags & DAP_SOCK_SIGNAL_CLOSE) && !dap_cur->no_close ) {
//    log_it(L_ERROR,"Close signal" );

//    dap_server_remove_socket( dap_cur );
//    dap_client_remote_remove( dap_cur, _current_run_server );
//  }

}


/*
=========================================================
  dap_server_listen( )

  Create server_t instance and start to listen tcp port with selected address

=========================================================
*/
dap_server_t *dap_server_listen( const char *addr, uint16_t port, dap_server_type_t type )
{
  dap_server_t* sh = dap_server_new( );

  sh->socket_listener = -111;

  if( type == DAP_SERVER_TCP )
    sh->socket_listener = socket( AF_INET, SOCK_STREAM, 0 );
  else {
    dap_server_delete( sh );
    return NULL;
  }
  
  if ( set_nonblock_socket(sh->socket_listener) == -1 ) {
    log_it( L_WARNING, "error server socket nonblock" );
    dap_server_delete( sh );
    return NULL;
  }

  if ( sh->socket_listener < 0 ) {
    log_it ( L_ERROR,"Socket error %s", strerror(errno) );
    dap_server_delete( sh );
    return NULL;
  }

  log_it( L_NOTICE," Socket created..." );

  int32_t reuse = 1;

  if ( reuse ) 
    if ( setsockopt( sh->socket_listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0 )
      log_it( L_WARNING, "Can't set up REUSEADDR flag to the socket" );

  sh->listener_addr.sin_family = AF_INET;
  sh->listener_addr.sin_port = htons( port );
  inet_pton( AF_INET, addr, &(sh->listener_addr.sin_addr) );

  if( bind(sh->socket_listener, (struct sockaddr *)&(sh->listener_addr), sizeof(sh->listener_addr)) < 0 ) {
    log_it( L_ERROR,"Bind error: %s",strerror(errno) );
    dap_server_delete( sh );
    return NULL;
  }

  log_it( L_INFO,"Binded %s:%u", addr, port );
  listen( sh->socket_listener, DAP_MAX_THREAD_EVENTS * _count_threads );

  return sh;
}


/*
=========================================================
  thread_loop( )

  Server listener thread loop
=========================================================
*/
void  *thread_loop( void *arg )
{
  dap_client_remote_t *dap_cur, *tmp;
  dap_server_thread_t *dsth = (dap_server_thread_t *)arg;
  uint32_t tn  = dsth->thread_num;
  EPOLL_HANDLE efd = dsth->epoll_fd;
  struct epoll_event  *events = dsth->epoll_events;
  time_t next_time_timeout_check = time( NULL ) + SOCKETS_TIMEOUT_CHECK_PERIOD;

  log_it(L_NOTICE, "Start loop listener socket thread %u efd %u", tn, efd );

  #ifndef _WIN32
  cpu_set_t mask;
  CPU_ZERO( &mask );
  CPU_SET( tn, &mask );

  int err;
#ifndef ANDROID
  err = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &mask);
#else
  err = sched_setaffinity(pthread_self(), sizeof(cpu_set_t), &mask);
#endif
  if (err) {
    log_it( L_CRITICAL, "Error pthread_setaffinity_np() You really have %d or more core in CPU?", tn );
    abort();
  }
  #else

  if ( !SetThreadAffinityMask( GetCurrentThread(), (DWORD_PTR)(1 << tn) ) ) {
    log_it( L_CRITICAL, "Error pthread_setaffinity_np() You really have %d or more core in CPU?", tn );
    abort();
  }

  #endif

  do {

    int32_t n = epoll_wait( efd, events, DAP_MAX_THREAD_EVENTS, 1000 );

//    log_it(L_WARNING,"[THREAD %u] epoll events %u", tn, n  );
//    Sleep(300);

    if ( bQuitSignal )
      break;

    if ( n < 0 ) {
      if ( errno == EINTR )
        continue;
      break;
    }

    time_t cur_time = time( NULL );

    for ( int32_t i = 0; i < n; ++ i ) {

//      log_it(L_ERROR,"[THREAD %u] process epoll event %u", tn, i  );
      dap_cur = (dap_client_remote_t *)events[i].data.ptr;

      if ( !dap_cur ) {
        log_it( L_ERROR,"dap_client_remote_t NULL" );
        continue;
      }

      dap_cur->last_time_active = cur_time;
      if( events[i].events & EPOLLERR ) {
          log_it( L_ERROR,"Socket error: %u, remove it" , dap_cur->socket );
          dap_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
      }
#ifdef _WIN32
      set_nonblock_socket(dap_cur->socket); // pconst: for winsock2 has no appropriate MSG attributes
#endif
      if ( !(dap_cur->flags & DAP_SOCK_SIGNAL_CLOSE) || dap_cur->no_close )
        read_write_cb( dap_cur, events[i].events );

      if ( (dap_cur->flags & DAP_SOCK_SIGNAL_CLOSE) && !dap_cur->no_close ) {

        pthread_mutex_lock( &dsth->mutex_dlist_add_remove );

        if ( dap_cur->kill_signal ) {
          pthread_mutex_unlock( &dsth->mutex_dlist_add_remove );
          continue;
        }

//        pthread_mutex_unlock( &dsth->mutex_dlist_add_remove );
//        dap_server_kill_socket( dap_cur );
//        continue;

        log_it( L_INFO, "Got signal to close %u socket, closing...[ %u ]", dap_cur->socket, tn );

        dap_server_remove_socket( dap_cur );
        dap_client_remote_remove( dap_cur );

        pthread_mutex_unlock( &dsth->mutex_dlist_add_remove );
      }

    } // for

    if ( cur_time >= next_time_timeout_check ) {

      s_socket_all_check_activity( tn, cur_time );
      next_time_timeout_check = cur_time + SOCKETS_TIMEOUT_CHECK_PERIOD;
    }

    pthread_mutex_lock( &dsth->mutex_dlist_add_remove );
    if ( !dsth->to_kill_count ) {

      pthread_mutex_unlock( &dsth->mutex_dlist_add_remove );
      continue;
    }

    dap_cur = dsth->dap_clients_to_kill;

    do {

      if ( dap_cur->no_close ) {
        dap_cur = dap_cur->knext;
        continue;
      }

      log_it( L_INFO, "Kill %u socket ...............[ thread %u ]", dap_cur->socket, tn );

      tmp = dap_cur->knext;
      DL_LIST_REMOVE_NODE( dsth->dap_clients_to_kill, dap_cur, kprev, knext, dsth->to_kill_count );

      dap_server_remove_socket( dap_cur );
      dap_client_remote_remove( dap_cur );
      dap_cur = tmp;

    } while ( dap_cur );

    log_it( L_INFO, "[ Thread %u ] coneections: %u, to kill: %u", tn, dsth->connections_count, dsth->to_kill_count  );
    pthread_mutex_unlock( &dsth->mutex_dlist_add_remove );

  } while( !bQuitSignal ); 

  return NULL;
}

/*
=========================================================
  dap_server_loop( )

  Main server loop

  @param a_server Server instance
  @return Zero if ok others if not
=========================================================
*/
int32_t dap_server_loop( dap_server_t *d_server )
{
  int errCode = 0;

  if(d_server == NULL){
    log_it(L_ERROR, "Server is NULL");
    return -1;
  }

  _current_run_server = d_server;

  EPOLL_HANDLE efd = epoll_create1( 0 );
  if ( (intptr_t)efd == -1 ) {
    return -10;
  }

  struct epoll_event  pev;
  struct epoll_event  events[ 16 ];

  memset(&pev, 0, sizeof(pev));
  pev.events = EPOLLIN | EPOLLERR;
  pev.data.fd = d_server->socket_listener;

  if( epoll_ctl( efd, EPOLL_CTL_ADD, d_server->socket_listener, &pev) != 0 ) {
      log_it( L_ERROR, "epoll_ctl failed 004" );
      return -20;
  }

  while( !bQuitSignal && errCode == 0 ) {
    int32_t n = epoll_wait( efd, &events[0], 16, 1000 );

    if ( bQuitSignal )
      break;

    if ( n < 0 ) {
      if ( errno == EINTR )
        continue;
      log_it( L_ERROR, "Server wakeup on error: %i", errno );
      errCode = -30;
    }

    for( int32_t i = 0; i < n && errCode == 0; ++i ) {

      if ( events[i].events & EPOLLIN ) {
        int client_fd = accept( events[i].data.fd, 0, 0 );

        if ( client_fd < 0 ) {
          log_it( L_ERROR, "accept_cb: error accept socket");
          continue;
        }

        set_nonblock_socket( client_fd );
        dap_server_add_socket( client_fd, -1 );
      }
      else if( events[i].events & EPOLLERR ) {
        log_it( L_ERROR, "Server socket error event" );
        errCode = -40;
      }

    } // for
  } // while

  if (efd != -1) {
    #ifndef _WIN32
      close( efd );
    #else
      epoll_close( efd );
    #endif
  }

  return errCode;
}
