/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Limited   https://demlabs.net
 * Cellframe https://cellframe.net
 * Copyright  (c) 2017-2020
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
#define __USE_GNU

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#ifdef DAP_OS_UNIX
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>

#ifdef DAP_OS_LINUX
#include <sys/timerfd.h>
#endif

#if defined(DAP_OS_ANDROID)
#define NO_POSIX_SHED
#define NO_TIMER
#else
#endif

#ifdef DAP_OS_WINDOWS
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#endif

#include <utlist.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_server.h"
#include "dap_events.h"
#include "dap_events_socket.h"


#define LOG_TAG "dap_events"

bool s_workers_init = false;
static uint32_t s_threads_count = 1;
dap_worker_t *s_workers = NULL;
dap_thread_t *s_threads = NULL;


uint32_t dap_get_cpu_count( )
{
#ifdef _WIN32
  SYSTEM_INFO si;

  GetSystemInfo( &si );
  return si.dwNumberOfProcessors;
#else
#ifndef NO_POSIX_SHED
  cpu_set_t cs;
  CPU_ZERO( &cs );
  sched_getaffinity( 0, sizeof(cs), &cs );

  uint32_t count = 0;
  for ( int i = 0; i < 32; i++ ){
    if ( CPU_ISSET(i, &cs) )
    count ++;
  }
  return count;
#else
  return 1;
#endif
#endif
}

/**
 * @brief sa_server_init Init server module
 * @arg a_threads_count  number of events processor workers in parallel threads
 * @return Zero if ok others if no
 */
int dap_events_init( uint32_t a_threads_count, size_t a_conn_timeout )
{
    s_threads_count = a_threads_count ? a_threads_count : dap_get_cpu_count( );

    s_workers =  DAP_NEW_S_SIZE(dap_worker_t,sizeof(dap_worker_t) * s_threads_count );
    s_threads = DAP_NEW_Z_SIZE(dap_thread_t, sizeof(dap_thread_t) * s_threads_count );
    if ( !s_workers || !s_threads )
        return -1;

    s_workers_init = true;

    dap_worker_init(a_conn_timeout);
    if ( dap_events_socket_init() != 0 ) {
        log_it( L_CRITICAL, "Can't init client submodule dap_events_socket_init( )" );
        goto err;
    }

    log_it( L_NOTICE, "Initialized socket server module" );

#ifdef DAP_OS_UNIX
    signal( SIGPIPE, SIG_IGN );
#endif
    return 0;

err:
    dap_events_deinit();
    dap_worker_deinit();
    return -1;
}

/**
 * @brief sa_server_deinit Deinit server module
 */
void dap_events_deinit( )
{
    dap_events_socket_deinit();
    dap_worker_deinit();
    if ( s_threads )
        DAP_DELETE( s_threads );

    if ( s_workers )
        DAP_DELETE( s_workers );
}

/**
 * @brief server_new Creates new empty instance of server_t
 * @return New instance
 */
dap_events_t * dap_events_new( )
{
  dap_events_t *ret = (dap_events_t *)calloc( 1, sizeof(dap_events_t) );

  pthread_rwlock_init( &ret->sockets_rwlock, NULL );
  pthread_rwlock_init( &ret->servers_rwlock, NULL );

  return ret;
}

/**
 * @brief server_delete Delete event processor instance
 * @param sh Pointer to the server instance
 */
void dap_events_delete( dap_events_t *a_events )
{
    if (a_events) {
        dap_events_socket_t *l_cur, *l_tmp;
        HASH_ITER( hh, a_events->sockets,l_cur, l_tmp ) {
            dap_events_socket_delete_unsafe( l_cur, true );
        }

        if ( a_events->_inheritor )
            DAP_DELETE( a_events->_inheritor );

        pthread_rwlock_destroy( &a_events->servers_rwlock );
        pthread_rwlock_destroy( &a_events->sockets_rwlock );

        DAP_DELETE( a_events );
    }
}

/**
 * @brief sa_server_loop Main server loop
 * @param sh Server instance
 * @return Zero if ok others if not
 */
int dap_events_start( dap_events_t *a_events )
{
    for( uint32_t i = 0; i < s_threads_count; i++) {
        s_workers[i].id = i;
        s_workers[i].events = a_events;
#ifdef DAP_EVENTS_CAPS_EPOLL
        s_workers[i].epoll_fd = epoll_create( DAP_MAX_EPOLL_EVENTS );
        if ( (intptr_t)s_workers[i].epoll_fd == -1 ) {
            int l_errno = errno;
            char l_errbuf[128];
            strerror_r(l_errno, l_errbuf, sizeof ( l_errbuf) );
            log_it(L_CRITICAL, "Error create epoll fd: %s (%d)", l_errbuf, l_errno);
            return -1;
        }
#endif
      pthread_mutex_init( &s_workers[i].locker_on_count, NULL );
      pthread_create( &s_threads[i].tid, NULL, dap_worker_thread, &s_workers[i] );
    }
    return 0;
}

/**
 * @brief dap_events_wait
 * @param sh
 * @return
 */
int dap_events_wait( dap_events_t *a_events )
{
    (void) a_events;
    for( uint32_t i = 0; i < s_threads_count; i ++ ) {
        void *ret;
        pthread_join( s_threads[i].tid, &ret );
    }
    return 0;
}

/**
 * @brief dap_events_stop
 * @param a_events
 */
void dap_events_stop_all( )
{
    // TODO implement signal to stop the workers
}


/**
 * @brief dap_worker_get_index_min
 * @return
 */
uint32_t dap_events_worker_get_index_min( )
{
    uint32_t min = 0;
    uint32_t i;

    for( i = 1; i < s_threads_count; i++ ) {

    if ( s_workers[min].event_sockets_count > s_workers[i].event_sockets_count )
        min = i;
    }

    return min;
}

uint32_t dap_events_worker_get_count()
{
    return  s_threads_count;
}

/**
 * @brief dap_worker_get_min
 * @return
 */
dap_worker_t *dap_events_worker_get_min( )
{
    dap_worker_t *l_workers = &s_workers[dap_events_worker_get_index_min()];
    return l_workers;
}

/**
 * @brief dap_worker_get_index
 * @param a_index
 * @return
 */
dap_worker_t * dap_events_worker_get_index(uint8_t a_index)
{
    return a_index < s_threads_count ? &s_workers[a_index] : NULL;
}

/**
 * @brief dap_worker_print_all
 */
void dap_events_worker_print_all( )
{
    uint32_t i;
    for( i = 0; i < s_threads_count; i ++ ) {
        log_it( L_INFO, "Worker: %d, count open connections: %d",
                s_workers[i].id, s_workers[i].event_sockets_count );
    }
}
