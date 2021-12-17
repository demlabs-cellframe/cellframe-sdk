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
#include <pthread.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

//#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>

#if defined(DAP_OS_LINUX)
#include <sys/timerfd.h>
#endif

#if defined(DAP_OS_BSD)
#include <sys/event.h>
#include <err.h>
#endif

#if defined(DAP_OS_DARWIN)
#include <sys/types.h>
#include <sys/sysctl.h>

#include <mach/thread_policy.h>
#include <mach/thread_act.h>
#elif defined (DAP_OS_BSD)
#include <pthread_np.h>
typedef cpuset_t cpu_set_t; // Adopt BSD CPU setstructure to POSIX variant
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

#endif

#include <utlist.h>
#include <pthread.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_server.h"
#include "dap_events.h"
#include "dap_events_socket.h"
#include "dap_proc_thread.h"

#define LOG_TAG "dap_events"

static bool s_workers_init = false;
static uint32_t s_threads_count = 1;
static dap_worker_t **s_workers = NULL;
static dap_thread_t *s_threads = NULL;
static dap_events_t * s_events_default = NULL;

/**
 * @brief dap_get_cpu_count
 * 
 * @return uint32_t 
 */
uint32_t dap_get_cpu_count( )
{
#ifdef _WIN32
  SYSTEM_INFO si;

  GetSystemInfo( &si );
  return si.dwNumberOfProcessors;
#else
#ifndef NO_POSIX_SHED
#ifndef DAP_OS_DARWIN
  cpu_set_t cs;
  CPU_ZERO( &cs );
#endif

#if defined (DAP_OS_ANDROID) 
  sched_getaffinity( 0, sizeof(cs), &cs );
#elif defined (DAP_OS_DARWIN)
  int count=0;
  size_t count_len = sizeof(count);
  sysctlbyname("hw.logicalcpu", &count, &count_len, NULL, 0);

#else
  pthread_getaffinity_np(pthread_self(), sizeof(cs), &cs);
#endif

#ifndef DAP_OS_DARWIN
  uint32_t count = 0;
  for ( int i = 0; i < 32; i++ ){
    if ( CPU_ISSET(i, &cs) )
    count ++;
  }
#endif
  return count;

#else
  return 1;
#endif
#endif
}

/**
 * @brief dap_cpu_assign_thread_on
 * 
 * @param a_cpu_id 
 */
void dap_cpu_assign_thread_on(uint32_t a_cpu_id)
{
#ifndef DAP_OS_WINDOWS
#ifndef NO_POSIX_SHED

#ifdef DAP_OS_DARWIN
    pthread_t l_pthread_id = pthread_self();
    mach_port_t l_pthread_mach_port = pthread_mach_thread_np(l_pthread_id);
#else
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(a_cpu_id, &mask);
#endif
    int l_retcode;
#ifdef DAP_OS_DARWIN
    thread_affinity_policy_data_t l_policy_data={.affinity_tag = a_cpu_id};
    l_retcode = thread_policy_set(l_pthread_mach_port , THREAD_AFFINITY_POLICY, (thread_policy_t)&l_policy_data , 1);
#elif defined(DAP_OS_ANDROID)
    l_retcode = sched_setaffinity(pthread_self(), sizeof(cpu_set_t), &mask);
#else
    l_retcode = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &mask);
#endif
    if(l_retcode != 0)
    {
        char l_errbuf[128]={0};
        switch (l_retcode) {
            case EFAULT: strncpy(l_errbuf,"A supplied memory address was invalid.",sizeof (l_errbuf)-1); break;
            case EINVAL: strncpy(l_errbuf,"The affinity bit mask mask contains no processors that are currently physically on the system and permitted to the thread",sizeof (l_errbuf)-1); break;
            case ESRCH:  strncpy(l_errbuf,"No thread with the ID thread could be found",sizeof (l_errbuf)-1); break;
            case EPFNOSUPPORT: strncpy(l_errbuf,"System doesn't support thread affinity set",sizeof (l_errbuf)-1); break;
            default:     strncpy(l_errbuf,"Unknown error",sizeof (l_errbuf)-1);
        }
        log_it(L_ERROR, "Worker #%u: error in set affinity thread call: %s (%d)",a_cpu_id, l_errbuf , l_retcode);
        //abort();
    }
#endif
#else

  if ( !SetThreadAffinityMask( GetCurrentThread(), (DWORD_PTR)(1 << a_cpu_id) ) ) {
    log_it( L_CRITICAL, "Error pthread_setaffinity_np() You really have %d or more core in CPU?", a_cpu_id );
    abort();
  }
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

    s_workers =  DAP_NEW_Z_SIZE(dap_worker_t*,s_threads_count*sizeof (dap_worker_t*) );
    s_threads = DAP_NEW_Z_SIZE(dap_thread_t, sizeof(dap_thread_t) * s_threads_count );
    if ( !s_workers || !s_threads )
        return -1;

    s_workers_init = true;

    dap_worker_init(a_conn_timeout);
    if ( dap_events_socket_init() != 0 ) {
        log_it( L_CRITICAL, "Can't init client submodule dap_events_socket_init( )" );
        goto err;
    }
    log_it( L_NOTICE, "Initialized event socket reactor for %u threads", s_threads_count );

    return 0;

err:
    log_it(L_ERROR,"Deinit events subsystem");
    dap_events_deinit();
    return -1;
}

/**
 * @brief sa_server_deinit Deinit server module
 */
void dap_events_deinit( )
{
	dap_proc_thread_deinit();
    dap_events_socket_deinit();
    dap_worker_deinit();
	
	dap_events_wait(s_events_default);
    if ( s_threads )
        DAP_DELETE( s_threads );

    if ( s_workers )
        DAP_DELETE( s_workers );
}

/**
 * @brief server_new Creates new empty instance of server_t
 * Additionally checking s_events_default and create thread (pthread_key_create)
 * @return New instance
 */
dap_events_t * dap_events_new( )
{
    dap_events_t *ret = DAP_NEW_Z(dap_events_t);

    if ( s_events_default == NULL)
        s_events_default = ret;
    pthread_key_create( &ret->pth_key_worker, NULL);

    return ret;
}

/**
 * @brief dap_events_get_default
 * simply return s_events_default
 * @return dap_events_t* 
 */
dap_events_t* dap_events_get_default( )
{
    return s_events_default;
}

/**
 * @brief server_delete Delete event processor instance
 * @param sh Pointer to the server instance
 */
void dap_events_delete( dap_events_t *a_events )
{
    if (a_events) {
        if ( a_events->_inheritor )
            DAP_DELETE( a_events->_inheritor );

        DAP_DELETE( a_events );
    }
}

/**
 * @brief dap_events_remove_and_delete_socket_unsafe
 * calls dap_events_socket_remove_and_delete_unsafe
 * @param a_events 
 * @param a_socket 
 * @param a_preserve_inheritor 
 */
void dap_events_remove_and_delete_socket_unsafe(dap_events_t *a_events, dap_events_socket_t *a_socket, bool a_preserve_inheritor)
{
    (void) a_events;
//    int l_sock = a_socket->socket;
//    if( a_socket->type == DESCRIPTOR_TYPE_TIMER)
//        log_it(L_DEBUG,"Remove timer %d", l_sock);

    dap_events_socket_remove_and_delete_unsafe(a_socket, a_preserve_inheritor);
}

/**
 * @brief sa_server_loop Main server loop
 * @param sh Server instance
 * @return Zero if ok others if not
 */
int dap_events_start( dap_events_t *a_events )
{

    for( uint32_t i = 0; i < s_threads_count; i++) {
        dap_worker_t * l_worker = DAP_NEW_Z(dap_worker_t);

        l_worker->id = i;
        l_worker->events = a_events;
        l_worker->esockets = NULL;
        pthread_rwlock_init(&l_worker->esocket_rwlock,NULL);
        pthread_mutex_init(& l_worker->started_mutex, NULL);
        pthread_cond_init( & l_worker->started_cond, NULL);

#if defined(DAP_EVENTS_CAPS_EPOLL)
        l_worker->epoll_fd = epoll_create( DAP_MAX_EVENTS_COUNT );
        //log_it(L_DEBUG, "Created event_fd %d for worker %u", l_worker->epoll_fd,i);
#ifdef DAP_OS_WINDOWS
        if (!l_worker->epoll_fd) {
            int l_errno = WSAGetLastError();
#else
        if ( l_worker->epoll_fd == -1 ) {
            int l_errno = errno;
#endif
            char l_errbuf[128];
            strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
            log_it(L_CRITICAL, "Error create epoll fd: %s (%d)", l_errbuf, l_errno);
            DAP_DELETE(l_worker);
            return -1;
        }
#elif defined(DAP_EVENTS_CAPS_POLL)
#elif defined(DAP_EVENTS_CAPS_KQUEUE)
#else
#error "Not defined worker init for your platform"
#endif
        s_workers[i] = l_worker;
        pthread_mutex_lock(&l_worker->started_mutex);
        struct timespec l_timeout;
        clock_gettime(CLOCK_REALTIME, &l_timeout);
        l_timeout.tv_sec+=15;
        pthread_create( &s_threads[i].tid, NULL, dap_worker_thread, l_worker );
        int l_ret;
        l_ret=pthread_cond_timedwait(&l_worker->started_cond, &l_worker->started_mutex, &l_timeout);
        pthread_mutex_unlock(&l_worker->started_mutex);
        if ( l_ret== ETIMEDOUT ){
            log_it(L_CRITICAL, "Timeout 15 seconds is out: worker #%u thread don't respond", i);
            return -2;
        } else if (l_ret != 0){
            log_it(L_CRITICAL, "Can't wait on condition: %d error code", l_ret);
            return -3;
        }
    }
    // Link queues between
    for( uint32_t i = 0; i < s_threads_count; i++) {
        dap_worker_t * l_worker = s_workers[i];
        l_worker->queue_es_new_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)* s_threads_count);
        l_worker->queue_es_delete_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)* s_threads_count);
        l_worker->queue_es_reassign_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)* s_threads_count);
        l_worker->queue_es_io_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)* s_threads_count);
        for( uint32_t n = 0; n < s_threads_count; n++) {
            l_worker->queue_es_new_input[n] = dap_events_socket_queue_ptr_create_input(s_workers[n]->queue_es_new);
            l_worker->queue_es_delete_input[n] = dap_events_socket_queue_ptr_create_input(s_workers[n]->queue_es_delete);
            l_worker->queue_es_reassign_input[n] = dap_events_socket_queue_ptr_create_input(s_workers[n]->queue_es_reassign);
            l_worker->queue_es_io_input[n] = dap_events_socket_queue_ptr_create_input(s_workers[n]->queue_es_io);
        }
    }

    // Init callback processor
    if (dap_proc_thread_init(s_threads_count) != 0 ){
        log_it( L_CRITICAL, "Can't init proc threads" );
        return -4;
    }

    return 0;
}

/**
 * @brief dap_events_wait
 * @param dap_events_t *a_events
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
 * @param
 */
void dap_events_stop_all( )
{
    for( uint32_t i = 0; i < s_threads_count; i ++ ) {
        dap_events_socket_event_signal( s_workers[i]->event_exit, 1);
    }
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

    if ( s_workers[min]->event_sockets_count > s_workers[i]->event_sockets_count )
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
dap_worker_t *dap_events_worker_get_auto( )
{
    return s_workers[dap_events_worker_get_index_min()];
}

/**
 * @brief dap_worker_get_index
 * @param a_index
 * @return
 */
dap_worker_t * dap_events_worker_get(uint8_t a_index)
{
    if (a_index < s_threads_count){
        return   s_workers[a_index];
    }else
        return NULL;
}

/**
 * @brief dap_worker_print_all
 */
void dap_events_worker_print_all( )
{
    uint32_t i;
    for( i = 0; i < s_threads_count; i ++ ) {
        log_it( L_INFO, "Worker: %d, count open connections: %d",
                s_workers[i]->id, s_workers[i]->event_sockets_count );
    }
}
