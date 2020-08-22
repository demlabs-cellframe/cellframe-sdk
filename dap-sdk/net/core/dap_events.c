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

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/epoll.h>

#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#if 1
#include <sys/timerfd.h>
#elif defined(DAP_OS_ANDROID)
#define NO_POSIX_SHED
#define NO_TIMER
#endif

#else
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#endif

#include <utlist.h>
#include <sched.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_server.h"
#include "dap_events.h"
#include "dap_events_socket.h"

#define DAP_MAX_EPOLL_EVENTS    8192

//typedef struct open_connection_info_s {
//    dap_events_socket_t *es;
//    struct open_connection_info *prev;
//    struct open_connection_info *next;
//} dap_events_socket_info_t;

//dap_events_socket_info_t **s_dap_events_sockets;
#define LOG_TAG "dap_events"

static uint32_t s_threads_count = 1;
static time_t s_connection_timeout = 6000;
static struct epoll_event *g_epoll_events = NULL;
static volatile bool bEventsAreActive = true;

bool s_workers_init = false;
dap_worker_t *s_workers = NULL;
dap_thread_t *s_threads = NULL;
static void s_new_es_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_delete_es_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_reassign_es_callback( dap_events_socket_t * a_es, void * a_arg);


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
int32_t dap_events_init( uint32_t a_threads_count, size_t conn_timeout )
{
  s_threads_count = a_threads_count ? a_threads_count : dap_get_cpu_count( );

  if ( conn_timeout )
    s_connection_timeout = conn_timeout;

  s_workers = (dap_worker_t *) calloc( 1, sizeof(dap_worker_t) * s_threads_count );
  s_threads = (dap_thread_t *) calloc( 1, sizeof(dap_thread_t) * s_threads_count );
  if ( !s_workers || !s_threads )
    goto err;

  g_epoll_events = (struct epoll_event *)malloc( sizeof(struct epoll_event) * DAP_MAX_EPOLL_EVENTS * s_threads_count );
  if ( !g_epoll_events )
    goto err;

  if ( dap_events_socket_init() != 0 ) {

    log_it( L_CRITICAL, "Can't init client submodule dap_events_socket_init( )" );
    goto err;
  }
  s_workers_init = true;

  log_it( L_NOTICE, "Initialized socket server module" );

  #ifndef _WIN32
    signal( SIGPIPE, SIG_IGN );
  #endif
  return 0;

err:
  dap_events_deinit( );
  return -1;
}

/**
 * @brief sa_server_deinit Deinit server module
 */
void dap_events_deinit( )
{
  dap_events_socket_deinit( );

  if ( g_epoll_events )
    free( g_epoll_events );

  if ( s_threads )
    free( s_threads );

  if ( s_workers )
    free( s_workers );
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
  dap_events_socket_t *cur, *tmp;

  if ( a_events ) {

    HASH_ITER( hh, a_events->sockets,cur, tmp ) {
      dap_events_socket_delete_unsafe( cur, true );
    }

    if ( a_events->_inheritor )
      free( a_events->_inheritor );

    pthread_rwlock_destroy( &a_events->servers_rwlock );
    pthread_rwlock_destroy( &a_events->sockets_rwlock );

    free( a_events );
  }
}

/**
 * @brief s_socket_info_all_check_activity
 * @param n_thread
 * @param sh
 */
static void s_socket_all_check_activity( dap_worker_t *dap_worker, dap_events_t *a_events, time_t cur_time )
{
  dap_events_socket_t *a_es, *tmp;

  pthread_rwlock_rdlock(&a_events->sockets_rwlock);
  HASH_ITER(hh, a_events->sockets, a_es, tmp ) {

    if ( a_es->type == DESCRIPTOR_TYPE_FILE)
      continue;

    if ( !a_es->kill_signal && cur_time >=  (time_t)a_es->last_time_active + s_connection_timeout && !a_es->no_close ) {

      log_it( L_INFO, "Socket %u timeout, closing...", a_es->socket );
      if (a_es->callbacks.error_callback) {
          a_es->callbacks.error_callback(a_es, (void *)ETIMEDOUT);
      }

      if ( epoll_ctl( dap_worker->epoll_fd, EPOLL_CTL_DEL, a_es->socket, &a_es->ev) == -1 )
        log_it( L_ERROR,"Can't remove event socket's handler from the epoll_fd" );
      else
        log_it( L_DEBUG,"Removed epoll's event from dap_worker #%u", dap_worker->id );

      pthread_rwlock_unlock(&a_events->sockets_rwlock);
      dap_events_socket_delete_unsafe(a_es, true );
      pthread_rwlock_rdlock(&a_events->sockets_rwlock);
    }
  }
  pthread_rwlock_unlock(&a_events->sockets_rwlock);

}

/**
 * @brief s_thread_worker_function
 * @param arg
 * @return
 */
static void *s_thread_worker_function(void *arg)
{
    dap_events_socket_t *l_cur;
    dap_worker_t *l_worker = (dap_worker_t *) arg;
    time_t l_next_time_timeout_check = time( NULL) + s_connection_timeout / 2;
    uint32_t l_tn = l_worker->id;

#ifndef _WIN32
#ifndef NO_POSIX_SHED
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(l_tn, &mask);

    int err;
#ifndef __ANDROID__
    err = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &mask);
#else
  err = sched_setaffinity(pthread_self(), sizeof(cpu_set_t), &mask);
#endif
    if(err)
    {
        log_it(L_CRITICAL, "Error pthread_setaffinity_np() You really have %d or more core in CPU?", *(int* )arg);
        abort();
    }
#endif
#else

  if ( !SetThreadAffinityMask( GetCurrentThread(), (DWORD_PTR)(1 << tn) ) ) {
    log_it( L_CRITICAL, "Error pthread_setaffinity_np() You really have %d or more core in CPU?", tn );
    abort();
  }
  #endif

    l_worker->event_new_es = dap_events_socket_create_type_event( l_worker, s_new_es_callback);
    l_worker->event_delete_es = dap_events_socket_create_type_event( l_worker, s_new_es_callback);

    log_it(L_INFO, "Worker %d started, epoll fd %d", l_worker->id, l_worker->epoll_fd);

    struct epoll_event *events = &g_epoll_events[ DAP_MAX_EPOLL_EVENTS * l_tn];

//  memset( &ev, 0, sizeof(ev) );
//  memset( &events, 0, sizeof(events) );

    size_t total_sent;
    int bytes_sent = 0;

    while(bEventsAreActive) {

        int selected_sockets = epoll_wait(l_worker->epoll_fd, events, DAP_MAX_EPOLL_EVENTS, 1000);

        if(selected_sockets == -1) {
            if( errno == EINTR)
                continue;
            log_it(L_ERROR, "Worker thread %d got errno: %d", l_worker->id, errno);
            break;
        }

        time_t cur_time = time( NULL);
        for(int32_t n = 0; n < selected_sockets; n++) {

            l_cur = (dap_events_socket_t *) events[n].data.ptr;

            if(!l_cur) {

                log_it(L_ERROR, "dap_events_socket NULL");
                continue;
            }
            l_cur->last_time_active = cur_time;
            //log_it(L_DEBUG, "Worker=%d fd=%d socket=%d event=0x%x(%d)", w->number_thread, w->epoll_fd,cur->socket, events[n].events,events[n].events);
            int l_sock_err = 0, l_sock_err_size = sizeof(l_sock_err);
            //connection already closed (EPOLLHUP - shutdown has been made in both directions)
            if(events[n].events & EPOLLHUP) { // && events[n].events & EPOLLERR) {
                switch (l_cur->type ){
                    case DESCRIPTOR_TYPE_SOCKET_LISTENING:
                    case DESCRIPTOR_TYPE_SOCKET:
                        getsockopt(l_cur->socket, SOL_SOCKET, SO_ERROR, (void *)&l_sock_err, (socklen_t *)&l_sock_err_size);
                        //if(!(events[n].events & EPOLLIN))
                        //cur->no_close = false;
                        if (l_sock_err) {
                            l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            log_it(L_DEBUG, "Socket shutdown (EPOLLHUP): %s", strerror(l_sock_err));
                        }
                   default: log_it(L_WARNING, "Unimplemented EPOLLHUP for socket type %d", l_cur->type);
                }
            }

            if(events[n].events & EPOLLERR) {
                switch (l_cur->type ){
                    case DESCRIPTOR_TYPE_SOCKET_LISTENING:
                    case DESCRIPTOR_TYPE_SOCKET:
                        getsockopt(l_cur->socket, SOL_SOCKET, SO_ERROR, (void *)&l_sock_err, (socklen_t *)&l_sock_err_size);
                        log_it(L_ERROR, "Socket error: %s", strerror(l_sock_err));
                    default: ;
                }
                l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                l_cur->callbacks.error_callback(l_cur, NULL); // Call callback to process error event
            }


            if(events[n].events & EPOLLIN) {

                //log_it(DEBUG,"Comes connection in active read set");
                if(l_cur->buf_in_size == sizeof(l_cur->buf_in)) {
                    log_it(L_WARNING, "Buffer is full when there is smth to read. Its dropped!");
                    l_cur->buf_in_size = 0;
                }

                int32_t bytes_read = 0;
                int l_errno=0;
                bool l_must_read_smth = false;
                switch (l_cur->type) {
                    case DESCRIPTOR_TYPE_FILE:
                        l_must_read_smth = true;
                        bytes_read = read(l_cur->socket, (char *) (l_cur->buf_in + l_cur->buf_in_size),
                                sizeof(l_cur->buf_in) - l_cur->buf_in_size);
                        l_errno = errno;
                    break;
                    case DESCRIPTOR_TYPE_SOCKET:
                        l_must_read_smth = true;
                        bytes_read = recv(l_cur->fd, (char *) (l_cur->buf_in + l_cur->buf_in_size),
                                sizeof(l_cur->buf_in) - l_cur->buf_in_size, 0);
                        l_errno = errno;
                    break;
                    case DESCRIPTOR_TYPE_SOCKET_LISTENING:
                        // Accept connection
                    break;
                    case DESCRIPTOR_TYPE_TIMER:{
                        uint64_t val;
                        /* if we not reading data from socket, he triggered again */
                        read( l_cur->fd, &val, 8);
                        if (l_cur->callbacks.timer_callback)
                            l_cur->callbacks.timer_callback(l_cur);
                        else
                            log_it(L_ERROR, "Socket %d with timer callback fired, but callback is NULL ", l_cur->socket);

                    } break;
                    case DESCRIPTOR_TYPE_EVENT:
                        if (l_cur->callbacks.event_callback){
                            void * l_event_ptr = NULL;
#if defined(DAP_EVENTS_CAPS_EVENT_PIPE_PKT_MODE)
                            if(read( l_cur->fd, &l_event_ptr,sizeof (&l_event_ptr)) == sizeof (&l_event_ptr))
                                l_cur->callbacks.event_callback(l_cur, l_event_ptr);
                            else if ( (errno != EAGAIN) && (errno != EWOULDBLOCK) )  // we use blocked socket for now but who knows...
                                log_it(L_WARNING, "Can't read packet from pipe");
#endif
                        }else
                            log_it(L_ERROR, "Socket %d with event callback fired, but callback is NULL ", l_cur->socket);
                    break;
                }

                if (l_must_read_smth){ // Socket/Descriptor read
                    if(bytes_read > 0) {
                        l_cur->buf_in_size += bytes_read;
                        //log_it(DEBUG, "Received %d bytes", bytes_read);
                        l_cur->callbacks.read_callback(l_cur, NULL); // Call callback to process read event. At the end of callback buf_in_size should be zero if everything was read well
                    }
                    else if(bytes_read < 0) {
                        if (l_errno != EAGAIN && l_errno != EWOULDBLOCK){ // Socket is blocked
                            log_it(L_ERROR, "Some error occured in recv() function: %s", strerror(errno));
                            dap_events_socket_set_readable_unsafe(l_cur, false);
                            l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                        }
                    }
                    else if(bytes_read == 0) {
                        log_it(L_INFO, "Client socket disconnected");
                        dap_events_socket_set_readable_unsafe(l_cur, false);
                        l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                    }
                }
            }

            // Socket is ready to write
            if(((events[n].events & EPOLLOUT) || (l_cur->flags & DAP_SOCK_READY_TO_WRITE))
                    && !(l_cur->flags & DAP_SOCK_SIGNAL_CLOSE)) {
                ///log_it(DEBUG, "Main loop output: %u bytes to send",sa_cur->buf_out_size);
                if(l_cur->callbacks.write_callback)
                    l_cur->callbacks.write_callback(l_cur, NULL); // Call callback to process write event

                if(l_cur->flags & DAP_SOCK_READY_TO_WRITE) {

                    static const uint32_t buf_out_zero_count_max = 20;
                    l_cur->buf_out[l_cur->buf_out_size] = 0;

                    if(!l_cur->buf_out_size) {

                        //log_it(L_WARNING, "Output: nothing to send. Why we are in write socket set?");
                        l_cur->buf_out_zero_count++;

                        if(l_cur->buf_out_zero_count > buf_out_zero_count_max) { // How many time buf_out on write event could be empty
                            log_it(L_ERROR, "Output: nothing to send %u times, remove socket from the write set",
                                    buf_out_zero_count_max);
                            dap_events_socket_set_writable_unsafe(l_cur, false);
                        }
                    }
                    else
                        l_cur->buf_out_zero_count = 0;
                }
                //for(total_sent = 0; total_sent < cur->buf_out_size;) { // If after callback there is smth to send - we do it
                int l_errno;
                if(l_cur->type == DESCRIPTOR_TYPE_SOCKET) {
                    bytes_sent = send(l_cur->socket, (char *) (l_cur->buf_out + total_sent),
                            l_cur->buf_out_size - total_sent, MSG_DONTWAIT | MSG_NOSIGNAL);
                    l_errno = errno;
                }else if(l_cur->type == DESCRIPTOR_TYPE_FILE) {
                    bytes_sent = write(l_cur->socket, (char *) (l_cur->buf_out + total_sent),
                            l_cur->buf_out_size - total_sent);
                    l_errno = errno;
                }

                if(bytes_sent < 0) {
                    if (l_errno != EAGAIN && l_errno != EWOULDBLOCK ){ // If we have non-blocking socket
                        log_it(L_ERROR, "Some error occured in send(): %s", strerror(errno));
                        l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                        break;
                    }
                }else{
                    total_sent += bytes_sent;
                    //log_it(L_DEBUG, "Output: %u from %u bytes are sent ", total_sent,sa_cur->buf_out_size);
                    //}
                    //log_it(L_DEBUG,"Output: sent %u bytes",total_sent);
                    if (total_sent) {
                        pthread_mutex_lock(&l_cur->mutex);
                        l_cur->buf_out_size -= total_sent;
                        if (l_cur->buf_out_size) {
                            memmove(l_cur->buf_out, &l_cur->buf_out[total_sent], l_cur->buf_out_size);
                        } else {
                            l_cur->flags &= ~DAP_SOCK_READY_TO_WRITE;
                        }
                        pthread_mutex_unlock(&l_cur->mutex);
                    }
                }
            }

            if((l_cur->flags & DAP_SOCK_SIGNAL_CLOSE) && !l_cur->no_close) {
                // protect against double deletion
                l_cur->kill_signal = true;
                //dap_events_socket_remove_and_delete(cur, true);
                log_it(L_INFO, "Got signal to close %s, sock %u [thread %u]", l_cur->hostaddr, l_cur->socket, l_tn);
            }

            if(l_cur->kill_signal) {
                log_it(L_INFO, "Kill %u socket (processed).... [ thread %u ]", l_cur->socket, l_tn);
                dap_events_socket_delete_unsafe( l_cur, false);
            }

        }

#ifndef  NO_TIMER
        if(cur_time >= l_next_time_timeout_check) {
            s_socket_all_check_activity(l_worker, l_worker->events, cur_time);
            l_next_time_timeout_check = cur_time + s_connection_timeout / 2;
        }
#endif

    } // while

    return NULL;
}

/**
 * @brief s_new_es_callback
 * @param a_es
 * @param a_arg
 */
static void s_new_es_callback( dap_events_socket_t * a_es, void * a_arg)
{
    dap_events_socket_t * l_es_new =(dap_events_socket_t *) a_arg;
    dap_worker_t * w = a_es->worker;
    log_it(L_DEBUG, "Received event socket %p to add on worker", l_es_new);
    l_es_new->worker = w;
    if (  l_es_new->type == DESCRIPTOR_TYPE_SOCKET  ||  l_es_new->type == DESCRIPTOR_TYPE_SOCKET_LISTENING ){
        int l_cpu = w->id;
        setsockopt(l_es_new->socket , SOL_SOCKET, SO_INCOMING_CPU, &l_cpu, sizeof(l_cpu));
    }

    if ( ! l_es_new->is_initalized ){
        if (l_es_new->callbacks.new_callback)
            l_es_new->callbacks.new_callback(l_es_new, NULL);
        l_es_new->is_initalized = true;
    }

    if (l_es_new->socket>0){
        pthread_rwlock_wrlock(&w->events->sockets_rwlock);
        HASH_ADD_INT(w->events->sockets, socket, l_es_new );
        pthread_rwlock_unlock(&w->events->sockets_rwlock);

        struct epoll_event l_ev={0};
        l_ev.events = l_es_new->flags ;
        if(l_es_new->flags & DAP_SOCK_READY_TO_READ )
            l_ev.events |= EPOLLIN;
        if(l_es_new->flags & DAP_SOCK_READY_TO_WRITE )
            l_ev.events |= EPOLLOUT;
        l_ev.data.ptr = l_es_new;

        if ( epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, l_es_new->socket, &l_ev) == 1 )
            log_it(L_CRITICAL,"Can't add event socket's handler to epoll_fd");
        else{
            log_it(L_DEBUG, "Added socket %d on worker %u", l_es_new->socket, w->id);
            if (l_es_new->callbacks.worker_assign_callback)
                l_es_new->callbacks.worker_assign_callback(l_es_new, w);

        }
    }else{
        log_it(L_ERROR, "Incorrect socket %d after new callback. Dropping this handler out", l_es_new->socket);
        dap_events_socket_delete_unsafe( l_es_new, false );
    }
}

/**
 * @brief s_delete_es_callback
 * @param a_es
 * @param a_arg
 */
static void s_delete_es_callback( dap_events_socket_t * a_es, void * a_arg)
{
    ((dap_events_socket_t*)a_arg)->kill_signal = true; // Send signal to socket to kill
}

/**
 * @brief s_reassign_es_callback
 * @param a_es
 * @param a_arg
 */
static void s_reassign_es_callback( dap_events_socket_t * a_es, void * a_arg)
{
    dap_events_socket_t * l_es_reassign = ((dap_events_socket_t* ) a_arg);
    dap_events_socket_remove_from_worker_unsafe( l_es_reassign, a_es->worker );
    if (l_es_reassign->callbacks.worker_unassign_callback)
        l_es_reassign->callbacks.worker_unassign_callback(l_es_reassign, a_es->worker);

    dap_events_socket_assign_on_worker( l_es_reassign, l_es_reassign->worker );
}


/**
 * @brief dap_worker_get_min
 * @return
 */
dap_worker_t *dap_worker_get_min( )
{
    // wait for s_workers init
    while(!s_workers_init)
        dap_usleep(DAP_USEC_PER_SEC / 1000);
    dap_worker_t *l_workers = &s_workers[dap_worker_get_index_min()];
    // wait for worker start
    while(!l_workers->events)
        dap_usleep(DAP_USEC_PER_SEC / 1000);
    return l_workers;
}

/**
 * @brief dap_worker_get_index_min
 * @return
 */
uint32_t dap_worker_get_index_min( )
{
  uint32_t min = 0;
  uint32_t i;

  for( i = 1; i < s_threads_count; i++ ) {

    if ( s_workers[min].event_sockets_count > s_workers[i].event_sockets_count )
      min = i;
  }

  return min;
}

dap_worker_t * dap_worker_get_index(uint8_t a_index)
{
    return a_index < s_threads_count ? &s_workers[a_index] : NULL;
}

/**
 * @brief dap_worker_print_all
 */
void dap_worker_print_all( )
{
  uint32_t i;

  for( i = 0; i < s_threads_count; i ++ ) {

    log_it( L_INFO, "Worker: %d, count open connections: %d",
            s_workers[i].id, s_workers[i].event_sockets_count );
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

    s_workers[i].epoll_fd = epoll_create( DAP_MAX_EPOLL_EVENTS );
    if ( (intptr_t)s_workers[i].epoll_fd == -1 ) {
      log_it(L_CRITICAL, "Error create epoll fd");
      return -1;
    }

    //s_workers[i].event_to_kill_count = 0;
    s_workers[i].event_sockets_count = 0;
    s_workers[i].id = i;
    s_workers[i].events = a_events;

    pthread_mutex_init( &s_workers[i].locker_on_count, NULL );
    pthread_create( &s_threads[i].tid, NULL, s_thread_worker_function, &s_workers[i] );
  }

  return 0;
}

void dap_events_stop()
{
  bEventsAreActive = false;
}

/**
 * @brief dap_events_wait
 * @param sh
 * @return
 */
int dap_events_wait( dap_events_t *sh )
{
  (void) sh;

  for( uint32_t i = 0; i < s_threads_count; i ++ ) {
    void *ret;
    pthread_join( s_threads[i].tid, &ret );
  }

  return 0;
}

/**
 * @brief sap_worker_add_events_socket
 * @param a_events_socket
 * @param a_worker
 */
void dap_worker_add_events_socket(dap_events_socket_t * a_events_socket, dap_worker_t * a_worker)
{
    dap_events_socket_send_event( a_worker->event_new_es, a_events_socket );
}

/**
 * @brief dap_worker_add_events_socket
 * @param a_worker
 * @param a_events_socket
 */
void dap_worker_add_events_socket_auto( dap_events_socket_t *a_es)
{
//  struct epoll_event ev = {0};
  dap_worker_t *l_worker = dap_worker_get_min( );

  a_es->worker = l_worker;
  a_es->events = a_es->worker->events;
}

/**
 * @brief dap_events__thread_wake_up
 * @param th
 */
void dap_events_thread_wake_up( dap_thread_t *th )
{
  (void) th;
 //pthread_kill(th->tid,SIGUSR1);
}
