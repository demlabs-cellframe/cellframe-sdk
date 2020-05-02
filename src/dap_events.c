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

#define DAP_MAX_EPOLL_EVENTS    8192

//typedef struct open_connection_info_s {
//    dap_events_socket_t *es;
//    struct open_connection_info *prev;
//    struct open_connection_info *next;
//} dap_events_socket_info_t;

//dap_events_socket_info_t **s_dap_events_sockets;

static uint32_t s_threads_count = 1;
static size_t   s_connection_timeout = 6000;
static struct epoll_event *g_epoll_events = NULL;

bool s_workers_init = false;
dap_worker_t *s_workers = NULL;
dap_thread_t *s_threads = NULL;

#define LOG_TAG "dap_events"

uint32_t s_get_cpu_count( )
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
  s_threads_count = a_threads_count ? a_threads_count : s_get_cpu_count( );

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
      dap_events_socket_delete( cur, true );
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
static void s_socket_all_check_activity( dap_worker_t *dap_worker, dap_events_t *d_ev, time_t cur_time )
{
  dap_events_socket_t *a_es, *tmp;

  pthread_mutex_lock( &dap_worker->locker_on_count );
  DL_FOREACH_SAFE( d_ev->dlsockets, a_es, tmp ) {

    if ( !a_es->kill_signal && cur_time >= a_es->last_time_active + s_connection_timeout && !a_es->no_close ) {

      log_it( L_INFO, "Socket %u timeout, closing...", a_es->socket );
      if (a_es->callbacks->error_callback) {
          a_es->callbacks->error_callback(a_es, (void *)ETIMEDOUT);
      }

      if ( epoll_ctl( dap_worker->epoll_fd, EPOLL_CTL_DEL, a_es->socket, &a_es->ev) == -1 )
        log_it( L_ERROR,"Can't remove event socket's handler from the epoll_fd" );
      else
        log_it( L_DEBUG,"Removed epoll's event from dap_worker #%u", dap_worker->number_thread );

      dap_worker->event_sockets_count --;
      DL_DELETE( d_ev->dlsockets, a_es );
      dap_events_socket_delete( a_es, true );
    }
  }
  pthread_mutex_unlock( &dap_worker->locker_on_count );

}

/**
 * @brief thread_worker_function
 * @param arg
 * @return
 */
static void *thread_worker_function(void *arg)
{
    dap_events_socket_t *cur;
    dap_worker_t *w = (dap_worker_t *) arg;
    time_t next_time_timeout_check = time( NULL) + s_connection_timeout / 2;
    uint32_t tn = w->number_thread;

#ifndef _WIN32
#ifndef NO_POSIX_SHED
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(tn, &mask);

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

    log_it(L_INFO, "Worker %d started, epoll fd %d", w->number_thread, w->epoll_fd);

    struct epoll_event *events = &g_epoll_events[ DAP_MAX_EPOLL_EVENTS * tn];

//  memset( &ev, 0, sizeof(ev) );
//  memset( &events, 0, sizeof(events) );

    size_t total_sent;
    int bytes_sent;

    while(1) {

        int selected_sockets = epoll_wait(w->epoll_fd, events, DAP_MAX_EPOLL_EVENTS, 1000);

        if(selected_sockets == -1) {
            if( errno == EINTR)
                continue;
            break;
        }

        time_t cur_time = time( NULL);
        for(int32_t n = 0; n < selected_sockets; n++) {

            cur = (dap_events_socket_t *) events[n].data.ptr;

            if(!cur) {

                log_it(L_ERROR, "dap_events_socket NULL");
                continue;
            }
            //log_it(L_DEBUG, "Worker=%d fd=%d socket=%d event=0x%x(%d)", w->number_thread, w->epoll_fd,cur->socket, events[n].events,events[n].events);
            int l_sock_err, l_sock_err_size;
            //connection already closed (EPOLLHUP - shutdown has been made in both directions)
            if(events[n].events & EPOLLHUP) { // && events[n].events & EPOLLERR) {
                getsockopt(cur->socket, SOL_SOCKET, SO_ERROR, (void *)&l_sock_err, (socklen_t *)&l_sock_err_size);
                //if(!(events[n].events & EPOLLIN))
                //cur->no_close = false;
                if (l_sock_err) {
                    cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                    log_it(L_DEBUG, "Socket shutdown (EPOLLHUP): %s", strerror(l_sock_err));
                    if(!(events[n].events & EPOLLERR))
                        cur->callbacks->error_callback(cur, NULL); // Call callback to process error event
                }
            }

            if(events[n].events & EPOLLERR) {
                getsockopt(cur->socket, SOL_SOCKET, SO_ERROR, (void *)&l_sock_err, (socklen_t *)&l_sock_err_size);
                log_it(L_ERROR, "Socket error: %s", strerror(l_sock_err));
                cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                cur->callbacks->error_callback(cur, NULL); // Call callback to process error event
            }

            cur->last_time_active = cur_time;

            if(events[n].events & EPOLLIN) {

                //log_it(DEBUG,"Comes connection in active read set");
                if(cur->buf_in_size == sizeof(cur->buf_in)) {
                    log_it(L_WARNING, "Buffer is full when there is smth to read. Its dropped!");
                    cur->buf_in_size = 0;
                }

                int32_t bytes_read = 0;
                if(cur->type == DESCRIPTOR_TYPE_SOCKET) {
                    bytes_read = recv(cur->socket, (char *) (cur->buf_in + cur->buf_in_size),
                            sizeof(cur->buf_in) - cur->buf_in_size, 0);
                }else if(cur->type = DESCRIPTOR_TYPE_FILE) {
                    bytes_read = read(cur->socket, (char *) (cur->buf_in + cur->buf_in_size),
                            sizeof(cur->buf_in) - cur->buf_in_size);
                }

                if(bytes_read > 0) {
                    cur->buf_in_size += bytes_read;
                    //log_it(DEBUG, "Received %d bytes", bytes_read);
                    cur->callbacks->read_callback(cur, NULL); // Call callback to process read event. At the end of callback buf_in_size should be zero if everything was read well
                }
                else if(bytes_read < 0) {
                    log_it(L_ERROR, "Some error occured in recv() function: %s", strerror(errno));
                    dap_events_socket_set_readable(cur, false);
                    cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                }
                else if(bytes_read == 0) {
                    log_it(L_INFO, "Client socket disconnected");
                    dap_events_socket_set_readable(cur, false);
                    cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                }
            }

            // Socket is ready to write
            if(((events[n].events & EPOLLOUT) || (cur->flags & DAP_SOCK_READY_TO_WRITE))
                    && !(cur->flags & DAP_SOCK_SIGNAL_CLOSE)) {
                ///log_it(DEBUG, "Main loop output: %u bytes to send",sa_cur->buf_out_size);
                cur->callbacks->write_callback(cur, NULL); // Call callback to process write event

                if(cur->flags & DAP_SOCK_READY_TO_WRITE) {

                    static const uint32_t buf_out_zero_count_max = 20;
                    cur->buf_out[cur->buf_out_size] = 0;

                    if(!cur->buf_out_size) {

                        //log_it(L_WARNING, "Output: nothing to send. Why we are in write socket set?");
                        cur->buf_out_zero_count++;

                        if(cur->buf_out_zero_count > buf_out_zero_count_max) { // How many time buf_out on write event could be empty
                            log_it(L_ERROR, "Output: nothing to send %u times, remove socket from the write set",
                                    buf_out_zero_count_max);
                            dap_events_socket_set_writable(cur, false);
                        }
                    }
                    else
                        cur->buf_out_zero_count = 0;
                }
                for(total_sent = 0; total_sent < cur->buf_out_size;) { // If after callback there is smth to send - we do it
                    if(cur->type == DESCRIPTOR_TYPE_SOCKET) {
                        bytes_sent = send(cur->socket, (char *) (cur->buf_out + total_sent),
                                cur->buf_out_size - total_sent, MSG_DONTWAIT | MSG_NOSIGNAL);
                    }else if(cur->type == DESCRIPTOR_TYPE_FILE) {
                        bytes_sent = write(cur->socket, (char *) (cur->buf_out + total_sent),
                                cur->buf_out_size - total_sent);
                    }

                    if(bytes_sent < 0) {
                        log_it(L_ERROR, "Some error occured in send(): %s", strerror(errno));
                        cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                        break;
                    }
                    total_sent += bytes_sent;
                    //log_it(L_DEBUG, "Output: %u from %u bytes are sent ", total_sent,sa_cur->buf_out_size);
                }
                //log_it(L_DEBUG,"Output: sent %u bytes",total_sent);
                pthread_mutex_lock(&cur->write_hold);
                cur->buf_out_size -= total_sent;
                if (cur->buf_out_size) {
                    memcpy(cur->buf_out, &cur->buf_out[total_sent], cur->buf_out_size);
                } else {
                    cur->flags &= ~DAP_SOCK_READY_TO_WRITE;
                }
                pthread_mutex_unlock(&cur->write_hold);
            }

            pthread_mutex_lock(&w->locker_on_count);

            if((cur->flags & DAP_SOCK_SIGNAL_CLOSE) && !cur->no_close) {
                // protect against double deletion
                cur->kill_signal = true;
                //dap_events_socket_remove_and_delete(cur, true);
                log_it(L_INFO, "Got signal to close %s, sock %u [thread %u]", cur->hostaddr, cur->socket, tn);
            }

            if(cur->kill_signal) {
                log_it(L_INFO, "Kill %u socket (processed).... [ thread %u ]", cur->socket, tn);
                dap_events_socket_remove(cur);
                pthread_mutex_unlock(&w->locker_on_count);
                dap_events_socket_delete( cur, true);
            }
            else
                pthread_mutex_unlock(&w->locker_on_count);

            /*
            if(!w->event_to_kill_count) {

             pthread_mutex_unlock(&w->locker_on_count);
             continue;

             do {

//      if ( cur->no_close ) {
//        cur = cur->knext;
//        continue;
//      }
                tmp = cur_del->knext;

                // delete only current events_socket because others may be active in the other workers
                //if(cur_del == cur)
                if(cur->kill_signal) {
                    log_it(L_INFO, "Kill %u socket (processed).... [ thread %u ]", cur_del->socket, tn);
                    DL_LIST_REMOVE_NODE(w->events->to_kill_sockets, cur, kprev, knext, w->event_to_kill_count);
                    dap_events_socket_remove_and_delete(cur_del, true);
                }
                cur_del = tmp;

            } while(cur_del);

            log_it(L_INFO, "[ Thread %u ] coneections: %u, to kill: %u", tn, w->event_sockets_count,
                    w->event_to_kill_count);

            pthread_mutex_unlock(&w->locker_on_count);
            */
        } // for

#ifndef  NO_TIMER
        if(cur_time >= next_time_timeout_check) {
            s_socket_all_check_activity(w, w->events, cur_time);
            next_time_timeout_check = cur_time + s_connection_timeout / 2;
        }
#endif

    } // while

    return NULL;
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

/**
 * @brief dap_worker_print_all
 */
void dap_worker_print_all( )
{
  uint32_t i;

  for( i = 0; i < s_threads_count; i ++ ) {

    log_it( L_INFO, "Worker: %d, count open connections: %d",
            s_workers[i].number_thread, s_workers[i].event_sockets_count );
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
    s_workers[i].number_thread = i;
    s_workers[i].events = a_events;

    pthread_mutex_init( &s_workers[i].locker_on_count, NULL );
    pthread_create( &s_threads[i].tid, NULL, thread_worker_function, &s_workers[i] );
  }

  return 0;
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
 * @brief dap_worker_add_events_socket
 * @param a_worker
 * @param a_events_socket
 */
void dap_worker_add_events_socket( dap_events_socket_t *a_es)
{
//  struct epoll_event ev = {0};
  dap_worker_t *l_worker = dap_worker_get_min( );

  a_es->dap_worker = l_worker;
  a_es->events = a_es->dap_worker->events;
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
