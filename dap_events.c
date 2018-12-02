/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/epoll.h>

#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <signal.h>



#if 1
#include <sys/timerfd.h>
#elif defined(DAP_OS_ANDROID)
#define NO_POSIX_SHED
#define NO_TIMER
#endif

#include <utlist.h>

#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>

#include "dap_common.h"
#include "dap_events.h"


typedef struct open_connection_info {
    dap_events_socket_t *es;
    struct open_connection_info *next;
} dap_events_socket_info_t;

dap_events_socket_info_t **s_dap_events_sockets;
static uint8_t s_threads_count = 1;
static size_t s_connection_timeout = 600;

dap_worker_t * s_workers = NULL;
dap_thread_t * s_threads = NULL;

#define LOG_TAG "dap_events"
#define MAX_EPOLL_EVENTS 255

size_t s_get_cpu_count()
{
#ifndef NO_POSIX_SHED
    cpu_set_t cs;
    CPU_ZERO(&cs);
    sched_getaffinity(0, sizeof(cs), &cs);

    size_t count = 0;
    for (int i = 0; i < 32; i++){
        if (CPU_ISSET(i, &cs))
        count++;
    }
    return count;
#else
    return 1;
#endif
}
/**
 * @brief sa_server_init Init server module
 * @arg a_threads_count  number of events processor workers in parallel threads
 * @return Zero if ok others if no
 */
int dap_events_init(size_t a_threads_count,size_t conn_timeout)
{
    s_threads_count = a_threads_count?a_threads_count: s_get_cpu_count();

    if(conn_timeout)s_connection_timeout=conn_timeout;

    s_workers = (dap_worker_t *) calloc(1,sizeof(dap_worker_t)*s_threads_count );
    s_threads = (dap_thread_t *) calloc(1,sizeof(dap_thread_t)*s_threads_count );

    if(dap_events_socket_init() != 0 )
    {
        log_it(L_CRITICAL, "Can't init client submodule");
        return -1;
    }

    s_dap_events_sockets = malloc(sizeof(dap_events_socket_info_t *) * s_threads_count );
    for(int i = 0; i < s_threads_count; i++)
        s_dap_events_sockets[i] = NULL; // i == index == thread number

 //   *open_connection_info = malloc(sizeof(open_connection_info) * my_config.threads_cnt);
    log_it(L_NOTICE,"Initialized socket server module");
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

/**
 * @brief sa_server_deinit Deinit server module
 */
void dap_events_deinit()
{
    dap_events_socket_deinit();
}



/**
 * @brief server_new Creates new empty instance of server_t
 * @return New instance
 */
dap_events_t * dap_events_new()
{
    dap_events_t* ret=(dap_events_t*) calloc(1,sizeof(dap_events_t));
    pthread_rwlock_init(&ret->sockets_rwlock,NULL);
    pthread_rwlock_init(&ret->servers_rwlock,NULL);

    return ret;
}

/**
 * @brief server_delete Delete event processor instance
 * @param sh Pointer to the server instance
 */
void dap_events_delete(dap_events_t * a_events)
{
    dap_events_socket_t * cur, * tmp;

    if (a_events)
    {
        HASH_ITER(hh,a_events->sockets,cur,tmp)
            dap_events_socket_delete(cur,false);

        if (a_events->_inheritor)
            free(a_events->_inheritor);
        pthread_rwlock_destroy(&a_events->sockets_rwlock);
        pthread_rwlock_destroy(&a_events->servers_rwlock);
        free(a_events);
    }
}

/**
 * @brief dap_events_socket_info_remove
 * @param cl
 * @param n_thread
 * @return
 */
static bool dap_events_socket_info_remove(dap_events_socket_t* cl, uint8_t n_thread)
{
    if(  n_thread >= s_threads_count ){
        log_it(L_WARNING, "Number thread %u not exists. remove client from list error", n_thread);
        return false;
    }
    dap_events_socket_info_t *el, *tmp;

    LL_FOREACH_SAFE(s_dap_events_sockets[n_thread], el, tmp)
    {
        if( el->es == cl )
        {
            LL_DELETE(s_dap_events_sockets[n_thread], el);
            log_it(L_DEBUG, "Removed event socket from the thread's list");
            return true;
        }
    }

    log_it(L_WARNING, "Try remove client from list but not find."
                    " Thread: %d client socket %d", n_thread, cl->socket);
    return false;
}

/**
 * @brief s_socket_info_all_check_activity
 * @param n_thread
 * @param sh
 */
static void s_socket_info_all_check_activity(uint8_t n_thread, dap_events_t *sh)
{
//    log_it(L_INFO, "========================================================= Socket check");
//    return; /// TODO debug and make thats shit working, bitch!
    dap_events_socket_info_t *ei;
    LL_FOREACH(s_dap_events_sockets[n_thread], ei){
        if( ei->es->is_pingable ){
            if(( time(NULL) - ei->es->last_ping_request ) > (time_t) s_connection_timeout ){ // conn timeout
                log_it(L_INFO, "Connection on socket %d close by timeout", ei->es->socket);

                dap_events_socket_t * cur = dap_events_socket_find(ei->es->socket, sh);
                if ( cur != NULL ){
                    dap_events_socket_remove_and_delete( cur );
                } else {
                    log_it(L_ERROR, "Trying close socket but not find on client hash!");
                    close(ei->es->socket);
                }
            } else if(( time(NULL) - ei->es->last_ping_request ) > (time_t) s_connection_timeout/3 ){
                log_it(L_INFO, "Connection on socket %d last chance to remain alive", ei->es->socket);

            }
        }
    }
}

/**
 * @brief thread_worker_function
 * @param arg
 * @return
 */
static void* thread_worker_function(void *arg)
{
    dap_worker_t* w = (dap_worker_t*) arg;
    dap_events_socket_t* cur;

#ifndef NO_POSIX_SHED
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(*(int*)arg, &mask);

    if ( pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &mask) != 0 )
    {
        log_it(L_CRITICAL, "Error pthread_setaffinity_np() You really have %d or more core in CPU?", *(int*)arg);
        abort();
    }
#endif

    log_it(L_INFO, "Worker %d started, epoll fd %d", w->number_thread, w->epoll_fd);
    struct epoll_event ev, events[MAX_EPOLL_EVENTS];
    memzero(&ev,sizeof(ev));
    memzero(&events,sizeof(events));
#ifndef NO_TIMER
    int timerfd;
    if ((timerfd = timerfd_create(CLOCK_MONOTONIC, 0)) < 0)
    {
        log_it(L_CRITICAL, "Failed to create timer");
        abort();
    }
#endif

    struct itimerspec timerValue;
    memzero(&timerValue, sizeof(timerValue));

    timerValue.it_value.tv_sec = 10;
    timerValue.it_value.tv_nsec = 0;
    timerValue.it_interval.tv_sec = s_connection_timeout / 2;
    timerValue.it_interval.tv_nsec = 0;


#ifndef NO_TIMER
    ev.events = EPOLLIN;
    ev.data.fd = timerfd;
    epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, timerfd, &ev);

    if (timerfd_settime(timerfd, 0, &timerValue, NULL) < 0) {
        log_it(L_CRITICAL, "Could not start timer");
        abort();
    }
#endif

    size_t total_sent; int bytes_sent;
    while(1) {
        int selected_sockets = epoll_wait(w->epoll_fd, events, MAX_EPOLL_EVENTS, -1);
    //    log_it(INFO, "Epoll pwait trigered worker %d", w->number_worker);
        for(int n = 0; n < selected_sockets; n++) {
#ifndef  NO_TIMER
            if (events[n].data.fd == timerfd) {
                static uint64_t val;
                /* if we not reading data from socket, he triggered again */
                read(events[n].data.fd, &val, 8);
                s_socket_info_all_check_activity(w->number_thread, w->events);
            } else
#endif
            if (  ( cur = dap_events_socket_find(events[n].data.fd, w->events) ) != NULL  ) {
                if( events[n].events & EPOLLERR ) {
                    log_it(L_ERROR,"Socket error: %s",strerror(errno));
                    cur->signal_close=true;
                    cur->callbacks->error_callback(cur,NULL); // Call callback to process error event
                } else {
                    if( events[n].events & EPOLLIN ) {
                        //log_it(DEBUG,"Comes connection in active read set");
                        if(cur->buf_in_size == sizeof(cur->buf_in))
                        {
                            log_it(L_WARNING, "Buffer is full when there is smth to read. Its dropped!");
                            cur->buf_in_size=0;
                        }

                        int bytes_read = recv(cur->socket,
                                              cur->buf_in + cur->buf_in_size,
                                              sizeof(cur->buf_in)-cur->buf_in_size, 0);

                        if(bytes_read > 0) {
                            cur->buf_in_size += bytes_read;
                            //log_it(DEBUG, "Received %d bytes", bytes_read);
                            cur->callbacks->read_callback(cur, NULL); // Call callback to process read event. At the end of callback buf_in_size should be zero if everything was read well

                        } else if(bytes_read < 0) {
                            log_it(L_ERROR,"Some error occured in recv() function: %s",strerror(errno));
                            cur->signal_close = true;
                        } else if (bytes_read == 0) {
                            log_it(L_INFO, "Client socket disconnected");
                            cur->signal_close = true;
                        }
                    }

                    // Socket is ready to write
                    if( ( events[n].events & EPOLLOUT  ||  cur->_ready_to_write  )
                            &&  ( !cur->signal_close )  ) {
                        ///log_it(DEBUG, "Main loop output: %u bytes to send",sa_cur->buf_out_size);
                        cur->callbacks->write_callback(cur, NULL); // Call callback to process write event

                        if(cur->_ready_to_write)
                        {
                            cur->buf_out[cur->buf_out_size]='\0';
                            static const uint32_t buf_out_zero_count_max = 20;
                            if(cur->buf_out_size == 0)
                            {
                                log_it(L_WARNING, "Output: nothing to send. Why we are in write socket set?");
                                cur->buf_out_zero_count++;
                                if(cur->buf_out_zero_count > buf_out_zero_count_max) // How many time buf_out on write event could be empty
                                {
                                    log_it(L_ERROR, "Output: nothing to send %u times, remove socket from the write set",buf_out_zero_count_max);
                                    dap_events_socket_set_writable(cur,false);
                                }
                            }
                            else
                                cur->buf_out_zero_count=0;
                        }

                        for(total_sent = 0; total_sent < cur->buf_out_size;)
                        { // If after callback there is smth to send - we do it
                            bytes_sent = send(cur->socket,
                                                  cur->buf_out + total_sent,
                                                  cur->buf_out_size - total_sent,
                                                  MSG_DONTWAIT | MSG_NOSIGNAL );
                            if(bytes_sent < 0)
                            {
                                log_it(L_ERROR,"Some error occured in send() function");
                                break;
                            }
                            total_sent+= bytes_sent;
                            //log_it(L_DEBUG, "Output: %u from %u bytes are sent ", total_sent,sa_cur->buf_out_size);
                        }

                        //log_it(L_DEBUG,"Output: sent %u bytes",total_sent);
                        cur->buf_out_size = 0;
                    }
                }

                if(cur->signal_close)
                {
                    log_it(L_INFO, "Got signal to close from the client %s", cur->hostaddr);
                    dap_events_socket_remove_and_delete(cur);
                }
            }  else {
                log_it(L_ERROR,"Socket %d is not present in epoll set", events[n].data.fd);
                ev.events = EPOLLIN | EPOLLOUT | EPOLLERR;
                ev.data.fd=events[n].data.fd;

                if (epoll_ctl(w->epoll_fd, EPOLL_CTL_DEL, events[n].data.fd, &ev) == -1)
                    log_it(L_ERROR,"Can't remove not presented socket from the epoll_fd");
            }
        }
    }
    return NULL;
}

/**
 * @brief dap_worker_get_min
 * @return
 */
dap_worker_t * dap_worker_get_min()
{
    return &s_workers[dap_worker_get_index_min()];
}

/**
 * @brief dap_worker_get_index_min
 * @return
 */
uint8_t dap_worker_get_index_min()
{
    uint8_t min = 0;
    uint8_t i;
    for(i = 1; i < s_threads_count; i++)
    {
        if ( s_workers[min].event_sockets_count > s_workers[i].event_sockets_count )
            min = i;
    }

    return min;
}

/**
 * @brief dap_worker_print_all
 */
void dap_worker_print_all()
{
    uint8_t i;
    for(i = 0; i < s_threads_count; i++)
    {
        log_it(L_INFO, "Worker: %d, count open connections: %d",
              s_workers[i].number_thread, s_workers[i].event_sockets_count);
    }
}

/**
 * @brief sa_server_loop Main server loop
 * @param sh Server instance
 * @return Zero if ok others if not
 */
int dap_events_start(dap_events_t * a_events)
{
    int i;
    for(i = 0; i < s_threads_count; i++)
    {
        if ( (s_workers[i].epoll_fd = epoll_create(MAX_EPOLL_EVENTS)) == -1 )
        {
            log_it(L_CRITICAL, "Error create epoll fd");
            return -1;
        }
        s_workers[i].event_sockets_count = 0;
        s_workers[i].number_thread = i;
        s_workers[i].events = a_events;
        pthread_mutex_init(&s_workers[i].locker_on_count, NULL);
        pthread_create(&s_threads[i].tid, NULL, thread_worker_function, &s_workers[i]);
    }

    return 0;
}

/**
 * @brief dap_events_wait
 * @param sh
 * @return
 */
int dap_events_wait(dap_events_t * sh)
{
    (void) sh;
    int i;
    for(i = 0; i < s_threads_count; i++){
        void * ret;
        pthread_join(s_threads[i].tid,&ret);
    }
   return 0;
}



/**
 * @brief dap_worker_add_events_socket
 * @param a_worker
 * @param a_events_socket
 */
void dap_worker_add_events_socket(dap_events_socket_t * a_events_socket)
{
    struct epoll_event ev = {0};
    dap_worker_t *l_worker =dap_worker_get_min();

    ev.events = EPOLLIN | EPOLLERR | EPOLLOUT;
    ev.data.fd = a_events_socket->socket;


    pthread_mutex_lock(&l_worker->locker_on_count);
    l_worker->event_sockets_count++;
    pthread_mutex_unlock(&l_worker->locker_on_count);

    dap_events_socket_info_t * l_es_info = DAP_NEW_Z(dap_events_socket_info_t);
    l_es_info->es = a_events_socket;
    a_events_socket->dap_worker = l_worker;
    LL_APPEND(s_dap_events_sockets[l_worker->number_thread], l_es_info);

    if ( epoll_ctl(l_worker->epoll_fd, EPOLL_CTL_ADD, a_events_socket->socket, &ev) == 1 )
        log_it(L_CRITICAL,"Can't add event socket's handler to epoll_fd");

}

/**
 * @brief dap_events_socket_delete
 * @param a_es
 */
void dap_events_socket_remove_and_delete(dap_events_socket_t* a_es)
{

    struct epoll_event ev={0};
    ev.events = EPOLLIN | EPOLLOUT | EPOLLERR;
    ev.data.fd=a_es->socket;

    if (epoll_ctl(a_es->dap_worker->epoll_fd, EPOLL_CTL_DEL, a_es->socket, &ev) == -1)
        log_it(L_ERROR,"Can't remove event socket's handler from the epoll_fd");
    else
        log_it(L_DEBUG,"Removed epoll's event from dap_worker #%u",a_es->dap_worker->number_thread);

    pthread_mutex_lock(&a_es->dap_worker->locker_on_count);
    a_es->dap_worker->event_sockets_count--;
    pthread_mutex_unlock(&a_es->dap_worker->locker_on_count);

    dap_events_socket_info_remove(a_es, a_es->dap_worker->number_thread);
    dap_events_socket_delete(a_es,true);

}

/**
 * @brief dap_events__thread_wake_up
 * @param th
 */
void dap_events_thread_wake_up(dap_thread_t * th)
{
    (void) th;

   //pthread_kill(th->tid,SIGUSR1);
}
