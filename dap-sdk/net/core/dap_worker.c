/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2017
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_worker.h"
#include "dap_events.h"

#define LOG_TAG "dap_worker"


static time_t s_connection_timeout = 20000;


static void s_socket_all_check_activity( void * a_arg);
static void s_new_es_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_delete_es_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_reassign_es_callback( dap_events_socket_t * a_es, void * a_arg);

/**
 * @brief dap_worker_init
 * @param a_threads_count
 * @param conn_timeout
 * @return
 */
int dap_worker_init( size_t a_conn_timeout )
{
    if ( a_conn_timeout )
      s_connection_timeout = a_conn_timeout;
    return 0;
}

void dap_worker_deinit( )
{
}

/**
 * @brief dap_worker_thread
 * @param arg
 * @return
 */
void *dap_worker_thread(void *arg)
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

    int l_retcode;
#ifndef __ANDROID__
    l_retcode = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &mask);
#else
  err = sched_setaffinity(pthread_self(), sizeof(cpu_set_t), &mask);
#endif
    if(l_retcode != 0)
    {
        char l_errbuf[128]={0};
        switch (l_retcode) {
            case EFAULT: strncpy(l_errbuf,"A supplied memory address was invalid.",sizeof (l_errbuf)-1); break;
            case EINVAL: strncpy(l_errbuf,"The affinity bit mask mask contains no processors that are currently physically on the system and permitted to the thread",sizeof (l_errbuf)-1); break;
            case ESRCH:  strncpy(l_errbuf,"No thread with the ID thread could be found",sizeof (l_errbuf)-1); break;
            default:     strncpy(l_errbuf,"Unknown error",sizeof (l_errbuf)-1);
        }
        log_it(L_CRITICAL, "Worker #%u: error pthread_setaffinity_np(): %s (%d)", l_errbuf , l_retcode);
        abort();
    }
#endif
#else

  if ( !SetThreadAffinityMask( GetCurrentThread(), (DWORD_PTR)(1 << tn) ) ) {
    log_it( L_CRITICAL, "Error pthread_setaffinity_np() You really have %d or more core in CPU?", tn );
    abort();
  }
  #endif

    l_worker->queue_new_es = dap_events_socket_create_type_queue( l_worker, s_new_es_callback);
    l_worker->queue_delete_es = dap_events_socket_create_type_queue( l_worker, s_new_es_callback);
    l_worker->queue_data_out = dap_events_socket_create_type_queue( l_worker, s_new_es_callback);
    l_worker->timer_check_activity = dap_timerfd_start_on_worker( l_worker,s_connection_timeout / 2,s_socket_all_check_activity,l_worker);

#ifdef DAP_EVENTS_CAPS_EPOLL
    struct epoll_event l_epoll_events[ DAP_MAX_EPOLL_EVENTS]= {{0}};
    log_it(L_INFO, "Worker #%d started with epoll fd %d and assigned to dedicated CPU unit", l_worker->id, l_worker->epoll_fd);
#else
#error "Unimplemented socket array for this platform"
#endif

    pthread_cond_broadcast(&l_worker->started_cond);
    bool s_loop_is_active = true;
    while(s_loop_is_active) {
#ifdef DAP_EVENTS_CAPS_EPOLL
        int l_selected_sockets = epoll_wait(l_worker->epoll_fd, l_epoll_events, DAP_MAX_EPOLL_EVENTS, -1);
#else
#error "Unimplemented poll wait analog for this platform"
#endif
        if(l_selected_sockets == -1) {
            if( errno == EINTR)
                continue;
            int l_errno = errno;
            char l_errbuf[128];
            strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
            log_it(L_ERROR, "Worker thread %d got errno:\"%s\" (%d)", l_worker->id, l_errbuf, l_errno);
            break;
        }

        time_t l_cur_time = time( NULL);
        for(int32_t n = 0; n < l_selected_sockets; n++) {

            l_cur = (dap_events_socket_t *) l_epoll_events[n].data.ptr;
            if(!l_cur) {
                log_it(L_ERROR, "dap_events_socket NULL");
                continue;
            }
            l_cur->last_time_active = l_cur_time;

            //log_it(L_DEBUG, "Worker=%d fd=%d socket=%d event=0x%x(%d)", l_worker->id,
             //      l_worker->epoll_fd,l_cur->socket, l_epoll_events[n].events,l_epoll_events[n].events);
            int l_sock_err = 0, l_sock_err_size = sizeof(l_sock_err);
            //connection already closed (EPOLLHUP - shutdown has been made in both directions)
            if(l_epoll_events[n].events & EPOLLHUP) { // && events[n].events & EPOLLERR) {
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

            if(l_epoll_events[n].events & EPOLLERR) {
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


            if(l_epoll_events[n].events & EPOLLIN) {

                //log_it(DEBUG,"Comes connection in active read set");
                if(l_cur->buf_in_size == sizeof(l_cur->buf_in)) {
                    log_it(L_WARNING, "Buffer is full when there is smth to read. Its dropped!");
                    l_cur->buf_in_size = 0;
                }

                int32_t l_bytes_read = 0;
                int l_errno=0;
                bool l_must_read_smth = false;
                switch (l_cur->type) {
                    case DESCRIPTOR_TYPE_FILE:
                        l_must_read_smth = true;
                        l_bytes_read = read(l_cur->socket, (char *) (l_cur->buf_in + l_cur->buf_in_size),
                                sizeof(l_cur->buf_in) - l_cur->buf_in_size);
                        l_errno = errno;
                    break;
                    case DESCRIPTOR_TYPE_SOCKET:
                        l_must_read_smth = true;
                        l_bytes_read = recv(l_cur->fd, (char *) (l_cur->buf_in + l_cur->buf_in_size),
                                sizeof(l_cur->buf_in) - l_cur->buf_in_size, 0);
                        l_errno = errno;
                    break;
                    case DESCRIPTOR_TYPE_SOCKET_LISTENING:
                        // Accept connection
                        if ( l_cur->callbacks.accept_callback){
                            struct sockaddr l_remote_addr;
                            socklen_t l_remote_addr_size= sizeof (l_remote_addr);
                            int l_remote_socket= accept(l_cur->socket ,&l_remote_addr,&l_remote_addr_size);
                            int l_errno = errno;
                            if ( l_remote_socket == -1 ){
                                if( l_errno == EAGAIN || l_errno == EWOULDBLOCK){// Everything is good, we'll receive ACCEPT on next poll
                                    continue;
                                }else{
                                    char l_errbuf[128];
                                    strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                                    log_it(L_WARNING,"accept() on socket %d error:\"%s\"(%d)",l_cur->socket, l_errbuf,l_errno);
                                }
                            }

                            l_cur->callbacks.accept_callback(l_cur,l_remote_socket,&l_remote_addr);
                        }else
                            log_it(L_ERROR,"No accept_callback on listening socket");
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
                    case DESCRIPTOR_TYPE_QUEUE:
                        if (l_cur->callbacks.event_callback){
                            void * l_event_ptr = NULL;
#if defined(DAP_EVENTS_CAPS_EVENT_PIPE2)
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
                    if(l_bytes_read > 0) {
                        l_cur->buf_in_size += l_bytes_read;
                        //log_it(DEBUG, "Received %d bytes", bytes_read);
                        if(l_cur->callbacks.read_callback)
                            l_cur->callbacks.read_callback(l_cur, NULL); // Call callback to process read event. At the end of callback buf_in_size should be zero if everything was read well
                        else{
                            log_it(L_WARNING, "We have incomming %u data but no read callback on socket %d, removing from read set", l_cur->socket);
                            dap_events_socket_set_readable_unsafe(l_cur,false);
                        }
                    }
                    else if(l_bytes_read < 0) {
                        if (l_errno != EAGAIN && l_errno != EWOULDBLOCK){ // Socket is blocked
                            log_it(L_ERROR, "Some error occured in recv() function: %s", strerror(errno));
                            dap_events_socket_set_readable_unsafe(l_cur, false);
                            l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                        }
                    }
                    else if(l_bytes_read == 0) {
                        log_it(L_INFO, "Client socket disconnected");
                        dap_events_socket_set_readable_unsafe(l_cur, false);
                        l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                    }
                }
            }

            // Socket is ready to write
            if(((l_epoll_events[n].events & EPOLLOUT) || (l_cur->flags & DAP_SOCK_READY_TO_WRITE))
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
                size_t l_bytes_sent =0;
                int l_errno;
                if(l_cur->type == DESCRIPTOR_TYPE_SOCKET) {
                    l_bytes_sent = send(l_cur->socket, l_cur->buf_out,
                            l_cur->buf_out_size, MSG_DONTWAIT | MSG_NOSIGNAL);
                    l_errno = errno;
                }else if(l_cur->type == DESCRIPTOR_TYPE_FILE) {
                    l_bytes_sent = write(l_cur->socket, (char *) (l_cur->buf_out + l_bytes_sent),
                            l_cur->buf_out_size );
                    l_errno = errno;
                }

                if(l_bytes_sent < 0) {
                    if (l_errno != EAGAIN && l_errno != EWOULDBLOCK ){ // If we have non-blocking socket
                        log_it(L_ERROR, "Some error occured in send(): %s", strerror(errno));
                        l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                        break;
                    }
                }else{
                    //log_it(L_DEBUG, "Output: %u from %u bytes are sent ", l_bytes_sent,l_cur->buf_out_size);
                    //}
                    //log_it(L_DEBUG,"Output: sent %u bytes",total_sent);
                    if (l_bytes_sent) {
                        l_cur->buf_out_size -= l_bytes_sent;
                        //log_it(L_DEBUG,"Output: left %u bytes in buffer",l_cur->buf_out_size);
                        if (l_cur->buf_out_size) {
                            memmove(l_cur->buf_out, &l_cur->buf_out[l_bytes_sent], l_cur->buf_out_size);
                        } else {
                            l_cur->flags &= ~DAP_SOCK_READY_TO_WRITE;
                        }
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
    //log_it(L_DEBUG, "Received event socket %p to add on worker", l_es_new);
    l_es_new->worker = w;
    if (  l_es_new->type == DESCRIPTOR_TYPE_SOCKET  ||  l_es_new->type == DESCRIPTOR_TYPE_SOCKET_LISTENING ){
        int l_cpu = w->id;
        setsockopt(l_es_new->socket , SOL_SOCKET, SO_INCOMING_CPU, &l_cpu, sizeof(l_cpu));
    }

    // We need to differ new and reassigned esockets. If its new - is_initialized is false
    if ( ! l_es_new->is_initalized ){
        if (l_es_new->callbacks.new_callback)
            l_es_new->callbacks.new_callback(l_es_new, NULL);
        l_es_new->is_initalized = true;
    }

    if (l_es_new->socket>0){
        int l_ret = -1;
#ifdef DAP_EVENTS_CAPS_EPOLL
        // Init events for EPOLL
        l_es_new->ev.events = l_es_new->ev_base_flags ;
        if(l_es_new->flags & DAP_SOCK_READY_TO_READ )
            l_es_new->ev.events |= EPOLLIN;
        if(l_es_new->flags & DAP_SOCK_READY_TO_WRITE )
            l_es_new->ev.events |= EPOLLOUT;
        l_es_new->ev.data.ptr = l_es_new;
        l_ret = epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, l_es_new->socket, &l_es_new->ev);
#else
#error "Unimplemented new esocket on worker callback for current platform"
#endif
        if (  l_ret != 0 ){
            log_it(L_CRITICAL,"Can't add event socket's handler to worker i/o poll mechanism");
        }else{
            // Add in global list
            pthread_rwlock_wrlock(&w->events->sockets_rwlock);
            HASH_ADD(hh, w->events->sockets, socket, sizeof (int), l_es_new );
            pthread_rwlock_unlock(&w->events->sockets_rwlock);
            // Add in worker
            HASH_ADD(hh_worker, w->sockets, socket, sizeof (int), l_es_new );

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
 * @brief s_socket_all_check_activity
 * @param a_arg
 */
static void s_socket_all_check_activity( void * a_arg)
{
    dap_worker_t *l_worker = (dap_worker_t*) a_arg;
    assert(l_worker);
    dap_events_socket_t *a_es, *tmp;
    char l_curtimebuf[64];
    time_t l_curtime= time(NULL);
    ctime_r(&l_curtime, l_curtimebuf);
    log_it(L_DEBUG,"Check sockets activity on worker #%u at %s", l_worker->id, l_curtimebuf);

    HASH_ITER(hh_worker, l_worker->sockets, a_es, tmp ) {
        if ( a_es->type == DESCRIPTOR_TYPE_SOCKET  ){
            if ( !a_es->kill_signal && l_curtime >=  (time_t)a_es->last_time_active + s_connection_timeout && !a_es->no_close ) {
                log_it( L_INFO, "Socket %u timeout, closing...", a_es->socket );
                if (a_es->callbacks.error_callback) {
                    a_es->callbacks.error_callback(a_es, (void *)ETIMEDOUT);
                }
                dap_events_socket_queue_remove_and_delete( a_es);
            }
        }
    }
}

/**
 * @brief sap_worker_add_events_socket
 * @param a_events_socket
 * @param a_worker
 */
void dap_worker_add_events_socket(dap_events_socket_t * a_events_socket, dap_worker_t * a_worker)
{
    dap_events_socket_queue_send( a_worker->queue_new_es, a_events_socket );
}

/**
 * @brief dap_worker_add_events_socket
 * @param a_worker
 * @param a_events_socket
 */
void dap_worker_add_events_socket_auto( dap_events_socket_t *a_es)
{
//  struct epoll_event ev = {0};
  dap_worker_t *l_worker = dap_events_worker_get_auto( );

  a_es->worker = l_worker;
  a_es->events = a_es->worker->events;
  dap_worker_add_events_socket( a_es, l_worker);
}



