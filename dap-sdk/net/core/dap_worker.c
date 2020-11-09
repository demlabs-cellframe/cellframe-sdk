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
#if ! defined (_GNU_SOURCE)
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_worker.h"
#include "dap_events.h"

#define LOG_TAG "dap_worker"

// temporary too big timout for no closing sockets opened to not keep alive peers
static time_t s_connection_timeout = 20000; // 60;    // seconds


static void s_socket_all_check_activity( void * a_arg);
static void s_queue_add_es_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_queue_delete_es_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_queue_es_reassign_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_queue_callback_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_queue_es_io_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_event_exit_callback( dap_events_socket_t * a_es, uint64_t a_flags);

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
    struct rlimit l_fdlimit;
    if (getrlimit(RLIMIT_NOFILE, &l_fdlimit))
        return -1;
    rlim_t l_oldlimit = l_fdlimit.rlim_cur;
    l_fdlimit.rlim_cur = l_fdlimit.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &l_fdlimit))
        return -2;
    log_it(L_INFO, "Set maximum opened descriptors from %d to %d", l_oldlimit, l_fdlimit.rlim_cur);
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
    //time_t l_next_time_timeout_check = time( NULL) + s_connection_timeout / 2;
    uint32_t l_tn = l_worker->id;

    dap_cpu_assign_thread_on(l_worker->id);
    struct sched_param l_shed_params;
    l_shed_params.sched_priority = 0;
    pthread_setschedparam(pthread_self(),SCHED_FIFO ,&l_shed_params);

#ifdef DAP_EVENTS_CAPS_EPOLL
    struct epoll_event l_epoll_events[ DAP_EVENTS_SOCKET_MAX]= {{0}};
    log_it(L_INFO, "Worker #%d started with epoll fd %d and assigned to dedicated CPU unit", l_worker->id, l_worker->epoll_fd);
#elif defined(DAP_EVENTS_CAPS_POLL)
    l_worker->poll_count_max = DAP_EVENTS_SOCKET_MAX;
    l_worker->poll = DAP_NEW_Z_SIZE(struct pollfd,l_worker->poll_count_max*sizeof (struct pollfd));
    l_worker->poll_esocket = DAP_NEW_Z_SIZE(dap_events_socket_t*,l_worker->poll_count_max*sizeof (dap_events_socket_t*));
#else
#error "Unimplemented socket array for this platform"
#endif


    l_worker->queue_es_new = dap_events_socket_create_type_queue_ptr_unsafe( l_worker, s_queue_add_es_callback);
    l_worker->queue_es_delete = dap_events_socket_create_type_queue_ptr_unsafe( l_worker, s_queue_delete_es_callback);
    l_worker->queue_es_io = dap_events_socket_create_type_queue_ptr_unsafe( l_worker, s_queue_es_io_callback);
    l_worker->queue_es_reassign = dap_events_socket_create_type_queue_ptr_unsafe( l_worker, s_queue_es_reassign_callback );
    l_worker->queue_callback= dap_events_socket_create_type_queue_ptr_unsafe( l_worker, s_queue_callback_callback);
    l_worker->event_exit = dap_events_socket_create_type_event_unsafe(l_worker, s_event_exit_callback );
    l_worker->timer_check_activity = dap_timerfd_start_on_worker( l_worker, s_connection_timeout * 1000 / 2,
                                                                  s_socket_all_check_activity, l_worker, true );

    pthread_setspecific(l_worker->events->pth_key_worker, l_worker);
    pthread_cond_broadcast(&l_worker->started_cond);
    bool s_loop_is_active = true;
    while(s_loop_is_active) {
#ifdef DAP_EVENTS_CAPS_EPOLL
        int l_selected_sockets = epoll_wait(l_worker->epoll_fd, l_epoll_events, DAP_EVENTS_SOCKET_MAX, -1);
        size_t l_sockets_max = l_selected_sockets;
#elif defined(DAP_EVENTS_CAPS_POLL)
        int l_selected_sockets = poll(l_worker->poll, l_worker->poll_count, -1);
        size_t l_sockets_max = l_worker->poll_count;
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
        for(size_t n = 0; n < l_sockets_max; n++) {

            bool l_flag_hup, l_flag_rdhup, l_flag_read, l_flag_write, l_flag_error;
#ifdef DAP_EVENTS_CAPS_EPOLL
            l_cur = (dap_events_socket_t *) l_epoll_events[n].data.ptr;
            l_flag_hup = l_epoll_events[n].events & EPOLLHUP;
            l_flag_rdhup = l_epoll_events[n].events & EPOLLHUP;
            l_flag_write = l_epoll_events[n].events & EPOLLOUT;
            l_flag_read = l_epoll_events[n].events & EPOLLIN;
            l_flag_error = l_epoll_events[n].events & EPOLLERR;
#elif defined ( DAP_EVENTS_CAPS_POLL)
            short l_cur_events =l_worker->poll[n].revents;
            if (!l_cur_events) // No events for this socket
                continue;
            l_flag_hup =  l_cur_events& POLLHUP;
            l_flag_rdhup = l_cur_events & POLLHUP;
            l_flag_write = l_cur_events & POLLOUT;
            l_flag_read = l_cur_events & POLLIN;
            l_flag_error = l_cur_events & POLLERR;
            l_cur = l_worker->poll_esocket[n];
            //log_it(L_DEBUG, "flags: returned events 0x%0X requested events 0x%0X",l_worker->poll[n].revents,l_worker->poll[n].events );
#else
#error "Unimplemented fetch esocket after poll"
#endif
            if(!l_cur) {
                log_it(L_ERROR, "dap_events_socket NULL");
                continue;
            }
            //            log_it(L_DEBUG, "Worker=%d fd=%d", l_worker->id, l_cur->socket);

            int l_sock_err = 0, l_sock_err_size = sizeof(l_sock_err);
            //connection already closed (EPOLLHUP - shutdown has been made in both directions)
            if( l_flag_hup) {
                switch (l_cur->type ){
                    case DESCRIPTOR_TYPE_SOCKET_LISTENING:
                    case DESCRIPTOR_TYPE_SOCKET:
                        getsockopt(l_cur->socket, SOL_SOCKET, SO_ERROR, (void *)&l_sock_err, (socklen_t *)&l_sock_err_size);
                        if (l_sock_err) {
                            dap_events_socket_set_readable_unsafe(l_cur, false);
                            dap_events_socket_set_writable_unsafe(l_cur, false);
                            l_cur->buf_out_size = 0;
                            l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_flag_error = l_flag_read = l_flag_write = false;
                            l_cur->callbacks.error_callback(l_cur, l_sock_err); // Call callback to process error event
                            log_it(L_INFO, "Socket shutdown (EPOLLHUP): %s", strerror(l_sock_err));
                        }
                    break;
                    default: log_it(L_WARNING, "Unimplemented EPOLLHUP for socket type %d", l_cur->type);
                }
            }

            if(l_flag_error) {
                switch (l_cur->type ){
                    case DESCRIPTOR_TYPE_SOCKET_LISTENING:
                    case DESCRIPTOR_TYPE_SOCKET:
                        getsockopt(l_cur->socket, SOL_SOCKET, SO_ERROR, (void *)&l_sock_err, (socklen_t *)&l_sock_err_size);
                        log_it(L_ERROR, "Socket error: %s", strerror(l_sock_err));
                    default: ;
                }
                dap_events_socket_set_readable_unsafe(l_cur, false);
                dap_events_socket_set_writable_unsafe(l_cur, false);
                l_cur->buf_out_size = 0;
                l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                l_cur->callbacks.error_callback(l_cur, l_sock_err); // Call callback to process error event
            }

            /*if (l_flag_hup) {
                log_it(L_INFO, "Client socket disconnected");
                dap_events_socket_set_readable_unsafe(l_cur, false);
                dap_events_socket_set_writable_unsafe(l_cur, false);
                l_cur->buf_out_size = 0;
                l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;

            }*/

            if(l_flag_read) {

                //log_it(L_DEBUG, "Comes connection with type %d", l_cur->type);
                if(l_cur->buf_in_size == sizeof(l_cur->buf_in)) {
                    log_it(L_WARNING, "Buffer is full when there is smth to read. Its dropped!");
                    l_cur->buf_in_size = 0;
                }

                int32_t l_bytes_read = 0;
                int l_errno=0;
                bool l_must_read_smth = false;
                switch (l_cur->type) {
                    case DESCRIPTOR_TYPE_PIPE:
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
                    case DESCRIPTOR_TYPE_SOCKET_UDP: {
                        l_must_read_smth = true;
                        socklen_t l_size = sizeof(l_cur->remote_addr);
                        l_bytes_read = recvfrom(l_cur->fd, (char *) (l_cur->buf_in + l_cur->buf_in_size),
                                                sizeof(l_cur->buf_in) - l_cur->buf_in_size, 0,
                                                (struct sockaddr *)&l_cur->remote_addr, &l_size);

                        l_errno = errno;
                    }
                    break;
                    case DESCRIPTOR_TYPE_SOCKET_LISTENING:
                        // Accept connection
                        if ( l_cur->callbacks.accept_callback){
                            struct sockaddr l_remote_addr;
                            socklen_t l_remote_addr_size= sizeof (l_remote_addr);
                            int l_remote_socket= accept(l_cur->socket ,&l_remote_addr,&l_remote_addr_size);
                            fcntl( l_remote_socket, F_SETFL, O_NONBLOCK);

                            int l_errno = errno;
                            if ( l_remote_socket == -1 ){
                                if( l_errno == EAGAIN || l_errno == EWOULDBLOCK){// Everything is good, we'll receive ACCEPT on next poll
                                    continue;
                                }else{
                                    char l_errbuf[128];
                                    strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                                    log_it(L_WARNING,"accept() on socket %d error:\"%s\"(%d)",l_cur->socket, l_errbuf,l_errno);
                                    break;
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
                        dap_events_socket_queue_proc_input_unsafe(l_cur);
                    break;
                    case DESCRIPTOR_TYPE_EVENT:
                        dap_events_socket_event_proc_input_unsafe(l_cur);
                    break;
                }

                if (l_must_read_smth){ // Socket/Descriptor read
                    if(l_bytes_read > 0) {
                        if (l_cur->type == DESCRIPTOR_TYPE_SOCKET  || l_cur->type == DESCRIPTOR_TYPE_SOCKET_UDP) {
                            l_cur->last_time_active = l_cur_time;
                        }
                        l_cur->buf_in_size += l_bytes_read;
                        //log_it(L_DEBUG, "Received %d bytes", l_bytes_read);
                        if(l_cur->callbacks.read_callback){
                            l_cur->callbacks.read_callback(l_cur, NULL); // Call callback to process read event. At the end of callback buf_in_size should be zero if everything was read well
                            if (l_cur->worker == NULL ){ // esocket was unassigned in callback, we don't need any ops with it now,
                                                         // continue to poll another esockets
                                continue;
                            }
                        }else{
                            log_it(L_WARNING, "We have incomming %u data but no read callback on socket %d, removing from read set",
                                   l_bytes_read, l_cur->socket);
                            dap_events_socket_set_readable_unsafe(l_cur,false);
                        }
                    }
                    else if(l_bytes_read < 0) {
                        if (l_errno != EAGAIN && l_errno != EWOULDBLOCK){ // Socket is blocked
                            log_it(L_ERROR, "Some error occured in recv() function: %s", strerror(errno));
                            dap_events_socket_set_readable_unsafe(l_cur, false);
                            l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_cur->buf_out_size = 0;
                        }
                    }
                    else if (  (! l_flag_rdhup || !l_flag_error ) && (!(l_cur->flags& DAP_SOCK_CONNECTING )) ) {
                        log_it(L_WARNING, "EPOLLIN triggered but nothing to read");
                        dap_events_socket_set_readable_unsafe(l_cur,false);
                    }
                }
            }

            //if (l_flag_write)
             //   log_it(L_DEBUG,"Alarmed write flag for remote %s", l_cur->remote_addr_str[0]?l_cur->remote_addr_str:"(null)");

            // If its outgoing connection
            if ( l_flag_write &&  ! l_cur->server &&  l_cur->flags& DAP_SOCK_CONNECTING &&
                 (l_cur->type == DESCRIPTOR_TYPE_SOCKET || l_cur->type == DESCRIPTOR_TYPE_SOCKET_UDP )){
                int l_error = 0;
                socklen_t l_error_len = sizeof(l_error);
                char l_error_buf[128];
                l_error_buf[0]='\0';
                getsockopt(l_cur->socket, SOL_SOCKET, SO_ERROR, &l_error, &l_error_len);
                if (l_error){
                    strerror_r(l_error, l_error_buf, sizeof (l_error_buf));
                    log_it(L_ERROR,"Connecting error with %s: \"%s\" (code %d)", l_cur->remote_addr_str[0]? l_cur->remote_addr_str: "(NULL)"
                                                                                 ,
                           l_error_buf, l_error);
                    if ( l_cur->callbacks.error_callback )
                        l_cur->callbacks.error_callback(l_cur, l_error);
                }else if(l_error == EINPROGRESS) {
                    log_it(L_DEBUG, "Connecting with %s in progress...", l_cur->remote_addr_str[0]? l_cur->remote_addr_str: "(NULL)");
                }else{
                   // log_it(L_NOTICE, "Connected with %s",l_cur->remote_addr_str[0]? l_cur->remote_addr_str: "(NULL)");
                    l_cur->flags ^= DAP_SOCK_CONNECTING;
                    if (l_cur->callbacks.connected_callback)
                        l_cur->callbacks.connected_callback(l_cur);
                    dap_events_socket_worker_poll_update_unsafe(l_cur);
                }
            }

            // Socket is ready to write and not going to close
            if(   ( l_flag_write&&(l_cur->flags & DAP_SOCK_READY_TO_WRITE) ) ||
                 (    (l_cur->flags & DAP_SOCK_READY_TO_WRITE) && !(l_cur->flags & DAP_SOCK_SIGNAL_CLOSE) ) ) {
                //log_it(L_DEBUG, "Main loop output: %u bytes to send", l_cur->buf_out_size);
                if(l_cur->callbacks.write_callback)
                    l_cur->callbacks.write_callback(l_cur, NULL); // Call callback to process write event

                if ( l_cur->worker ){ // esocket wasn't unassigned in callback, we need some other ops with it
                    if(l_cur->flags & DAP_SOCK_READY_TO_WRITE) {

                        static const uint32_t buf_out_zero_count_max = 2;
                        //l_cur->buf_out[l_cur->buf_out_size] = 0;

                        if(!l_cur->buf_out_size) {

                            //log_it(L_WARNING, "Output: nothing to send. Why we are in write socket set?");
                            l_cur->buf_out_zero_count++;

                            if(l_cur->buf_out_zero_count > buf_out_zero_count_max) { // How many time buf_out on write event could be empty
                                //log_it(L_WARNING, "Output: nothing to send %u times, remove socket from the write set",
                                //        buf_out_zero_count_max);
                                dap_events_socket_set_writable_unsafe(l_cur, false);
                            }
                        }
                        else
                            l_cur->buf_out_zero_count = 0;
                    }
                    //for(total_sent = 0; total_sent < cur->buf_out_size;) { // If after callback there is smth to send - we do it
                    ssize_t l_bytes_sent =0;
                    int l_errno;
                    switch (l_cur->type){
                        case DESCRIPTOR_TYPE_SOCKET:
                            l_bytes_sent = send(l_cur->socket, (const char *)l_cur->buf_out,
                                                l_cur->buf_out_size, MSG_DONTWAIT | MSG_NOSIGNAL);
                            l_errno = errno;
                        break;
                        case DESCRIPTOR_TYPE_SOCKET_UDP:
                            l_bytes_sent = sendto(l_cur->socket, (const char *)l_cur->buf_out,
                                                  l_cur->buf_out_size, MSG_DONTWAIT | MSG_NOSIGNAL,
                                                  (struct sockaddr *)&l_cur->remote_addr, sizeof(l_cur->remote_addr));
                            l_errno = errno;
                        break;
                        case DESCRIPTOR_TYPE_PIPE:
                        case DESCRIPTOR_TYPE_FILE:
                            l_bytes_sent = write(l_cur->socket, (char *) (l_cur->buf_out + l_bytes_sent),
                                    l_cur->buf_out_size );
                            l_errno = errno;
                        break;
                        default:
                            log_it(L_WARNING, "Socket %d is not SOCKET, PIPE or FILE but has WRITE state on. Switching it off");
                            dap_events_socket_set_writable_unsafe(l_cur,false);
                    }

                    if(l_bytes_sent < 0) {
                        if (l_errno != EAGAIN && l_errno != EWOULDBLOCK ){ // If we have non-blocking socket
                            log_it(L_ERROR, "Some error occured in send(): %s", strerror(errno));
                            l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_cur->buf_out_size = 0;
                        }
                    }else{
                        //log_it(L_DEBUG, "Output: %u from %u bytes are sent ", l_bytes_sent,l_cur->buf_out_size);
                        if (l_bytes_sent) {
                            if ( l_bytes_sent <= (ssize_t) l_cur->buf_out_size ){
                                l_cur->buf_out_size -= l_bytes_sent;
                                if (l_cur->buf_out_size ) {
                                    memmove(l_cur->buf_out, &l_cur->buf_out[l_bytes_sent], l_cur->buf_out_size);
                                }
                            }else{
                                log_it(L_ERROR, "Wrong bytes sent, %zd more then was in buffer %zd",l_bytes_sent, l_cur->buf_out_size);
                                l_cur->buf_out_size = 0;
                            }
                        }
                    }
                }
            }
            if (l_cur->buf_out_size) {
                dap_events_socket_set_writable_unsafe(l_cur,true);
            }

            if ((l_cur->flags & DAP_SOCK_SIGNAL_CLOSE) && !l_cur->no_close)
            {
                if (l_cur->buf_out_size == 0) {
                    log_it(L_INFO, "Process signal to close %s, sock %u [thread %u]", l_cur->hostaddr, l_cur->socket, l_tn);
                    dap_events_socket_remove_and_delete_unsafe( l_cur, false);
                } else if (l_cur->buf_out_size ) {
                    log_it(L_INFO, "Got signal to close %s, sock %u [thread %u] but buffer is not empty(%zd)", l_cur->hostaddr, l_cur->socket, l_tn,
                           l_cur->buf_out_size);
                }
            }

            if( l_worker->signal_exit){
                log_it(L_NOTICE,"Worker :%u finished", l_worker->id);
                return NULL;
            }
        }
#ifdef DAP_EVENTS_CAPS_POLL
      /***********************************************************/
       /* If the compress_array flag was turned on, we need       */
       /* to squeeze together the array and decrement the number  */
       /* of file descriptors. We do not need to move back the    */
       /* events and revents fields because the events will always*/
       /* be POLLIN in this case, and revents is output.          */
       /***********************************************************/
       if ( l_worker->poll_compress){
           l_worker->poll_compress = false;
           for (size_t i = 0; i < l_worker->poll_count ; i++)  {
               if ( l_worker->poll[i].fd == -1){
                   for(size_t j = i; j < l_worker->poll_count-1; j++){
                       l_worker->poll[j].fd = l_worker->poll[j+1].fd;
                       l_worker->poll_esocket[j] = l_worker->poll_esocket[j+1];
                       l_worker->poll_esocket[j]->poll_index = j;
                   }
                   i--;
                   l_worker->poll_count--;
               }
           }
       }
#endif
    } // while
    log_it(L_NOTICE,"Exiting thread #%u", l_worker->id);
    return NULL;
}

/**
 * @brief s_new_es_callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_add_es_callback( dap_events_socket_t * a_es, void * a_arg)
{
    dap_events_socket_t * l_es_new =(dap_events_socket_t *) a_arg;
    dap_worker_t * w = a_es->worker;
    //log_it(L_DEBUG, "Received event socket %p to add on worker", l_es_new);
    if(dap_events_socket_check_unsafe( w, l_es_new)){
        // Socket already present in worker, it's OK
        return;
    }

    switch( l_es_new->type){

        case DESCRIPTOR_TYPE_SOCKET_UDP:
        case DESCRIPTOR_TYPE_SOCKET:
        case DESCRIPTOR_TYPE_SOCKET_LISTENING:{
            int l_cpu = w->id;
            setsockopt(l_es_new->socket , SOL_SOCKET, SO_INCOMING_CPU, &l_cpu, sizeof(l_cpu));
        }break;
        default: {}
    }

    l_es_new->worker = w;
    l_es_new->last_time_active = time(NULL);
    // We need to differ new and reassigned esockets. If its new - is_initialized is false
    if ( ! l_es_new->is_initalized ){
        if (l_es_new->callbacks.new_callback)
            l_es_new->callbacks.new_callback(l_es_new, NULL);
        l_es_new->is_initalized = true;
    }

    if (l_es_new->socket>0){
        int l_ret = dap_worker_add_events_socket_unsafe(l_es_new,w);
        if (  l_ret != 0 ){
            log_it(L_CRITICAL,"Can't add event socket's handler to worker i/o poll mechanism with error %d", errno);
        }else{
            // Add in global list
            // Add in worker
            l_es_new->me = l_es_new;
            HASH_ADD(hh_worker, w->esockets, me, sizeof(void *), l_es_new );
            w->event_sockets_count++;
            //log_it(L_DEBUG, "Added socket %d on worker %u", l_es_new->socket, w->id);
            if (l_es_new->callbacks.worker_assign_callback)
                l_es_new->callbacks.worker_assign_callback(l_es_new, w);

        }
    }else{
        log_it(L_ERROR, "Incorrect socket %d after new callback. Dropping this handler out", l_es_new->socket);
        dap_events_socket_remove_and_delete_unsafe( l_es_new, false );
    }
}

/**
 * @brief s_delete_es_callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_delete_es_callback( dap_events_socket_t * a_es, void * a_arg)
{
    dap_events_socket_t * l_esocket = (dap_events_socket_t*) a_arg;
    if (dap_events_socket_check_unsafe(a_es->worker,l_esocket)){
        ((dap_events_socket_t*)a_arg)->flags |= DAP_SOCK_SIGNAL_CLOSE; // Send signal to socket to kill
    }else
        log_it(L_INFO, "While we were sending the delete() message, esocket %p has been disconnected", l_esocket);
}

/**
 * @brief s_reassign_es_callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_es_reassign_callback( dap_events_socket_t * a_es, void * a_arg)
{
    dap_worker_msg_reassign_t * l_msg = (dap_worker_msg_reassign_t*) a_arg;
    dap_events_socket_t * l_es_reassign = l_msg->esocket;
    if (dap_events_socket_check_unsafe(a_es->worker,l_es_reassign)){
        if( l_es_reassign->was_reassigned && l_es_reassign->flags & DAP_SOCK_REASSIGN_ONCE) {
            log_it(L_INFO, "Reassgment request with DAP_SOCK_REASSIGN_ONCE allowed only once, declined reassigment from %u to %u",
                   l_es_reassign->worker->id, l_msg->worker_new->id);

        }else{
            dap_events_socket_reassign_between_workers_unsafe(l_es_reassign,l_msg->worker_new);
        }
    }else{
        log_it(L_INFO, "While we were sending the reassign message, esocket %p has been disconnected", l_msg->esocket);
    }
    DAP_DELETE(l_msg);
}

/**
 * @brief s_queue_callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_callback_callback( dap_events_socket_t * a_es, void * a_arg)
{
    dap_worker_msg_callback_t * l_msg = (dap_worker_msg_callback_t *) a_arg;
    assert(l_msg);
    assert(l_msg->callback);
    l_msg->callback(a_es->worker, l_msg->arg);
    DAP_DELETE(l_msg);
}

/**
 * @brief s_event_exit_callback
 * @param a_es
 * @param a_flags
 */
static void s_event_exit_callback( dap_events_socket_t * a_es, uint64_t a_flags)
{
    (void) a_flags;
    a_es->worker->signal_exit = true;
    log_it(L_NOTICE, "Worker :%u signaled to exit", a_es->worker->id);
}

/**
 * @brief s_pipe_data_out_read_callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_es_io_callback( dap_events_socket_t * a_es, void * a_arg)
{
    dap_worker_msg_io_t * l_msg = a_arg;

    // Check if it was removed from the list
    dap_events_socket_t *l_msg_es = NULL;
    HASH_FIND(hh_worker, a_es->worker->esockets, &l_msg->esocket , sizeof (void*), l_msg_es );
    if ( l_msg_es == NULL){
        log_it(L_INFO, "We got i/o message for client thats now not in list. Lost %u data", l_msg->data_size);
        DAP_DELETE(l_msg);
        return;
    }
    if (l_msg->flags_set & DAP_SOCK_CONNECTING)
        if (!  (l_msg_es->flags & DAP_SOCK_CONNECTING) ){
            l_msg_es->flags |= DAP_SOCK_CONNECTING;
            dap_events_socket_worker_poll_update_unsafe(l_msg_es);
        }

    if (l_msg->flags_set & DAP_SOCK_CONNECTING)
        if (!  (l_msg_es->flags & DAP_SOCK_CONNECTING) ){
            l_msg_es->flags ^= DAP_SOCK_CONNECTING;
            dap_events_socket_worker_poll_update_unsafe(l_msg_es);
        }

    if (l_msg->flags_set & DAP_SOCK_READY_TO_READ)
        dap_events_socket_set_readable_unsafe(l_msg_es, true);
    if (l_msg->flags_unset & DAP_SOCK_READY_TO_READ)
        dap_events_socket_set_readable_unsafe(l_msg_es, false);
    if (l_msg->flags_set & DAP_SOCK_READY_TO_WRITE)
        dap_events_socket_set_writable_unsafe(l_msg_es, true);
    if (l_msg->flags_unset & DAP_SOCK_READY_TO_WRITE)
        dap_events_socket_set_writable_unsafe(l_msg_es, false);
    if (l_msg->data_size && l_msg->data)
        dap_events_socket_write_unsafe(l_msg_es, l_msg->data,l_msg->data_size);
    DAP_DELETE(l_msg);
}

/**
 * @brief s_socket_all_check_activity
 * @param a_arg
 */
static void s_socket_all_check_activity( void * a_arg)
{
    dap_worker_t *l_worker = (dap_worker_t*) a_arg;
    assert(l_worker);
    dap_events_socket_t *l_es, *tmp;
    char l_curtimebuf[64];
    time_t l_curtime= time(NULL);
    ctime_r(&l_curtime, l_curtimebuf);
    //log_it(L_DEBUG,"Check sockets activity on worker #%u at %s", l_worker->id, l_curtimebuf);

    HASH_ITER(hh_worker, l_worker->esockets, l_es, tmp ) {
        if ( l_es->type == DESCRIPTOR_TYPE_SOCKET  || l_es->type == DESCRIPTOR_TYPE_SOCKET_UDP ){
            if ( !(l_es->flags & DAP_SOCK_SIGNAL_CLOSE) &&
                 (  l_curtime >=  (l_es->last_time_active + s_connection_timeout) ) && !l_es->no_close ) {
                log_it( L_INFO, "Socket %u timeout (diff %u ), closing...", l_es->socket, l_curtime -  (time_t)l_es->last_time_active - s_connection_timeout );
                if (l_es->callbacks.error_callback) {
                    l_es->callbacks.error_callback(l_es, ETIMEDOUT);
                }
                dap_events_socket_remove_and_delete_mt( l_worker, l_es);
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
    int l_ret = dap_events_socket_queue_ptr_send( a_worker->queue_es_new, a_events_socket );
    if(l_ret != 0 ){
        char l_errbuf[128];
        *l_errbuf = 0;
        strerror_r(l_ret,l_errbuf,sizeof (l_errbuf));
        log_it(L_ERROR, "Cant send pointer in queue: \"%s\"(code %d)", l_errbuf, l_ret);
    }
}

/**
 * @brief dap_worker_add_events_socket_unsafe
 * @param a_worker
 * @param a_esocket
 */
int dap_worker_add_events_socket_unsafe( dap_events_socket_t * a_esocket, dap_worker_t * a_worker )
{

#ifdef DAP_EVENTS_CAPS_EPOLL
        // Init events for EPOLL
        a_esocket->ev.events = a_esocket->ev_base_flags ;
        if(a_esocket->flags & DAP_SOCK_READY_TO_READ )
            a_esocket->ev.events |= EPOLLIN;
        if(a_esocket->flags & DAP_SOCK_READY_TO_WRITE )
            a_esocket->ev.events |= EPOLLOUT;
        a_esocket->ev.data.ptr = a_esocket;
        return epoll_ctl(a_worker->epoll_fd, EPOLL_CTL_ADD, a_esocket->socket, &a_esocket->ev);
#elif defined (DAP_EVENTS_CAPS_POLL)
    if (  a_worker->poll_count == a_worker->poll_count_max ){ // realloc
        a_worker->poll_count_max *= 2;
        log_it(L_WARNING, "Too many descriptors (%u), resizing array twice to %u", a_worker->poll_count, a_worker->poll_count_max);
        a_worker->poll =DAP_REALLOC(a_worker->poll, a_worker->poll_count_max * sizeof(*a_worker->poll));
        a_worker->poll_esocket =DAP_REALLOC(a_worker->poll_esocket, a_worker->poll_count_max * sizeof(*a_worker->poll_esocket));
    }
    a_worker->poll[a_worker->poll_count].fd = a_esocket->socket;
    a_esocket->poll_index = a_worker->poll_count;
    a_worker->poll[a_worker->poll_count].events = a_esocket->poll_base_flags;
    if( a_esocket->flags & DAP_SOCK_READY_TO_READ )
        a_worker->poll[a_worker->poll_count].events |= POLLIN;
    if( (a_esocket->flags & DAP_SOCK_READY_TO_WRITE) || (a_esocket->flags & DAP_SOCK_CONNECTING) )
        a_worker->poll[a_worker->poll_count].events |= POLLOUT;


    a_worker->poll_esocket[a_worker->poll_count] = a_esocket;
    a_worker->poll_count++;
    return 0;
#else
#error "Unimplemented new esocket on worker callback for current platform"
#endif

}

/**
 * @brief dap_worker_exec_callback_on
 */
void dap_worker_exec_callback_on(dap_worker_t * a_worker, dap_worker_callback_t a_callback, void * a_arg)
{
    dap_worker_msg_callback_t * l_msg = DAP_NEW_Z(dap_worker_msg_callback_t);
    l_msg->callback = a_callback;
    l_msg->arg = a_arg;
    int l_ret=dap_events_socket_queue_ptr_send( a_worker->queue_callback,l_msg );
    if(l_ret != 0 ){
        char l_errbuf[128];
        *l_errbuf = 0;
        strerror_r(l_ret,l_errbuf,sizeof (l_errbuf));
        log_it(L_ERROR, "Cant send pointer in queue: \"%s\"(code %d)", l_errbuf, l_ret);
    }

}


/**
 * @brief dap_worker_add_events_socket
 * @param a_worker
 * @param a_events_socket
 */
dap_worker_t *dap_worker_add_events_socket_auto( dap_events_socket_t *a_es)
{
//  struct epoll_event ev = {0};
  dap_worker_t *l_worker = dap_events_worker_get_auto( );

  a_es->events = l_worker->events;
  dap_worker_add_events_socket( a_es, l_worker);
  return l_worker;
}



