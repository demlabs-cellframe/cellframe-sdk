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
#include "dap_events_socket.h"
#include <time.h>
#include <errno.h>
#include <unistd.h>
#if ! defined (_GNU_SOURCE)
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#endif
#include <fcntl.h>
#include <sys/types.h>
#ifdef DAP_OS_UNIX
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#elif defined DAP_OS_WINDOWS
#include <ws2tcpip.h>
#endif

#ifdef DAP_OS_DARWIN
#define NOTE_READ NOTE_LOWAT

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL SO_NOSIGPIPE
#endif

#endif

#include "dap_common.h"
#include "dap_config.h"
#include "dap_math_ops.h"
#include "dap_worker.h"
#include "dap_timerfd.h"
#include "dap_events.h"
#include "dap_enc_base64.h"
#include "dap_proc_queue.h"

#ifndef DAP_NET_CLIENT_NO_SSL
#include <wolfssl/options.h>
#include "wolfssl/ssl.h"
#endif

#define LOG_TAG "dap_worker"

static time_t s_connection_timeout = 60;    // seconds

static bool s_socket_all_check_activity( void * a_arg);
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

#ifdef DAP_OS_UNIX
    struct rlimit l_fdlimit;
    if (getrlimit(RLIMIT_NOFILE, &l_fdlimit))
        return -1;

    rlim_t l_oldlimit = l_fdlimit.rlim_cur;
    l_fdlimit.rlim_cur = l_fdlimit.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &l_fdlimit))
        return -2;
    log_it(L_INFO, "Set maximum opened descriptors from %lu to %lu", l_oldlimit, l_fdlimit.rlim_cur);
#endif
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
dap_events_socket_t *l_es;
dap_worker_t *l_worker = (dap_worker_t *) arg;
uint32_t l_tn = l_worker->id;
int l_errno = 0, l_selected_sockets;
socklen_t l_error_len = sizeof(l_errno);
char l_error_buf[128] = {0};
ssize_t l_bytes_sent = 0, l_bytes_read = 0, l_sockets_max;
const struct sched_param l_shed_params = {0};


    dap_cpu_assign_thread_on(l_worker->id);
    pthread_setspecific(l_worker->events->pth_key_worker, l_worker);

#ifdef DAP_OS_WINDOWS
    if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL))
        log_it(L_ERROR, "Couldn'r set thread priority, err: %lu", GetLastError());
#else
    pthread_setschedparam(pthread_self(),SCHED_FIFO ,&l_shed_params);
#endif

#ifdef DAP_EVENTS_CAPS_EPOLL
    struct epoll_event *l_epoll_events = l_worker->epoll_events;
    log_it(L_INFO, "Worker #%d started with epoll fd %"DAP_FORMAT_HANDLE" and assigned to dedicated CPU unit", l_worker->id, l_worker->epoll_fd);
#elif defined(DAP_EVENTS_CAPS_KQUEUE)
    l_worker->kqueue_fd = kqueue();

    if (l_worker->kqueue_fd == -1 ){
        int l_errno = errno;
        char l_errbuf[255];
        strerror_r(l_errno,l_errbuf,sizeof(l_errbuf));
        log_it (L_CRITICAL,"Can't create kqueue(): '%s' code %d",l_errbuf,l_errno);
        pthread_cond_broadcast(&l_worker->started_cond);
        return NULL;
    }

    l_worker->kqueue_events_selected_count_max = 100;
    l_worker->kqueue_events_count_max = DAP_EVENTS_SOCKET_MAX;
    l_worker->kqueue_events_selected = DAP_NEW_Z_SIZE(struct kevent, l_worker->kqueue_events_selected_count_max *sizeof(struct kevent));
#elif defined(DAP_EVENTS_CAPS_POLL)
    l_worker->poll_count_max = DAP_EVENTS_SOCKET_MAX;
    l_worker->poll = DAP_NEW_Z_SIZE(struct pollfd,l_worker->poll_count_max*sizeof (struct pollfd));
    l_worker->poll_esocket = DAP_NEW_Z_SIZE(dap_events_socket_t*,l_worker->poll_count_max*sizeof (dap_events_socket_t*));
#else
#error "Unimplemented socket array for this platform"
#endif

    l_worker->queue_es_new_input      = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)* dap_events_worker_get_count() );
    l_worker->queue_es_delete_input   = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)* dap_events_worker_get_count() );
    l_worker->queue_es_io_input       = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)* dap_events_worker_get_count() );
    l_worker->queue_es_reassign_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)* dap_events_worker_get_count() );


    l_worker->queue_es_new      = dap_events_socket_create_type_queue_ptr_unsafe(l_worker, s_queue_add_es_callback);
    l_worker->queue_es_delete   = dap_events_socket_create_type_queue_ptr_unsafe(l_worker, s_queue_delete_es_callback);
    l_worker->queue_es_io       = dap_events_socket_create_type_queue_ptr_unsafe(l_worker, s_queue_es_io_callback);
    l_worker->queue_es_reassign = dap_events_socket_create_type_queue_ptr_unsafe(l_worker, s_queue_es_reassign_callback );


    for( size_t n = 0; n < dap_events_worker_get_count(); n++) {
        l_worker->queue_es_new_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_es_new);
        l_worker->queue_es_delete_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_es_delete);
        l_worker->queue_es_io_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_es_io);
        l_worker->queue_es_reassign_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_es_reassign);
    }

    l_worker->queue_callback    = dap_events_socket_create_type_queue_ptr_unsafe(l_worker, s_queue_callback_callback);
    l_worker->event_exit        = dap_events_socket_create_type_event_unsafe(l_worker, s_event_exit_callback);

    l_worker->timer_check_activity = dap_timerfd_create(s_connection_timeout * 1000 / 2,
                                                        s_socket_all_check_activity, l_worker);
    dap_worker_add_events_socket_unsafe(  l_worker->timer_check_activity->events_socket, l_worker);
    pthread_mutex_lock(&l_worker->started_mutex);
    pthread_cond_broadcast(&l_worker->started_cond);
    pthread_mutex_unlock(&l_worker->started_mutex);

    while (1) {
#ifdef DAP_EVENTS_CAPS_EPOLL
        l_selected_sockets = epoll_wait(l_worker->epoll_fd, l_epoll_events, DAP_EVENTS_SOCKET_MAX, -1);
        l_sockets_max = l_selected_sockets;
#elif defined(DAP_EVENTS_CAPS_POLL)
        l_selected_sockets = poll(l_worker->poll, l_worker->poll_count, -1);
        l_sockets_max = l_worker->poll_count;
#elif defined(DAP_EVENTS_CAPS_KQUEUE)
        l_selected_sockets = kevent(l_worker->kqueue_fd,NULL,0,l_worker->kqueue_events_selected,l_worker->kqueue_events_selected_count_max,
                                                        NULL);
        l_sockets_max = l_selected_sockets;
#else
#error "Unimplemented poll wait analog for this platform"
#endif
        if(l_selected_sockets == -1) {
            if( errno == EINTR)
                continue;
#ifdef DAP_OS_WINDOWS
            log_it(L_ERROR, "Worker thread %d got errno %d", l_worker->id, WSAGetLastError());
#else
            strerror_r(l_errno, l_error_buf, sizeof (l_error_buf) - 1);
            log_it(L_ERROR, "Worker thread %d got errno:\"%s\" (%d)", l_worker->id, l_error_buf, l_errno);
            assert(l_errno);
#endif
            break;
        }

        time_t l_cur_time = time( NULL);
        l_worker->esocket_current = l_sockets_max;
        for(ssize_t n = 0; n < l_sockets_max; n++) {
            int l_flag_hup, l_flag_rdhup, l_flag_read, l_flag_write, l_flag_error, l_flag_nval, l_flag_msg, l_flag_pri;
            l_worker->esocket_current = n;
#ifdef DAP_EVENTS_CAPS_EPOLL
            l_es = (dap_events_socket_t *) l_epoll_events[n].data.ptr;
            uint32_t l_cur_flags = l_epoll_events[n].events;
            l_flag_hup      = l_cur_flags & EPOLLHUP;
            l_flag_rdhup    = l_cur_flags & EPOLLRDHUP;
            l_flag_write    = l_cur_flags & EPOLLOUT;
            l_flag_read     = l_cur_flags & EPOLLIN;
            l_flag_error    = l_cur_flags & EPOLLERR;
            l_flag_pri      = l_cur_flags & EPOLLPRI;
            l_flag_nval     = false;
            l_flag_msg = false;
#elif defined ( DAP_EVENTS_CAPS_POLL)
            int l_cur_flags = l_worker->poll[n].revents;

            if (l_worker->poll[n].fd == -1) // If it was deleted on previous iterations
                continue;

            if (!l_cur_flags) // No events for this socket
                continue;

            l_flag_hup =  l_cur_flags& POLLHUP;
            l_flag_rdhup = l_cur_flags & POLLRDHUP;
            l_flag_write = (l_cur_flags & POLLOUT) || (l_cur_flags &POLLWRNORM)|| (l_cur_flags &POLLWRBAND ) ;
            l_flag_read = l_cur_flags & POLLIN || (l_cur_flags &POLLRDNORM)|| (l_cur_flags &POLLRDBAND );
            l_flag_error = l_cur_flags & POLLERR;
            l_flag_nval = l_cur_flags & POLLNVAL;
            l_flag_pri = l_cur_flags & POLLPRI;
            l_flag_msg = l_cur_flags & POLLMSG;
            l_es = l_worker->poll_esocket[n];
            //log_it(L_DEBUG, "flags: returned events 0x%0X requested events 0x%0X",l_worker->poll[n].revents,l_worker->poll[n].events );
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
        l_flag_hup=l_flag_rdhup=l_flag_read=l_flag_write=l_flag_error=l_flag_nval=l_flag_msg =l_flag_pri = false;
        struct kevent * l_kevent_selected = &l_worker->kqueue_events_selected[n];
        if ( l_kevent_selected->filter == EVFILT_USER){ // If we have USER event it sends little different pointer
            dap_events_socket_w_data_t * l_es_w_data = (dap_events_socket_w_data_t *) l_kevent_selected->udata;
            if(l_es_w_data){
            //if(g_debug_reactor)
            //    log_it(L_DEBUG,"EVFILT_USER: udata=%p", l_es_w_data);

                l_es = l_es_w_data->esocket;
                assert(l_es);
                memcpy(&l_es->kqueue_event_catched_data, l_es_w_data, sizeof (*l_es_w_data)); // Copy event info for further processing

                if ( l_es->pipe_out == NULL){ // If we're not the input for pipe or queue
                                               // we must drop write flag and set read flag
                    l_flag_read  = true;
                }else{
                    l_flag_write = true;
                }
                void * l_ptr = &l_es->kqueue_event_catched_data;
                if(l_es_w_data != l_ptr){
                    DAP_DELETE(l_es_w_data);
                }else if (g_debug_reactor){
                    log_it(L_DEBUG,"Own event signal without actual event data");
                }
            }else
                l_es = NULL;
        }else{
            switch (l_kevent_selected->filter) {
                case EVFILT_TIMER:
                case EVFILT_READ: l_flag_read = true; break;
                case EVFILT_WRITE: l_flag_write = true; break;
                case EVFILT_EXCEPT : l_flag_rdhup = true; break;
                default: log_it(L_CRITICAL,"Unknown filter type in polling, exit thread"); return NULL;
            }
            if (l_kevent_selected->flags & EV_EOF)
                l_flag_rdhup = true;
            l_es = (dap_events_socket_t*) l_kevent_selected->udata;
            if (l_kevent_selected->filter == EVFILT_TIMER && l_es->type != DESCRIPTOR_TYPE_TIMER) {
                log_it(L_WARNING, "Filer type and socket descriptor type missmatch");
                continue;
            }
        }

        l_es->kqueue_event_catched = l_kevent_selected;
#ifndef DAP_OS_DARWIN
            u_int l_cur_flags = l_kevent_selected->flags;
#else
            uint32_t l_cur_flags = l_kevent_selected->flags;
#endif

#else
#error "Unimplemented fetch esocket after poll"
#endif
            // Previously deleted socket, its really bad when it appears
            if (!l_es || (l_es->worker && l_es->worker != l_worker)) {
                log_it(L_ATT, "dap_events_socket was destroyed earlier");
                continue;
            }
            switch (l_es->type) {
            case DESCRIPTOR_TYPE_SOCKET_CLIENT:
            case DESCRIPTOR_TYPE_SOCKET_UDP:
            case DESCRIPTOR_TYPE_SOCKET_LISTENING:
            case DESCRIPTOR_TYPE_SOCKET_LOCAL_LISTENING:
            case DESCRIPTOR_TYPE_SOCKET_LOCAL_CLIENT:
                if (l_es->socket == INVALID_SOCKET) {
                    log_it(L_ATT, "dap_events_socket have invalid socket number");
                    continue;
                } break;
            // TODO define condition for invalid socket with other descriptor types
            case DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL:
            case DESCRIPTOR_TYPE_QUEUE:
            case DESCRIPTOR_TYPE_PIPE:
            case DESCRIPTOR_TYPE_TIMER:
            case DESCRIPTOR_TYPE_EVENT:
            case DESCRIPTOR_TYPE_FILE:
                if (l_es->fd == -1 || l_es->fd2 == -1) {

                }
            default: break;
            }

            if(g_debug_reactor) {
                log_it(L_DEBUG, "--Worker #%u esocket %p uuid 0x%016"DAP_UINT64_FORMAT_x" type %d fd=%"DAP_FORMAT_SOCKET" flags=0x%0X (%s:%s:%s:%s:%s:%s:%s:%s)--",
                       l_worker->id, l_es, l_es->uuid, l_es->type, l_es->socket,
                    l_cur_flags, l_flag_read?"read":"", l_flag_write?"write":"", l_flag_error?"error":"",
                    l_flag_hup?"hup":"", l_flag_rdhup?"rdhup":"", l_flag_msg?"msg":"", l_flag_nval?"nval":"",
                       l_flag_pri?"pri":"");
            }

            int l_sock_err = 0, l_sock_err_size = sizeof(l_sock_err);
            //connection already closed (EPOLLHUP - shutdown has been made in both directions)

            if( l_flag_hup ) {
                switch (l_es->type ){
                case DESCRIPTOR_TYPE_SOCKET_UDP:
                case DESCRIPTOR_TYPE_SOCKET_CLIENT: {
                    getsockopt(l_es->socket, SOL_SOCKET, SO_ERROR, (void *)&l_sock_err, (socklen_t *)&l_sock_err_size);
#ifndef DAP_OS_WINDOWS
                    if (l_sock_err) {
                         log_it(L_DEBUG, "[es:%p] Socket #%d, errno=%d", l_es, l_es->socket, l_sock_err);
#else
                    log_it(L_DEBUG, "Socket %"DAP_FORMAT_SOCKET" will be shutdown (EPOLLHUP), error %d", l_es->socket, WSAGetLastError());
#endif
                    dap_events_socket_set_readable_unsafe(l_es, false);
                    dap_events_socket_set_writable_unsafe(l_es, false);
                    l_es->buf_out_size = 0;
                    l_es->flags |= DAP_SOCK_SIGNAL_CLOSE;
                    l_flag_error = l_flag_write = false;
                    if (l_es->callbacks.error_callback)
                        l_es->callbacks.error_callback(l_es, l_sock_err); // Call callback to process error event
#ifndef DAP_OS_WINDOWS
                        log_it(L_INFO, "[es:%p] Socket #%d shutdown (EPOLLHUP): %s", l_es, l_es->socket, strerror(l_sock_err));
                    }
#endif
                    break;
                }
                default:
                    debug_if(g_debug_reactor, L_WARNING, "[es:%p] HUP event on Socket #%"DAP_FORMAT_SOCKET" type %d", l_es, l_es->socket, l_es->type );
                }
            }

            if(l_flag_nval ){
                log_it(L_WARNING, "[es:%p] NVAL flag armed for Socket #%"DAP_FORMAT_SOCKET"", l_es, l_es->socket);
                l_es->buf_out_size = 0;
                l_es->buf_in_size = 0;
                l_es->flags |= DAP_SOCK_SIGNAL_CLOSE;
                if (l_es->callbacks.error_callback)
                    l_es->callbacks.error_callback(l_es, l_sock_err); // Call callback to process error event
                if (l_es->fd == 0 || l_es->fd == -1) {
#ifdef DAP_OS_WINDOWS
                    log_it(L_ERROR, "Wrong fd: %d", l_es->fd);
#else
                    assert(errno);
#endif
                }
                // If its not null or -1 we should try first to remove it from poll. Assert only if it doesn't help
            }

            if(l_flag_error) {
                switch (l_es->type ){
                    case DESCRIPTOR_TYPE_SOCKET_LISTENING:
                    case DESCRIPTOR_TYPE_SOCKET_CLIENT:
                        getsockopt(l_es->socket, SOL_SOCKET, SO_ERROR, (void *)&l_sock_err, (socklen_t *)&l_sock_err_size);
#ifdef DAP_OS_WINDOWS
                        log_it(L_ERROR, "Winsock error: %d", l_sock_err);
#else
                        log_it(L_ERROR, "[es:%p] Socket #%d error: %s", l_es, l_es->socket, strerror(l_sock_err));
#endif
                    default: ;
                }
                dap_events_socket_set_readable_unsafe(l_es, false);
                dap_events_socket_set_writable_unsafe(l_es, false);
                l_es->buf_out_size = 0;
                if (!l_es->no_close)
                    l_es->flags |= DAP_SOCK_SIGNAL_CLOSE;
                if(l_es->callbacks.error_callback)
                    l_es->callbacks.error_callback(l_es, l_sock_err); // Call callback to process error event
            }

            if (l_flag_read && !(l_es->flags & DAP_SOCK_SIGNAL_CLOSE)) {

                //log_it(L_DEBUG, "Comes connection with type %d", l_cur->type);
                if(l_es->buf_in_size_max && l_es->buf_in_size >= l_es->buf_in_size_max ) {
                    log_it(L_WARNING, "[es:%p] Buffer is full when there is smth to read. Its dropped! (Socket #%"DAP_FORMAT_SOCKET")", l_es, l_es->socket);
                    l_es->buf_in_size = 0;
                }

                int l_must_read_smth = false;
                switch (l_es->type) {
                    case DESCRIPTOR_TYPE_PIPE:
                    case DESCRIPTOR_TYPE_FILE:
                        l_must_read_smth = true;
#ifdef DAP_OS_WINDOWS
                        l_bytes_read = dap_recvfrom(l_es->socket, l_es->buf_in + l_es->buf_in_size, l_es->buf_in_size_max - l_es->buf_in_size);
#else
                        l_bytes_read = read(l_es->socket, (char *) (l_es->buf_in + l_es->buf_in_size),
                                            l_es->buf_in_size_max - l_es->buf_in_size);
#endif
                        l_errno = errno;
                    break;
                    case DESCRIPTOR_TYPE_SOCKET_LOCAL_CLIENT:
                    case DESCRIPTOR_TYPE_SOCKET_CLIENT:
                        l_must_read_smth = true;
                        l_bytes_read = recv(l_es->fd, (char *) (l_es->buf_in + l_es->buf_in_size),
                                            l_es->buf_in_size_max - l_es->buf_in_size, 0);
#ifdef DAP_OS_WINDOWS
                        l_errno = WSAGetLastError();
#else
                        l_errno = errno;
#endif
                    break;
                    case DESCRIPTOR_TYPE_SOCKET_UDP: {
                        l_must_read_smth = true;
                        socklen_t l_size = sizeof(l_es->remote_addr);
                        l_bytes_read = recvfrom(l_es->fd, (char *) (l_es->buf_in + l_es->buf_in_size),
                                                l_es->buf_in_size_max - l_es->buf_in_size, 0,
                                                (struct sockaddr *)&l_es->remote_addr, &l_size);

#ifdef DAP_OS_WINDOWS
                        l_errno = WSAGetLastError();
#else
                        l_errno = errno;
#endif
                    }
                    break;
                    case DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL: {
                        l_must_read_smth = true;
#ifndef DAP_NET_CLIENT_NO_SSL
                        WOLFSSL *l_ssl = SSL(l_cur);
                        l_bytes_read =  wolfSSL_read(l_ssl, (char *) (l_es->buf_in + l_es->buf_in_size),
                                                     l_es->buf_in_size_max - l_es->buf_in_size);
                        l_errno = wolfSSL_get_error(l_ssl, 0);
                        if (l_bytes_read > 0 && g_debug_reactor)
                            log_it(L_DEBUG, "SSL read: %s", (char *)(l_es->buf_in + l_es->buf_in_size));
#endif
                    }
                    break;
                    case DESCRIPTOR_TYPE_SOCKET_LOCAL_LISTENING:
                    case DESCRIPTOR_TYPE_SOCKET_LISTENING:
                        // Accept connection
                        if ( l_es->callbacks.accept_callback) {
                            struct sockaddr l_remote_addr;
                            socklen_t l_remote_addr_size = sizeof (l_remote_addr);
                            SOCKET l_remote_socket = accept(l_es->socket ,&l_remote_addr,&l_remote_addr_size);
#ifdef DAP_OS_WINDOWS
                            /*u_long l_mode = 1;
                            ioctlsocket((SOCKET)l_remote_socket, (long)FIONBIO, &l_mode); */
                            // no need, since l_cur->socket is already NBIO
                            if (l_remote_socket == INVALID_SOCKET) {
                                int l_errno = WSAGetLastError();
                                if (l_errno == WSAEWOULDBLOCK)
                                    continue;
                                else {
                                    log_it(L_WARNING,"Can't accept on socket %"DAP_FORMAT_SOCKET", WSA errno: %d", l_es->socket, l_errno);
                                    break;
                                }
                            }
#else
                            fcntl( l_remote_socket, F_SETFL, O_NONBLOCK);
                            int l_errno = errno;
                            if ( l_remote_socket == INVALID_SOCKET ){
                                if( l_errno == EAGAIN || l_errno == EWOULDBLOCK){// Everything is good, we'll receive ACCEPT on next poll
                                    continue;
                                }else{
                                    char l_errbuf[128];
                                    strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                                    log_it(L_WARNING,"[es:%p] accept() on Socket #%d error:\"%s\"(%d)",l_es, l_es->socket, l_errbuf,l_errno);
                                    break;
                                }
                            }
#endif
                            l_es->callbacks.accept_callback(l_es,l_remote_socket,&l_remote_addr);
                        } else
                            log_it(L_ERROR, "No accept_callback on listening socket");
                    break;

                    case DESCRIPTOR_TYPE_TIMER:{
                        /* if we not reading data from socket, he triggered again */
#ifdef DAP_OS_WINDOWS
                        l_bytes_read = dap_recvfrom(l_es->socket, NULL, 0);
#elif defined(DAP_OS_LINUX)
                        uint64_t val;
                        read( l_es->fd, &val, 8);
#endif
                        if (l_es->callbacks.timer_callback)
                            l_es->callbacks.timer_callback(l_es);
                        else
                            log_it(L_ERROR, "[es:%p] Socket %"DAP_FORMAT_SOCKET" with timer callback fired, but callback is NULL ", l_es, l_es->socket);

                    } break;

                    case DESCRIPTOR_TYPE_QUEUE:
                        dap_events_socket_queue_proc_input_unsafe(l_es);
                        dap_events_socket_set_writable_unsafe(l_es, false);
                    break;
                    case DESCRIPTOR_TYPE_EVENT:
                        dap_events_socket_event_proc_input_unsafe(l_es);
                    break;
                }

                if (l_must_read_smth){ // Socket/Descriptor read
                    if(l_bytes_read > 0) {
                        if (l_es->type == DESCRIPTOR_TYPE_SOCKET_CLIENT  || l_es->type == DESCRIPTOR_TYPE_SOCKET_UDP) {
                            l_es->last_time_active = l_cur_time;
                        }
                        l_es->buf_in_size += l_bytes_read;
                        debug_if(g_debug_reactor, L_DEBUG, "[es:%p] Received %zd bytes for fd %d ", l_es, l_bytes_read, l_es->fd);
                        if(l_es->callbacks.read_callback){
                            l_es->callbacks.read_callback(l_es, NULL); // Call callback to process read event. At the end of callback buf_in_size should be zero if everything was read well
                            if (l_es->worker == NULL ){ // esocket was unassigned in callback, we don't need any ops with it now,
                                                         // continue to poll another esockets
                                continue;
                            }
                        }else{
                            log_it(L_WARNING, "[es:%p] We have incoming %zd data but no read callback on socket %"DAP_FORMAT_SOCKET", removing from read set",
                                   l_es, l_bytes_read, l_es->socket);
                            dap_events_socket_set_readable_unsafe(l_es, false);
                        }
                    }
                    else if(l_bytes_read < 0) {
#ifdef DAP_OS_WINDOWS
                        if (l_es->type != DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_errno != WSAEWOULDBLOCK) {
                            log_it(L_ERROR, "Can't recv on socket %zu, WSA error: %d", l_es->socket, l_errno);
#else
                        if (l_es->type != DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_errno != EAGAIN && l_errno != EWOULDBLOCK)
                        { // If we have non-blocking socket
                            log_it(L_ERROR, "[es:%p] Some error occured in recv(Socket #%d), errno=%d", l_es, l_es->socket, l_errno);
#endif
                            dap_events_socket_set_readable_unsafe(l_es, false);
                            if (!l_es->no_close)
                                l_es->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_es->buf_out_size = 0;
                        }
#ifndef DAP_NET_CLIENT_NO_SSL
                        if (l_es->type == DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_errno != SSL_ERROR_WANT_READ && l_errno != SSL_ERROR_WANT_WRITE) {
                            char l_err_str[80];
                            wolfSSL_ERR_error_string(l_errno, l_err_str);
                            log_it(L_ERROR, "Some error occured in SSL read(): %s (code %d)", l_err_str, l_errno);
                            dap_events_socket_set_readable_unsafe(l_es, false);
                            if (!l_es->no_close)
                                l_es->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_es->buf_out_size = 0;
                        }
#endif
                    }
                    else if (!l_flag_rdhup && !l_flag_error && !(l_es->flags & DAP_SOCK_CONNECTING )) {
                        log_it(L_DEBUG, "[es:%p] EPOLLIN triggered but nothing to read on Socket #%d", l_es, l_es->socket);
                        //dap_events_socket_set_readable_unsafe(l_cur,false);
                    }
                }
            }

            // Possibly have data to read despite EPOLLRDHUP
            if (l_flag_rdhup){
                switch (l_es->type ){
                    case DESCRIPTOR_TYPE_SOCKET_UDP:
                    case DESCRIPTOR_TYPE_SOCKET_CLIENT:
                    case DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL:
                            dap_events_socket_set_readable_unsafe(l_es, false);
                            dap_events_socket_set_writable_unsafe(l_es, false);
                            l_es->buf_out_size = 0;
                            l_es->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_flag_error = l_flag_write = false;
                    break;
                    default:{}
                }
                if(g_debug_reactor)
                    log_it(L_DEBUG, "[es:%p] RDHUP event on sd #%"DAP_FORMAT_SOCKET", type %d", l_es, l_es->socket, l_es->type);
            }

            // If its outgoing connection
            if ((l_flag_write && !l_es->server && l_es->flags & DAP_SOCK_CONNECTING && l_es->type == DESCRIPTOR_TYPE_SOCKET_CLIENT) ||
                  (l_es->type == DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_es->flags & DAP_SOCK_CONNECTING)) {
                if (l_es->type == DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL) {
#ifndef DAP_NET_CLIENT_NO_SSL
                    WOLFSSL *l_ssl = SSL(l_es);
                    int l_res = wolfSSL_negotiate(l_ssl);
                    if (l_res != WOLFSSL_SUCCESS) {
                        char l_err_str[80];
                        int l_err = wolfSSL_get_error(l_ssl, l_res);
                        if (l_err != WOLFSSL_ERROR_WANT_READ && l_err != WOLFSSL_ERROR_WANT_WRITE) {
                            wolfSSL_ERR_error_string(l_err, l_err_str);
                            log_it(L_ERROR, "SSL handshake error \"%s\" with code %d", l_err_str, l_err);
                            if ( l_es->callbacks.error_callback )
                                l_es->callbacks.error_callback(l_es, l_error);
                        }
                    } else {
                        if(g_debug_reactor)
                            log_it(L_NOTICE, "SSL handshake done with %s", l_es->remote_addr_str ? l_es->remote_addr_str: "(NULL)");
                        l_es->flags ^= DAP_SOCK_CONNECTING;
                        if (l_es->callbacks.connected_callback)
                            l_es->callbacks.connected_callback(l_es);
                        dap_events_socket_worker_poll_update_unsafe(l_es);
                    }
#endif
                } else {
                    l_error_len = sizeof(l_errno);

                    getsockopt(l_es->socket, SOL_SOCKET, SO_ERROR, (void *)&l_errno, &l_error_len);
                    if(l_errno == EINPROGRESS) {
                        log_it(L_DEBUG, "[es:%p] Connecting with %s in progress...", l_es, l_es->remote_addr_str);
                    }else if (l_errno){
                        strerror_r(l_errno, l_error_buf, sizeof (l_error_buf));
                        log_it(L_ERROR, "[es:%p] Connecting error with %s: \"%s\" (code %d)", l_es, l_es->remote_addr_str,
                               l_error_buf, l_errno);
                        if ( l_es->callbacks.error_callback )
                            l_es->callbacks.error_callback(l_es, l_errno);
                    }else{
                        debug_if(g_debug_reactor, L_NOTICE, "[es:%p] Connected with %s", l_es, l_es->remote_addr_str);
                        l_es->flags &= ~DAP_SOCK_CONNECTING;
                        if (l_es->callbacks.connected_callback)
                            l_es->callbacks.connected_callback(l_es);
                        dap_events_socket_worker_poll_update_unsafe(l_es);
                    }
                }
            }

            l_bytes_sent = 0;

            if (l_flag_write && (l_es->flags & DAP_SOCK_READY_TO_WRITE) && !(l_es->flags & DAP_SOCK_CONNECTING)) {
                debug_if (g_debug_reactor, L_DEBUG, "[es:%p] Main loop output: %zu bytes to send", l_es, l_es->buf_out_size);
                if (l_es->callbacks.write_callback)
                    l_es->callbacks.write_callback(l_es, NULL);           /* Call callback to process write event */
                /*
                 * Socket is ready to write and not going to close
                 */
                if ( !l_es->buf_out_size )                                     /* Check firstly that output buffer is not empty */
                {
                    dap_events_socket_set_writable_unsafe(l_es, false);        /* Clear "enable write flag" */

                    if ( l_es->callbacks.write_finished_callback )             /* Optionaly call I/O completion routine */
                        l_es->callbacks.write_finished_callback(l_es, l_es->callbacks.arg, 0);

                    l_flag_write = 0;                                           /* Clear flag to exclude unecessary processing of output */
                }

                if ( l_es->worker && l_flag_write ){ // esocket wasn't unassigned in callback, we need some other ops with it
                        switch (l_es->type){
                            case DESCRIPTOR_TYPE_SOCKET_CLIENT: {
                                l_bytes_sent = send(l_es->socket, (const char *)l_es->buf_out,
                                                    l_es->buf_out_size, MSG_DONTWAIT | MSG_NOSIGNAL);
                                if (l_bytes_sent == -1)
#ifdef DAP_OS_WINDOWS
                                    l_errno = WSAGetLastError();
#else
                                    l_errno = errno;
#endif
                                else
                                    l_errno = 0;

                            }
                            break;
                            case DESCRIPTOR_TYPE_SOCKET_UDP:
                                l_bytes_sent = sendto(l_es->socket, (const char *)l_es->buf_out,
                                                      l_es->buf_out_size, MSG_DONTWAIT | MSG_NOSIGNAL,
                                                      (struct sockaddr *)&l_es->remote_addr, sizeof(l_es->remote_addr));
#ifdef DAP_OS_WINDOWS
                                dap_events_socket_set_writable_unsafe(l_es,false);
                                l_errno = WSAGetLastError();
#else
                                l_errno = errno;
#endif
                            break;
                            case DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL: {
#ifndef DAP_NET_CLIENT_NO_SSL
                                WOLFSSL *l_ssl = SSL(l_cur);
                                l_bytes_sent = wolfSSL_write(l_ssl, (char *)(l_es->buf_out), l_es->buf_out_size);
                                if (l_bytes_sent > 0)
                                    log_it(L_DEBUG, "SSL write: %s", (char *)(l_es->buf_out));
                                l_errno = wolfSSL_get_error(l_ssl, 0);
#endif
                            }

                            case DESCRIPTOR_TYPE_QUEUE:
                                if (l_es->flags & DAP_SOCK_QUEUE_PTR && l_es->buf_out_size>= sizeof (void*)){
#if defined(DAP_EVENTS_CAPS_QUEUE_PIPE2)
                                   l_bytes_sent = write(l_es->socket, l_es->buf_out, /*sizeof(void*)*/ l_es->buf_out_size);
                                   debug_if(g_debug_reactor, L_NOTICE, "send %ld bytes to pipe", l_bytes_sent);
                                   l_errno = l_bytes_sent < (ssize_t)l_es->buf_out_size ? errno : 0;
                                   debug_if(l_errno, L_ERROR, "Writing to pipe %d bytes failed, sent %d only...", l_es->buf_out_size, l_bytes_sent);
#elif defined (DAP_EVENTS_CAPS_QUEUE_POSIX)
                                   l_bytes_sent = mq_send(a_es->mqd, (const char *)&a_arg,sizeof (a_arg),0);
#elif defined DAP_EVENTS_CAPS_MSMQ
                                    /* TODO: Windows-way message waiting and handling
                                     *
                                    DWORD l_mp_id = 0;
                                    MQMSGPROPS    l_mps;
                                    MQPROPVARIANT l_mpvar[1];
                                    MSGPROPID     l_p_id[1];
                                    HRESULT       l_mstatus[1];

                                    l_p_id[l_mp_id] = PROPID_M_BODY;
                                    l_mpvar[l_mp_id].vt = VT_VECTOR | VT_UI1;
                                    l_mpvar[l_mp_id].caub.pElems = l_cur->buf_out;
                                    l_mpvar[l_mp_id].caub.cElems = l_cur->buf_out_size;//(u_long)sizeof(void*);
                                    l_mp_id++;

                                    l_mps.cProp = l_mp_id;
                                    l_mps.aPropID = l_p_id;
                                    l_mps.aPropVar = l_mpvar;
                                    l_mps.aStatus = l_mstatus;

                                    HRESULT hr = MQSendMessage(l_cur->mqh, &l_mps, MQ_NO_TRANSACTION);
                                    if (hr != MQ_OK) {
                                        l_errno = hr;
                                        log_it(L_ERROR, "An error occured on sending message to queue, errno: %ld", hr);
                                    } else {
                                        l_errno = WSAGetLastError();
                                        if (dap_sendto(l_cur->socket, l_cur->port, NULL, 0) == SOCKET_ERROR)
                                            log_it(L_ERROR, "Write to socket error: %d", WSAGetLastError());
                                        l_bytes_sent = l_cur->buf_out_size;
                                    }

                                    */
                                    l_bytes_sent = dap_sendto(l_es->socket, l_es->port, l_es->buf_out, l_es->buf_out_size);
                                    if (l_bytes_sent == SOCKET_ERROR) {
                                        log_it(L_ERROR, "Write to socket error: %d", WSAGetLastError());
                                    }
#elif defined (DAP_EVENTS_CAPS_QUEUE_MQUEUE)
                                    debug_if(g_debug_reactor, L_NOTICE, "[es:%p] Sending data to queue thru input buffer...", l_es);
                                    l_bytes_sent = !mq_send(l_es->mqd, (char*)l_es->buf_out, l_es->buf_out_size, 0) ? l_es->buf_out_size : 0;
                                    l_errno = l_bytes_sent ? 0 : errno == EINVAL ? EAGAIN : errno;
                                    debug_if(l_errno, L_ERROR, "[es:%p] mq_send [%lu bytes] failed, errno %d", l_es, l_es->buf_out_size, l_errno);
                                    if (l_errno == EMSGSIZE) {
                                        struct mq_attr l_attr = { 0 };
                                        mq_getattr(l_es->mqd, &l_attr);
                                        log_it(L_ERROR, "[es:%p] Msg size %lu > permitted size %lu", l_es, l_es->buf_out_size, l_attr.mq_msgsize);
                                    }
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
                                    struct kevent* l_event=&l_es->kqueue_event;
                                    dap_events_socket_w_data_t * l_es_w_data = DAP_NEW_Z(dap_events_socket_w_data_t);
                                    l_es_w_data->esocket = l_es;
                                    memcpy(&l_es_w_data->ptr, l_es->buf_out,sizeof(l_es));
                                    EV_SET(l_event,l_es->socket, l_es->kqueue_base_filter,l_es->kqueue_base_flags, l_es->kqueue_base_fflags,l_es->kqueue_data, l_es_w_data);
                                    int l_n = kevent(l_worker->kqueue_fd,l_event,1,NULL,0,NULL);
                                    if (l_n == 1){
                                        l_bytes_sent = sizeof(l_es);
                                    }else{
                                        l_errno = errno;
                                        log_it(L_WARNING,"queue ptr send error: kevent %p errno: %d", l_es_w_data, l_errno);
                                        DAP_DELETE(l_es_w_data);
                                    }

#else
#error "Not implemented dap_events_socket_queue_ptr_send() for this platform"
#endif
                                } else {
                                     assert("Not implemented non-ptr queue send from outgoing buffer");
                                     // TODO Implement non-ptr queue output
                                }
                            break;
                            case DESCRIPTOR_TYPE_PIPE:
                            case DESCRIPTOR_TYPE_FILE:
                                l_bytes_sent = write(l_es->fd, (char *) (l_es->buf_out), l_es->buf_out_size );
                                l_errno = errno;
                            break;
                            default:
                                log_it(L_ERROR, "[es:%p] Socket %"DAP_FORMAT_SOCKET" is not SOCKET, PIPE or FILE but has WRITE state on. Switching it off", l_es, l_es->socket);
                                dap_events_socket_set_writable_unsafe(l_es, false);
                        }

                    if(l_bytes_sent < 0) {
#ifdef DAP_OS_WINDOWS
                        if (l_es->type != DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_errno != WSAEWOULDBLOCK) {
                            log_it(L_ERROR, "Can't send to socket %zu, WSA error: %d", l_es->socket, l_errno);
#else
                        if (l_es->type != DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_errno != EAGAIN && l_errno != EWOULDBLOCK)
                        { // If we have non-blocking socket
                            log_it(L_ERROR, "[es:%p] Some error occured in send(): %s (code %d)", l_es, strerror(l_errno), l_errno);
#endif
                            if (!l_es->no_close)
                                l_es->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_es->buf_out_size = 0;
                        }
#ifndef DAP_NET_CLIENT_NO_SSL
                        if (l_es->type == DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_errno != SSL_ERROR_WANT_READ && l_errno != SSL_ERROR_WANT_WRITE) {
                            char l_err_str[80];
                            wolfSSL_ERR_error_string(l_errno, l_err_str);
                            log_it(L_ERROR, "Some error occured in SSL write(): %s (code %d)", l_err_str, l_errno);
                            if (!l_es->no_close)
                                l_es->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_es->buf_out_size = 0;
                        }
#endif
                    }else{
                        debug_if(g_debug_reactor, L_DEBUG, "[es:%p] sent %zd bytes, left %zd in buf", l_es, l_bytes_sent, l_es->buf_out_size);
                        if (l_bytes_sent) {
                            if (l_es->type == DESCRIPTOR_TYPE_SOCKET_CLIENT  || l_es->type == DESCRIPTOR_TYPE_SOCKET_UDP) {
                                l_es->last_time_active = l_cur_time;
                            }
                            if ( l_bytes_sent <= (ssize_t) l_es->buf_out_size ){
                                l_es->buf_out_size -= l_bytes_sent;
                                if (l_es->buf_out_size ) {
                                    memmove(l_es->buf_out, &l_es->buf_out[l_bytes_sent], l_es->buf_out_size);
                                } else {
                                    /*
                                     * If whole buffer has been sent - clear "write flag" for socket/file descriptor to prevent
                                     * generation of unexpected I/O events like POLLOUT and consuming CPU by this.
                                     */
                                    dap_events_socket_set_writable_unsafe(l_es, false);/* Clear "enable write flag" */
                                    if ( l_es->callbacks.write_finished_callback ) {    /* Optionaly call I/O completion routine */
                                        if (l_errno == EWOULDBLOCK || l_errno == EAGAIN || l_errno == EINTR)
                                            l_errno = 0;
                                        l_es->callbacks.write_finished_callback(l_es, l_es->callbacks.arg, l_errno);
                                    }
                                }
                            }else{
                                log_it(L_ERROR, "[es:%p] Wrong bytes sent, %zd more then was in buffer %zd", l_es, l_bytes_sent, l_es->buf_out_size);
                                l_es->buf_out_size = 0;
                            }
                        }
                    }
                }
            }

            if (l_es->flags & DAP_SOCK_SIGNAL_CLOSE)
            {
                if (l_es->buf_out_size == 0) {
                    debug_if(g_debug_reactor, L_INFO, "[es:%p] Process signal to close %s sock %"DAP_FORMAT_SOCKET" (ptr %p uuid 0x%016"DAP_UINT64_FORMAT_x") type %d [thread %u]",
                           l_es, l_es->remote_addr_str, l_es->socket, l_es, l_es->uuid,
                               l_es->type, l_tn);

                    for (ssize_t nn = n + 1; nn < l_sockets_max; nn++) { // Check for current selection if it has event duplication
                        dap_events_socket_t *l_es_selected = NULL;
#ifdef DAP_EVENTS_CAPS_EPOLL
                        l_es_selected = (dap_events_socket_t *) l_epoll_events[nn].data.ptr;
#elif defined ( DAP_EVENTS_CAPS_POLL)
                        l_es_selected = l_worker->poll_esocket[nn];
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
                        struct kevent * l_kevent_selected = &l_worker->kqueue_events_selected[n];
                        if ( l_kevent_selected->filter == EVFILT_USER){ // If we have USER event it sends little different pointer
                            dap_events_socket_w_data_t * l_es_w_data = (dap_events_socket_w_data_t *) l_kevent_selected->udata;
                            l_es_selected = l_es_w_data->esocket;
                        }else{
                            l_es_selected = (dap_events_socket_t*) l_kevent_selected->udata;
                        }
#else
#error "No selection esockets left to proc implemenetation"
#endif
                        if(l_es_selected == NULL || l_es_selected == l_es ){
                            if(l_es_selected == NULL)
                                log_it(L_CRITICAL, "NULL esocket found when cleaning selected list");
                            else if(g_debug_reactor)
                                log_it(L_INFO, "Duplicate esockets removed from selected event list");
                            n=nn; // TODO here we need to make smth like poll() array compressing.
                                  // Here we expect thats event duplicates goes together in it. If not - we lose some events between.
                        }
                    }
                    //dap_events_socket_remove_and_delete_unsafe( l_cur, false);
                    dap_events_socket_remove_and_delete_unsafe(l_es, false);
#ifdef DAP_EVENTS_CAPS_KQUEUE
                    l_worker->kqueue_events_count--;
#endif
                } else {
                    debug_if(g_debug_reactor, L_INFO, "[es:%p] Got signal to close %s sock %"DAP_FORMAT_SOCKET" [thread %u] type %d but buffer is not empty(%zu)",
                           l_es, l_es->remote_addr_str, l_es->socket, l_es->type, l_tn,
                           l_es->buf_out_size);
                }
            }

            if( l_worker->signal_exit){
                log_it(L_ATT, "Worker :%u finished", l_worker->id);
                return NULL;
            }

        }
#ifdef DAP_EVENTS_CAPS_POLL
        /***********************************************************/
        /* If the compress_array flag was turned on, we need       */
        /* to squeeze together the array and decrement the number  */
        /* of file descriptors.                                    */
        /***********************************************************/
        if ( l_worker->poll_compress){
            l_worker->poll_compress = false;
            for (size_t i = 0; i < l_worker->poll_count ; i++)  {
                if ( l_worker->poll[i].fd == -1){
                    if( l_worker->poll_count){
                        for(size_t j = i; j < l_worker->poll_count-1; j++){
                             l_worker->poll[j].fd = l_worker->poll[j+1].fd;
                             l_worker->poll[j].events = l_worker->poll[j+1].events;
                             l_worker->poll[j].revents = l_worker->poll[j+1].revents;
                             l_worker->poll_esocket[j] = l_worker->poll_esocket[j+1];
                             if(l_worker->poll_esocket[j])
                                 l_worker->poll_esocket[j]->poll_index = j;
                        }
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
    dap_worker_t * l_worker = a_es->worker;
    dap_events_socket_t * l_es_new =(dap_events_socket_t *) a_arg;
    if (!l_es_new){
        log_it(L_ERROR,"NULL esocket accepted to add on worker #%u", l_worker->id);
        return;
    }

    debug_if(g_debug_reactor, L_NOTICE, "[es:%p] [sd #%"DAP_FORMAT_SOCKET" type %d] add on worker", l_es_new, l_es_new->socket, l_es_new->type);

    switch( l_es_new->type){
        case DESCRIPTOR_TYPE_SOCKET_UDP: break;
        case DESCRIPTOR_TYPE_SOCKET_CLIENT: break;
        default:{}
    }

#ifdef DAP_EVENTS_CAPS_KQUEUE
    if(l_es_new->socket!=0 && l_es_new->socket != -1 &&
            l_es_new->type != DESCRIPTOR_TYPE_EVENT &&
        l_es_new->type != DESCRIPTOR_TYPE_QUEUE &&
        l_es_new->type != DESCRIPTOR_TYPE_TIMER
            )
#else
    if(l_es_new->socket!=0 && l_es_new->socket != INVALID_SOCKET)

#endif
    if(dap_worker_esocket_find_uuid( l_worker, l_es_new->uuid)){
        // Socket already present in worker, it's OK
        return;
    }

    switch( l_es_new->type){

        case DESCRIPTOR_TYPE_SOCKET_UDP:
        case DESCRIPTOR_TYPE_SOCKET_CLIENT:
        case DESCRIPTOR_TYPE_SOCKET_LISTENING:{

#ifdef DAP_OS_UNIX
#if defined (SO_INCOMING_CPU)
            int l_cpu = l_worker->id;
            setsockopt(l_es_new->socket , SOL_SOCKET, SO_INCOMING_CPU, &l_cpu, sizeof(l_cpu));
#endif
#endif
        } break;
        default: {}
    }

    l_es_new->worker = l_worker;
    l_es_new->last_time_active = time(NULL);
    // We need to differ new and reassigned esockets. If its new - is_initialized is false
    if ( ! l_es_new->is_initalized ){
        if (l_es_new->callbacks.new_callback)
            l_es_new->callbacks.new_callback(l_es_new, NULL);
        l_es_new->is_initalized = true;
    }

    int l_ret = dap_worker_add_events_socket_unsafe(l_es_new,l_worker);
    if (  l_ret != 0 ){
        log_it(L_CRITICAL,"Can't add event socket's handler to worker i/o poll mechanism with error %d", errno);
    }else{
        // Add in worker
        l_es_new->me = l_es_new;
        if (l_es_new->socket!=0 && l_es_new->socket != INVALID_SOCKET){
            pthread_rwlock_wrlock(&l_worker->esocket_rwlock);
            HASH_ADD(hh_worker, l_worker->esockets, uuid, sizeof(l_es_new->uuid), l_es_new );
            l_worker->event_sockets_count++;
            pthread_rwlock_unlock(&l_worker->esocket_rwlock);
        }
        //log_it(L_DEBUG, "Added socket %d on worker %u", l_es_new->socket, w->id);
        if (l_es_new->callbacks.worker_assign_callback)
            l_es_new->callbacks.worker_assign_callback(l_es_new, l_worker);

    }
}

/**
 * @brief s_delete_es_callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_delete_es_callback( dap_events_socket_t * a_es, void * a_arg)
{
    assert(a_arg);
    dap_events_socket_uuid_t * l_es_uuid_ptr = (dap_events_socket_uuid_t*) a_arg;
    dap_events_socket_t * l_es;
    if ( (l_es = dap_worker_esocket_find_uuid(a_es->worker,*l_es_uuid_ptr)) != NULL ){
        //l_es->flags |= DAP_SOCK_SIGNAL_CLOSE; // Send signal to socket to kill
        dap_events_socket_remove_and_delete_unsafe(l_es,false);
    }else
        log_it(L_INFO, "While we were sending the delete() message, esocket %"DAP_UINT64_FORMAT_U" has been disconnected ", *l_es_uuid_ptr);
    DAP_DELETE(l_es_uuid_ptr);
}

/**
 * @brief s_reassign_es_callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_es_reassign_callback( dap_events_socket_t * a_es, void * a_arg)
{
    assert(a_es);
    dap_worker_t * l_worker = a_es->worker;
    assert(l_worker);
    dap_worker_msg_reassign_t * l_msg = (dap_worker_msg_reassign_t*) a_arg;
    assert(l_msg);
    dap_events_socket_t * l_es_reassign;
    if ( ( l_es_reassign = dap_worker_esocket_find_uuid(l_worker, l_msg->esocket_uuid))!= NULL ){
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
    if(g_debug_reactor)
        log_it(L_DEBUG, "Worker :%u signaled to exit", a_es->worker->id);
}

/**
 * @brief s_pipe_data_out_read_callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_es_io_callback( dap_events_socket_t * a_es, void * a_arg)
{
    assert(a_es);
    dap_worker_t * l_worker = a_es->worker;
    dap_worker_msg_io_t * l_msg = a_arg;
    assert(l_msg);
    // Check if it was removed from the list
    dap_events_socket_t *l_msg_es = dap_worker_esocket_find_uuid(l_worker, l_msg->esocket_uuid);
    if ( l_msg_es == NULL){
        log_it(L_INFO, "We got i/o message for esocket %"DAP_UINT64_FORMAT_U" thats now not in list. Lost %zu data", l_msg->esocket_uuid, l_msg->data_size);
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
    if (l_msg->data_size && l_msg->data) {
        dap_events_socket_write_unsafe(l_msg_es, l_msg->data,l_msg->data_size);
        DAP_DELETE(l_msg->data);
    }
    DAP_DELETE(l_msg);
}

/**
 * @brief s_socket_all_check_activity
 * @param a_arg
 */
static bool s_socket_all_check_activity( void * a_arg)
{
    dap_worker_t *l_worker = (dap_worker_t*) a_arg;
    assert(l_worker);
    dap_events_socket_t *l_es = NULL, *tmp = NULL;
    char l_curtimebuf[64];
    time_t l_curtime= time(NULL);
    //dap_ctime_r(&l_curtime, l_curtimebuf);
    //log_it(L_DEBUG,"Check sockets activity on worker #%u at %s", l_worker->id, l_curtimebuf);
    pthread_rwlock_rdlock(&l_worker->esocket_rwlock);
    HASH_ITER(hh_worker, l_worker->esockets, l_es, tmp ) {
        pthread_rwlock_unlock(&l_worker->esocket_rwlock);
        if (l_es->type == DESCRIPTOR_TYPE_SOCKET_CLIENT){
            if ( !(l_es->flags & DAP_SOCK_SIGNAL_CLOSE) &&
                 (  l_curtime >=  (l_es->last_time_active + s_connection_timeout) ) && !l_es->no_close ) {
                log_it( L_INFO, "Socket %"DAP_FORMAT_SOCKET" timeout (diff %"DAP_UINT64_FORMAT_U" ), closing...",
                                l_es->socket, l_curtime -  (time_t)l_es->last_time_active - s_connection_timeout );
                if (l_es->callbacks.error_callback) {
                    l_es->callbacks.error_callback(l_es, ETIMEDOUT);
                }
                dap_events_socket_remove_and_delete_unsafe(l_es,false);
            }
        }
        pthread_rwlock_rdlock(&l_worker->esocket_rwlock);
    }
    pthread_rwlock_unlock(&l_worker->esocket_rwlock);
    return true;
}

/**
 * @brief sap_worker_add_events_socket
 * @param a_events_socket
 * @param a_worker
 */
void dap_worker_add_events_socket(dap_events_socket_t * a_es, dap_worker_t * a_worker)
{
char l_errbuf[128] = {0};
int l_ret;

    debug_if(g_debug_reactor, L_DEBUG,"[es:%p] Worker add socket %"DAP_FORMAT_SOCKET, a_es, a_es->socket);
    if ( (l_ret = dap_events_socket_queue_ptr_send( a_worker->queue_es_new, a_es))) {
        strerror_r(l_ret, l_errbuf, sizeof(l_errbuf));
        log_it(L_ERROR, "[es:%p] Can't send pointer in queue: \"%s\"(code %d)", a_es, l_errbuf, l_ret);
    }
}

/**
 * @brief dap_worker_add_events_socket_inter
 * @param a_es_input
 * @param a_events_socket
 */
void dap_worker_add_events_socket_inter(dap_events_socket_t * a_es_input, dap_events_socket_t * a_events_socket)
{
    if( dap_events_socket_queue_ptr_send_to_input( a_es_input, a_events_socket ) != 0 ){
        int l_errno = errno;
        char l_errbuf[128];
        *l_errbuf = 0;
        strerror_r(l_errno,l_errbuf,sizeof (l_errbuf));
        log_it(L_ERROR, "Cant send pointer to interthread queue input: \"%s\"(code %d)", l_errbuf, l_errno);
    }
}

/**
 * @brief dap_worker_add_events_socket_unsafe
 * @param a_worker
 * @param a_esocket
 */
int dap_worker_add_events_socket_unsafe( dap_events_socket_t * a_esocket, dap_worker_t * a_worker )
{
    if(g_debug_reactor){
        log_it(L_DEBUG,"Add event socket %p (socket %"DAP_FORMAT_SOCKET" type %d)", a_esocket, a_esocket->socket, a_esocket->type);
    }
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
        log_it(L_WARNING, "Too many descriptors (%u), resizing array twice to %zu", a_worker->poll_count, a_worker->poll_count_max);
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
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
    a_esocket->worker = a_worker;
    if ( a_esocket->type == DESCRIPTOR_TYPE_QUEUE ){
        return 0;
    }
    if ( a_esocket->type == DESCRIPTOR_TYPE_EVENT ){
        return 0;
    }

    struct kevent l_event;
    u_short l_flags = a_esocket->kqueue_base_flags;
    u_int   l_fflags = a_esocket->kqueue_base_fflags;
    short l_filter = a_esocket->kqueue_base_filter;
    int l_kqueue_fd =a_worker->kqueue_fd;
    if ( l_kqueue_fd == -1 ){
        log_it(L_ERROR, "Esocket is not assigned with anything ,exit");
    }
    // Check & add
    bool l_is_error=false;
    int l_errno=0;


    {
        if( l_filter){
            EV_SET(&l_event, a_esocket->socket, l_filter,l_flags| EV_ADD,l_fflags,a_esocket->kqueue_data,a_esocket);
            if( kevent( l_kqueue_fd,&l_event,1,NULL,0,NULL) != 0 ){
                l_is_error = true;
                l_errno = errno;
            }else if (g_debug_reactor){
                log_it(L_DEBUG, "kevent set custom filter %d on fd %d",l_filter, a_esocket->socket);
            }
        }else{
            if( a_esocket->flags & DAP_SOCK_READY_TO_READ ){
                EV_SET(&l_event, a_esocket->socket, EVFILT_READ,l_flags| EV_ADD,l_fflags,a_esocket->kqueue_data,a_esocket);
                if( kevent( l_kqueue_fd,&l_event,1,NULL,0,NULL) != 0 ){
                    l_is_error = true;
                    l_errno = errno;
                }else if (g_debug_reactor){
                    log_it(L_DEBUG, "kevent set EVFILT_READ on fd %d", a_esocket->socket);
                }

            }
            if( !l_is_error){
                if( a_esocket->flags & DAP_SOCK_READY_TO_WRITE || a_esocket->flags &DAP_SOCK_CONNECTING ){
                    EV_SET(&l_event, a_esocket->socket, EVFILT_WRITE,l_flags| EV_ADD,l_fflags,a_esocket->kqueue_data,a_esocket);
                    if(kevent( l_kqueue_fd,&l_event,1,NULL,0,NULL) != 0){
                        l_is_error = true;
                        l_errno = errno;
                    }else if (g_debug_reactor){
                        log_it(L_DEBUG, "kevent set EVFILT_WRITE on fd %d", a_esocket->socket);
                    }
                }
            }
        }
    }

    if ( l_is_error ){
        char l_errbuf[128];
        l_errbuf[0]=0;
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        log_it(L_ERROR,"Can't update client socket state on kqueue fd %d: \"%s\" (%d)",
            a_esocket->socket, l_errbuf, l_errno);
        return l_errno;
    }else
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



