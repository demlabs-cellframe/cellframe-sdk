/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2022
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

#define LOG_TAG "dap_context"

#include "dap_common.h"
#include "dap_context.h"
#include "dap_worker.h"

pthread_key_t g_dap_context_pth_key;

/**
 * @brief dap_context_init
 * @return
 */
int dap_context_init()
{
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

/**
 * @brief dap_context_new
 * @return
 */
dap_context_t * dap_context_new()
{
   dap_context_t * l_context = DAP_NEW_Z(dap_context_t);
   static uint32_t s_context_id_max = 0;
   l_context->id = s_context_id_max;
   s_context_id_max++;
   return l_context;
}

/**
 * @brief dap_context_thread_init
 * @param a_context
 * @return
 */
int dap_context_thread_init(dap_context_t * a_context)
{
    pthread_setspecific(g_dap_context_pth_key, a_context);

#if defined(DAP_EVENTS_CAPS_KQUEUE)
    a_context->kqueue_fd = kqueue();

    if (a_context->kqueue_fd == -1 ){
        int l_errno = errno;
        char l_errbuf[255];
        strerror_r(l_errno,l_errbuf,sizeof(l_errbuf));
        log_it (L_CRITICAL,"Can't create kqueue(): '%s' code %d",l_errbuf,l_errno);
        return -1;
    }

    a_context->kqueue_events_selected_count_max = 100;
    a_context->kqueue_events_count_max = DAP_EVENTS_SOCKET_MAX;
    a_context->kqueue_events_selected = DAP_NEW_Z_SIZE(struct kevent, a_context->kqueue_events_selected_count_max *sizeof(struct kevent));
#elif defined(DAP_EVENTS_CAPS_POLL)
    a_context->poll_count_max = DAP_EVENTS_SOCKET_MAX;
    a_context->poll = DAP_NEW_Z_SIZE(struct pollfd,a_context->poll_count_max*sizeof (struct pollfd));
    a_context->poll_esocket = DAP_NEW_Z_SIZE(dap_events_socket_t*,a_context->poll_count_max*sizeof (dap_events_socket_t*));
#else
#error "Unimplemented socket array for this platform"
#endif
    return 0;
}

/**
 * @brief dap_context_thread_loop
 * @param a_context
 * @return
 */
int dap_context_thread_loop(dap_context_t * a_context)
{
    int l_errno = 0, l_selected_sockets = 0;
    dap_events_socket_t *l_cur = NULL;

    socklen_t l_error_len = sizeof(l_errno);
    char l_error_buf[128] = {0};
    ssize_t l_bytes_sent = 0, l_bytes_read = 0, l_sockets_max;

    do {
#ifdef DAP_EVENTS_CAPS_EPOLL
        l_selected_sockets = epoll_wait(a_context->epoll_fd, l_epoll_events, DAP_EVENTS_SOCKET_MAX, -1);
        l_sockets_max = l_selected_sockets;
#elif defined(DAP_EVENTS_CAPS_POLL)
        l_selected_sockets = poll(a_context->poll, a_context->poll_count, -1);
        l_sockets_max = a_context->poll_count;
#elif defined(DAP_EVENTS_CAPS_KQUEUE)
        l_selected_sockets = kevent(a_context->kqueue_fd,NULL,0,a_context->kqueue_events_selected,a_context->kqueue_events_selected_count_max,
                                                        NULL);
        l_sockets_max = l_selected_sockets;
#else
#error "Unimplemented poll wait analog for this platform"
#endif
        if(l_selected_sockets == -1) {
            if( errno == EINTR)
                continue;
#ifdef DAP_OS_WINDOWS
            log_it(L_ERROR, "Context thread %d got errno %d", a_context->id, WSAGetLastError());
#else
            strerror_r(l_errno, l_error_buf, sizeof (l_error_buf) - 1);
            log_it(L_ERROR, "Context thread %d got errno:\"%s\" (%d)", a_context->id, l_error_buf, l_errno);
            assert(l_errno);
#endif
            break;
        }

        time_t l_cur_time = time( NULL);
        for(ssize_t n = 0; n < l_sockets_max; n++) {
            bool l_flag_hup, l_flag_rdhup, l_flag_read, l_flag_write, l_flag_error, l_flag_nval, l_flag_msg, l_flag_pri;

#ifdef DAP_EVENTS_CAPS_EPOLL
            l_cur = (dap_events_socket_t *) l_epoll_events[n].data.ptr;
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
            short l_cur_flags =a_context->poll[n].revents;

            if (a_context->poll[n].fd == -1) // If it was deleted on previous iterations
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
            l_cur = a_context->poll_esocket[n];
            //log_it(L_DEBUG, "flags: returned events 0x%0X requested events 0x%0X",a_context->poll[n].revents,a_context->poll[n].events );
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
        l_flag_hup=l_flag_rdhup=l_flag_read=l_flag_write=l_flag_error=l_flag_nval=l_flag_msg =l_flag_pri = false;
        struct kevent * l_kevent_selected = &a_context->kqueue_events_selected[n];
        if ( l_kevent_selected->filter == EVFILT_USER){ // If we have USER event it sends little different pointer
            dap_events_socket_w_data_t * l_es_w_data = (dap_events_socket_w_data_t *) l_kevent_selected->udata;
            //if(g_debug_reactor)
            //    log_it(L_DEBUG,"EVFILT_USER: udata=%p", l_es_w_data);

            l_cur = l_es_w_data->esocket;
            assert(l_cur);
            memcpy(&l_cur->kqueue_event_catched_data, l_es_w_data, sizeof (*l_es_w_data)); // Copy event info for further processing

            if ( l_cur->pipe_out == NULL){ // If we're not the input for pipe or queue
                                           // we must drop write flag and set read flag
                l_flag_read  = true;
            }else{
                l_flag_write = true;
            }
            void * l_ptr = &l_cur->kqueue_event_catched_data;
            if(l_es_w_data != l_ptr){
                DAP_DELETE(l_es_w_data);
            }else if (g_debug_reactor){
                log_it(L_DEBUG,"Own event signal without actual event data");
            }
        }else{
            switch (l_kevent_selected->filter) {
                case EVFILT_TIMER:
                case EVFILT_READ: l_flag_read = true; break;
                case EVFILT_WRITE: l_flag_write = true; break;
                case EVFILT_EXCEPT : l_flag_rdhup = true; break;
                default:
                    log_it(L_CRITICAL,"Unknown filter type in polling, exit thread");
                    return -1;
            }
            if (l_kevent_selected->flags & EV_EOF)
                l_flag_rdhup = true;
            l_cur = (dap_events_socket_t*) l_kevent_selected->udata;
        }

        if( !l_cur) {
            log_it(L_WARNING, "dap_events_socket was destroyed earlier");
            continue;
        }


        l_cur->kqueue_event_catched = l_kevent_selected;
#ifndef DAP_OS_DARWIN
            u_int l_cur_flags = l_kevent_selected->flags;
#else
            uint32_t l_cur_flags = l_kevent_selected->flags;
#endif

#else
#error "Unimplemented fetch esocket after poll"
#endif
            if(!l_cur || (l_cur->context && l_cur->context != a_context)) {
                log_it(L_WARNING, "dap_events_socket was destroyed earlier");
                continue;
            }
            if(g_debug_reactor) {
                log_it(L_DEBUG, "--Context #%u esocket %p uuid 0x%016"DAP_UINT64_FORMAT_x" type %d fd=%"DAP_FORMAT_SOCKET" flags=0x%0X (%s:%s:%s:%s:%s:%s:%s:%s)--",
                       a_context->id, l_cur, l_cur->uuid, l_cur->type, l_cur->socket,
                    l_cur_flags, l_flag_read?"read":"", l_flag_write?"write":"", l_flag_error?"error":"",
                    l_flag_hup?"hup":"", l_flag_rdhup?"rdhup":"", l_flag_msg?"msg":"", l_flag_nval?"nval":"",
                       l_flag_pri?"pri":"");
            }

            int l_sock_err = 0, l_sock_err_size = sizeof(l_sock_err);
            //connection already closed (EPOLLHUP - shutdown has been made in both directions)

            if( l_flag_hup ) {
                switch (l_cur->type ){
                case DESCRIPTOR_TYPE_SOCKET_UDP:
                case DESCRIPTOR_TYPE_SOCKET_CLIENT: {
                    getsockopt(l_cur->socket, SOL_SOCKET, SO_ERROR, (void *)&l_sock_err, (socklen_t *)&l_sock_err_size);
#ifndef DAP_OS_WINDOWS
                    if (l_sock_err) {
                         log_it(L_DEBUG, "Socket %d error %d", l_cur->socket, l_sock_err);
#else
                    log_it(L_DEBUG, "Socket %"DAP_FORMAT_SOCKET" will be shutdown (EPOLLHUP), error %d", l_cur->socket, WSAGetLastError());
#endif
                    dap_events_socket_set_readable_unsafe(l_cur, false);
                    dap_events_socket_set_writable_unsafe(l_cur, false);
                    l_cur->buf_out_size = 0;
                    l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                    l_flag_error = l_flag_write = false;
                    if (l_cur->callbacks.error_callback)
                        l_cur->callbacks.error_callback(l_cur, l_sock_err); // Call callback to process error event
#ifndef DAP_OS_WINDOWS
                        log_it(L_INFO, "Socket shutdown (EPOLLHUP): %s", strerror(l_sock_err));
                    }
#endif
                    break;
                }
                default:
                    if(g_debug_reactor)
                        log_it(L_WARNING, "HUP event on esocket %p (%"DAP_FORMAT_SOCKET") type %d", l_cur, l_cur->socket, l_cur->type );
                }
            }

            if(l_flag_nval ){
                log_it(L_WARNING, "NVAL flag armed for socket %p (%"DAP_FORMAT_SOCKET")", l_cur, l_cur->socket);
                l_cur->buf_out_size = 0;
                l_cur->buf_in_size = 0;
                l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                if (l_cur->callbacks.error_callback)
                    l_cur->callbacks.error_callback(l_cur, l_sock_err); // Call callback to process error event
                if (l_cur->fd == 0 || l_cur->fd == -1) {
#ifdef DAP_OS_WINDOWS
                    log_it(L_ERROR, "Wrong fd: %d", l_cur->fd);
#else
                    assert(errno);
#endif
                }
                // If its not null or -1 we should try first to remove it from poll. Assert only if it doesn't help
            }

            if(l_flag_error) {
                switch (l_cur->type ){
                    case DESCRIPTOR_TYPE_SOCKET_LISTENING:
                    case DESCRIPTOR_TYPE_SOCKET_CLIENT:
                        getsockopt(l_cur->socket, SOL_SOCKET, SO_ERROR, (void *)&l_sock_err, (socklen_t *)&l_sock_err_size);
#ifdef DAP_OS_WINDOWS
                        log_it(L_ERROR, "Winsock error: %d", l_sock_err);
#else
                        log_it(L_ERROR, "Socket error: %s", strerror(l_sock_err));
#endif
                    default: ;
                }
                dap_events_socket_set_readable_unsafe(l_cur, false);
                dap_events_socket_set_writable_unsafe(l_cur, false);
                l_cur->buf_out_size = 0;
                if (!l_cur->no_close)
                    l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                if(l_cur->callbacks.error_callback)
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
                if(l_cur->buf_in_size_max && l_cur->buf_in_size >= l_cur->buf_in_size_max ) {
                    log_it(L_WARNING, "Buffer is full when there is smth to read. Its dropped! esocket %p (%"DAP_FORMAT_SOCKET")", l_cur, l_cur->socket);
                    l_cur->buf_in_size = 0;
                }

                bool l_must_read_smth = false;
                switch (l_cur->type) {
                    case DESCRIPTOR_TYPE_PIPE:
                    case DESCRIPTOR_TYPE_FILE:
                        l_must_read_smth = true;
#ifdef DAP_OS_WINDOWS
                        l_bytes_read = dap_recvfrom(l_cur->socket, l_cur->buf_in + l_cur->buf_in_size, l_cur->buf_in_size_max - l_cur->buf_in_size);
#else
                        l_bytes_read = read(l_cur->socket, (char *) (l_cur->buf_in + l_cur->buf_in_size),
                                            l_cur->buf_in_size_max - l_cur->buf_in_size);
#endif
                        l_errno = errno;
                    break;
                    case DESCRIPTOR_TYPE_SOCKET_LOCAL_CLIENT:
                    case DESCRIPTOR_TYPE_SOCKET_CLIENT:
                        l_must_read_smth = true;
                        l_bytes_read = recv(l_cur->fd, (char *) (l_cur->buf_in + l_cur->buf_in_size),
                                            l_cur->buf_in_size_max - l_cur->buf_in_size, 0);
#ifdef DAP_OS_WINDOWS
                        l_errno = WSAGetLastError();
#else
                        l_errno = errno;
#endif
                    break;
                    case DESCRIPTOR_TYPE_SOCKET_UDP: {
                        l_must_read_smth = true;
                        socklen_t l_size = sizeof(l_cur->remote_addr);
                        l_bytes_read = recvfrom(l_cur->fd, (char *) (l_cur->buf_in + l_cur->buf_in_size),
                                                l_cur->buf_in_size_max - l_cur->buf_in_size, 0,
                                                (struct sockaddr *)&l_cur->remote_addr, &l_size);

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
                        l_bytes_read =  wolfSSL_read(l_ssl, (char *) (l_cur->buf_in + l_cur->buf_in_size),
                                                     l_cur->buf_in_size_max - l_cur->buf_in_size);
                        l_errno = wolfSSL_get_error(l_ssl, 0);
                        if (l_bytes_read > 0 && g_debug_reactor)
                            log_it(L_DEBUG, "SSL read: %s", (char *)(l_cur->buf_in + l_cur->buf_in_size));
#endif
                    }
                    break;
                    case DESCRIPTOR_TYPE_SOCKET_LOCAL_LISTENING:
                    case DESCRIPTOR_TYPE_SOCKET_LISTENING:
                        // Accept connection
                        if ( l_cur->callbacks.accept_callback){
                            struct sockaddr l_remote_addr;
                            socklen_t l_remote_addr_size= sizeof (l_remote_addr);
                            SOCKET l_remote_socket = accept(l_cur->socket ,&l_remote_addr,&l_remote_addr_size);
#ifdef DAP_OS_WINDOWS
                            /*u_long l_mode = 1;
                            ioctlsocket((SOCKET)l_remote_socket, (long)FIONBIO, &l_mode); */
                            // no need, since l_cur->socket is already NBIO
                            if (l_remote_socket == INVALID_SOCKET) {
                                int l_errno = WSAGetLastError();
                                if (l_errno == WSAEWOULDBLOCK)
                                    continue;
                                else {
                                    log_it(L_WARNING,"Can't accept on socket %"DAP_FORMAT_SOCKET", WSA errno: %d", l_cur->socket, l_errno);
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
                                    log_it(L_WARNING,"accept() on socket %d error:\"%s\"(%d)",l_cur->socket, l_errbuf,l_errno);
                                    break;
                                }
                            }
#endif
                            l_cur->callbacks.accept_callback(l_cur,l_remote_socket,&l_remote_addr);
                        }else
                            log_it(L_ERROR,"No accept_callback on listening socket");
                    break;
                    case DESCRIPTOR_TYPE_TIMER:{
                        /* if we not reading data from socket, he triggered again */
#ifdef DAP_OS_WINDOWS
                        l_bytes_read = dap_recvfrom(l_cur->socket, NULL, 0);
#else
                        uint64_t val;
                        read( l_cur->fd, &val, 8);
#endif
                        if (l_cur->callbacks.timer_callback)
                            l_cur->callbacks.timer_callback(l_cur);
                        else
                            log_it(L_ERROR, "Socket %"DAP_FORMAT_SOCKET" with timer callback fired, but callback is NULL ", l_cur->socket);

                    } break;
                    case DESCRIPTOR_TYPE_QUEUE:
#ifdef DAP_OS_WINDOWS
                        l_bytes_read = dap_recvfrom(l_cur->socket, NULL, 0);
#endif
                        dap_events_socket_queue_proc_input_unsafe(l_cur);
                        dap_events_socket_set_writable_unsafe(l_cur, false);
                    break;
                    case DESCRIPTOR_TYPE_EVENT:
#ifdef DAP_OS_WINDOWS
                        l_bytes_read = dap_recvfrom(l_cur->socket, NULL, 0);
#endif
                        dap_events_socket_event_proc_input_unsafe(l_cur);
                    break;
                }

                if (l_must_read_smth){ // Socket/Descriptor read
                    if(l_bytes_read > 0) {
                        if (l_cur->type == DESCRIPTOR_TYPE_SOCKET_CLIENT  || l_cur->type == DESCRIPTOR_TYPE_SOCKET_UDP) {
                            l_cur->last_time_active = l_cur_time;
                        }
                        l_cur->buf_in_size += l_bytes_read;
                        if(g_debug_reactor)
                            log_it(L_DEBUG, "Received %zd bytes for fd %d ", l_bytes_read, l_cur->fd);
                        if(l_cur->callbacks.read_callback){
                            l_cur->callbacks.read_callback(l_cur, NULL); // Call callback to process read event. At the end of callback buf_in_size should be zero if everything was read well
                            if (l_cur->context == NULL ){ // esocket was unassigned in callback, we don't need any ops with it now,
                                                         // continue to poll another esockets
                                continue;
                            }
                        }else{
                            log_it(L_WARNING, "We have incomming %zd data but no read callback on socket %"DAP_FORMAT_SOCKET", removing from read set",
                                   l_bytes_read, l_cur->socket);
                            dap_events_socket_set_readable_unsafe(l_cur,false);
                        }
                    }
                    else if(l_bytes_read < 0) {
#ifdef DAP_OS_WINDOWS
                        if (l_cur->type != DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_errno != WSAEWOULDBLOCK) {
                            log_it(L_ERROR, "Can't recv on socket %zu, WSA error: %d", l_cur->socket, l_errno);
#else
                        if (l_cur->type != DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_errno != EAGAIN && l_errno != EWOULDBLOCK)
                        { // If we have non-blocking socket
                            log_it(L_ERROR, "Some error occured in recv() function: %s", strerror(errno));
#endif
                            dap_events_socket_set_readable_unsafe(l_cur, false);
                            if (!l_cur->no_close)
                                l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_cur->buf_out_size = 0;
                        }
#ifndef DAP_NET_CLIENT_NO_SSL
                        if (l_cur->type == DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_errno != SSL_ERROR_WANT_READ && l_errno != SSL_ERROR_WANT_WRITE) {
                            char l_err_str[80];
                            wolfSSL_ERR_error_string(l_errno, l_err_str);
                            log_it(L_ERROR, "Some error occured in SSL read(): %s (code %d)", l_err_str, l_errno);
                            dap_events_socket_set_readable_unsafe(l_cur, false);
                            if (!l_cur->no_close)
                                l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_cur->buf_out_size = 0;
                        }
#endif
                    }
                    else if (!l_flag_rdhup && !l_flag_error && !(l_cur->flags & DAP_SOCK_CONNECTING )) {
                        log_it(L_DEBUG, "EPOLLIN triggered but nothing to read");
                        //dap_events_socket_set_readable_unsafe(l_cur,false);
                    }
                }
            }

            // Possibly have data to read despite EPOLLRDHUP
            if (l_flag_rdhup){
                switch (l_cur->type ){
                    case DESCRIPTOR_TYPE_SOCKET_UDP:
                    case DESCRIPTOR_TYPE_SOCKET_CLIENT:
                    case DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL:
                            dap_events_socket_set_readable_unsafe(l_cur, false);
                            dap_events_socket_set_writable_unsafe(l_cur, false);
                            l_cur->buf_out_size = 0;
                            l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_flag_error = l_flag_write = false;
                    break;
                    default:{}
                }
                if(g_debug_reactor)
                    log_it(L_DEBUG, "RDHUP event on esocket %p (%"DAP_FORMAT_SOCKET") type %d", l_cur, l_cur->socket, l_cur->type);
            }

            // If its outgoing connection
            if ((l_flag_write && !l_cur->server && l_cur->flags & DAP_SOCK_CONNECTING && l_cur->type == DESCRIPTOR_TYPE_SOCKET_CLIENT) ||
                  (l_cur->type == DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_cur->flags & DAP_SOCK_CONNECTING)) {
                if (l_cur->type == DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL) {
#ifndef DAP_NET_CLIENT_NO_SSL
                    WOLFSSL *l_ssl = SSL(l_cur);
                    int l_res = wolfSSL_negotiate(l_ssl);
                    if (l_res != WOLFSSL_SUCCESS) {
                        char l_err_str[80];
                        int l_err = wolfSSL_get_error(l_ssl, l_res);
                        if (l_err != WOLFSSL_ERROR_WANT_READ && l_err != WOLFSSL_ERROR_WANT_WRITE) {
                            wolfSSL_ERR_error_string(l_err, l_err_str);
                            log_it(L_ERROR, "SSL handshake error \"%s\" with code %d", l_err_str, l_err);
                            if ( l_cur->callbacks.error_callback )
                                l_cur->callbacks.error_callback(l_cur, l_error);
                        }
                    } else {
                        if(g_debug_reactor)
                            log_it(L_NOTICE, "SSL handshake done with %s", l_cur->remote_addr_str ? l_cur->remote_addr_str: "(NULL)");
                        l_cur->flags ^= DAP_SOCK_CONNECTING;
                        if (l_cur->callbacks.connected_callback)
                            l_cur->callbacks.connected_callback(l_cur);
                        dap_context_poll_update(l_cur);
                    }
#endif
                } else {
                    l_error_len = sizeof(l_errno);

                    getsockopt(l_cur->socket, SOL_SOCKET, SO_ERROR, (void *)&l_errno, &l_error_len);
                    if(l_errno == EINPROGRESS) {
                        log_it(L_DEBUG, "Connecting with %s in progress...", l_cur->remote_addr_str ? l_cur->remote_addr_str: "(NULL)");
                    }else if (l_errno){
                        strerror_r(l_errno, l_error_buf, sizeof (l_error_buf));
                        log_it(L_ERROR,"Connecting error with %s: \"%s\" (code %d)", l_cur->remote_addr_str ? l_cur->remote_addr_str: "(NULL)",
                               l_error_buf, l_errno);
                        if ( l_cur->callbacks.error_callback )
                            l_cur->callbacks.error_callback(l_cur, l_errno);
                    }else{
                        if(g_debug_reactor)
                            log_it(L_NOTICE, "Connected with %s",l_cur->remote_addr_str ? l_cur->remote_addr_str: "(NULL)");
                        l_cur->flags ^= DAP_SOCK_CONNECTING;
                        if (l_cur->callbacks.connected_callback)
                            l_cur->callbacks.connected_callback(l_cur);
                        dap_context_poll_update(l_cur);
                    }
                }
            }

            l_bytes_sent = 0;

            if (l_flag_write && (l_cur->flags & DAP_SOCK_READY_TO_WRITE) && !(l_cur->flags & DAP_SOCK_SIGNAL_CLOSE)) {
                debug_if (g_debug_reactor, L_DEBUG, "Main loop output: %zu bytes to send", l_cur->buf_out_size);
                /*
                 * Socket is ready to write and not going to close
                 */
                if ( !l_cur->buf_out_size )                                     /* Check firstly that output buffer is not empty */
                {
                    dap_events_socket_set_writable_unsafe(l_cur, false);        /* Clear "enable write flag" */

                    if ( l_cur->callbacks.write_finished_callback )             /* Optionaly call I/O completion routine */
                        l_cur->callbacks.write_finished_callback(l_cur, l_cur->callbacks.arg, l_errno);

                    l_flag_write = 0;                                           /* Clear flag to exclude unecessary processing of output */
                }

                if (l_cur->callbacks.write_callback)
                    l_cur->callbacks.write_callback(l_cur, NULL);           /* Call callback to process write event */

                if ( l_cur->context && l_flag_write ){ // esocket wasn't unassigned in callback, we need some other ops with it
                        switch (l_cur->type){
                            case DESCRIPTOR_TYPE_SOCKET_CLIENT: {
                                l_bytes_sent = send(l_cur->socket, (const char *)l_cur->buf_out,
                                                    l_cur->buf_out_size, MSG_DONTWAIT | MSG_NOSIGNAL);
#ifdef DAP_OS_WINDOWS
                                //dap_events_socket_set_writable_unsafe(l_cur,false); // enabling this will break windows server replies
                                l_errno = WSAGetLastError();
#else
                                l_errno = errno;
#endif
                            }
                            break;
                            case DESCRIPTOR_TYPE_SOCKET_UDP:
                                l_bytes_sent = sendto(l_cur->socket, (const char *)l_cur->buf_out,
                                                      l_cur->buf_out_size, MSG_DONTWAIT | MSG_NOSIGNAL,
                                                      (struct sockaddr *)&l_cur->remote_addr, sizeof(l_cur->remote_addr));
#ifdef DAP_OS_WINDOWS
                                dap_events_socket_set_writable_unsafe(l_cur,false);
                                l_errno = WSAGetLastError();
#else
                                l_errno = errno;
#endif
                            break;
                            case DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL: {
#ifndef DAP_NET_CLIENT_NO_SSL
                                WOLFSSL *l_ssl = SSL(l_cur);
                                l_bytes_sent = wolfSSL_write(l_ssl, (char *)(l_cur->buf_out), l_cur->buf_out_size);
                                if (l_bytes_sent > 0)
                                    log_it(L_DEBUG, "SSL write: %s", (char *)(l_cur->buf_out));
                                l_errno = wolfSSL_get_error(l_ssl, 0);
#endif
                            }
                            case DESCRIPTOR_TYPE_QUEUE:
                                 if (l_cur->flags & DAP_SOCK_QUEUE_PTR && l_cur->buf_out_size>= sizeof (void*)){
#if defined(DAP_EVENTS_CAPS_QUEUE_PIPE2)
                                    l_bytes_sent = write(l_cur->socket, l_cur->buf_out, sizeof (void *) ); // We send pointer by pointer
#elif defined (DAP_EVENTS_CAPS_QUEUE_POSIX)
                                    l_bytes_sent = mq_send(a_es->mqd, (const char *)&a_arg,sizeof (a_arg),0);
#elif defined DAP_EVENTS_CAPS_MSMQ
                                     DWORD l_mp_id = 0;
                                     MQMSGPROPS    l_mps;
                                     MQPROPVARIANT l_mpvar[1];
                                     MSGPROPID     l_p_id[1];
                                     HRESULT       l_mstatus[1];

                                     l_p_id[l_mp_id] = PROPID_M_BODY;
                                     l_mpvar[l_mp_id].vt = VT_VECTOR | VT_UI1;
                                     l_mpvar[l_mp_id].caub.pElems = l_cur->buf_out;
                                     l_mpvar[l_mp_id].caub.cElems = (u_long)sizeof(void*);
                                     l_mp_id++;

                                     l_mps.cProp = l_mp_id;
                                     l_mps.aPropID = l_p_id;
                                     l_mps.aPropVar = l_mpvar;
                                     l_mps.aStatus = l_mstatus;
                                     HRESULT hr = MQSendMessage(l_cur->mqh, &l_mps, MQ_NO_TRANSACTION);

                                     if (hr != MQ_OK) {
                                         l_errno = hr;
                                         log_it(L_ERROR, "An error occured on sending message to queue, errno: %ld", hr);
                                         break;
                                     } else {
                                         l_errno = WSAGetLastError();

                                         if(dap_sendto(l_cur->socket, l_cur->port, NULL, 0) == SOCKET_ERROR) {
                                             log_it(L_ERROR, "Write to socket error: %d", WSAGetLastError());
                                         }
                                         l_bytes_sent = sizeof(void*);

                                     }
#elif defined (DAP_EVENTS_CAPS_QUEUE_MQUEUE)
                                    l_bytes_sent = mq_send(l_cur->mqd , (const char *)l_cur->buf_out,sizeof (void*),0);
                                    if(l_bytes_sent == 0)
                                        l_bytes_sent = sizeof (void*);
                                    l_errno = errno;
                                    if (l_bytes_sent == -1 && l_errno == EINVAL) // To make compatible with other
                                        l_errno = EAGAIN;                        // non-blocking sockets
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
                                    struct kevent* l_event=&l_cur->kqueue_event;
                                    dap_events_socket_w_data_t * l_es_w_data = DAP_NEW_Z(dap_events_socket_w_data_t);
                                    l_es_w_data->esocket = l_cur;
                                    memcpy(&l_es_w_data->ptr, l_cur->buf_out,sizeof(l_cur));
                                    EV_SET(l_event,l_cur->socket, l_cur->kqueue_base_filter,l_cur->kqueue_base_flags, l_cur->kqueue_base_fflags,l_cur->kqueue_data, l_es_w_data);
                                    int l_n = kevent(a_context->kqueue_fd,l_event,1,NULL,0,NULL);
                                    if (l_n == 1){
                                        l_bytes_sent = sizeof(l_cur);
                                    }else{
                                        l_errno = errno;
                                        log_it(L_WARNING,"queue ptr send error: kevent %p errno: %d", l_es_w_data, l_errno);
                                        DAP_DELETE(l_es_w_data);
                                    }

#else
#error "Not implemented dap_events_socket_queue_ptr_send() for this platform"
#endif
                                }else{
                                     assert("Not implemented non-ptr queue send from outgoing buffer");
                                     // TODO Implement non-ptr queue output
                                 }
                            break;
                            case DESCRIPTOR_TYPE_PIPE:
                            case DESCRIPTOR_TYPE_FILE:
                                l_bytes_sent = write(l_cur->fd, (char *) (l_cur->buf_out), l_cur->buf_out_size );
                                l_errno = errno;
                            break;
                            default:
                                log_it(L_WARNING, "Socket %"DAP_FORMAT_SOCKET" is not SOCKET, PIPE or FILE but has WRITE state on. Switching it off", l_cur->socket);
                                dap_events_socket_set_writable_unsafe(l_cur,false);
                        }

                    if(l_bytes_sent < 0) {
#ifdef DAP_OS_WINDOWS
                        if (l_cur->type != DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_errno != WSAEWOULDBLOCK) {
                            log_it(L_ERROR, "Can't send to socket %zu, WSA error: %d", l_cur->socket, l_errno);
#else
                        if (l_cur->type != DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_errno != EAGAIN && l_errno != EWOULDBLOCK)
                        { // If we have non-blocking socket
                            log_it(L_ERROR, "Some error occured in send(): %s (code %d)", strerror(l_errno), l_errno);
#endif
                            if (!l_cur->no_close)
                                l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_cur->buf_out_size = 0;
                        }
#ifndef DAP_NET_CLIENT_NO_SSL
                        if (l_cur->type == DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL && l_errno != SSL_ERROR_WANT_READ && l_errno != SSL_ERROR_WANT_WRITE) {
                            char l_err_str[80];
                            wolfSSL_ERR_error_string(l_errno, l_err_str);
                            log_it(L_ERROR, "Some error occured in SSL write(): %s (code %d)", l_err_str, l_errno);
                            if (!l_cur->no_close)
                                l_cur->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_cur->buf_out_size = 0;
                        }
#endif
                    }else{
                        //log_it(L_DEBUG, "Output: %u from %u bytes are sent ", l_bytes_sent,l_cur->buf_out_size);
                        if (l_bytes_sent) {
                            if (l_cur->type == DESCRIPTOR_TYPE_SOCKET_CLIENT  || l_cur->type == DESCRIPTOR_TYPE_SOCKET_UDP) {
                                l_cur->last_time_active = l_cur_time;
                            }
                            if ( l_bytes_sent <= (ssize_t) l_cur->buf_out_size ){
                                l_cur->buf_out_size -= l_bytes_sent;
                                if (l_cur->buf_out_size ) {
                                    memmove(l_cur->buf_out, &l_cur->buf_out[l_bytes_sent], l_cur->buf_out_size);
                                } else {
                                    /*
                                     * If whole buffer has been sent - clear "write flag" for socket/file descriptor to prevent
                                     * generation of unexpected I/O events like POLLOUT and consuming CPU by this.
                                     */
                                    dap_events_socket_set_writable_unsafe(l_cur, false);/* Clear "enable write flag" */
                                    if ( l_cur->callbacks.write_finished_callback )     /* Optionaly call I/O completion routine */
                                        l_cur->callbacks.write_finished_callback(l_cur, l_cur->callbacks.arg, l_errno);
                                }
                            }else{
                                log_it(L_ERROR, "Wrong bytes sent, %zd more then was in buffer %zd",l_bytes_sent, l_cur->buf_out_size);
                                l_cur->buf_out_size = 0;
                            }
                        }
                    }
                }
            }

            if (l_cur->flags & DAP_SOCK_SIGNAL_CLOSE)
            {
                if (l_cur->buf_out_size == 0) {
                    if(g_debug_reactor)
                        log_it(L_INFO, "Process signal to close %s sock %"DAP_FORMAT_SOCKET" (ptr 0x%p uuid 0x%016"DAP_UINT64_FORMAT_x") type %d [context #%u]",
                           l_cur->remote_addr_str ? l_cur->remote_addr_str : "", l_cur->socket, l_cur, l_cur->uuid,
                               l_cur->type, a_context->id);

                    for (ssize_t nn = n + 1; nn < l_sockets_max; nn++) { // Check for current selection if it has event duplication
                        dap_events_socket_t *l_es_selected = NULL;
#ifdef DAP_EVENTS_CAPS_EPOLL
                        l_es_selected = (dap_events_socket_t *) l_epoll_events[nn].data.ptr;
#elif defined ( DAP_EVENTS_CAPS_POLL)
                        l_es_selected = a_context->poll_esocket[nn];
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
                        struct kevent * l_kevent_selected = &a_context->kqueue_events_selected[n];
                        if ( l_kevent_selected->filter == EVFILT_USER){ // If we have USER event it sends little different pointer
                            dap_events_socket_w_data_t * l_es_w_data = (dap_events_socket_w_data_t *) l_kevent_selected->udata;
                            l_es_selected = l_es_w_data->esocket;
                        }else{
                            l_es_selected = (dap_events_socket_t*) l_kevent_selected->udata;
                        }
#else
#error "No selection esockets left to proc implemenetation"
#endif
                        if(l_es_selected == NULL || l_es_selected == l_cur ){
                            if(l_es_selected == NULL)
                                log_it(L_CRITICAL,"NULL esocket found when cleaning selected list");
                            else if(g_debug_reactor)
                                log_it(L_INFO,"Duplicate esockets removed from selected event list");
                            n=nn; // TODO here we need to make smth like poll() array compressing.
                                  // Here we expect thats event duplicates goes together in it. If not - we lose some events between.
                        }
                    }
                    //dap_events_socket_remove_and_delete_unsafe( l_cur, false);
                    dap_events_remove_and_delete_socket_unsafe(dap_events_get_default(), l_cur, false);
#ifdef DAP_EVENTS_CAPS_KQUEUE
                    a_context->kqueue_events_count--;
#endif
                } else if (l_cur->buf_out_size ) {
                    if(g_debug_reactor)
                        log_it(L_INFO, "Got signal to close %s sock %"DAP_FORMAT_SOCKET" [context #%u] type %d but buffer is not empty(%zu)",
                           l_cur->remote_addr_str ? l_cur->remote_addr_str : "", l_cur->socket, l_cur->type, a_context->id,
                           l_cur->buf_out_size);
                }
            }

        }
#ifdef DAP_EVENTS_CAPS_POLL
        /***********************************************************/
        /* If the compress_array flag was turned on, we need       */
        /* to squeeze together the array and decrement the number  */
        /* of file descriptors.                                    */
        /***********************************************************/
        if ( a_context->poll_compress){
            a_context->poll_compress = false;
            for (size_t i = 0; i < a_context->poll_count ; i++)  {
                if ( a_context->poll[i].fd == -1){
                    if( a_context->poll_count){
                        for(size_t j = i; j < a_context->poll_count-1; j++){
                             a_context->poll[j].fd = a_context->poll[j+1].fd;
                             a_context->poll[j].events = a_context->poll[j+1].events;
                             a_context->poll[j].revents = a_context->poll[j+1].revents;
                             a_context->poll_esocket[j] = a_context->poll_esocket[j+1];
                             if(a_context->poll_esocket[j])
                                 a_context->poll_esocket[j]->poll_index = j;
                        }
                    }
                    i--;
                    a_context->poll_count--;
                }
            }
        }
#endif
    } while(!a_context->signal_exit);

    log_it(L_ATT,"Context :%u finished", a_context->id);
    return 0;
}


/**
 * @brief dap_context_poll_update
 * @param a_esocket
 */
void dap_context_poll_update(dap_events_socket_t * a_esocket)
{
    #if defined (DAP_EVENTS_CAPS_EPOLL)
        int events = a_esocket->ev_base_flags | EPOLLERR;

        // Check & add
        if( a_esocket->flags & DAP_SOCK_READY_TO_READ )
            events |= EPOLLIN;

        if( a_esocket->flags & DAP_SOCK_READY_TO_WRITE || a_esocket->flags &DAP_SOCK_CONNECTING )
            events |= EPOLLOUT;

        a_esocket->ev.events = events;

        if( a_esocket->context){
            if ( epoll_ctl(a_esocket->context->epoll_fd, EPOLL_CTL_MOD, a_esocket->socket, &a_esocket->ev) ){
#ifdef DAP_OS_WINDOWS
                int l_errno = WSAGetLastError();
#else
                int l_errno = errno;
#endif
                char l_errbuf[128];
                l_errbuf[0]=0;
                strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                log_it(L_ERROR,"Can't update client socket state in the epoll_fd %"DAP_FORMAT_HANDLE": \"%s\" (%d)",
                       a_esocket->context->epoll_fd, l_errbuf, l_errno);
            }
        }
    #elif defined (DAP_EVENTS_CAPS_POLL)
        if( a_esocket->context && a_esocket->is_initalized){
            if (a_esocket->poll_index < a_esocket->context->poll_count ){
                struct pollfd * l_poll = &a_esocket->context->poll[a_esocket->poll_index];
                l_poll->events = a_esocket->poll_base_flags | POLLERR ;
                // Check & add
                if( a_esocket->flags & DAP_SOCK_READY_TO_READ )
                    l_poll->events |= POLLIN;
                if( a_esocket->flags & DAP_SOCK_READY_TO_WRITE || a_esocket->flags &DAP_SOCK_CONNECTING )
                    l_poll->events |= POLLOUT;
            }else{
                log_it(L_ERROR, "Wrong poll index when remove from context (unsafe): %u when total count %u", a_esocket->poll_index,
                       a_esocket->context->poll_count);
            }
        }
    #elif defined (DAP_EVENTS_CAPS_KQUEUE)
    if (a_esocket->socket != -1  ){ // Not everything we add in poll
        struct kevent * l_event = &a_esocket->kqueue_event;
        short l_filter  =a_esocket->kqueue_base_filter;
        u_short l_flags =a_esocket->kqueue_base_flags;
        u_int l_fflags =a_esocket->kqueue_base_fflags;

        int l_kqueue_fd = a_esocket->context? a_esocket->context->kqueue_fd : -1;
        if ( l_kqueue_fd == -1 ){
            log_it(L_ERROR, "Esocket is not assigned with anything ,exit");
        }

        // Check & add
        bool l_is_error=false;
        int l_errno=0;
        if (a_esocket->type == DESCRIPTOR_TYPE_EVENT ){
            EV_SET(l_event, a_esocket->socket, EVFILT_USER,EV_ADD| EV_CLEAR ,0,0, &a_esocket->kqueue_event_catched_data );
            if( kevent( l_kqueue_fd,l_event,1,NULL,0,NULL) == -1){
                l_is_error = true;
                l_errno = errno;
            }
        }else{
            EV_SET(l_event, a_esocket->socket, l_filter,l_flags| EV_ADD,l_fflags,a_esocket->kqueue_data,a_esocket);
            if( a_esocket->flags & DAP_SOCK_READY_TO_READ ){
                EV_SET(l_event, a_esocket->socket, EVFILT_READ,l_flags| EV_ADD,l_fflags,a_esocket->kqueue_data,a_esocket);
                if( kevent( l_kqueue_fd,l_event,1,NULL,0,NULL) == -1 ){
                    l_is_error = true;
                    l_errno = errno;
                }
            }
            if( !l_is_error){
                if( a_esocket->flags & DAP_SOCK_READY_TO_WRITE || a_esocket->flags &DAP_SOCK_CONNECTING ){
                    EV_SET(l_event, a_esocket->socket, EVFILT_WRITE,l_flags| EV_ADD,l_fflags,a_esocket->kqueue_data,a_esocket);
                    if(kevent( l_kqueue_fd,l_event,1,NULL,0,NULL) == -1){
                        l_is_error = true;
                        l_errno = errno;
                    }
                }
            }
        }
        if (l_is_error && l_errno == EBADF){
            log_it(L_ATT,"Poll update: socket %d (%p ) disconnected, rise CLOSE flag to remove from queue, lost %"DAP_UINT64_FORMAT_U":%" DAP_UINT64_FORMAT_U
                         " bytes",a_esocket->socket,a_esocket,a_esocket->buf_in_size,a_esocket->buf_out_size);
            a_esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
            a_esocket->buf_in_size = a_esocket->buf_out_size = 0; // Reset everything from buffer, we close it now all
        }else if ( l_is_error && l_errno != EINPROGRESS && l_errno != ENOENT){
            char l_errbuf[128];
            l_errbuf[0]=0;
            strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
            log_it(L_ERROR,"Can't update client socket state on kqueue fd %d: \"%s\" (%d)",
                l_kqueue_fd, l_errbuf, l_errno);
        }
     }

    #else
    #error "Not defined dap_events_socket_set_writable_unsafe for your platform"
    #endif

}


/**
 * @brief dap_context_add_events_socket_unsafe
 * @param IOa_context
 * @param a_esocket
 */
int dap_context_add_esocket(dap_context_t * a_context, dap_events_socket_t * a_esocket )
{
    if(g_debug_reactor){
        log_it(L_DEBUG,"Add event socket %p (socket %"DAP_FORMAT_SOCKET")", a_esocket, a_esocket->socket);
    }
#ifdef DAP_EVENTS_CAPS_EPOLL
        // Init events for EPOLL
        a_esocket->ev.events = a_esocket->ev_base_flags ;
        if(a_esocket->flags & DAP_SOCK_READY_TO_READ )
            a_esocket->ev.events |= EPOLLIN;
        if(a_esocket->flags & DAP_SOCK_READY_TO_WRITE )
            a_esocket->ev.events |= EPOLLOUT;
        a_esocket->ev.data.ptr = a_esocket;
        a_esocket->context = a_context;
        return epoll_ctl(a_context->epoll_fd, EPOLL_CTL_ADD, a_esocket->socket, &a_esocket->ev);
#elif defined (DAP_EVENTS_CAPS_POLL)
    if (  a_context->poll_count == a_context->poll_count_max ){ // realloc
        a_context->poll_count_max *= 2;
        log_it(L_WARNING, "Too many descriptors (%u), resizing array twice to %zu", a_context->poll_count, a_context->poll_count_max);
        a_context->poll =DAP_REALLOC(a_context->poll, a_context->poll_count_max * sizeof(*a_context->poll));
        a_context->poll_esocket =DAP_REALLOC(a_context->poll_esocket, a_context->poll_count_max * sizeof(*a_context->poll_esocket));
    }
    a_context->poll[a_context->poll_count].fd = a_esocket->socket;
    a_esocket->poll_index = a_context->poll_count;
    a_context->poll[a_context->poll_count].events = a_esocket->poll_base_flags;
    if( a_esocket->flags & DAP_SOCK_READY_TO_READ )
        a_context->poll[a_context->poll_count].events |= POLLIN;
    if( (a_esocket->flags & DAP_SOCK_READY_TO_WRITE) || (a_esocket->flags & DAP_SOCK_CONNECTING) )
        a_context->poll[a_context->poll_count].events |= POLLOUT;


    a_context->poll_esocket[a_context->poll_count] = a_esocket;
    a_context->poll_count++;
    a_esocket->context = a_context;
    return 0;
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
    if ( a_esocket->type == DESCRIPTOR_TYPE_QUEUE ){
        a_esocket->context = a_context;
        return 0;
    }
    if ( a_esocket->type == DESCRIPTOR_TYPE_EVENT && a_esocket->pipe_out){
        a_esocket->context = a_context;
        return 0;
    }
    struct kevent l_event;
    u_short l_flags = a_esocket->kqueue_base_flags;
    u_int   l_fflags = a_esocket->kqueue_base_fflags;
    short l_filter = a_esocket->kqueue_base_filter;
    int l_kqueue_fd =a_context->kqueue_fd;
    if ( l_kqueue_fd == -1 ){
        log_it(L_ERROR, "Esocket is not assigned with anything ,exit");
        return -1;
    }
    // Check & add
    bool l_is_error=false;
    int l_errno=0;
    if (a_esocket->type == DESCRIPTOR_TYPE_EVENT ){
        EV_SET(&l_event, a_esocket->socket, EVFILT_USER,EV_ADD| EV_CLEAR ,0,0, &a_esocket->kqueue_event_catched_data );
        if( kevent( l_kqueue_fd,&l_event,1,NULL,0,NULL)!=0){
            l_is_error = true;
            l_errno = errno;
        }
    }else{
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
    }else{
        a_esocket->context = a_context;
        return 0;
    }
#else
#error "Unimplemented new esocket on context callback for current platform"
#endif

}


/**
 * @brief dap_context_esocket_find_by_uuid
 * @param a_context
 * @param a_es_uuid
 * @return
 */
dap_events_socket_t *dap_context_esocket_find_by_uuid(dap_context_t * a_context, dap_events_socket_uuid_t a_es_uuid )
{
    if(a_context == NULL){
        log_it(L_ERROR, "Worker is NULL, can't fund esocket by UUID");
        return NULL;
    }
    dap_events_socket_t * l_ret = NULL;
    if(a_context->esockets ) {
        //HASH_FIND_PTR( a_worker->context->esockets, &a_es_uuid,l_ret );
        HASH_FIND(hh_worker, a_context->esockets, &a_es_uuid, sizeof(a_es_uuid), l_ret );
    }
    return l_ret;
}
