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


#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include "wepoll.h"
#include <pthread.h>
#endif

#include "dap_common.h"
#include "dap_worker.h"
#include "dap_events.h"

#include "dap_events_socket.h"

#define LOG_TAG "dap_events_socket"

/**
 * @brief dap_events_socket_init Init clients module
 * @return Zero if ok others if no
 */
int dap_events_socket_init( )
{
    log_it(L_NOTICE,"Initialized events socket module");
#if defined (DAP_EVENTS_CAPS_QUEUE_POSIX)
#ifdef DAP_OS_LINUX
#include <sys/time.h>
#include <sys/resource.h>

    struct rlimit l_mqueue_limit;
    l_mqueue_limit.rlim_cur = 1024;
    l_mqueue_limit.rlim_max = 1024;
//    setrlimit(RLIMIT_MSGQUEUE,&l_mqueue_limit);
#endif
#endif
    dap_timerfd_init();
    return 0;
}

/**
 * @brief dap_events_socket_deinit Deinit clients module
 */
void dap_events_socket_deinit( )
{

}


/**
 * @brief dap_events_socket_wrap
 * @param a_events
 * @param w
 * @param s
 * @param a_callbacks
 * @return
 */
dap_events_socket_t *dap_events_socket_wrap_no_add( dap_events_t *a_events,
                                            int a_sock, dap_events_socket_callbacks_t *a_callbacks )
{
    assert(a_events);
    assert(a_callbacks);

    dap_events_socket_t *ret = DAP_NEW_Z( dap_events_socket_t );

    ret->socket = a_sock;
    ret->events = a_events;
    memcpy(&ret->callbacks, a_callbacks, sizeof(ret->callbacks) );
    ret->flags = DAP_SOCK_READY_TO_READ;

    #if defined(DAP_EVENTS_CAPS_EPOLL)
    ret->ev_base_flags = EPOLLERR | EPOLLRDHUP | EPOLLHUP;
    #endif

    if ( a_sock!= 0 && a_sock != -1){
        pthread_rwlock_wrlock(&a_events->sockets_rwlock);
        HASH_ADD(hh,a_events->sockets, socket, sizeof (int), ret);
        pthread_rwlock_unlock(&a_events->sockets_rwlock);
    }else
        log_it(L_WARNING, "Be carefull, you've wrapped socket 0 or -1 so it wasn't added to global list. Do it yourself when possible");

    //log_it( L_DEBUG,"Dap event socket wrapped around %d sock a_events = %X", a_sock, a_events );

    return ret;
}

/**
 * @brief dap_events_socket_assign_on_worker
 * @param a_es
 * @param a_worker
 */
void dap_events_socket_assign_on_worker_mt(dap_events_socket_t * a_es, struct dap_worker * a_worker)
{
    a_es->last_ping_request = time(NULL);
   // log_it(L_DEBUG, "Assigned %p on worker %u", a_es, a_worker->id);
    dap_worker_add_events_socket(a_es,a_worker);
}


void dap_events_socket_reassign_between_workers_unsafe(dap_events_socket_t * a_es, dap_worker_t * a_worker_new)
{
    log_it(L_DEBUG, "reassign between workers");
    dap_events_socket_remove_from_worker_unsafe( a_es, a_es->worker );
    a_es->was_reassigned = true;
    if (a_es->callbacks.worker_unassign_callback)
        a_es->callbacks.worker_unassign_callback(a_es, a_es->worker);

    dap_events_socket_assign_on_worker_mt( a_es, a_worker_new );
}

void dap_events_socket_reassign_between_workers_mt(dap_worker_t * a_worker_old, dap_events_socket_t * a_es, dap_worker_t * a_worker_new)
{
    dap_worker_msg_reassign_t * l_msg = DAP_NEW_Z(dap_worker_msg_reassign_t);
    l_msg->esocket = a_es;
    l_msg->worker_new = a_worker_new;
    dap_events_socket_queue_ptr_send(a_worker_old->queue_es_reassign, l_msg);

}

/**
 * @brief dap_events_socket_assign_on_worker_unsafe
 * @param a_es
 * @param a_worker
 */
void dap_events_socket_assign_on_worker_unsafe(dap_events_socket_t * a_es, struct dap_worker * a_worker)
{
#if defined(DAP_EVENTS_CAPS_EPOLL)
    int l_event_fd = a_es->fd;
    //log_it( L_INFO, "Create event descriptor with queue %d (%p) and add it on epoll fd %d", l_event_fd, l_es, a_w->epoll_fd);
    a_es->ev.events = a_es->ev_base_flags;
    a_es->ev.data.ptr = a_es;
    epoll_ctl(a_worker->epoll_fd, EPOLL_CTL_ADD, l_event_fd, &a_es->ev);
#endif
}

/**
 * @brief s_create_type_pipe
 * @param a_w
 * @param a_callback
 * @param a_flags
 * @return
 */
dap_events_socket_t * s_create_type_pipe(dap_worker_t * a_w, dap_events_socket_callback_t a_callback, uint32_t a_flags)
{
    UNUSED(a_flags);
    dap_events_socket_t * l_es = DAP_NEW_Z(dap_events_socket_t);
    l_es->type = DESCRIPTOR_TYPE_PIPE;
    l_es->worker = a_w;
    l_es->events = a_w->events;
    l_es->callbacks.read_callback = a_callback; // Arm event callback
    l_es->ev_base_flags = EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP;

#if defined(DAP_EVENTS_CAPS_PIPE_POSIX)
    int l_pipe[2];
    int l_errno;
    char l_errbuf[128];
    if( pipe(l_pipe) < 0 ){
        l_errno = errno;
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        log_it( L_ERROR, "Error detected, can't create pipe(): '%s' (%d)", l_errbuf, l_errno);
        DAP_DELETE(l_es);
        return NULL;
    }//else
     //   log_it(L_DEBUG, "Created one-way unnamed bytestream pipe %d->%d", l_pipe[0], l_pipe[1]);
    l_es->fd = l_pipe[0];
    l_es->fd2 = l_pipe[1];
#else
#error "No defined s_create_type_pipe() for your platform"
#endif
    return l_es;
}

/**
 * @brief dap_events_socket_create_type_pipe_mt
 * @param a_w
 * @param a_callback
 * @param a_flags
 * @return
 */
dap_events_socket_t * dap_events_socket_create_type_pipe_mt(dap_worker_t * a_w, dap_events_socket_callback_t a_callback, uint32_t a_flags)
{
    dap_events_socket_t * l_es = s_create_type_pipe(a_w, a_callback, a_flags);
    dap_events_socket_assign_on_worker_unsafe(l_es,a_w);
    return  l_es;
}

/**
 * @brief dap_events_socket_create_type_pipe_unsafe
 * @param a_w
 * @param a_callback
 * @param a_flags
 * @return
 */
dap_events_socket_t * dap_events_socket_create_type_pipe_unsafe(dap_worker_t * a_w, dap_events_socket_callback_t a_callback, uint32_t a_flags)
{
    dap_events_socket_t * l_es = s_create_type_pipe(a_w, a_callback, a_flags);
    dap_events_socket_assign_on_worker_unsafe(l_es,a_w);
    return  l_es;
}

/**
 * @brief s_create_type_queue
 * @param a_w
 * @param a_flags
 * @return
 */
dap_events_socket_t * s_create_type_queue_ptr(dap_worker_t * a_w, dap_events_socket_callback_queue_ptr_t a_callback)
{
    dap_events_socket_t * l_es = DAP_NEW_Z(dap_events_socket_t);
    l_es->type = DESCRIPTOR_TYPE_QUEUE;
    l_es->flags =  DAP_SOCK_QUEUE_PTR;
    if (a_w){
        l_es->events = a_w->events;
        l_es->worker = a_w;
    }
    l_es->callbacks.queue_ptr_callback = a_callback; // Arm event callback
    l_es->ev_base_flags = EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP;

#ifdef DAP_EVENTS_CAPS_QUEUE_PIPE2
    int l_pipe[2];
    int l_errno;
    char l_errbuf[128];
    if( pipe2(l_pipe,O_DIRECT) < 0 ){
        l_errno = errno;
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        switch (l_errno) {
            case EINVAL: log_it(L_CRITICAL, "Too old linux version thats doesn't support O_DIRECT flag for pipes (%s)", l_errbuf); break;
            default: log_it( L_ERROR, "Error detected, can't create pipe(): '%s' (%d)", l_errbuf, l_errno);
        }
        DAP_DELETE(l_es);
        return NULL;
    }//else
     //   log_it(L_DEBUG, "Created one-way unnamed packet pipe %d->%d", l_pipe[0], l_pipe[1]);
    l_es->fd = l_pipe[0];
    l_es->fd2 = l_pipe[1];
    const int l_file_buf_size = 64;
    FILE* l_sys_max_pipe_size_fd = fopen("/proc/sys/fs/pipe-max-size", "r");
    if (l_sys_max_pipe_size_fd == NULL) {
        log_it(L_WARNING, "Сan't resize pipe buffer");
    }
    char l_file_buf[l_file_buf_size];
    memset(l_file_buf, 0, l_file_buf_size);
    fread(l_file_buf, l_file_buf_size, 1, l_sys_max_pipe_size_fd);
    uint64_t l_sys_max_pipe_size = strtoull(l_file_buf, 0, 10);
    if (l_sys_max_pipe_size && fcntl(l_pipe[0], F_SETPIPE_SZ, l_sys_max_pipe_size) == l_sys_max_pipe_size) {
        log_it(L_DEBUG, "Successfully resized pipe buffer to %lld", l_sys_max_pipe_size);
    }
#elif defined (DAP_EVENTS_CAPS_QUEUE_POSIX)
    char l_mq_name[64];
    struct mq_attr l_mq_attr ={0};
    l_mq_attr.mq_curmsgs = 9;
    l_mq_attr.mq_maxmsg = 9; // Don't think we need to hold more than 1024 messages
    l_mq_attr.mq_msgsize = sizeof (void *); // We send only pointer on memory,
                                            // so use it with shared memory if you do access from another process
    snprintf(l_mq_name,sizeof (l_mq_name),"/dap-%d-esocket-0x%p",getpid(),l_es);

    l_es->mqd = mq_open(l_mq_name,O_CREAT|O_RDWR,S_IRWXU, &l_mq_attr);
    if (l_es->mqd == -1 ){
        int l_errno = errno;
        char l_errbuf[128]={0};
        strerror_r(l_errno,l_errbuf,sizeof (l_errbuf) );
        DAP_DELETE(l_es);
        l_es = NULL;
        log_it(L_CRITICAL,"Can't create mqueue descriptor %s: \"%s\" code %d",l_mq_name, l_errbuf, l_errno);
    }
#else
#error "Not implemented s_create_type_queue_ptr() on your platform"
#endif
    return l_es;
}

/**
 * @brief dap_events_socket_create_type_queue_mt
 * @param a_w
 * @param a_callback
 * @param a_flags
 * @return
 */
dap_events_socket_t * dap_events_socket_create_type_queue_ptr_mt(dap_worker_t * a_w, dap_events_socket_callback_queue_ptr_t a_callback)
{
    dap_events_socket_t * l_es = s_create_type_queue_ptr(a_w, a_callback);
    assert(l_es);
    // If no worker - don't assign
    if ( a_w)
        dap_events_socket_assign_on_worker_mt(l_es,a_w);
    return  l_es;
}


/**
 * @brief dap_events_socket_create_type_queue
 * @param a_w
 * @param a_callback
 * @return
 */
dap_events_socket_t * dap_events_socket_create_type_queue_ptr_unsafe(dap_worker_t * a_w, dap_events_socket_callback_queue_ptr_t a_callback)
{
    dap_events_socket_t * l_es = s_create_type_queue_ptr(a_w, a_callback);
    assert(l_es);
    // If no worker - don't assign
    if ( a_w)
        dap_events_socket_assign_on_worker_unsafe(l_es,a_w);
    return  l_es;
}

/**
 * @brief dap_events_socket_queue_proc_input
 * @param a_esocket
 */
int dap_events_socket_queue_proc_input_unsafe(dap_events_socket_t * a_esocket)
{
    if (a_esocket->callbacks.queue_callback){
        if (a_esocket->flags & DAP_SOCK_QUEUE_PTR){
            void * l_queue_ptr = NULL;
#if defined(DAP_EVENTS_CAPS_QUEUE_PIPE2)
            if(read( a_esocket->fd, &l_queue_ptr,sizeof (void *)) == sizeof (void *))
                a_esocket->callbacks.queue_ptr_callback(a_esocket, l_queue_ptr);
            else if ( (errno != EAGAIN) && (errno != EWOULDBLOCK) )  // we use blocked socket for now but who knows...
                log_it(L_WARNING, "Can't read packet from pipe");
#elif defined (DAP_EVENTS_CAPS_QUEUE_POSIX)
            struct timespec s_timeout;
            clock_gettime(CLOCK_REALTIME, &s_timeout);
            s_timeout.tv_sec+=1;
            ssize_t l_ret = mq_timedreceive(a_esocket->mqd,(char*) &l_queue_ptr, sizeof (l_queue_ptr),NULL,&s_timeout );
            if (l_ret == -1){
                int l_errno = errno;
                char l_errbuf[128]={0};
                strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                log_it(L_ERROR, "Error in esocket queue_ptr:\"%s\" code %d", l_errbuf, l_errno);
                return -1;
            }
            a_esocket->callbacks.queue_ptr_callback (a_esocket, l_queue_ptr);
#else
#error "No Queue fetch mechanism implemented on your platform"
#endif
        }else{
            size_t l_read = read(a_esocket->socket, a_esocket->buf_in,sizeof(a_esocket->buf_in));
            a_esocket->callbacks.queue_callback(a_esocket,a_esocket->buf_in,l_read );
        }
    }else{
        log_it(L_ERROR, "Queue socket %d accepted data but callback is NULL ", a_esocket->socket);
        return -1;
    }
    return 0;
}

/**
 * @brief s_create_type_event
 * @param a_w
 * @param a_callback
 * @return
 */
dap_events_socket_t * s_create_type_event(dap_worker_t * a_w, dap_events_socket_callback_event_t a_callback)
{
    dap_events_socket_t * l_es = DAP_NEW_Z(dap_events_socket_t);
    l_es->type = DESCRIPTOR_TYPE_EVENT;
    if (a_w){
        l_es->events = a_w->events;
        l_es->worker = a_w;
    }
    l_es->callbacks.event_callback = a_callback; // Arm event callback
    l_es->ev_base_flags = EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP;

#ifdef DAP_EVENTS_CAPS_EVENT_EVENTFD
    if((l_es->fd = eventfd(0,0) ) < 0 ){
        int l_errno = errno;
        char l_errbuf[128];
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        switch (l_errno) {
            case EINVAL: log_it(L_CRITICAL, "An unsupported value was specified in flags: \"%s\" (%d)", l_errbuf, l_errno); break;
            case EMFILE: log_it(L_CRITICAL, "The per-process limit on the number of open file descriptors has been reached: \"%s\" (%d)", l_errbuf, l_errno); break;
            case ENFILE: log_it(L_CRITICAL, "The system-wide limit on the total number of open files has been reached: \"%s\" (%d)", l_errbuf, l_errno); break;
            case ENODEV: log_it(L_CRITICAL, "Could not mount (internal) anonymous inode device: \"%s\" (%d)", l_errbuf, l_errno); break;
            case ENOMEM: log_it(L_CRITICAL, "There was insufficient memory to create a new eventfd file descriptor: \"%s\" (%d)", l_errbuf, l_errno); break;
            default: log_it( L_ERROR, "Error detected, can't create eventfd: '%s' (%d)", l_errbuf, l_errno);
        }
        DAP_DELETE(l_es);
        return NULL;
    }else
        log_it(L_DEBUG, "Created eventfd descriptor %d", l_es->fd );
#endif
    return l_es;
}

/**
 * @brief dap_events_socket_create_type_event_mt
 * @param a_w
 * @param a_callback
 * @return
 */
dap_events_socket_t * dap_events_socket_create_type_event_mt(dap_worker_t * a_w, dap_events_socket_callback_event_t a_callback)
{
    dap_events_socket_t * l_es = s_create_type_event(a_w, a_callback);
    // If no worker - don't assign
    if ( a_w)
        dap_events_socket_assign_on_worker_mt(l_es,a_w);
    return  l_es;
}

/**
 * @brief dap_events_socket_create_type_event_unsafe
 * @param a_w
 * @param a_callback
 * @return
 */
dap_events_socket_t * dap_events_socket_create_type_event_unsafe(dap_worker_t * a_w, dap_events_socket_callback_event_t a_callback)
{
    dap_events_socket_t * l_es = s_create_type_event(a_w, a_callback);
    // If no worker - don't assign
    if ( a_w)
        dap_events_socket_assign_on_worker_unsafe(l_es,a_w);
    return  l_es;
}

/**
 * @brief dap_events_socket_event_proc_input_unsafe
 * @param a_esocket
 */
void dap_events_socket_event_proc_input_unsafe(dap_events_socket_t *a_esocket)
{
    if (a_esocket->callbacks.event_callback ){
#if defined(DAP_EVENTS_CAPS_EVENT_EVENTFD )
        eventfd_t l_value;
        if(eventfd_read( a_esocket->fd, &l_value)==0 ){ // would block if not ready
            a_esocket->callbacks.event_callback(a_esocket, l_value);
        }else if ( (errno != EAGAIN) && (errno != EWOULDBLOCK) ){  // we use blocked socket for now but who knows...
            int l_errno = errno;
            char l_errbuf[128];
            strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
            log_it(L_WARNING, "Can't read packet from event fd: \"%s\"(%d)", l_errbuf, l_errno);
        }else
            return; // do nothing
#else
#error "No Queue fetch mechanism implemented on your platform"
#endif
    }else
        log_it(L_ERROR, "Queue socket %d accepted data but callback is NULL ", a_esocket->socket);
}

/**
 * @brief dap_events_socket_send_event
 * @param a_es
 * @param a_arg
 */
int dap_events_socket_queue_ptr_send( dap_events_socket_t * a_es, void* a_arg)
{
#if defined(DAP_EVENTS_CAPS_QUEUE_PIPE2)
    int ret = write(a_es->fd2, &a_arg, sizeof(a_arg));
    int l_errno = errno;
    if (ret == sizeof(a_arg) )
        return  0;
    else
        return l_errno;
#elif defined (DAP_EVENTS_CAPS_QUEUE_POSIX)
    struct timespec l_timeout;
    clock_gettime(CLOCK_REALTIME, &l_timeout);
    l_timeout.tv_sec+=2; // Not wait more than 1 second to get and 2 to send
    int ret = mq_timedsend(a_es->mqd, (const char *)&a_arg,sizeof (a_arg),0, &l_timeout );
    int l_errno = errno;
    if (ret == sizeof(a_arg) )
        return  0;
    else
        return l_errno;
#else
#error "Not implemented dap_events_socket_queue_ptr_send() for this platform"
#endif
}

/**
 * @brief dap_events_socket_event_signal
 * @param a_es
 * @param a_value
 * @return
 */
int dap_events_socket_event_signal( dap_events_socket_t * a_es, uint64_t a_value)
{
#if defined(DAP_EVENTS_CAPS_EVENT_EVENTFD)
    int ret = eventfd_write( a_es->fd2,a_value);
    int l_errno = errno;
    if (ret == 0 )
        return  0;
    else if ( ret < 0)
        return l_errno;
    else
        return 1;
#else
#error "Not implemented dap_events_socket_event_signal() for this platform"
#endif
}

/**
 * @brief dap_events_socket_queue_on_remove_and_delete
 * @param a_es
 */
void dap_events_socket_queue_on_remove_and_delete(dap_events_socket_t* a_es)
{
    int l_ret= dap_events_socket_queue_ptr_send( a_es->worker->queue_es_delete, a_es );
    if( l_ret != 0 ){
        log_it(L_ERROR, "Queue send returned %d", l_ret);
    }
}

/**
 * @brief dap_events_socket_wrap
 * @param a_events
 * @param w
 * @param s
 * @param a_callbacks
 * @return
 */
dap_events_socket_t * dap_events_socket_wrap2( dap_server_t *a_server, struct dap_events *a_events,
                                            int a_sock, dap_events_socket_callbacks_t *a_callbacks )
{
  assert( a_events );
  assert( a_callbacks );
  assert( a_server );

  //log_it( L_DEBUG,"Dap event socket wrapped around %d sock", a_sock );
  dap_events_socket_t * ret = DAP_NEW_Z( dap_events_socket_t );

  ret->socket = a_sock;
  ret->events = a_events;
  ret->server = a_server;
  ret->is_dont_reset_write_flag = true;

  memcpy(&ret->callbacks,a_callbacks, sizeof ( ret->callbacks) );

  ret->flags = DAP_SOCK_READY_TO_READ;
  ret->is_pingable = true;
  ret->last_time_active = ret->last_ping_request = time( NULL );

  pthread_rwlock_wrlock( &a_events->sockets_rwlock );
  HASH_ADD_INT( a_events->sockets, socket, ret );
  pthread_rwlock_unlock( &a_events->sockets_rwlock );

  return ret;
}

/**
 * @brief dap_events_socket_find
 * @param sock
 * @param sh
 * @return
 */
dap_events_socket_t *dap_events_socket_find_unsafe( int sock, struct dap_events *a_events )
{
    // Why we have only unsafe socket? Because you need to lock sockets_rwlock when do any operations with
    // socket that you've find in global list
    dap_events_socket_t *ret = NULL;
    if(!a_events)
        return NULL;
    if(a_events->sockets)
        HASH_FIND_INT( a_events->sockets, &sock, ret );

    return ret;
}

/**
 * @brief dap_events_socket_ready_to_read
 * @param sc
 * @param isReady
 */
void dap_events_socket_set_readable_unsafe( dap_events_socket_t *sc, bool is_ready )
{
  if( is_ready == (bool)(sc->flags & DAP_SOCK_READY_TO_READ) )
    return;

  sc->ev.events = sc->ev_base_flags;
  sc->ev.events |= EPOLLERR;

  if ( is_ready )
    sc->flags |= DAP_SOCK_READY_TO_READ;
  else
    sc->flags ^= DAP_SOCK_READY_TO_READ;

  int events = EPOLLERR;

  if( sc->flags & DAP_SOCK_READY_TO_READ )
    events |= EPOLLIN;

  if( sc->flags & DAP_SOCK_READY_TO_WRITE )
    events |= EPOLLOUT;

  sc->ev.events = events;
  if (sc->worker)
    if ( epoll_ctl(sc->worker->epoll_fd, EPOLL_CTL_MOD, sc->socket, &sc->ev) == -1 ){
        int l_errno = errno;
        char l_errbuf[128];
        strerror_r( l_errno, l_errbuf, sizeof (l_errbuf));
        log_it( L_ERROR,"Can't update read client socket state in the epoll_fd: \"%s\" (%d)", l_errbuf, l_errno );
    }
}

/**
 * @brief dap_events_socket_ready_to_write
 * @param sc
 * @param isReady
 */
void dap_events_socket_set_writable_unsafe( dap_events_socket_t *sc, bool a_is_ready )
{
    if ( a_is_ready == (bool)(sc->flags & DAP_SOCK_READY_TO_WRITE) ) {
        return;
    }

    if ( a_is_ready )
        sc->flags |= DAP_SOCK_READY_TO_WRITE;
    else
        sc->flags ^= DAP_SOCK_READY_TO_WRITE;

    int events = sc->ev_base_flags | EPOLLERR;

    // Check & add
    if( sc->flags & DAP_SOCK_READY_TO_READ )
        events |= EPOLLIN;

    if( sc->flags & DAP_SOCK_READY_TO_WRITE )
        events |= EPOLLOUT;

    sc->ev.events = events;

    if (sc->worker)
        if ( epoll_ctl(sc->worker->epoll_fd, EPOLL_CTL_MOD, sc->socket, &sc->ev) ){
            int l_errno = errno;
            char l_errbuf[128];
            strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
            log_it(L_ERROR,"Can't update write client socket state in the epoll_fd %d: \"%s\" (%d)",
                   sc->worker->epoll_fd, l_errbuf, l_errno);
        }
}

/**
 * @brief dap_events_socket_remove Removes the client from the list
 * @param sc Connection instance
 */
void dap_events_socket_remove_and_delete_unsafe( dap_events_socket_t *a_es, bool preserve_inheritor )
{
    if ( !a_es )
        return;

    //log_it( L_DEBUG, "es is going to be removed from the lists and free the memory (0x%016X)", a_es );
    dap_events_socket_remove_from_worker_unsafe(a_es, a_es->worker);

    if (a_es->events){ // It could be socket NOT from events
        pthread_rwlock_wrlock( &a_es->events->sockets_rwlock );
        if(!dap_events_socket_find_unsafe(a_es->socket, a_es->events)){
            log_it( L_ERROR, "dap_events_socket 0x%x already deleted", a_es);
            pthread_rwlock_unlock( &a_es->events->sockets_rwlock );
            return ;
        }

        if(a_es->events->sockets)
            HASH_DEL( a_es->events->sockets, a_es );
        pthread_rwlock_unlock( &a_es->events->sockets_rwlock );
    }
    //log_it( L_DEBUG, "dap_events_socket wrapped around %d socket is removed", a_es->socket );

    if( a_es->callbacks.delete_callback )
        a_es->callbacks.delete_callback( a_es, NULL ); // Init internal structure

    if ( a_es->_inheritor && !preserve_inheritor )
        DAP_DELETE( a_es->_inheritor );

    if ( a_es->socket && a_es->socket != -1) {
#ifdef _WIN32
        closesocket( a_es->socket );
#else
        close( a_es->socket );
#ifdef DAP_EVENTS_CAPS_QUEUE_PIPE2
        if( a_es->type == DESCRIPTOR_TYPE_QUEUE){
            close( a_es->fd2);
        }
#endif

#endif
    }
    DAP_DELETE( a_es );
}

/**
 * @brief dap_events_socket_delete
 * @param a_es
 */
void dap_events_socket_remove_from_worker_unsafe( dap_events_socket_t *a_es, dap_worker_t * a_worker)
{
    if (!a_es->worker) {
        // Socket already removed from worker
        return;
    }
    if ( epoll_ctl( a_worker->epoll_fd, EPOLL_CTL_DEL, a_es->socket, &a_es->ev) == -1 ) {
        int l_errno = errno;
        char l_errbuf[128];
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        log_it( L_ERROR,"Can't remove event socket's handler from the epoll_fd %d  \"%s\" (%d)",
                a_worker->epoll_fd, l_errbuf, l_errno);
    } //else
      //  log_it( L_DEBUG,"Removed epoll's event from dap_worker #%u", a_worker->id );
    a_worker->event_sockets_count--;
    if(a_worker->esockets)
        HASH_DELETE(hh_worker,a_worker->esockets, a_es);
    a_es->worker = NULL;
}

/**
 * @brief dap_events_socket_check_unsafe
 * @param a_worker
 * @param a_es
 * @return
 */
bool dap_events_socket_check_unsafe(dap_worker_t * a_worker,dap_events_socket_t * a_es)
{
    if (a_es){
        if ( a_worker->esockets){
            dap_events_socket_t * l_es = NULL;
            HASH_FIND(hh_worker,a_worker->esockets,&a_es, sizeof(a_es), l_es );
            return l_es == a_es;
        }else
            return false;
    }else
        return false;
}

/**
 * @brief dap_events_socket_remove_and_delete
 * @param a_es
 * @param preserve_inheritor
 */
void dap_events_socket_remove_and_delete_mt(dap_worker_t * a_w,  dap_events_socket_t *a_es )
{
    if(a_w)
        dap_events_socket_queue_ptr_send( a_w->queue_es_delete, a_es );
}

/**
 * @brief dap_events_socket_set_readable_mt
 * @param a_w
 * @param a_es
 * @param a_is_ready
 */
void dap_events_socket_set_readable_mt(dap_worker_t * a_w, dap_events_socket_t * a_es,bool a_is_ready)
{
    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t);
    l_msg->esocket = a_es;
    if (a_is_ready)
        l_msg->flags_set = DAP_SOCK_READY_TO_READ;
    else
        l_msg->flags_unset = DAP_SOCK_READY_TO_READ;

    int l_ret= dap_events_socket_queue_ptr_send(a_w->queue_es_io, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg);
    }
}

/**
 * @brief dap_events_socket_set_writable_mt
 * @param sc
 * @param is_ready
 */
void dap_events_socket_set_writable_mt(dap_worker_t * a_w, dap_events_socket_t * a_es,bool a_is_ready)
{
    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t);
    l_msg->esocket = a_es;
    if (a_is_ready)
        l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    else
        l_msg->flags_unset = DAP_SOCK_READY_TO_WRITE;

    int l_ret= dap_events_socket_queue_ptr_send(a_w->queue_es_io, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg);
    }
}

/**
 * @brief dap_events_socket_write_mt
 * @param sc
 * @param data
 * @param data_size
 * @return
 */
size_t dap_events_socket_write_mt(dap_worker_t * a_w,dap_events_socket_t *a_es, const void * data, size_t l_data_size)
{
    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t);
    l_msg->esocket = a_es;
    l_msg->data = DAP_NEW_SIZE(void,l_data_size);
    l_msg->data_size = l_data_size;
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    memcpy( l_msg->data, data, l_data_size);

    int l_ret= dap_events_socket_queue_ptr_send(a_w->queue_es_io, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg);
        return 0;
    }
    return  l_data_size;
}

/**
 * @brief dap_events_socket_write_f_mt
 * @param a_es
 * @param format
 * @return
 */
size_t dap_events_socket_write_f_mt(dap_worker_t * a_w,dap_events_socket_t *a_es, const char * format,...)
{
    va_list ap, ap_copy;
    va_start(ap,format);
    va_copy(ap_copy, ap);
    int l_data_size = dap_vsnprintf(NULL,0,format,ap);
    va_end(ap);
    if (l_data_size <0 ){
        log_it(L_ERROR,"Can't write out formatted data '%s' with values",format);
        va_end(ap_copy);
        return 0;
    }
    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t);
    l_msg->esocket = a_es;
    l_msg->data = DAP_NEW_SIZE(void,l_data_size + 1);
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    l_data_size = dap_vsprintf(l_msg->data,format,ap_copy);
    va_end(ap_copy);
    if (l_data_size <0 ){
        log_it(L_ERROR,"Can't write out formatted data '%s' with values",format);
        DAP_DELETE(l_msg->data);
        DAP_DELETE(l_msg);
        return 0;
    }
    l_msg->data_size = l_data_size;
    int l_ret= dap_events_socket_queue_ptr_send(a_w->queue_es_io, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg->data);
        DAP_DELETE(l_msg);
        return 0;
    }
    return l_data_size;
}

/**
 * @brief dap_events_socket_write Write data to the client
 * @param sc Conn instance
 * @param data Pointer to data
 * @param data_size Size of data to write
 * @return Number of bytes that were placed into the buffer
 */
size_t dap_events_socket_write_unsafe(dap_events_socket_t *sc, const void * data, size_t data_size)
{
    //log_it(L_DEBUG,"dap_events_socket_write %u sock data %X size %u", sc->socket, data, data_size );
     data_size = ((sc->buf_out_size+data_size)<(sizeof(sc->buf_out)))?data_size:(sizeof(sc->buf_out)-sc->buf_out_size );
     memcpy(sc->buf_out+sc->buf_out_size,data,data_size);
     sc->buf_out_size+=data_size;
     dap_events_socket_set_writable_unsafe(sc, true);
     return data_size;
}

/**
 * @brief dap_events_socket_write_f Write formatted text to the client
 * @param sc Conn instance
 * @param format Format
 * @return Number of bytes that were placed into the buffer
 */
size_t dap_events_socket_write_f_unsafe(dap_events_socket_t *sc, const char * format,...)
{
    //log_it(L_DEBUG,"dap_events_socket_write_f %u sock", sc->socket );

    size_t max_data_size = sizeof(sc->buf_out)-sc->buf_out_size;
    va_list ap;
    va_start(ap,format);
    int ret=dap_vsnprintf((char*) sc->buf_out+sc->buf_out_size,max_data_size,format,ap);
    va_end(ap);
    if(ret>0){
        sc->buf_out_size+=ret;
    }else{
        log_it(L_ERROR,"Can't write out formatted data '%s'",format);
    }
    dap_events_socket_set_writable_unsafe(sc, true);
    return (ret > 0) ? ret : 0;
}

/**
 * @brief dap_events_socket_pop_from_buf_in Read data from input buffer
 * @param sc Conn instasnce
 * @param data Pointer to memory where to store the data
 * @param data_size Size of data to read
 * @return Actual bytes number that were read
 */
size_t dap_events_socket_pop_from_buf_in(dap_events_socket_t *sc, void *data, size_t data_size)
{
//    log_it(L_DEBUG,"dap_events_socket_read %u sock data %X size %u", sc->socket, data, data_size );

    if(data_size<sc->buf_in_size){
        memcpy(data,sc->buf_in,data_size);
        memmove(data,sc->buf_in+data_size,sc->buf_in_size-data_size);
    }else{
        if(data_size>sc->buf_in_size)
            data_size=sc->buf_in_size;
        memcpy(data,sc->buf_in,data_size);
    }
    sc->buf_in_size-=data_size;
    return data_size;
}


/**
 * @brief dap_events_socket_shrink_client_buf_in Shrink input buffer (shift it left)
 * @param cl Client instance
 * @param shrink_size Size on wich we shrink the buffer with shifting it left
 */
void dap_events_socket_shrink_buf_in(dap_events_socket_t * cl, size_t shrink_size)
{
    if((shrink_size==0)||(cl->buf_in_size==0) ){
        return;
    }else if(cl->buf_in_size>shrink_size){
        size_t buf_size=cl->buf_in_size-shrink_size;
        uint8_t* tmp = cl->buf_in + shrink_size;
        memmove(cl->buf_in,tmp,buf_size);
        cl->buf_in_size=buf_size;
    }else{
        //log_it(WARNING,"Shrinking size of input buffer on amount bigger than actual buffer's size");
        cl->buf_in_size=0;
    }

}
