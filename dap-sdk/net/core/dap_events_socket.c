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
#include <sys/select.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include "wepoll.h"
#endif

#if defined (DAP_EVENTS_CAPS_QUEUE_MQUEUE)
#include <sys/time.h>
#include <sys/resource.h>
#endif

#include <fcntl.h>
#include <pthread.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_list.h"
#include "dap_worker.h"
#include "dap_events.h"

#include "dap_timerfd.h"
#include "dap_events_socket.h"

#define LOG_TAG "dap_events_socket"

// Item for QUEUE_PTR input esocket
struct queue_ptr_input_item{
    dap_events_socket_t * esocket;
    void * ptr;
    struct queue_ptr_input_item * next;
};

// QUEUE_PTR input esocket pvt section
struct queue_ptr_input_pvt{
    dap_events_socket_t * esocket;
    struct queue_ptr_input_item * items_first;
    struct queue_ptr_input_item * items_last;
};
#define PVT_QUEUE_PTR_INPUT(a) ( (struct queue_ptr_input_pvt*) (a)->_pvt )

static bool s_debug_reactor = false;

/**
 * @brief dap_events_socket_init Init clients module
 * @return Zero if ok others if no
 */
int dap_events_socket_init( )
{
    log_it(L_NOTICE,"Initialized events socket module");
    s_debug_reactor = g_config? dap_config_get_item_bool_default(g_config, "general","debug_reactor", false) : false;
#if defined (DAP_EVENTS_CAPS_QUEUE_MQUEUE)
#include <sys/time.h>
#include <sys/resource.h>

    struct rlimit l_mqueue_limit;
    l_mqueue_limit.rlim_cur = RLIM_INFINITY;
    l_mqueue_limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_MSGQUEUE,&l_mqueue_limit);
    char l_cmd[256];
    snprintf(l_cmd,sizeof (l_cmd),"rm /dev/mqueue/%s-queue_ptr*", dap_get_appname());
    system(l_cmd);
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
    #elif defined(DAP_EVENTS_CAPS_POLL)
    ret->poll_base_flags = POLLERR | POLLRDHUP | POLLHUP;
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

void dap_events_socket_assign_on_worker_inter(dap_events_socket_t * a_es_input, dap_events_socket_t * a_es)
{
    if (!a_es)
        log_it(L_ERROR, "Can't send NULL esocket in interthreads pipe input");
    if (!a_es_input)
        log_it(L_ERROR, "Interthreads pipe input is NULL");
    if (! a_es || ! a_es_input)
        return;

    a_es->last_ping_request = time(NULL);
    //log_it(L_DEBUG, "Interthread assign esocket %p(fd %d) on input esocket %p (fd %d)", a_es, a_es->fd,
    //       a_es_input, a_es_input->fd);
    dap_worker_add_events_socket_inter(a_es_input,a_es);

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
#if defined(DAP_EVENTS_CAPS_EPOLL)
    l_es->ev_base_flags = EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP;
#elif defined(DAP_EVENTS_CAPS_POLL)
    l_es->poll_base_flags = POLLIN | POLLERR | POLLRDHUP | POLLHUP;
#else
#error "Not defined s_create_type_pipe for your platform"
#endif

#if defined(DAP_EVENTS_CAPS_PIPE_POSIX)
    int l_pipe[2];
    int l_errno;
    char l_errbuf[128];
    l_errbuf[0]=0;
    if( pipe(l_pipe) < 0 ){
        l_errno = errno;
#if defined DAP_OS_UNIX
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        log_it( L_ERROR, "Error detected, can't create pipe(): '%s' (%d)", l_errbuf, l_errno);
#elif defined DAP_OS_WINDOWS
        log_it( L_ERROR, "Can't create pipe, errno: %d", l_errno);
#endif
        DAP_DELETE(l_es);
        return NULL;
    }//else
     //   log_it(L_DEBUG, "Created one-way unnamed bytestream pipe %d->%d", l_pipe[0], l_pipe[1]);
    l_es->fd = l_pipe[0];
    l_es->fd2 = l_pipe[1];
#if defined DAP_OS_UNIX
    fcntl( l_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl( l_pipe[1], F_SETFL, O_NONBLOCK);
    // this sort of fd doesn't suit ioctlsocket()...
#endif

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
    dap_worker_add_events_socket_unsafe(l_es,a_w);
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
    dap_worker_add_events_socket_unsafe(l_es,a_w);
    return  l_es;
}

/**
 * @brief s_socket_type_queue_ptr_input_callback_delete
 * @param a_es
 * @param a_arg
 */
static void s_socket_type_queue_ptr_input_callback_delete(dap_events_socket_t * a_es, void * a_arg)
{
    (void) a_arg;
    for (struct queue_ptr_input_item * l_item = PVT_QUEUE_PTR_INPUT(a_es)->items_first; l_item;  ){
        struct queue_ptr_input_item * l_item_next= l_item->next;
        DAP_DELETE(l_item);
        l_item= l_item_next;
    }
    PVT_QUEUE_PTR_INPUT(a_es)->items_first = PVT_QUEUE_PTR_INPUT(a_es)->items_last = NULL;
}


/**
 * @brief dap_events_socket_queue_ptr_create_input
 * @param a_es
 * @return
 */
dap_events_socket_t * dap_events_socket_queue_ptr_create_input(dap_events_socket_t* a_es)
{
    dap_events_socket_t * l_es = DAP_NEW_Z(dap_events_socket_t);
    l_es->type = DESCRIPTOR_TYPE_QUEUE;
    l_es->events = a_es->events;
#if defined(DAP_EVENTS_CAPS_EPOLL)
    l_es->ev_base_flags = EPOLLERR | EPOLLRDHUP | EPOLLHUP;
#elif defined(DAP_EVENTS_CAPS_POLL)
    l_es->poll_base_flags = POLLERR | POLLRDHUP | POLLHUP;
#else
#error "Not defined s_create_type_pipe for your platform"
#endif

    l_es->type = DESCRIPTOR_TYPE_QUEUE;
#ifdef DAP_EVENTS_CAPS_QUEUE_MQUEUE
    l_es->mqd = a_es->mqd;
    char l_mq_name[64];
    struct mq_attr l_mq_attr;
    memset(&l_mq_attr,0,sizeof (l_mq_attr));
    l_mq_attr.mq_maxmsg = 8; // Don't think we need to hold more than 1024 messages
    l_mq_attr.mq_msgsize = sizeof (void*); // We send only pointer on memory,
                                            // so use it with shared memory if you do access from another process
    snprintf(l_mq_name,sizeof (l_mq_name),"/%s-queue_ptr-%u",dap_get_appname(), a_es->mqd_id );

    l_es->mqd = mq_open(l_mq_name,O_CREAT|O_WRONLY |O_NONBLOCK,0700, &l_mq_attr);
    l_es->mqd_id = a_es->mqd_id;
    if (l_es->mqd == -1  || l_es->mqd == 0){
        int l_errno = errno;
        char l_errbuf[128];
        l_errbuf[0]=0;
        if (l_errno == EMFILE)
            strncpy(l_errbuf,"EMFILE: The per-process limit on the number of open file and message queue descriptors has been reached",sizeof (l_errbuf)-1);
        else
            strerror_r(l_errno,l_errbuf,sizeof (l_errbuf) );
        DAP_DELETE(l_es);
        l_es = NULL;
        log_it(L_CRITICAL,"Can't create mqueue descriptor %s: \"%s\" code %d",l_mq_name, l_errbuf, l_errno);
        return NULL;
    }
    assert(l_es->mqd);
#elif defined (DAP_EVENTS_CAPS_QUEUE_PIPE2)
    l_es->fd = a_es->fd2;
#else
#error "Not defined dap_events_socket_queue_ptr_create_input() for this platform"
#endif

    l_es->flags = DAP_SOCK_QUEUE_PTR;
    l_es->_pvt = DAP_NEW_Z(struct queue_ptr_input_pvt);
    l_es->callbacks.delete_callback  = s_socket_type_queue_ptr_input_callback_delete;
    return l_es;
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
    if(!l_es){
        log_it(L_ERROR,"Can't allocate esocket!");
        return NULL;
    }
    l_es->type = DESCRIPTOR_TYPE_QUEUE;
    l_es->flags =  DAP_SOCK_QUEUE_PTR;
    if (a_w){
        l_es->events = a_w->events;
        l_es->worker = a_w;
    }
    l_es->callbacks.queue_ptr_callback = a_callback; // Arm event callback

#if defined(DAP_EVENTS_CAPS_EPOLL)
    l_es->ev_base_flags = EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP;
#elif defined(DAP_EVENTS_CAPS_POLL)
    l_es->poll_base_flags = POLLIN | POLLERR | POLLRDHUP | POLLHUP;
#else
#error "Not defined s_create_type_queue_ptr for your platform"
#endif


#ifdef DAP_EVENTS_CAPS_QUEUE_PIPE2
    int l_pipe[2];
    int l_errno;
    char l_errbuf[128];
    l_errbuf[0]=0;
    if( pipe2(l_pipe,O_DIRECT | O_NONBLOCK ) < 0 ){
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
    fcntl(l_pipe[0], F_SETPIPE_SZ, l_sys_max_pipe_size);

#elif defined (DAP_EVENTS_CAPS_QUEUE_MQUEUE)
    char l_mq_name[64];
    struct mq_attr l_mq_attr;
    static uint32_t l_mq_last_number=0;
    memset(&l_mq_attr,0,sizeof (l_mq_attr));
    l_mq_attr.mq_maxmsg = 8; // Don't think we need to hold more than 1024 messages
    l_mq_attr.mq_msgsize = sizeof (void*); // We send only pointer on memory,
                                            // so use it with shared memory if you do access from another process
    snprintf(l_mq_name,sizeof (l_mq_name),"/%s-queue_ptr-%u",dap_get_appname(),l_mq_last_number );

    l_es->mqd = mq_open(l_mq_name,O_CREAT|O_RDWR |O_NONBLOCK,0700, &l_mq_attr);
    if (l_es->mqd == -1  || l_es->mqd == 0){
        int l_errno = errno;
        char l_errbuf[128];
        l_errbuf[0]=0;
        if (l_errno == EMFILE)
            strncpy(l_errbuf,"EMFILE: The per-process limit on the number of open file and message queue descriptors has been reached",sizeof (l_errbuf)-1);
        else
            strerror_r(l_errno,l_errbuf,sizeof (l_errbuf) );
        DAP_DELETE(l_es);
        l_es = NULL;
        log_it(L_CRITICAL,"Can't create mqueue descriptor %s: \"%s\" code %d",l_mq_name, l_errbuf, l_errno);
        return NULL;
    }else{
        l_es->mqd_id = l_mq_last_number;
        l_mq_last_number++;
    }
    assert(l_es->mqd);
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
        dap_worker_add_events_socket_unsafe(l_es,a_w);
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
            ssize_t l_read_ret = read( a_esocket->fd, &l_queue_ptr,sizeof (void *));
            int l_read_errno = errno;
            if( l_read_ret == (ssize_t) sizeof (void *))
                a_esocket->callbacks.queue_ptr_callback(a_esocket, l_queue_ptr);
            else if ( (errno != EAGAIN) && (errno != EWOULDBLOCK) )  // we use blocked socket for now but who knows...
                log_it(L_WARNING, "Can't read packet from pipe");
#elif defined (DAP_EVENTS_CAPS_QUEUE_MQUEUE)
            ssize_t l_ret = mq_receive(a_esocket->mqd,(char*) &l_queue_ptr, sizeof (l_queue_ptr),NULL);
            if (l_ret == -1){
                int l_errno = errno;
                char l_errbuf[128];
                l_errbuf[0]=0;
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
    dap_events_socket_t * l_es = DAP_NEW_Z(dap_events_socket_t); if (!l_es) return NULL;
    l_es->type = DESCRIPTOR_TYPE_EVENT;
    if (a_w){
        l_es->events = a_w->events;
        l_es->worker = a_w;
    }
    l_es->callbacks.event_callback = a_callback; // Arm event callback
#if defined(DAP_EVENTS_CAPS_EPOLL)
    l_es->ev_base_flags = EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP;
#elif defined(DAP_EVENTS_CAPS_POLL)
    l_es->poll_base_flags = POLLIN | POLLERR | POLLRDHUP | POLLHUP;
#else
#error "Not defined s_create_type_event for your platform"
#endif

#ifdef DAP_EVENTS_CAPS_EVENT_EVENTFD
    if((l_es->fd = eventfd(0,EFD_NONBLOCK) ) < 0 ){
        int l_errno = errno;
        char l_errbuf[128];
        l_errbuf[0]=0;
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
    }else {
        l_es->fd2 = l_es->fd;
        //log_it(L_DEBUG, "Created eventfd descriptor %d", l_es->fd );
    }
#elif defined DAP_OS_WINDOWS
    int l_pipe[2];
    if (pipe(l_pipe) < 0) {
        log_it(L_ERROR, "Can't create pipe for event type, error: %d", errno);
        DAP_DELETE(l_es);
        return NULL;
    }
    l_es->fd2   = l_pipe[0];
    l_es->fd    = l_pipe[1];
    log_it(L_DEBUG, "Created pipe for event type, %d -> %d", l_es->fd2, l_es->fd);
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
        dap_worker_add_events_socket_unsafe(l_es,a_w);
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
            l_errbuf[0]=0;
            strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
            log_it(L_WARNING, "Can't read packet from event fd: \"%s\"(%d)", l_errbuf, l_errno);
        }else
            return; // do nothing
#elif defined DAP_OS_WINDOWS
        uint64_t l_value;
        int l_ret;
        switch (l_ret = read(a_esocket->fd, &l_value, 8)) {
        case -1:
            log_it(L_CRITICAL, "Can't read from event socket pipe, error: %d", errno);
            break;
        case 0:
            return;
        default:
            a_esocket->callbacks.event_callback(a_esocket, l_value);
            break;
        }
#else
#error "No Queue fetch mechanism implemented on your platform"
#endif
    }else
        log_it(L_ERROR, "Event socket %d accepted data but callback is NULL ", a_esocket->socket);
}


typedef struct dap_events_socket_buf_item
{
    dap_events_socket_t * es;
    void *arg;
} dap_events_socket_buf_item_t;

int dap_events_socket_queue_ptr_send(dap_events_socket_t * a_es, void* a_arg);

/**
 *  Waits on the socket
 *  return 0: timeout, 1: may send data, -1 error
 */
static int wait_send_socket(int a_sockfd, long timeout_ms)
{
    struct timeval l_tv;
    fd_set l_outfd, l_errfd;

    l_tv.tv_sec = timeout_ms / 1000;
    l_tv.tv_usec = (timeout_ms % 1000) * 1000;

    FD_ZERO(&l_outfd);
    FD_ZERO(&l_errfd);
    FD_SET(a_sockfd, &l_errfd);
    FD_SET(a_sockfd, &l_outfd);

    while(1) {
#ifdef DAP_OS_WINDOWS
    int l_res = select(1, NULL, &l_outfd, &l_errfd, &l_tv);
#else
        int l_res = select(a_sockfd + 1, NULL, &l_outfd, &l_errfd, &l_tv);
#endif
        if(l_res == 0){
            l_res = -2;
            //log_it(L_DEBUG, "socket %d timed out", a_sockfd)
            break;
        }
        if(l_res == -1) {
            if(errno == EINTR)
                continue;
            log_it(L_DEBUG, "socket %d waiting errno=%d", errno);
            return l_res;
        }
        break;
    };

    if(FD_ISSET(a_sockfd, &l_outfd))
        return 0;

    return -1;
}

/**
 * @brief dap_events_socket_buf_thread
 * @param arg
 * @return
 */
void *dap_events_socket_buf_thread(void *arg)
{
    dap_events_socket_buf_item_t *l_item = (dap_events_socket_buf_item_t*) arg;
    if(!l_item) {
        pthread_exit(0);
    }
    int l_res = 0;
    int l_count = 0;
    while(l_res < 1 && l_count < 3) {
    // wait max 5 min
        l_res = wait_send_socket(l_item->es->fd2, 300000);
        if (l_res == 0){
            dap_events_socket_queue_ptr_send(l_item->es, l_item->arg);
            break;
        }
        l_count++;
    }
    if(l_res != 0)
        log_it(L_WARNING, "Lost data bulk in events socket buf thread");

    DAP_DELETE(l_item);
    pthread_exit(0);
}

static void add_ptr_to_buf(dap_events_socket_t * a_es, void* a_arg)
{
    dap_events_socket_buf_item_t *l_item = DAP_NEW(dap_events_socket_buf_item_t); if (!l_item) return;
    l_item->es = a_es;
    l_item->arg = a_arg;
    pthread_t l_thread;
    pthread_create(&l_thread, NULL, dap_events_socket_buf_thread, l_item);
}

/**
 * @brief dap_events_socket_queue_ptr_send_to_input
 * @param a_es_input
 * @param a_arg
 * @return
 */
int dap_events_socket_queue_ptr_send_to_input(dap_events_socket_t * a_es_input, void * a_arg)
{
    volatile void * l_arg = a_arg;
    int ret= dap_events_socket_write_unsafe(a_es_input,&l_arg,sizeof (l_arg) )==sizeof (l_arg)?0:1 ;
    return ret;
}

/**
 * @brief dap_events_socket_send_event
 * @param a_es
 * @param a_arg
 */
int dap_events_socket_queue_ptr_send( dap_events_socket_t * a_es, void* a_arg)
{
    int l_ret;
    int l_errno;
    if (s_debug_reactor)
        log_it(L_DEBUG,"Sent ptr %p to esocket queue %p (%d)", a_arg, a_es, a_es? a_es->fd : -1);
#if defined(DAP_EVENTS_CAPS_QUEUE_PIPE2)
    l_ret = write(a_es->fd2, &a_arg, sizeof(a_arg));
    l_errno = errno;
#elif defined (DAP_EVENTS_CAPS_QUEUE_MQUEUE)
    assert(a_es);
    assert(a_es->mqd);
    l_ret = mq_send(a_es->mqd, (const char *)&a_arg,sizeof (a_arg),0);
    l_errno = errno;
    if (l_errno == EINVAL || l_errno == EINTR || l_errno == ETIMEDOUT)
        l_errno = EAGAIN;
    if (l_ret == 0)
        l_ret = sizeof (a_arg);
#else
#error "Not implemented dap_events_socket_queue_ptr_send() for this platform"
#endif
    if (l_ret == sizeof(a_arg) )
        return  0;
    else{
        // Try again
        if(l_errno == EAGAIN || l_errno == EWOULDBLOCK ){
            add_ptr_to_buf(a_es, a_arg);
            return 0;
        }
        char l_errbuf[128];
        log_it(L_ERROR, "Can't send ptr to queue:\"%s\" code %d", strerror_r(l_errno, l_errbuf, sizeof (l_errbuf)), l_errno);
        return l_errno;
    }
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
#elif defined DAP_OS_WINDOWS
    byte_t l_bytes[sizeof(void*)] = { 0 };
    if(write(a_es->fd2, l_bytes, sizeof(l_bytes)) == -1) {
        return errno;
    } else {
        return 0;
    }
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
  dap_events_socket_t * ret = DAP_NEW_Z( dap_events_socket_t ); if (!ret) return NULL;

  ret->socket = a_sock;
  ret->events = a_events;
  ret->server = a_server;

  memcpy(&ret->callbacks,a_callbacks, sizeof ( ret->callbacks) );

  ret->flags = DAP_SOCK_READY_TO_READ;
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

void dap_events_socket_worker_poll_update_unsafe(dap_events_socket_t * a_esocket)
{
    #if defined (DAP_EVENTS_CAPS_EPOLL)
        int events = a_esocket->ev_base_flags | EPOLLERR;

        // Check & add
        if( a_esocket->flags & DAP_SOCK_READY_TO_READ )
            events |= EPOLLIN;

        if( a_esocket->flags & DAP_SOCK_READY_TO_WRITE || a_esocket->flags &DAP_SOCK_CONNECTING )
            events |= EPOLLOUT;

        a_esocket->ev.events = events;

        if( a_esocket->worker){
            if ( epoll_ctl(a_esocket->worker->epoll_fd, EPOLL_CTL_MOD, a_esocket->socket, &a_esocket->ev) ){
                int l_errno = errno;
                char l_errbuf[128];
                l_errbuf[0]=0;
                strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                log_it(L_ERROR,"Can't update client socket state in the epoll_fd %d: \"%s\" (%d)",
                       a_esocket->worker->epoll_fd, l_errbuf, l_errno);
            }
        }
    #elif defined (DAP_EVENTS_CAPS_POLL)
        if( a_esocket->worker){
            if (a_esocket->poll_index < a_esocket->worker->poll_count ){
                struct pollfd * l_poll = &a_esocket->worker->poll[a_esocket->poll_index];
                l_poll->events = a_esocket->poll_base_flags | POLLERR ;
                // Check & add
                if( a_esocket->flags & DAP_SOCK_READY_TO_READ )
                    l_poll->events |= POLLIN;
                if( a_esocket->flags & DAP_SOCK_READY_TO_WRITE || a_esocket->flags &DAP_SOCK_CONNECTING )
                    l_poll->events |= POLLOUT;
            }else{
                log_it(L_ERROR, "Wrong poll index when remove from worker (unsafe): %u when total count %u", a_esocket->poll_index,
                       a_esocket->worker->poll_count);
            }
        }
    #else
    #error "Not defined dap_events_socket_set_writable_unsafe for your platform"
    #endif

}

/**
 * @brief dap_events_socket_ready_to_read
 * @param sc
 * @param isReady
 */
void dap_events_socket_set_readable_unsafe( dap_events_socket_t *a_esocket, bool is_ready )
{
    if( is_ready == (bool)(a_esocket->flags & DAP_SOCK_READY_TO_READ))
        return;

    if ( is_ready )
        a_esocket->flags |= DAP_SOCK_READY_TO_READ;
    else
        a_esocket->flags ^= DAP_SOCK_READY_TO_READ;

    if( a_esocket->worker)
        dap_events_socket_worker_poll_update_unsafe( a_esocket);
}

/**
 * @brief dap_events_socket_ready_to_write
 * @param a_esocket
 * @param isReady
 */
void dap_events_socket_set_writable_unsafe( dap_events_socket_t *a_esocket, bool a_is_ready )
{
    if ( a_is_ready == (bool)(a_esocket->flags & DAP_SOCK_READY_TO_WRITE)) {
        return;
    }

    if ( a_is_ready )
        a_esocket->flags |= DAP_SOCK_READY_TO_WRITE;
    else
        a_esocket->flags ^= DAP_SOCK_READY_TO_WRITE;

    if( a_esocket->worker )
        dap_events_socket_worker_poll_update_unsafe(a_esocket);
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
    if ( a_es->worker)
        dap_events_socket_remove_from_worker_unsafe(a_es, a_es->worker);

    //log_it( L_DEBUG, "dap_events_socket wrapped around %d socket is removed", a_es->socket );

    if( a_es->callbacks.delete_callback )
        a_es->callbacks.delete_callback( a_es, NULL ); // Init internal structure

    dap_events_socket_delete_unsafe(a_es, preserve_inheritor);
}

/**
 * @brief dap_events_socket_delete_unsafe
 * @param a_esocket
 * @param a_preserve_inheritor
 */
void dap_events_socket_delete_unsafe( dap_events_socket_t * a_esocket , bool a_preserve_inheritor)
{
    if (a_esocket->events){ // It could be socket NOT from events
        pthread_rwlock_wrlock( &a_esocket->events->sockets_rwlock );
        if(!dap_events_socket_find_unsafe(a_esocket->socket, a_esocket->events)){
            log_it( L_ERROR, "dap_events_socket 0x%x already deleted", a_esocket);
            pthread_rwlock_unlock( &a_esocket->events->sockets_rwlock );
            return ;
        }

        if(a_esocket->events->sockets)
            HASH_DEL( a_esocket->events->sockets, a_esocket );
        pthread_rwlock_unlock( &a_esocket->events->sockets_rwlock );
    }

    if ( a_esocket->_inheritor && !a_preserve_inheritor )
        DAP_DELETE( a_esocket->_inheritor );
    if (a_esocket->_pvt)
        DAP_DELETE(a_esocket->_pvt);

    if ( a_esocket->socket && a_esocket->socket != -1) {
    #ifdef _WIN32
        closesocket( a_esocket->socket );
    #else
        close( a_esocket->socket );
    #ifdef DAP_EVENTS_CAPS_QUEUE_PIPE2
        if( a_esocket->type == DESCRIPTOR_TYPE_QUEUE){
            close( a_esocket->fd2);
        }
    #endif

    #endif
    }
    DAP_DELETE( a_esocket );
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
#ifdef DAP_EVENTS_CAPS_EPOLL

    if ( epoll_ctl( a_worker->epoll_fd, EPOLL_CTL_DEL, a_es->socket, &a_es->ev) == -1 ) {
        int l_errno = errno;
        char l_errbuf[128];
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        log_it( L_ERROR,"Can't remove event socket's handler from the epoll_fd %d  \"%s\" (%d)",
                a_worker->epoll_fd, l_errbuf, l_errno);
    } //else
      //  log_it( L_DEBUG,"Removed epoll's event from dap_worker #%u", a_worker->id );
#elif defined (DAP_EVENTS_CAPS_POLL)
    if (a_es->poll_index < a_worker->poll_count ){
        a_worker->poll[a_es->poll_index].fd = -1;
    }else{
        log_it(L_ERROR, "Wrong poll index when remove from worker (unsafe): %u when total count %u", a_es->poll_index, a_worker->poll_count);
    }
#else
#error "Unimplemented new esocket on worker callback for current platform"
#endif

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
    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t); if (! l_msg) return;
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
    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t); if (!l_msg) return;
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
 * @brief dap_events_socket_write_inter
 * @param a_es_input
 * @param a_es
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_events_socket_write_inter(dap_events_socket_t * a_es_input, dap_events_socket_t *a_es, const void * a_data, size_t a_data_size)
{
    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t); if( !l_msg) return 0;
    l_msg->esocket = a_es;
    l_msg->data = DAP_NEW_SIZE(void,a_data_size);
    l_msg->data_size = a_data_size;
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    memcpy( l_msg->data, a_data, a_data_size);

    int l_ret= dap_events_socket_queue_ptr_send_to_input( a_es_input, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg);
        return 0;
    }
    return  a_data_size;
}

/**
 * @brief dap_events_socket_write_f_inter
 * @param a_es_input
 * @param sc
 * @param format
 * @return
 */
size_t dap_events_socket_write_f_inter(dap_events_socket_t * a_es_input, dap_events_socket_t *a_es, const char * a_format,...)
{
    va_list ap, ap_copy;
    va_start(ap,a_format);
    va_copy(ap_copy, ap);
    int l_data_size = dap_vsnprintf(NULL,0,a_format,ap);
    va_end(ap);
    if (l_data_size <0 ){
        log_it(L_ERROR,"Can't write out formatted data '%s' with values",a_format);
        va_end(ap_copy);
        return 0;
    }

    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t);
    l_msg->esocket = a_es;
    l_msg->data = DAP_NEW_SIZE(void,l_data_size);
    l_msg->data_size = l_data_size;
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    l_data_size = dap_vsprintf(l_msg->data,a_format,ap_copy);
    va_end(ap_copy);

    int l_ret= dap_events_socket_queue_ptr_send_to_input(a_es_input, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wasn't send pointer to queue input: code %d", l_ret);
        DAP_DELETE(l_msg);
        return 0;
    }
    return  l_data_size;
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
    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t); if (!l_msg) return 0;
    l_msg->esocket = a_es;
    l_msg->data = DAP_NEW_SIZE(void,l_data_size);
    l_msg->data_size = l_data_size;
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    memcpy( l_msg->data, data, l_data_size);

    int l_ret= dap_events_socket_queue_ptr_send(a_w->queue_es_io, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wasn't send pointer to queue input: code %d", l_ret);
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
    if(sc->buf_out_size>sizeof(sc->buf_out)){
        log_it(L_DEBUG,"write buffer already overflow size=%u/max=%u", sc->buf_out_size, sizeof(sc->buf_out));
        return 0;
    }
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
