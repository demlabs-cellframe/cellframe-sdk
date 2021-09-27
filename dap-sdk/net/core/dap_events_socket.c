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

#if defined (DAP_OS_LINUX)
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#elif defined (DAP_OS_BSD)
#include <sys/types.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#elif defined (DAP_OS_WINDOWS)
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <io.h>

#endif



#if defined (DAP_EVENTS_CAPS_QUEUE_MQUEUE)
#include <sys/time.h>
#include <sys/resource.h>
#endif

#ifdef DAP_OS_BSD
#include <sys/event.h>
#include <err.h>

#ifndef DAP_OS_DARWIN
#include <pthread_np.h>
typedef cpuset_t cpu_set_t; // Adopt BSD CPU setstructure to POSIX variant
#else
#define NOTE_READ NOTE_LOWAT

#endif

#endif


#include <fcntl.h>
#include <pthread.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_list.h"
#include "dap_worker.h"
#include "dap_uuid.h"
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
static uint64_t s_delayed_ops_timeout_ms = 5000;
bool s_remove_and_delete_unsafe_delayed_delete_callback(void * a_arg);



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
    FILE *l_mq_msg_max = fopen("/proc/sys/fs/mqueue/msg_max", "w");
    if (l_mq_msg_max) {
        fprintf(l_mq_msg_max, "%d", DAP_QUEUE_MAX_MSGS);
        fclose(l_mq_msg_max);
    } else {
        log_it(L_ERROR, "Сan't open /proc/sys/fs/mqueue/msg_max file for writing");
    }
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

#ifdef DAP_OS_WINDOWS
void __stdcall mq_receive_cb(HRESULT hr, QUEUEHANDLE qh, DWORD timeout
                             , DWORD action, MQMSGPROPS *pmsgprops, LPOVERLAPPED pov, HANDLE cursor) {
    switch (hr) {
    case MQ_OK:
        SetEvent(pov->hEvent);
        break;
    }
}
#endif

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

    dap_events_socket_t *l_ret = DAP_NEW_Z( dap_events_socket_t );
    if (!l_ret)
        return NULL;

    l_ret->socket = a_sock;
    l_ret->events = a_events;
    l_ret->uuid = dap_uuid_generate_uint64();
    if (a_callbacks)
        memcpy(&l_ret->callbacks, a_callbacks, sizeof(l_ret->callbacks) );
    l_ret->flags = DAP_SOCK_READY_TO_READ;

    l_ret->buf_in_size_max = DAP_EVENTS_SOCKET_BUF;
    l_ret->buf_out_size_max = DAP_EVENTS_SOCKET_BUF;

    l_ret->buf_in     = a_callbacks->timer_callback ? NULL : DAP_NEW_Z_SIZE(byte_t, l_ret->buf_in_size_max + 1);
    l_ret->buf_out    = a_callbacks->timer_callback ? NULL : DAP_NEW_Z_SIZE(byte_t, l_ret->buf_out_size_max + 1);
    l_ret->buf_in_size = l_ret->buf_out_size = 0;
    #if defined(DAP_EVENTS_CAPS_EPOLL)
    l_ret->ev_base_flags = EPOLLERR | EPOLLRDHUP | EPOLLHUP;
    #elif defined(DAP_EVENTS_CAPS_POLL)
    l_ret->poll_base_flags = POLLERR | POLLRDHUP | POLLHUP;
    #elif defined(DAP_EVENTS_CAPS_KQUEUE)
        l_ret->kqueue_event_catched_data.esocket = l_ret;
        l_ret->kqueue_base_flags = 0;
        l_ret->kqueue_base_filter = 0;
    #endif

    //log_it( L_DEBUG,"Dap event socket wrapped around %d sock a_events = %X", a_sock, a_events );

    return l_ret;
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

/**
 * @brief dap_events_socket_reassign_between_workers_unsafe
 * @param a_es
 * @param a_worker_new
 */
void dap_events_socket_reassign_between_workers_unsafe(dap_events_socket_t * a_es, dap_worker_t * a_worker_new)
{
    dap_worker_t * l_worker = a_es->worker;
    dap_events_socket_t * l_queue_input= l_worker->queue_es_new_input[a_worker_new->id];
    log_it(L_DEBUG, "Reassign between %u->%u workers: %p (%d)  ", l_worker->id, a_worker_new->id, a_es, a_es->fd );

    dap_events_socket_remove_from_worker_unsafe( a_es, l_worker );
    a_es->was_reassigned = true;
    if (a_es->callbacks.worker_unassign_callback)
        a_es->callbacks.worker_unassign_callback(a_es, l_worker);

    dap_worker_add_events_socket_inter( l_queue_input,  a_es);
}

/**
 * @brief dap_events_socket_reassign_between_workers_mt
 * @param a_worker_old
 * @param a_es
 * @param a_worker_new
 */
void dap_events_socket_reassign_between_workers_mt(dap_worker_t * a_worker_old, dap_events_socket_t * a_es, dap_worker_t * a_worker_new)
{
    dap_worker_msg_reassign_t * l_msg = DAP_NEW_Z(dap_worker_msg_reassign_t);
    l_msg->esocket = a_es;
    l_msg->esocket_uuid = a_es->uuid;
    l_msg->worker_new = a_worker_new;
    if( dap_events_socket_queue_ptr_send(a_worker_old->queue_es_reassign, l_msg) != 0 ){
        log_it(L_ERROR,"Haven't sent reassign message with esocket %d", a_es?a_es->socket:-1);
        DAP_DELETE(l_msg);
    }
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
#ifdef DAP_OS_WINDOWS
    return NULL;
#else
    UNUSED(a_flags);
    dap_events_socket_t * l_es = DAP_NEW_Z(dap_events_socket_t);
    l_es->type = DESCRIPTOR_TYPE_PIPE;
    l_es->worker = a_w;
    l_es->events = a_w->events;
    l_es->uuid = dap_uuid_generate_uint64();
    l_es->callbacks.read_callback = a_callback; // Arm event callback
#if defined(DAP_EVENTS_CAPS_EPOLL)
    l_es->ev_base_flags = EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP;
#elif defined(DAP_EVENTS_CAPS_POLL)
    l_es->poll_base_flags = POLLIN | POLLERR | POLLRDHUP | POLLHUP;
#elif defined(DAP_EVENTS_CAPS_KQUEUE)
    l_es->kqueue_event_catched_data.esocket = l_es;
    l_es->kqueue_base_flags = EV_ENABLE | EV_CLEAR;
    l_es->kqueue_base_fflags = NOTE_DELETE | NOTE_REVOKE ;
#if !defined(DAP_OS_DARWIN)
    l_es->kqueue_base_fflags |= NOTE_CLOSE | NOTE_CLOSE_WRITE ;
#endif
    l_es->kqueue_base_filter = EVFILT_VNODE;
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
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        log_it( L_ERROR, "Error detected, can't create pipe(): '%s' (%d)", l_errbuf, l_errno);
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
#endif
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
 * @brief dap_events_socket_create
 * @param a_type
 * @param a_callbacks
 * @return
 */
dap_events_socket_t * dap_events_socket_create(dap_events_desc_type_t a_type, dap_events_socket_callbacks_t* a_callbacks)
{
    int l_sock_type = SOCK_STREAM;
    int l_sock_class = AF_INET;

    switch(a_type){
        case DESCRIPTOR_TYPE_SOCKET_CLIENT:
        break;
        case DESCRIPTOR_TYPE_SOCKET_UDP :
            l_sock_type = SOCK_DGRAM;
        break;
        case DESCRIPTOR_TYPE_SOCKET_LOCAL_LISTENING:
#ifdef DAP_OS_UNIX
            l_sock_class = AF_LOCAL;
#elif defined DAP_OS_WINDOWS
            l_sock_class = AF_INET;
#endif
        break;
        default:
            log_it(L_CRITICAL,"Can't create socket type %d", a_type );
            return NULL;
    }

#ifdef DAP_OS_WINDOWS
    SOCKET l_sock = socket(l_sock_class, l_sock_type, IPPROTO_IP);
    u_long l_socket_flags = 1;
    if (ioctlsocket((SOCKET)l_sock, (long)FIONBIO, &l_socket_flags))
        log_it(L_ERROR, "Error ioctl %d", WSAGetLastError());
#else
    int l_sock = socket(l_sock_class, l_sock_type, 0);
    int l_sock_flags = fcntl( l_sock, F_GETFL);
    l_sock_flags |= O_NONBLOCK;
    fcntl( l_sock, F_SETFL, l_sock_flags);

    if (l_sock == INVALID_SOCKET) {
        log_it(L_ERROR, "Socket create error");
        return NULL;
    }
#endif
    dap_events_socket_t * l_es =dap_events_socket_wrap_no_add(dap_events_get_default(),l_sock,a_callbacks);
    if(!l_es){
        log_it(L_CRITICAL,"Can't allocate memory for the new esocket");
        return NULL;
    }
    l_es->type = a_type ;
    if(s_debug_reactor)
        log_it(L_DEBUG,"Created socket %d type %d", l_sock,l_es->type);
    return l_es;
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
    l_es->buf_out_size_max = DAP_QUEUE_MAX_MSGS * sizeof(void*);
    l_es->buf_out       = DAP_NEW_Z_SIZE(byte_t,l_es->buf_out_size_max );
    l_es->buf_in_size_max = DAP_QUEUE_MAX_MSGS * sizeof(void*);
    l_es->buf_in       = DAP_NEW_Z_SIZE(byte_t,l_es->buf_in_size_max );
    //l_es->buf_out_size  = 8 * sizeof(void*);
    l_es->events = a_es->events;
    l_es->uuid = dap_uuid_generate_uint64();
#if defined(DAP_EVENTS_CAPS_EPOLL)
    l_es->ev_base_flags = EPOLLERR | EPOLLRDHUP | EPOLLHUP;
#elif defined(DAP_EVENTS_CAPS_POLL)
    l_es->poll_base_flags = POLLERR | POLLRDHUP | POLLHUP;
#elif defined(DAP_EVENTS_CAPS_KQUEUE)
    // Here we have event identy thats we copy
    l_es->fd = a_es->fd; //
    l_es->pipe_out = a_es;
    l_es->kqueue_base_flags = EV_CLEAR;
    l_es->kqueue_base_fflags = 0;
    l_es->kqueue_base_filter = EVFILT_USER;
    l_es->kqueue_event_catched_data.esocket = l_es;

#else
#error "Not defined s_create_type_pipe for your platform"
#endif

#ifdef DAP_EVENTS_CAPS_QUEUE_MQUEUE
    l_es->mqd = a_es->mqd;
    char l_mq_name[64];
    struct mq_attr l_mq_attr;
    memset(&l_mq_attr,0,sizeof (l_mq_attr));
    l_mq_attr.mq_maxmsg = DAP_QUEUE_MAX_MSGS; // Don't think we need to hold more than 1024 messages
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
#elif defined (DAP_EVENTS_CAPS_QUEUE_PIPE2) || defined (DAP_EVENTS_CAPS_QUEUE_PIPE)
    l_es->fd = a_es->fd2;
#elif defined DAP_EVENTS_CAPS_MSMQ
    l_es->mqh       = a_es->mqh;
    l_es->mqh_recv  = a_es->mqh_recv;

    l_es->socket        = a_es->socket;
    l_es->port          = a_es->port;
    l_es->mq_num        = a_es->mq_num;

    WCHAR l_direct_name[MQ_MAX_Q_NAME_LEN] = { 0 };
    int pos = 0;
#ifdef DAP_BRAND
    pos = _snwprintf_s(l_direct_name, sizeof(l_direct_name)/sizeof(l_direct_name[0]), _TRUNCATE, L"DIRECT=OS:.\\PRIVATE$\\" DAP_BRAND "mq%d", l_es->mq_num);
#else
    pos = _snwprintf_s(l_direct_name, sizeof(l_direct_name)/sizeof(l_direct_name[0]), _TRUNCATE, L"DIRECT=OS:.\\PRIVATE$\\%hs_esmq%d", dap_get_appname(), l_es->mq_num);
#endif
    if (pos < 0) {
        log_it(L_ERROR, "Message queue path error");
        DAP_DELETE(l_es);
        return NULL;
    }

    HRESULT hr = MQOpenQueue(l_direct_name, MQ_SEND_ACCESS, MQ_DENY_NONE, &(l_es->mqh));
    if (hr == MQ_ERROR_QUEUE_NOT_FOUND) {
        log_it(L_INFO, "Queue still not created, wait a bit...");
        Sleep(300);
        hr = MQOpenQueue(l_direct_name, MQ_SEND_ACCESS, MQ_DENY_NONE, &(l_es->mqh));
        if (hr != MQ_OK) {
            log_it(L_ERROR, "Can't open message queue for queue type, error: 0x%x", hr);
            return NULL;
        }
    }
    hr = MQOpenQueue(l_direct_name, MQ_RECEIVE_ACCESS, MQ_DENY_NONE, &(l_es->mqh_recv));
    if (hr != MQ_OK) {
        log_it(L_ERROR, "Can't open message queue for queue type, error: 0x%x", hr);
        return NULL;
    }
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
    // We don't create descriptor for kqueue at all
#else
#error "Not defined dap_events_socket_queue_ptr_create_input() for this platform"
#endif

    l_es->flags = DAP_SOCK_QUEUE_PTR;
    l_es->_pvt = DAP_NEW_Z(struct queue_ptr_input_pvt);
    l_es->callbacks.delete_callback  = s_socket_type_queue_ptr_input_callback_delete;
    l_es->callbacks.queue_ptr_callback = a_es->callbacks.queue_ptr_callback;
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
    l_es->uuid = dap_uuid_generate_uint64();
    if (a_w){
        l_es->events = a_w->events;
        l_es->worker = a_w;
    }
    l_es->callbacks.queue_ptr_callback = a_callback; // Arm event callback
    l_es->buf_in_size_max = DAP_QUEUE_MAX_MSGS * sizeof(void*);
    l_es->buf_in = DAP_NEW_Z_SIZE(byte_t,l_es->buf_in_size_max);
    l_es->buf_out = NULL;

#if defined(DAP_EVENTS_CAPS_EPOLL)
    l_es->ev_base_flags = EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP;
#elif defined(DAP_EVENTS_CAPS_POLL)
    l_es->poll_base_flags = POLLIN | POLLERR | POLLRDHUP | POLLHUP;
#elif defined(DAP_EVENTS_CAPS_KQUEUE)
    l_es->kqueue_event_catched_data.esocket = l_es;
    l_es->kqueue_base_flags =  EV_CLEAR;
    l_es->kqueue_base_fflags = 0;
    l_es->kqueue_base_filter = EVFILT_USER;
    l_es->socket = arc4random();
#else
#error "Not defined s_create_type_queue_ptr for your platform"
#endif


#if defined(DAP_EVENTS_CAPS_QUEUE_PIPE2) || defined(DAP_EVENTS_CAPS_QUEUE_PIPE)
    int l_pipe[2];
    int l_errno;
    char l_errbuf[128];
    l_errbuf[0]=0;
#if defined(DAP_EVENTS_CAPS_QUEUE_PIPE2)
    if( pipe2(l_pipe,O_DIRECT | O_NONBLOCK ) < 0 ){
#elif defined(DAP_EVENTS_CAPS_QUEUE_PIPE)
    if( pipe(l_pipe) < 0 ){
#endif
        l_errno = errno;
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        switch (l_errno) {
            case EINVAL: log_it(L_CRITICAL, "Too old linux version thats doesn't support O_DIRECT flag for pipes (%s)", l_errbuf); break;
            default: log_it( L_ERROR, "Error detected, can't create pipe(): '%s' (%d)", l_errbuf, l_errno);
        }
        DAP_DELETE(l_es);
        return NULL;
    }
    //else
     //   log_it(L_DEBUG, "Created one-way unnamed packet pipe %d->%d", l_pipe[0], l_pipe[1]);
    l_es->fd = l_pipe[0];
    l_es->fd2 = l_pipe[1];
    
#if defined(DAP_EVENTS_CAPS_QUEUE_PIPE)
    // If we have no pipe2() we should set nonblock mode via fcntl
    if (l_es->fd > 0 && l_es->fd2 > 0 ) {
	int l_flags = fcntl(l_es->fd, F_GETFL, 0);
	if (l_flags != -1){
	    l_flags |= O_NONBLOCK);
	    fcntl(l_es->fd, F_SETFL, l_flags) == 0);
	}
	l_flags = fcntl(l_es->fd2, F_GETFL, 0);
	if (l_flags != -1){
	    l_flags |= O_NONBLOCK);
	    fcntl(l_es->fd2, F_SETFL, l_flags) == 0);
	}
    }
#endif

#if !defined (DAP_OS_ANDROID)
    FILE* l_sys_max_pipe_size_fd = fopen("/proc/sys/fs/pipe-max-size", "r");
    if (l_sys_max_pipe_size_fd) {
        const int l_file_buf_size = 64;
        char l_file_buf[l_file_buf_size];
        memset(l_file_buf, 0, l_file_buf_size);
        fread(l_file_buf, l_file_buf_size, 1, l_sys_max_pipe_size_fd);
        uint64_t l_sys_max_pipe_size = strtoull(l_file_buf, 0, 10);
        fcntl(l_pipe[0], F_SETPIPE_SZ, l_sys_max_pipe_size);
        fclose(l_sys_max_pipe_size_fd);
    }
#endif

#elif defined (DAP_EVENTS_CAPS_QUEUE_MQUEUE)
    char l_mq_name[64];
    struct mq_attr l_mq_attr;
    static uint32_t l_mq_last_number=0;
    memset(&l_mq_attr,0,sizeof (l_mq_attr));
    l_mq_attr.mq_maxmsg = DAP_QUEUE_MAX_MSGS; // Don't think we need to hold more than 1024 messages
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
#elif defined DAP_EVENTS_CAPS_MSMQ
    l_es->socket        = socket(AF_INET, SOCK_DGRAM, 0);

    if (l_es->socket == INVALID_SOCKET) {
        log_it(L_ERROR, "Error creating socket for TYPE_QUEUE: %d", WSAGetLastError());
        DAP_DELETE(l_es);
        return NULL;
    }

    int buffsize = 1024;
    setsockopt(l_es->socket, SOL_SOCKET, SO_RCVBUF, (char *)&buffsize, sizeof(int));

    int reuse = 1;
    if (setsockopt(l_es->socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        log_it(L_WARNING, "Can't set up REUSEADDR flag to the socket, err: %d", WSAGetLastError());

    unsigned long l_mode = 1;
    ioctlsocket(l_es->socket, FIONBIO, &l_mode);

    int l_addr_len;
    struct sockaddr_in l_addr;
    l_addr.sin_family = AF_INET;
    IN_ADDR _in_addr = { { .S_addr = htonl(INADDR_LOOPBACK) } };
    l_addr.sin_addr = _in_addr;
    l_addr.sin_port = 0; //l_es->socket  + 32768;
    l_addr_len = sizeof(struct sockaddr_in);

    if (bind(l_es->socket, (struct sockaddr*)&l_addr, sizeof(l_addr)) < 0) {
        log_it(L_ERROR, "Bind error: %d", WSAGetLastError());
    } else {
        int dummy = 100;
        getsockname(l_es->socket, (struct sockaddr*)&l_addr, &dummy);
        l_es->port = l_addr.sin_port;
        //log_it(L_DEBUG, "Bound to port %d", l_addr.sin_port);
    }

    MQQUEUEPROPS   l_qps;
    MQPROPVARIANT  l_qp_var[1];
    QUEUEPROPID    l_qp_id[1];
    HRESULT        l_q_status[1];

    WCHAR l_pathname[MQ_MAX_Q_NAME_LEN - 10] = { 0 };
    static atomic_uint s_queue_num = 0;
    int pos = 0;
#ifdef DAP_BRAND
    pos = _snwprintf_s(l_pathname, sizeof(l_pathname)/sizeof(l_pathname[0]), _TRUNCATE, L".\\PRIVATE$\\" DAP_BRAND "mq%d", l_es->mq_num = s_queue_num++);
#else
    pos = _snwprintf_s(l_pathname, sizeof(l_pathname)/sizeof(l_pathname[0]), _TRUNCATE, L".\\PRIVATE$\\%hs_esmq%d", dap_get_appname(), l_es->mq_num = s_queue_num++);
#endif
    if (pos < 0) {
        log_it(L_ERROR, "Message queue path error");
        DAP_DELETE(l_es);
        return NULL;
    }
    u_long l_p_id         = 0;
    l_qp_id[l_p_id]       = PROPID_Q_PATHNAME;
    l_qp_var[l_p_id].vt   = VT_LPWSTR;
    l_qp_var[l_p_id].pwszVal = l_pathname;
    l_p_id++;

    l_qps.cProp     = l_p_id;
    l_qps.aPropID   = l_qp_id;
    l_qps.aPropVar  = l_qp_var;
    l_qps.aStatus   = l_q_status;

    WCHAR l_direct_name[MQ_MAX_Q_NAME_LEN]      = { 0 };
    WCHAR l_format_name[sizeof(l_direct_name) - 10] = { 0 };
    DWORD l_buflen = sizeof(l_format_name);
    HRESULT hr = MQCreateQueue(NULL, &l_qps, l_format_name, &l_buflen);
    if ((hr != MQ_OK) && (hr != MQ_ERROR_QUEUE_EXISTS) && (hr != MQ_INFORMATION_PROPERTY)) {
        log_it(L_ERROR, "Can't create message queue for queue type, error: 0x%x", hr);
        DAP_DELETE(l_es);
        return NULL;
    }
    _snwprintf_s(l_direct_name, sizeof(l_direct_name)/sizeof(l_direct_name[0]), _TRUNCATE, L"DIRECT=OS:%ls", l_pathname);

    hr = MQOpenQueue(l_direct_name, MQ_SEND_ACCESS, MQ_DENY_NONE, &(l_es->mqh));
    if (hr == MQ_ERROR_QUEUE_NOT_FOUND) {
        log_it(L_INFO, "Queue still not created, wait a bit...");
        Sleep(300);
        hr = MQOpenQueue(l_direct_name, MQ_SEND_ACCESS, MQ_DENY_NONE, &(l_es->mqh));
        if (hr != MQ_OK) {
            log_it(L_ERROR, "Can't open message queue for queue type, error: 0x%x", hr);
            DAP_DELETE(l_es);
            MQDeleteQueue(l_format_name);
            return NULL;
        }
    }
    hr = MQOpenQueue(l_direct_name, MQ_RECEIVE_ACCESS, MQ_DENY_NONE, &(l_es->mqh_recv));
    if (hr != MQ_OK) {
        log_it(L_ERROR, "Can't open message queue for queue type, error: 0x%x", hr);
        DAP_DELETE(l_es);
        MQCloseQueue(l_es->mqh);
        MQDeleteQueue(l_format_name);
        return NULL;
    }
    hr = MQPurgeQueue(l_es->mqh_recv);
    if (hr != MQ_OK) {
        log_it(L_DEBUG, "Message queue %d NOT purged, possible data corruption, err %d", l_es->mq_num, hr);
    }
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
    // We don't create descriptor for kqueue at all
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
    if ( a_w) {
        if(dap_worker_add_events_socket_unsafe(l_es,a_w)) {
#ifdef DAP_OS_WINDOWS
            errno = WSAGetLastError();
#endif
            log_it(L_ERROR, "Can't add esocket %d to polling, err %d", l_es->socket, errno);
        }
    }
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
#elif defined DAP_EVENTS_CAPS_MSMQ
            DWORD l_mp_id = 0;
            MQMSGPROPS    l_mps;
            MQPROPVARIANT l_mpvar[2];
            MSGPROPID     l_p_id[2];

            UCHAR l_body[1024] = { 0 };
            l_p_id[l_mp_id]				= PROPID_M_BODY;
            l_mpvar[l_mp_id].vt			= VT_UI1 | VT_VECTOR;
            l_mpvar[l_mp_id].caub.cElems = sizeof(l_body);
            l_mpvar[l_mp_id].caub.pElems = l_body;
            l_mp_id++;

            l_p_id[l_mp_id]				= PROPID_M_BODY_SIZE;
            l_mpvar[l_mp_id].vt			= VT_UI4;
            l_mp_id++;

            l_mps.cProp    = l_mp_id;
            l_mps.aPropID  = l_p_id;
            l_mps.aPropVar = l_mpvar;
            l_mps.aStatus  = NULL;

            HRESULT hr = MQReceiveMessage(a_esocket->mqh_recv, 1000, MQ_ACTION_RECEIVE, &l_mps, NULL, NULL, NULL, MQ_NO_TRANSACTION);
            if (hr != MQ_OK) {
                log_it(L_ERROR, "An error 0x%x occured receiving a message from queue", hr);
                return -1;
            }
            if (l_mpvar[1].ulVal % sizeof(void*)) {
                log_it(L_ERROR, "Queue message size incorrect: %d", l_mpvar[1].ulVal);
                if (l_mpvar[1].ulVal < sizeof(void*)) {
                    log_it(L_ERROR, "Queue socket %d received invalid data", a_esocket->socket);
                    return -1;
                }
            }
            for (u_int pad = 0; pad < l_mpvar[1].ulVal; pad += sizeof(void*)) {
                memcpy(&l_queue_ptr, l_body + pad, sizeof(void*));
                if(a_esocket->callbacks.queue_ptr_callback)
            	    a_esocket->callbacks.queue_ptr_callback (a_esocket, l_queue_ptr);
            }
#elif defined DAP_EVENTS_CAPS_KQUEUE
        l_queue_ptr = (void*) a_esocket->kqueue_event_catched_data.data;
        if(s_debug_reactor)
            log_it(L_INFO,"Queue ptr received %p ptr on input", l_queue_ptr);
	    if(a_esocket->callbacks.queue_ptr_callback)
            a_esocket->callbacks.queue_ptr_callback (a_esocket, l_queue_ptr);
#else
#error "No Queue fetch mechanism implemented on your platform"
#endif
        } else {
#ifdef DAP_OS_WINDOWS
            int l_read = dap_recvfrom(a_esocket->socket, a_esocket->buf_in, a_esocket->buf_in_size_max);
            if (l_read == SOCKET_ERROR) {
                log_it(L_ERROR, "Queue socket %d received invalid data, error %d", a_esocket->socket, WSAGetLastError());
                return -1;
            }
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
        void * l_queue_ptr = a_esocket->kqueue_event_catched_data.data;
        size_t l_queue_ptr_size = a_esocket->kqueue_event_catched_data.size;
        if(s_debug_reactor)
            log_it(L_INFO,"Queue received %z bytes on input", l_queue_ptr_size);

        a_esocket->callbacks.queue_callback(a_esocket, l_queue_ptr, l_queue_ptr_size);
#else
            size_t l_read = read(a_esocket->socket, a_esocket->buf_in, a_esocket->buf_in_size_max );
#endif
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
    l_es->buf_out_size_max = l_es->buf_in_size_max = 1;
    l_es->buf_out = DAP_NEW_Z_SIZE(byte_t, l_es->buf_out_size_max);
    l_es->type = DESCRIPTOR_TYPE_EVENT;
    l_es->uuid = dap_uuid_generate_uint64();
    if (a_w){
        l_es->events = a_w->events;
        l_es->worker = a_w;
    }
    l_es->callbacks.event_callback = a_callback; // Arm event callback
#if defined(DAP_EVENTS_CAPS_EPOLL)
    l_es->ev_base_flags = EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP;
#elif defined(DAP_EVENTS_CAPS_POLL)
    l_es->poll_base_flags = POLLIN | POLLERR | POLLRDHUP | POLLHUP;
#elif defined(DAP_EVENTS_CAPS_KQUEUE)
    l_es->kqueue_base_flags =  EV_CLEAR;
    l_es->kqueue_base_filter = EVFILT_USER;
    l_es->socket = arc4random();
    l_es->kqueue_event_catched_data.esocket = l_es;
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


    l_es->socket        = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (l_es->socket == INVALID_SOCKET) {
        log_it(L_ERROR, "Error creating socket for TYPE_QUEUE: %d", WSAGetLastError());
        DAP_DELETE(l_es);
        return NULL;
    }
    
    int buffsize = 1024;
    setsockopt(l_es->socket, SOL_SOCKET, SO_RCVBUF, (char *)&buffsize, sizeof(int));

    unsigned long l_mode = 1;
    ioctlsocket(l_es->socket, FIONBIO, &l_mode);

    int reuse = 1;
    if (setsockopt(l_es->socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        log_it(L_WARNING, "Can't set up REUSEADDR flag to the socket, err: %d", WSAGetLastError());

    int l_addr_len;
    struct sockaddr_in l_addr;
    l_addr.sin_family = AF_INET;
    IN_ADDR _in_addr = { { .S_addr = htonl(INADDR_LOOPBACK) } };
    l_addr.sin_addr = _in_addr;
    l_addr.sin_port = 0; //l_es->socket + 32768;
    l_addr_len = sizeof(struct sockaddr_in);

    if (bind(l_es->socket, (struct sockaddr*)&l_addr, sizeof(l_addr)) < 0) {
        log_it(L_ERROR, "Bind error: %d", WSAGetLastError());
    } else {
        int dummy = 100;
        getsockname(l_es->socket, (struct sockaddr*)&l_addr, &dummy);
        l_es->port = l_addr.sin_port;
        //log_it(L_DEBUG, "Bound to port %d", l_addr.sin_port);
    }
#elif defined(DAP_EVENTS_CAPS_KQUEUE)
    // nothing to do
#else 
#error "Not defined s_create_type_event() on your platform"
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
        u_short l_value;
        int l_ret;
        switch (l_ret = dap_recvfrom(a_esocket->socket, a_esocket->buf_in, a_esocket->buf_in_size)) {
        case SOCKET_ERROR:
            log_it(L_CRITICAL, "Can't read from event socket, error: %d", WSAGetLastError());
            break;
        case 0:
            return;
        default:
            l_value = a_esocket->buf_out[0];
            a_esocket->callbacks.event_callback(a_esocket, l_value);
            return;
        }
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
    a_esocket->callbacks.event_callback(a_esocket, a_esocket->kqueue_event_catched_data.value);

#else
#error "No Queue fetch mechanism implemented on your platform"
#endif
    } else
        log_it(L_ERROR, "Event socket %d accepted data but callback is NULL ", a_esocket->socket);
}


typedef struct dap_events_socket_buf_item
{
    dap_events_socket_t * es;
    void *arg;
} dap_events_socket_buf_item_t;

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
static void *dap_events_socket_buf_thread(void *arg)
{
    dap_events_socket_buf_item_t *l_item = (dap_events_socket_buf_item_t*) arg;
    if(!l_item) {
        pthread_exit(0);
    }
    int l_res = 0;
    int l_count = 0;
    while(l_res < 1 && l_count < 3) {
    // wait max 5 min
#ifdef DAP_OS_WINDOWS
		log_it(L_INFO, "Wait 5 minutes");
    	l_res = wait_send_socket(l_item->es->socket, 300000);
#else
        l_res = wait_send_socket(l_item->es->fd2, 300000);
#endif
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
#if defined (DAP_EVENTS_CAPS_KQUEUE)
    if (a_es_input->pipe_out){
        int l_ret;
        struct kevent l_event={0};
        dap_events_socket_t * l_es = a_es_input->pipe_out;
        assert(l_es);

        dap_events_socket_w_data_t * l_es_w_data = DAP_NEW_Z(dap_events_socket_w_data_t);
        if(!l_es_w_data){
            log_it(L_CRITICAL, "Can't allocate, out of memory");
            return -1024;
        }

        l_es_w_data->esocket = l_es;
        l_es_w_data->ptr = a_arg;
        EV_SET(&l_event,a_es_input->socket+arc4random()  , EVFILT_USER,EV_ADD | EV_CLEAR | EV_ONESHOT, NOTE_FFCOPY | NOTE_TRIGGER ,0, l_es_w_data);
        if(l_es->worker)
            l_ret=kevent(l_es->worker->kqueue_fd,&l_event,1,NULL,0,NULL);
        else if (l_es->proc_thread)
            l_ret=kevent(l_es->proc_thread->kqueue_fd,&l_event,1,NULL,0,NULL);
        else
            l_ret=-100;
        if(l_ret ==0 ){
            return 0;
        }else{
            log_it(L_ERROR,"Can't send message in queue, code %d", l_ret);
            DAP_DELETE(l_es_w_data);
            return l_ret;
        }
    }else{
        log_it(L_ERROR,"No pipe_out pointer for queue socket, possible created wrong");
        return -2;
    }
    
#else    
    void * l_arg = a_arg;
    /*if (a_es_input->buf_out_size >= sizeof(void*)) {
        if (memcmp(a_es_input->buf_out + a_es_input->buf_out_size - sizeof(void*), a_arg, sizeof(void*))) {
            log_it(L_INFO, "Ptr 0x%x already present in input, drop it", a_arg);
            return 2;
        }
    }*/
    return dap_events_socket_write_unsafe(a_es_input, &l_arg, sizeof(l_arg))
            == sizeof(l_arg) ? 0 : -1;
#endif
}

/**
 * @brief dap_events_socket_send_event
 * @param a_es
 * @param a_arg
 */
int dap_events_socket_queue_ptr_send( dap_events_socket_t * a_es, void* a_arg)
{
    int l_ret=-1024;
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
    if ( l_ret == EPERM){
        log_it(L_ERROR,"No permissions to send data in mqueue");
    }

    if (l_errno == EINVAL || l_errno == EINTR || l_errno == ETIMEDOUT)
        l_errno = EAGAIN;
    if (l_ret == 0)
        l_ret = sizeof (a_arg);
    else if (l_ret >0)
        l_ret = -l_ret;
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
#elif defined DAP_EVENTS_CAPS_MSMQ

    char *pbuf = (char *)&a_arg;

    DWORD l_mp_id = 0;
    MQMSGPROPS    l_mps;
    MQPROPVARIANT l_mpvar[1];
    MSGPROPID     l_p_id[1];
    HRESULT       l_mstatus[1];

    l_p_id[l_mp_id] = PROPID_M_BODY;
    l_mpvar[l_mp_id].vt = VT_VECTOR | VT_UI1;
    l_mpvar[l_mp_id].caub.pElems = (unsigned char*)(pbuf);
    l_mpvar[l_mp_id].caub.cElems = sizeof(void*);
    l_mp_id++;

    l_mps.cProp = l_mp_id;
    l_mps.aPropID = l_p_id;
    l_mps.aPropVar = l_mpvar;
    l_mps.aStatus = l_mstatus;
    HRESULT hr = MQSendMessage(a_es->mqh, &l_mps, MQ_NO_TRANSACTION);

    if (hr != MQ_OK) {
        log_it(L_ERROR, "An error occured on sending message to queue, errno: 0x%x", hr);
        return hr;
    }
    
    if(dap_sendto(a_es->socket, a_es->port, NULL, 0) == SOCKET_ERROR) {
        return WSAGetLastError();
    } else {
        return 0;
    }
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
    struct kevent l_event={0};
    dap_events_socket_w_data_t * l_es_w_data = DAP_NEW_Z(dap_events_socket_w_data_t);
    if(!l_es_w_data ) // Out of memory
        return -666;

    l_es_w_data->esocket = a_es;
    l_es_w_data->ptr = a_arg;
    EV_SET(&l_event,a_es->socket+arc4random()  , EVFILT_USER,EV_ADD | EV_CLEAR | EV_ONESHOT, NOTE_FFCOPY | NOTE_TRIGGER ,0, l_es_w_data);
    int l_n;
    if(a_es->pipe_out){ // If we have pipe out - we send events directly to the pipe out kqueue fd
        if(a_es->pipe_out->worker){
            if( s_debug_reactor) log_it(L_DEBUG, "Sent kevent() with ptr %p to pipe_out worker on esocket %d",a_arg,a_es);
            l_n = kevent(a_es->pipe_out->worker->kqueue_fd,&l_event,1,NULL,0,NULL);
        }else if (a_es->pipe_out->proc_thread){
            l_n = kevent(a_es->pipe_out->proc_thread->kqueue_fd,&l_event,1,NULL,0,NULL);
            if( s_debug_reactor) log_it(L_DEBUG, "Sent kevent() with ptr %p to pipe_out proc_thread on esocket %d",a_arg,a_es);
        }
        else {
            log_it(L_WARNING,"Trying to send pointer in pipe out queue thats not assigned to any worker or proc thread");
            l_n = 0;
            DAP_DELETE(l_es_w_data);
        }
    }else if(a_es->worker){
        l_n = kevent(a_es->worker->kqueue_fd,&l_event,1,NULL,0,NULL);
        if( s_debug_reactor) log_it(L_DEBUG, "Sent kevent() with ptr %p to worker on esocket %d",a_arg,a_es);
    }else if (a_es->proc_thread){
        l_n = kevent(a_es->proc_thread->kqueue_fd,&l_event,1,NULL,0,NULL);
        if( s_debug_reactor) log_it(L_DEBUG, "Sent kevent() with ptr %p to proc_thread on esocket %d",a_arg,a_es);
    }else {
        log_it(L_WARNING,"Trying to send pointer in queue thats not assigned to any worker or proc thread");
        l_n = 0;
        DAP_DELETE(l_es_w_data);
    }

    if(l_n == 0 ){
        l_ret = sizeof (a_arg);
    }else{
        l_errno = errno;
        log_it(L_ERROR,"Sending kevent error code %d", l_n);
        l_ret = -1;
    }
    
#else
#error "Not implemented dap_events_socket_queue_ptr_send() for this platform"
#endif
    if (l_ret == sizeof(a_arg) ){
        return 0;
    }else{
        // Try again
        if(l_errno == EAGAIN || l_errno == EWOULDBLOCK ){
            add_ptr_to_buf(a_es, a_arg);
            return 0;
        }else {
            char l_errbuf[128];
            log_it(L_ERROR, "Can't send ptr to queue:\"%s\" code %d", strerror_r(l_errno, l_errbuf, sizeof (l_errbuf)), l_errno);
            return l_errno;
        }
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
#elif defined (DAP_OS_WINDOWS)
    a_es->buf_out[0] = (u_short)a_value;
    if(dap_sendto(a_es->socket, a_es->port, a_es->buf_out, sizeof(uint64_t)) == SOCKET_ERROR) {
        return WSAGetLastError();
    } else {
        return 0;
    }
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
    struct kevent l_event={0};
    dap_events_socket_w_data_t * l_es_w_data = DAP_NEW_Z(dap_events_socket_w_data_t);
    l_es_w_data->esocket = a_es;
    l_es_w_data->value = a_value;

    EV_SET(&l_event,a_es->socket, EVFILT_USER,0, NOTE_TRIGGER ,(intptr_t) a_es->socket, l_es_w_data);

    int l_n;

    if(a_es->pipe_out){ // If we have pipe out - we send events directly to the pipe out kqueue fd
        if(a_es->pipe_out->worker)
            l_n = kevent(a_es->pipe_out->worker->kqueue_fd,&l_event,1,NULL,0,NULL);
        else if (a_es->pipe_out->proc_thread)
            l_n = kevent(a_es->pipe_out->proc_thread->kqueue_fd,&l_event,1,NULL,0,NULL);
        else {
            log_it(L_WARNING,"Trying to send pointer in pipe out queue thats not assigned to any worker or proc thread");
            l_n = -1;
        }
    }else if(a_es->worker)
        l_n = kevent(a_es->worker->kqueue_fd,&l_event,1,NULL,0,NULL);
    else if (a_es->proc_thread)
        l_n = kevent(a_es->proc_thread->kqueue_fd,&l_event,1,NULL,0,NULL);
    else
        l_n = -1;

    if(l_n != 0){
        log_it(L_ERROR,"Haven't sent pointer in pipe out queue, code %d", l_n);
        DAP_DELETE(l_es_w_data);
    }
    return l_n;
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
    dap_events_socket_uuid_t * l_es_uuid_ptr= DAP_NEW_Z(dap_events_socket_uuid_t);
    *l_es_uuid_ptr = a_es->uuid;

    int l_ret= dap_events_socket_queue_ptr_send( a_es->worker->queue_es_delete, l_es_uuid_ptr );
    if( l_ret != 0 ){
        log_it(L_ERROR, "Queue send returned %d", l_ret);
        DAP_DELETE(l_es_uuid_ptr);
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
    dap_events_socket_t * l_es = DAP_NEW_Z( dap_events_socket_t ); if (!l_es) return NULL;

    l_es->socket = a_sock;
    l_es->events = a_events;
    l_es->server = a_server;
    l_es->uuid = dap_uuid_generate_uint64();
    memcpy(&l_es->callbacks,a_callbacks, sizeof ( l_es->callbacks) );
    l_es->buf_out_size_max = l_es->buf_in_size_max = DAP_EVENTS_SOCKET_BUF;
    l_es->buf_in = a_callbacks->timer_callback ? NULL : DAP_NEW_Z_SIZE(byte_t, l_es->buf_in_size_max+1);
    l_es->buf_out = a_callbacks->timer_callback ? NULL : DAP_NEW_Z_SIZE(byte_t, l_es->buf_out_size_max+1);
    l_es->buf_in_size = l_es->buf_out_size = 0;
    l_es->flags = DAP_SOCK_READY_TO_READ;
    l_es->last_time_active = l_es->last_ping_request = time( NULL );

    return l_es;
}


/**
 * @brief dap_worker_esocket_find_uuid
 * @param a_worker
 * @param a_es_uuid
 * @return
 */
dap_events_socket_t *dap_worker_esocket_find_uuid(dap_worker_t * a_worker, dap_events_socket_uuid_t a_es_uuid )
{
    assert(a_worker);
    dap_events_socket_t * l_ret = NULL;
    if(a_worker->esockets ) {
        pthread_rwlock_rdlock(&a_worker->esocket_rwlock);
        //HASH_FIND_PTR( a_worker->esockets, &a_es_uuid,l_ret );
        HASH_FIND(hh_worker, a_worker->esockets, &a_es_uuid, sizeof(a_es_uuid), l_ret );
        pthread_rwlock_unlock(&a_worker->esocket_rwlock );
    }
    return l_ret;
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
#ifdef DAP_OS_WINDOWS
                int l_errno = WSAGetLastError();
#else
                int l_errno = errno;
#endif
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
    #elif defined (DAP_EVENTS_CAPS_KQUEUE)
    if (a_esocket->socket != -1  ){ // Not everything we add in poll
	    struct kevent * l_event = &a_esocket->kqueue_event;
	    short l_filter  =a_esocket->kqueue_base_filter;
	    u_short l_flags =a_esocket->kqueue_base_flags;
	    u_int l_fflags =a_esocket->kqueue_base_fflags;
	    
        int l_kqueue_fd = a_esocket->worker? a_esocket->worker->kqueue_fd :
                          a_esocket->proc_thread ? a_esocket->proc_thread->kqueue_fd : -1;
        if ( l_kqueue_fd == -1 ){
            log_it(L_ERROR, "Esocket is not assigned with anything ,exit");
        }

        // Check & add
        bool l_is_error=false;
        int l_errno=0;
        if (a_esocket->type == DESCRIPTOR_TYPE_EVENT ){
            EV_SET(l_event, a_esocket->socket, EVFILT_USER,EV_ADD| EV_CLEAR ,0,0, &a_esocket->kqueue_event_catched_data );
            if( kevent( l_kqueue_fd,l_event,1,NULL,0,NULL)!=0){
                l_is_error = true;
                l_errno = errno;
            }
        }else{
            EV_SET(l_event, a_esocket->socket, l_filter,l_flags| EV_ADD,l_fflags,a_esocket->kqueue_data,a_esocket);
            if( a_esocket->flags & DAP_SOCK_READY_TO_READ ){
                EV_SET(l_event, a_esocket->socket, EVFILT_READ,l_flags| EV_ADD,l_fflags,a_esocket->kqueue_data,a_esocket);
                if( kevent( l_kqueue_fd,l_event,1,NULL,0,NULL) != 1 ){
                    l_is_error = true;
                    l_errno = errno;
                }
            }
            if( !l_is_error){
                if( a_esocket->flags & DAP_SOCK_READY_TO_WRITE || a_esocket->flags &DAP_SOCK_CONNECTING ){
                    EV_SET(l_event, a_esocket->socket, EVFILT_WRITE,l_flags| EV_ADD,l_fflags,a_esocket->kqueue_data,a_esocket);
                    if(kevent( l_kqueue_fd,l_event,1,NULL,0,NULL) != 1){
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
 * @brief dap_events_socket_ready_to_read
 * @param sc
 * @param isReady
 */
void dap_events_socket_set_readable_unsafe( dap_events_socket_t *a_esocket, bool a_is_ready )
{
    if( a_is_ready == (bool)(a_esocket->flags & DAP_SOCK_READY_TO_READ))
        return;
    if ( a_is_ready ){
        a_esocket->flags |= DAP_SOCK_READY_TO_READ;
    }else{
        a_esocket->flags ^= DAP_SOCK_READY_TO_READ;
    }
#ifdef DAP_EVENTS_CAPS_EVENT_KEVENT
    if( a_esocket->type != DESCRIPTOR_TYPE_EVENT &&
        a_esocket->type != DESCRIPTOR_TYPE_QUEUE &&
        a_esocket->type != DESCRIPTOR_TYPE_TIMER  ){
        struct kevent l_event;
        uint16_t l_op_flag = a_is_ready? EV_ADD : EV_DELETE;
        EV_SET(&l_event, a_esocket->socket, EVFILT_READ,
               a_esocket->kqueue_base_flags | l_op_flag,a_esocket->kqueue_base_fflags ,
               a_esocket->kqueue_data,a_esocket);
        int l_kqueue_fd = a_esocket->worker? a_esocket->worker->kqueue_fd :
                          a_esocket->proc_thread ? a_esocket->proc_thread->kqueue_fd : -1;
        if( l_kqueue_fd>0 ){
            int l_kevent_ret = kevent(l_kqueue_fd,&l_event,1,NULL,0,NULL);
            int l_errno = errno;
            if ( l_kevent_ret !=1 && l_errno != EINPROGRESS ){
                char l_errbuf[128];
                l_errbuf[0]=0;
                strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                if (l_errno == EBADF){
                    log_it(L_ATT,"Set readable: socket %d (%p ) disconnected, rise CLOSE flag to remove from queue, lost %"DAP_UINT64_FORMAT_U":%" DAP_UINT64_FORMAT_U
                           " bytes",a_esocket->socket,a_esocket,a_esocket->buf_in_size,a_esocket->buf_out_size);
                    a_esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
                    a_esocket->buf_in_size = a_esocket->buf_out_size = 0; // Reset everything from buffer, we close it now all
                }else{
                    log_it(L_ERROR,"Can't update client socket %d state on kqueue fd for set_read op %d: \"%s\" (%d)",
                                    a_esocket->socket, l_kqueue_fd, l_errbuf, l_errno);
                }
            }
        }
    }else
        log_it(L_WARNING,"Trying to set readable/writable event, queue or timer thats you shouldnt do");
#else
    if( a_esocket->worker)
        dap_events_socket_worker_poll_update_unsafe( a_esocket);
    else if( a_esocket->proc_thread)
        dap_proc_thread_esocket_update_poll_flags(a_esocket->proc_thread,a_esocket );
#endif

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

    if ( a_is_ready ) {
        a_esocket->flags |= DAP_SOCK_READY_TO_WRITE;
#ifdef DAP_EVENTS_CAPS_EPOLL
        if (a_esocket->type == DESCRIPTOR_TYPE_QUEUE)
            a_esocket->ev_base_flags |= EPOLLONESHOT;
#endif
    }
    else {
        a_esocket->flags ^= DAP_SOCK_READY_TO_WRITE;
#ifdef DAP_EVENTS_CAPS_EPOLL
        if (a_esocket->type == DESCRIPTOR_TYPE_QUEUE)
            a_esocket->ev_base_flags ^= EPOLLONESHOT;
#endif
    }


#ifdef DAP_EVENTS_CAPS_EVENT_KEVENT
    if( a_esocket->type != DESCRIPTOR_TYPE_EVENT &&
        a_esocket->type != DESCRIPTOR_TYPE_QUEUE &&
        a_esocket->type != DESCRIPTOR_TYPE_TIMER  ){
        struct kevent l_event;
        uint16_t l_op_flag = a_is_ready? EV_ADD : EV_DELETE;
        int l_expected_reply = a_is_ready? 1: 0;
        EV_SET(&l_event, a_esocket->socket, EVFILT_WRITE,
               a_esocket->kqueue_base_flags | l_op_flag,a_esocket->kqueue_base_fflags ,
               a_esocket->kqueue_data,a_esocket);
        int l_kqueue_fd = a_esocket->worker? a_esocket->worker->kqueue_fd :
                          a_esocket->proc_thread ? a_esocket->proc_thread->kqueue_fd : -1;
        if( l_kqueue_fd>0 ){
            int l_kevent_ret=kevent(l_kqueue_fd,&l_event,1,NULL,0,NULL);
            int l_errno = errno;
            if ( l_kevent_ret!=l_expected_reply && l_errno != EINPROGRESS && l_errno != ENOENT ){
                char l_errbuf[128];
                l_errbuf[0]=0;
                strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                if (l_errno == EBADF){
                    log_it(L_ATT,"Set writable: socket %d (%p ) disconnected, rise CLOSE flag to remove from queue, lost %"DAP_UINT64_FORMAT_U":%" DAP_UINT64_FORMAT_U
                           " bytes",a_esocket->socket,a_esocket,a_esocket->buf_in_size,a_esocket->buf_out_size);
                    a_esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
                    a_esocket->buf_in_size = a_esocket->buf_out_size = 0; // Reset everything from buffer, we close it now all
                }else{
                    log_it(L_ERROR,"Can't update client socket %d state on kqueue fd for set_write op %d: \"%s\" (%d)",
                                    a_esocket->socket, l_kqueue_fd, l_errbuf, l_errno);
                }
            }
        }
    }else
        log_it(L_WARNING,"Trying to set readable/writable event, queue or timer thats you shouldnt do");
#else
    if( a_esocket->worker )
        dap_events_socket_worker_poll_update_unsafe(a_esocket);
    else if( a_esocket->proc_thread)
        dap_proc_thread_esocket_update_poll_flags(a_esocket->proc_thread,a_esocket );
#endif

}


/**
 * @brief s_remove_and_delete_unsafe_delayed_delete_callback
 * @param arg
 * @return
 */
bool s_remove_and_delete_unsafe_delayed_delete_callback(void * a_arg)
{
    dap_worker_t * l_worker = dap_events_get_current_worker(dap_events_get_default());
    dap_events_socket_uuid_w_data_t * l_es_handler = (dap_events_socket_uuid_w_data_t*) a_arg;
    assert(l_es_handler);
    assert(l_worker);
    dap_events_socket_t * l_es;
    if( (l_es = dap_worker_esocket_find_uuid(l_worker, l_es_handler->esocket_uuid)) != NULL)
        //dap_events_socket_remove_and_delete_unsafe(l_es,l_es_handler->value == 1);
        dap_events_remove_and_delete_socket_unsafe(dap_events_get_default(), l_es, l_es_handler->value == 1);
    DAP_DELETE(l_es_handler);

    return false;
}

/**
 * @brief dap_events_socket_remove_and_delete_unsafe_delayed
 * @param a_es
 * @param a_preserve_inheritor
 */
void dap_events_socket_remove_and_delete_unsafe_delayed( dap_events_socket_t *a_es, bool a_preserve_inheritor )
{
    dap_events_socket_uuid_w_data_t * l_es_handler = DAP_NEW_Z(dap_events_socket_uuid_w_data_t);
    l_es_handler->esocket_uuid = a_es->uuid;
    l_es_handler->value = a_preserve_inheritor ? 1 : 0;
    dap_events_socket_descriptor_close(a_es);

    dap_worker_t * l_worker = a_es->worker;
    dap_events_socket_remove_from_worker_unsafe( a_es, l_worker);
    a_es->flags |= DAP_SOCK_SIGNAL_CLOSE;
    dap_timerfd_start_on_worker(l_worker, s_delayed_ops_timeout_ms,
                                s_remove_and_delete_unsafe_delayed_delete_callback, l_es_handler );
}

/**
 * @brief dap_events_socket_remove Removes the client from the list
 * @param sc Connection instance
 */
void dap_events_socket_remove_and_delete_unsafe( dap_events_socket_t *a_es, bool preserve_inheritor )
{
    assert(a_es);

#ifdef DAP_EVENTS_CAPS_POLL
    if(a_es->worker){
        assert (a_es->poll_index>=0);
        a_es->worker->poll[a_es->poll_index].fd=-1;
        a_es->worker->poll_esocket[a_es->poll_index]=NULL;
    }
#endif

    //log_it( L_DEBUG, "es is going to be removed from the lists and free the memory (0x%016X)", a_es );
    dap_events_socket_remove_from_worker_unsafe(a_es, a_es->worker);

    //log_it( L_DEBUG, "dap_events_socket wrapped around %d socket is removed", a_es->socket );

    if( a_es->callbacks.delete_callback )
        a_es->callbacks.delete_callback( a_es, NULL ); // Init internal structure

    dap_events_socket_delete_unsafe(a_es, preserve_inheritor);

}

/**
 * @brief dap_events_socket_descriptor_close
 * @param a_socket
 */
void dap_events_socket_descriptor_close(dap_events_socket_t *a_esocket)
{
#ifdef DAP_OS_WINDOWS
    if ( a_esocket->socket && (a_esocket->socket != INVALID_SOCKET)) {
        closesocket( a_esocket->socket );
#else
    if ( a_esocket->socket && (a_esocket->socket != -1)) {
            close( a_esocket->socket );
        if( a_esocket->fd2 > 0 ){
            close( a_esocket->fd2);
        }
#endif
    }
    a_esocket->fd2 = -1;
    a_esocket->fd = -1;
}

/**
 * @brief dap_events_socket_delete_unsafe
 * @param a_esocket
 * @param a_preserve_inheritor
 */
void dap_events_socket_delete_unsafe( dap_events_socket_t * a_esocket , bool a_preserve_inheritor)
{
    dap_events_socket_descriptor_close(a_esocket);
    if (!a_preserve_inheritor )
        DAP_DEL_Z(a_esocket->_inheritor)

    DAP_DEL_Z(a_esocket->_pvt)
    DAP_DEL_Z(a_esocket->buf_in)
    DAP_DEL_Z(a_esocket->buf_out)
    DAP_DEL_Z(a_esocket->remote_addr_str)

    DAP_DEL_Z( a_esocket )
}

/**
 * @brief dap_events_socket_delete
 * @param a_es
 */
void dap_events_socket_remove_from_worker_unsafe( dap_events_socket_t *a_es, dap_worker_t * a_worker)
{
    if (!a_es->worker) {
        log_it(L_INFO, "No worker assigned to esocket %d", a_es->socket);
        return;
    }

    pthread_rwlock_wrlock(&a_worker->esocket_rwlock);
    a_worker->event_sockets_count--;
    HASH_DELETE(hh_worker,a_worker->esockets, a_es);
    pthread_rwlock_unlock(&a_worker->esocket_rwlock);

#if defined(DAP_EVENTS_CAPS_EPOLL)

    if ( epoll_ctl( a_worker->epoll_fd, EPOLL_CTL_DEL, a_es->socket, &a_es->ev) == -1 ) {
        int l_errno = errno;
        char l_errbuf[128];
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        log_it( L_ERROR,"Can't remove event socket's handler from the epoll_fd %d  \"%s\" (%d)",
                a_worker->epoll_fd, l_errbuf, l_errno);
    } //else
      //  log_it( L_DEBUG,"Removed epoll's event from dap_worker #%u", a_worker->id );
#elif defined(DAP_EVENTS_CAPS_KQUEUE)
    if (a_es->socket != -1 && a_es->type != DESCRIPTOR_TYPE_TIMER){
        struct kevent * l_event = &a_es->kqueue_event;
        if (a_es->kqueue_base_filter){
            EV_SET(l_event, a_es->socket, a_es->kqueue_base_filter ,EV_DELETE, 0,0,a_es);
            if ( kevent( a_worker->kqueue_fd,l_event,1,NULL,0,NULL) != 1 ) {
                int l_errno = errno;
                char l_errbuf[128];
                strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                log_it( L_ERROR,"Can't remove event socket's handler %d from the kqueue %d filter %d \"%s\" (%d)", a_es->socket,
                    a_worker->kqueue_fd,a_es->kqueue_base_filter,  l_errbuf, l_errno);
            }
        }else{
            EV_SET(l_event, a_es->socket, EVFILT_EXCEPT ,EV_DELETE, 0,0,a_es);
            kevent( a_worker->kqueue_fd,l_event,1,NULL,0,NULL); // If this filter is not set up - no warnings


            if(a_es->flags & DAP_SOCK_READY_TO_WRITE){
                EV_SET(l_event, a_es->socket, EVFILT_WRITE ,EV_DELETE, 0,0,a_es);
                if ( kevent( a_worker->kqueue_fd,l_event,1,NULL,0,NULL) != 0 ) {
                    int l_errno = errno;
                    char l_errbuf[128];
                    strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                    log_it( L_ERROR,"Can't remove event socket's handler %d from the kqueue %d filter EVFILT_WRITE \"%s\" (%d)", a_es->socket,
                        a_worker->kqueue_fd, l_errbuf, l_errno);
                }
            }
            if(a_es->flags & DAP_SOCK_READY_TO_READ){
                EV_SET(l_event, a_es->socket, EVFILT_READ ,EV_DELETE, 0,0,a_es);
                if ( kevent( a_worker->kqueue_fd,l_event,1,NULL,0,NULL) != 0 ) {
                    int l_errno = errno;
                    char l_errbuf[128];
                    strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                    log_it( L_ERROR,"Can't remove event socket's handler %d from the kqueue %d filter EVFILT_READ \"%s\" (%d)", a_es->socket,
                        a_worker->kqueue_fd, l_errbuf, l_errno);
                }
            }

        }
    }
#elif defined (DAP_EVENTS_CAPS_POLL)
    if (a_es->poll_index < a_worker->poll_count ){
        a_worker->poll[a_es->poll_index].fd = -1;
        a_worker->poll_compress = true;
    }else{
        log_it(L_ERROR, "Wrong poll index when remove from worker (unsafe): %u when total count %u", a_es->poll_index, a_worker->poll_count);
    }
#else
#error "Unimplemented new esocket on worker callback for current platform"
#endif
    a_es->worker = NULL;
}


/**
 * @brief dap_events_socket_remove_and_delete
 * @param a_w
 * @param a_es_uuid
 */
void dap_events_socket_remove_and_delete_mt(dap_worker_t * a_w,  dap_events_socket_uuid_t a_es_uuid )
{
    assert(a_w);
    dap_events_socket_uuid_t * l_es_uuid_ptr= DAP_NEW_Z(dap_events_socket_uuid_t);
    *l_es_uuid_ptr = a_es_uuid;

    if(dap_events_socket_queue_ptr_send( a_w->queue_es_delete, l_es_uuid_ptr ) != 0 ){
        log_it(L_ERROR,"Can't send %"DAP_UINT64_FORMAT_U" uuid in queue",a_es_uuid);
        DAP_DELETE(l_es_uuid_ptr);
    }
}

/**
 * @brief dap_events_socket_set_readable_mt
 * @param a_w
 * @param a_es_uuid
 * @param a_is_ready
 */
void dap_events_socket_set_readable_mt(dap_worker_t * a_w, dap_events_socket_uuid_t a_es_uuid,bool a_is_ready)
{
    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t); if (! l_msg) return;
    l_msg->esocket_uuid = a_es_uuid;
    if (a_is_ready)
        l_msg->flags_set = DAP_SOCK_READY_TO_READ;
    else
        l_msg->flags_unset = DAP_SOCK_READY_TO_READ;

    int l_ret= dap_events_socket_queue_ptr_send(a_w->queue_es_io, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "set readable mt: wasn't send pointer to queue with set readble flag: code %d", l_ret);
        DAP_DELETE(l_msg);
    }
}

/**
 * @brief dap_events_socket_set_writable_mt
 * @param a_w
 * @param a_es_uuid
 * @param a_is_ready
 */
void dap_events_socket_set_writable_mt(dap_worker_t * a_w, dap_events_socket_uuid_t a_es_uuid, bool a_is_ready)
{
    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t); if (!l_msg) return;
    l_msg->esocket_uuid = a_es_uuid;

    if (a_is_ready)
        l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    else
        l_msg->flags_unset = DAP_SOCK_READY_TO_WRITE;

    int l_ret= dap_events_socket_queue_ptr_send(a_w->queue_es_io, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "set writable mt: wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg);
    }
}

/**
 * @brief dap_events_socket_write_inter
 * @param a_es_input
 * @param a_es_uuid
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_events_socket_write_inter(dap_events_socket_t * a_es_input, dap_events_socket_uuid_t a_es_uuid, const void * a_data, size_t a_data_size)
{
    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t); if( !l_msg) return 0;
    l_msg->esocket_uuid = a_es_uuid;
    l_msg->data = DAP_NEW_SIZE(void,a_data_size);
    l_msg->data_size = a_data_size;
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    if( a_data)
        memcpy( l_msg->data, a_data, a_data_size);

    int l_ret= dap_events_socket_queue_ptr_send_to_input( a_es_input, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "write inter: wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg);
        return 0;
    }
    return  a_data_size;
}

/**
 * @brief dap_events_socket_write_f_inter
 * @param a_es_input
 * @param a_es_uuid
 * @param a_format
 * @return
 */
size_t dap_events_socket_write_f_inter(dap_events_socket_t * a_es_input, dap_events_socket_uuid_t a_es_uuid, const char * a_format,...)
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
    l_msg->esocket_uuid = a_es_uuid;
    l_msg->data = DAP_NEW_SIZE(void,l_data_size);
    l_msg->data_size = l_data_size;
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    l_data_size = dap_vsprintf(l_msg->data,a_format,ap_copy);
    va_end(ap_copy);

    int l_ret= dap_events_socket_queue_ptr_send_to_input(a_es_input, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "wite f inter: wasn't send pointer to queue input: code %d", l_ret);
        DAP_DELETE(l_msg);
        return 0;
    }
    return  l_data_size;
}

/**
 * @brief dap_events_socket_write_mt
 * @param a_w
 * @param a_es_uuid
 * @param a_data
 * @param l_data_size
 * @return
 */
size_t dap_events_socket_write_mt(dap_worker_t * a_w,dap_events_socket_uuid_t a_es_uuid, const void * data, size_t l_data_size)
{
    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t); if (!l_msg) return 0;
    l_msg->esocket_uuid = a_es_uuid;
    l_msg->data = DAP_NEW_SIZE(void,l_data_size);
    l_msg->data_size = l_data_size;
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    memcpy( l_msg->data, data, l_data_size);

    int l_ret= dap_events_socket_queue_ptr_send(a_w->queue_es_io, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "wite mt: wasn't send pointer to queue input: code %d", l_ret);
        DAP_DELETE(l_msg);
        return 0;
    }
    return  l_data_size;
}

/**
 * @brief dap_events_socket_write_f_mt
 * @param a_es_uuid
 * @param a_format
 * @return
 */
size_t dap_events_socket_write_f_mt(dap_worker_t * a_w,dap_events_socket_uuid_t a_es_uuid, const char * a_format,...)
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
    l_msg->esocket_uuid = a_es_uuid;
    l_msg->data = DAP_NEW_SIZE(void,l_data_size + 1);
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    l_data_size = dap_vsprintf(l_msg->data,a_format,ap_copy);
    va_end(ap_copy);
    if (l_data_size <0 ){
        log_it(L_ERROR,"Write f mt: can't write out formatted data '%s' with values",a_format);
        DAP_DELETE(l_msg->data);
        DAP_DELETE(l_msg);
        return 0;
    }
    l_msg->data_size = l_data_size;
    int l_ret= dap_events_socket_queue_ptr_send(a_w->queue_es_io, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wrrite f mt: wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg->data);
        DAP_DELETE(l_msg);
        return 0;
    }
    return l_data_size;
}

/**
 * @brief dap_events_socket_write_unsafe
 * @param a_es
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_events_socket_write_unsafe(dap_events_socket_t *a_es, const void * a_data, size_t a_data_size)
{
    if (a_es->buf_out_size + a_data_size > a_es->buf_out_size_max) {
        if (a_es->buf_out_size_max + a_data_size > DAP_EVENTS_SOCKET_BUF_LIMIT) {
            log_it(L_ERROR, "Write esocket buffer overflow size=%u/max=%u", a_es->buf_out_size_max, DAP_EVENTS_SOCKET_BUF_LIMIT);
            return 0;
        } else {
            size_t l_new_size = a_es->buf_out_size_max * 2;
            if (l_new_size > DAP_EVENTS_SOCKET_BUF_LIMIT)
                l_new_size = DAP_EVENTS_SOCKET_BUF_LIMIT;
            a_es->buf_out = DAP_REALLOC(a_es->buf_out, l_new_size);
            a_es->buf_out_size_max = l_new_size;
        }
     }
     a_data_size = (a_es->buf_out_size + a_data_size < a_es->buf_out_size_max) ? a_data_size : (a_es->buf_out_size_max - a_es->buf_out_size);
     memcpy(a_es->buf_out + a_es->buf_out_size, a_data, a_data_size);
     a_es->buf_out_size += a_data_size;
     dap_events_socket_set_writable_unsafe(a_es, true);
     return a_data_size;
}

/**
 * @brief dap_events_socket_write_f Write formatted text to the client
 * @param a_es Conn instance
 * @param a_format Format
 * @return Number of bytes that were placed into the buffer
 */
size_t dap_events_socket_write_f_unsafe(dap_events_socket_t *a_es, const char * a_format,...)
{
    size_t l_max_data_size = a_es->buf_out_size_max - a_es->buf_out_size;
    if (! l_max_data_size)
        return 0;
    if(!a_es->buf_out){
        log_it(L_ERROR,"Can't write formatted data to NULL buffer output");
        return 0;
    }

    va_list l_ap;
    va_start(l_ap, a_format);
    int l_ret=dap_vsnprintf( ((char*)a_es->buf_out) + a_es->buf_out_size, l_max_data_size, a_format, l_ap);
    va_end(l_ap);
    if(l_ret > 0) {
        a_es->buf_out_size += (unsigned int)l_ret;
    } else {
        log_it(L_ERROR,"Can't write out formatted data '%s'", a_format);
    }
    dap_events_socket_set_writable_unsafe(a_es, true);
    return (l_ret > 0) ? (unsigned int)l_ret : 0;
}

/**
 * @brief dap_events_socket_pop_from_buf_in
 * @param a_essc
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_events_socket_pop_from_buf_in(dap_events_socket_t *a_es, void *a_data, size_t a_data_size)
{
    if(a_data_size<a_es->buf_in_size){
        memcpy(a_data,a_es->buf_in,a_data_size);
        memmove(a_data,a_es->buf_in+a_data_size,a_es->buf_in_size-a_data_size);
    }else{
        if(a_data_size>a_es->buf_in_size)
            a_data_size=a_es->buf_in_size;
        memcpy(a_data,a_es->buf_in,a_data_size);
    }
    a_es->buf_in_size-=a_data_size;
    return a_data_size;
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

#ifdef DAP_OS_WINDOWS
inline int dap_recvfrom(SOCKET s, void* buf_in, size_t buf_size) {
    struct sockaddr_in l_dummy;
    socklen_t l_size = sizeof(l_dummy);
    int ret;
    if (buf_in) {
        memset(buf_in, 0, buf_size);
        ret = recvfrom(s, (char*)buf_in, (long)buf_size, 0, (struct sockaddr *)&l_dummy, &l_size);
    } else {
        char l_tempbuf[sizeof(void*)];
        ret = recvfrom(s, l_tempbuf, sizeof(l_tempbuf), 0, (struct sockaddr *)&l_dummy, &l_size);
    }
    return ret;
}

inline int dap_sendto(SOCKET s, u_short port, void* buf_out, size_t buf_out_size) {
    int l_addr_len;
    struct sockaddr_in l_addr;
    l_addr.sin_family = AF_INET;
    IN_ADDR _in_addr = { { .S_addr = htonl(INADDR_LOOPBACK) } };
    l_addr.sin_addr = _in_addr;
    l_addr.sin_port = port;
    l_addr_len = sizeof(struct sockaddr_in);
    int ret;
    if (buf_out) {
        ret = sendto(s, (char*)buf_out, (long)buf_out_size, MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *)&l_addr, l_addr_len);
    } else {
        char l_bytes[sizeof(void*)] = { 0 };
        ret = sendto(s, l_bytes, sizeof(l_bytes), MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *)&l_addr, l_addr_len);
    }
    return ret;
}
#endif
