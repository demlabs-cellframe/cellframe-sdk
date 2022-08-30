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
#include <stdatomic.h>

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
#include "dap_context.h"
#include "dap_events_socket.h"

#ifdef DAP_EVENTS_CAPS_AIO
#include <aio.h>

struct queue_ptr_aio{ // Pointer on buffer with pointer on itself
    void * ptr;
    struct queue_ptr_aio * self;
    struct aiocb * aiocb;
};

#endif


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

static uint64_t s_delayed_ops_timeout_ms = 5000;
bool s_remove_and_delete_unsafe_delayed_delete_callback(void * a_arg);

static pthread_attr_t s_attr_detached;                                      /* Thread's creation attribute = DETACHED ! */


/**
 * @brief dap_events_socket_init Init clients module
 * @return Zero if ok others if no
 */
int     dap_events_socket_init( void )
{
int l_rc;

    log_it(L_NOTICE,"Initialized events socket module");

    /*
     * @RRL: #6157
     * Use this thread's attribute to eliminate resource consuming by terminated threads
     */
    assert ( !(l_rc = pthread_attr_init(&s_attr_detached)) );
    assert ( !(l_rc = pthread_attr_setdetachstate(&s_attr_detached, PTHREAD_CREATE_DETACHED)) );

#if defined (DAP_EVENTS_CAPS_QUEUE_MQUEUE)
#include <sys/time.h>
#include <sys/resource.h>
    struct rlimit l_mqueue_limit;
    l_mqueue_limit.rlim_cur = RLIM_INFINITY;
    l_mqueue_limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_MSGQUEUE,&l_mqueue_limit);
    char l_cmd[256] ={0};
    snprintf(l_cmd, sizeof (l_cmd) - 1, "rm /dev/mqueue/%s-queue_ptr*", dap_get_appname());
    system(l_cmd);
    FILE *l_mq_msg_max = fopen("/proc/sys/fs/mqueue/msg_max", "w");
    if (l_mq_msg_max) {
        fprintf(l_mq_msg_max, "%d", DAP_QUEUE_MAX_MSGS);
        fclose(l_mq_msg_max);
    } else {
        log_it(L_ERROR, "Сan't open /proc/sys/fs/mqueue/msg_max file for writing, errno=%d", errno);
    }  
#endif
    dap_timerfd_init();
    return 0;
}

/**
 * @brief dap_events_socket_deinit Deinit clients module
 */
void dap_events_socket_deinit(void)
{
}

#ifdef DAP_OS_WINDOWS
void __stdcall mq_receive_cb(HRESULT hr, QUEUEHANDLE qh, DWORD timeout
                             , DWORD action, MQMSGPROPS *pmsgprops, LPOVERLAPPED pov, HANDLE cursor) {
    UNUSED(hr);
    UNUSED(qh);
    UNUSED(timeout);
    UNUSED(action);
    UNUSED(pmsgprops);
    UNUSED(cursor);
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
dap_events_socket_t *dap_events_socket_wrap_no_add( int a_sock, dap_events_socket_callbacks_t *a_callbacks )
{
    assert(a_callbacks);

    dap_events_socket_t *l_ret = DAP_NEW_Z( dap_events_socket_t );
    if (!l_ret)
        return NULL;

    l_ret->socket = a_sock;
    l_ret->uuid = dap_uuid_generate_uint64();
    if (a_callbacks)
        l_ret->callbacks = *a_callbacks;
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
    dap_worker_t *l_worker = a_es->context->worker;
    log_it(L_DEBUG, "Reassign between %u->%u workers: %p (%d)  ", l_worker->id, a_worker_new->id, a_es, a_es->fd );

    dap_context_remove(a_es);
    a_es->was_reassigned = true;
    if (a_es->callbacks.worker_unassign_callback)
        a_es->callbacks.worker_unassign_callback(a_es, l_worker);

    dap_worker_add_events_socket(a_es, a_worker_new);
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
#ifdef DAP_OS_WINDOWS
        log_it(L_ERROR,"Haven't sent reassign message with esocket %"DAP_UINT64_FORMAT_U, a_es ? a_es->socket : (SOCKET)-1);
#else
        log_it(L_ERROR,"Haven't sent reassign message with esocket %d", a_es?a_es->socket:-1);
#endif
        DAP_DELETE(l_msg);
    }
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
    dap_events_socket_t * l_es = dap_context_create_pipe(NULL, a_callback, a_flags);
    dap_worker_add_events_socket_unsafe(a_w, l_es);
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
    dap_events_socket_t * l_es =dap_events_socket_wrap_no_add(l_sock,a_callbacks);
    if(!l_es){
        log_it(L_CRITICAL,"Can't allocate memory for the new esocket");
        return NULL;
    }
    l_es->type = a_type ;
    if(g_debug_reactor)
        log_it(L_DEBUG,"Created socket %"DAP_FORMAT_SOCKET" type %d", l_sock,l_es->type);
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
    dap_events_socket_t * l_es = dap_context_create_pipe(NULL, a_callback, a_flags);
    dap_worker_add_events_socket_unsafe(a_w, l_es);
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
    l_es->uuid = dap_uuid_generate_uint64();
    l_es->pipe_out = a_es;
#if defined(DAP_EVENTS_CAPS_EPOLL)
    l_es->ev_base_flags = EPOLLERR | EPOLLRDHUP | EPOLLHUP;
#elif defined(DAP_EVENTS_CAPS_POLL)
    l_es->poll_base_flags = POLLERR | POLLRDHUP | POLLHUP;
#elif defined(DAP_EVENTS_CAPS_KQUEUE)
    // Here we have event identy thats we copy
    l_es->fd = a_es->fd; //
    l_es->kqueue_base_flags = EV_ONESHOT;
    l_es->kqueue_base_fflags = NOTE_TRIGGER | NOTE_FFNOP;
    l_es->kqueue_base_filter = EVFILT_USER;
    l_es->kqueue_event_catched_data.esocket = l_es;

#else
#error "Not defined s_create_type_pipe for your platform"
#endif

#ifdef DAP_EVENTS_CAPS_QUEUE_MQUEUE
    int  l_errno;
    char l_errbuf[128] = {0}, l_mq_name[64] = {0};
    struct mq_attr l_mq_attr = {0};

    l_es->mqd_id = a_es->mqd_id;
    l_mq_attr.mq_maxmsg = DAP_QUEUE_MAX_MSGS;                               // Don't think we need to hold more than 1024 messages
    l_mq_attr.mq_msgsize = sizeof (void*);                                  // We send only pointer on memory (???!!!),
                                                                            // so use it with shared memory if you do access from another process

    snprintf(l_mq_name,sizeof (l_mq_name), "/%s-queue_ptr-%u", dap_get_appname(), l_es->mqd_id );

    //if ( (l_errno = mq_unlink(l_mq_name)) )                                 /* Mark this MQ to be deleted as the process will be terminated */
    //    log_it(L_DEBUG, "mq_unlink(%s)->%d", l_mq_name, l_errno);

    if ( 0 >= (l_es->mqd = mq_open(l_mq_name, O_CREAT|O_WRONLY |O_NONBLOCK, 0700, &l_mq_attr)) )
    {
        log_it(L_CRITICAL,"Can't create mqueue descriptor %s: \"%s\" code %d (%s)", l_mq_name, l_errbuf, errno,
                           (strerror_r(errno, l_errbuf, sizeof (l_errbuf)), l_errbuf) );

        DAP_DELETE(l_es->buf_in);
        DAP_DELETE(l_es->buf_out);
        DAP_DELETE(l_es);
        return NULL;
    }

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
            log_it(L_ERROR, "Can't open message queue for queue type, error: %ld", hr);
            return NULL;
        }
    }
    hr = MQOpenQueue(l_direct_name, MQ_RECEIVE_ACCESS, MQ_DENY_NONE, &(l_es->mqh_recv));
    if (hr != MQ_OK) {
        log_it(L_ERROR, "Can't open message queue for queue type, error: %ld", hr);
        return NULL;
    }
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
    // We don't create descriptor for kqueue at all
#else
#error "Not defined dap_events_socket_queue_ptr_create_input() for this platform"
#endif
    l_es->flags = DAP_SOCK_QUEUE_PTR;
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
    dap_events_socket_t * l_es = dap_context_create_queue(NULL, a_callback);
    assert(l_es);
    // If no worker - don't assign
    if ( a_w)
        dap_events_socket_assign_on_worker_mt(l_es,a_w);
    return  l_es;
}


/**
 * @brief dap_events_socket_queue_proc_input
 * @param a_esocket
 */
int dap_events_socket_queue_proc_input_unsafe(dap_events_socket_t * a_esocket)
{
#ifdef DAP_OS_WINDOWS
    int l_read = dap_recvfrom(a_esocket->socket, a_esocket->buf_in, a_esocket->buf_in_size_max);
    if (l_read == SOCKET_ERROR) {
        log_it(L_ERROR, "Queue socket %zu received invalid data, error %d", a_esocket->socket, WSAGetLastError());
        return -1;
    }
#endif
    if (a_esocket->callbacks.queue_callback){
        if (a_esocket->flags & DAP_SOCK_QUEUE_PTR){
            void * l_queue_ptr = NULL;
#if defined(DAP_EVENTS_CAPS_QUEUE_PIPE2)
            char l_body[DAP_QUEUE_MAX_MSGS] = { '\0' };
#if defined (DAP_EVENTS_CAPS_AIO)
            struct queue_ptr_aio l_queue_ptr_aio={0};
            ssize_t l_read_ret = read( a_esocket->fd, &l_queue_ptr_aio,sizeof (l_queue_ptr_aio ));
#else
            ssize_t l_read_ret = read( a_esocket->fd, &l_queue_ptr,sizeof (void *));
#endif
            int l_read_errno = errno;
#if defined (DAP_EVENTS_CAPS_AIO)
            if(l_read_ret == (ssize_t) sizeof (l_queue_ptr_aio)){
                if(g_debug_reactor)
                    log_it(L_DEBUG,"Queue ptr received %p", l_queue_ptr_aio.ptr);
                a_esocket->callbacks.queue_ptr_callback(a_esocket, l_queue_ptr_aio.ptr);
                if (l_queue_ptr_aio.aiocb) {
                    if (aio_error(l_queue_ptr_aio.aiocb) == EINPROGRESS)
                        dap_slist_add2tail(&a_esocket->context->garbage_list, l_queue_ptr_aio.aiocb, 0);
                    else
                        DAP_DELETE(l_queue_ptr_aio.aiocb);
                }
                while (a_esocket->context->garbage_list.head) {
                    dap_slist_elm_t *l_elm = (dap_slist_elm_t *)a_esocket->context->garbage_list.head;
                    struct aiocb *l_aiocb = (struct aiocb *)l_elm->data;
                    if (aio_error(l_aiocb) == EINPROGRESS)
                        break;
                    dap_slist_get4head(&a_esocket->context->garbage_list, NULL, NULL);
                    DAP_DELETE(l_aiocb);
                }
                DAP_DELETE(l_queue_ptr_aio.self);
            } else if ( (l_read_errno != EAGAIN) && (l_read_errno != EWOULDBLOCK) )  // we use blocked socket for now but who knows...
                log_it(L_WARNING,"Queue ptr recieved %zd when expected to see %zd", l_read_ret,
                       sizeof (l_queue_ptr_aio));
            else if (g_debug_reactor)
                log_it(L_DEBUG, "%s code received, do nothing on this loop",
                       l_read_errno == EAGAIN? "EAGAIN": l_read_errno == EWOULDBLOCK ? "EWOULDBLOCK": "UNKNOWN" );
#else
            if(l_read_ret > 0) {
                debug_if(g_debug_reactor, L_NOTICE, "Got %ld bytes from pipe", l_read_ret);
                for (long shift = 0; shift < l_read_ret; shift += sizeof(void*)) {
                    l_queue_ptr = *(void **)(l_body + shift);
                    a_esocket->callbacks.queue_ptr_callback(a_esocket, l_queue_ptr);
                }
            }
            else if ((l_errno != EAGAIN) && (l_errno != EWOULDBLOCK) )  // we use blocked socket for now but who knows...
                log_it(L_ERROR, "Can't read message from pipe");
#endif

#elif defined (DAP_EVENTS_CAPS_QUEUE_MQUEUE)
            char l_body[DAP_QUEUE_MAX_BUFLEN * DAP_QUEUE_MAX_MSGS] = { '\0' };
            ssize_t l_ret, l_shift;
            for (l_ret = 0, l_shift = 0;
                 ((l_ret = mq_receive(a_esocket->mqd, l_body + l_shift, sizeof(void*), NULL)) == sizeof(void*)) && ((size_t)l_shift < sizeof(l_body) - sizeof(void*));
                 l_shift += l_ret)
            {
                l_queue_ptr = *(void**)(l_body + l_shift);
                a_esocket->callbacks.queue_ptr_callback(a_esocket, l_queue_ptr);
            }
            if (l_ret == -1) {
                int l_errno = errno;
                switch (l_errno) {
                case EAGAIN:
                    debug_if(g_debug_reactor, L_INFO, "Received and processed %lu callbacks in 1 pass", l_shift / 8);
                    break;
                default: {
                    char l_errbuf[128];
                    l_errbuf[0]=0;
                    strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                    log_it(L_ERROR, "mq_receive error in esocket queue_ptr:\"%s\" code %d", l_errbuf, l_errno);
                    return -1;
                }
                }
            }
#if defined (DAP_EVENTS_CAPS_AIO)
            struct queue_ptr_aio l_queue_ptr_aio;
            ssize_t l_ret = mq_receive(a_esocket->mqd,(char*) &l_queue_ptr_aio, sizeof (l_queue_ptr_aio),NULL);
#else
            ssize_t l_ret = mq_receive(a_esocket->mqd,(char*) &l_queue_ptr, sizeof (l_queue_ptr),NULL);
#endif
            if (l_ret == -1){
                int l_errno = errno;
                char l_errbuf[128];
                l_errbuf[0]=0;
                strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                log_it(L_ERROR, "Error in esocket queue_ptr:\"%s\" code %d", l_errbuf, l_errno);
                return -1;
            }
            #if defined (DAP_EVENTS_CAPS_AIO)
            if(l_ret != sizeof(l_queue_ptr_aio) ){
                log_it(L_ERROR, "Wrong AIO message in MQ, expected to have %zd but received %zd",
                       sizeof (l_queue_ptr_aio), l_ret);
                return -1;
            }
            l_queue_ptr = l_queue_ptr_aio.ptr;
            DAP_DELETE(l_queue_ptr_aio.self); // Clear send buffer
            #endif
            a_esocket->callbacks.queue_ptr_callback (a_esocket, l_queue_ptr);
#elif defined DAP_EVENTS_CAPS_MSMQ
            DWORD l_mp_id = 0;
            MQMSGPROPS    l_mps;
            MQPROPVARIANT l_mpvar[2];
            MSGPROPID     l_p_id[2];

            UCHAR l_body[4096] = { 0 }; // Normally a limit for MSMQ is ~4MB
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

            HRESULT hr;
            while ((hr = MQReceiveMessage(a_esocket->mqh_recv, 0, MQ_ACTION_RECEIVE, &l_mps, NULL, NULL, NULL, MQ_NO_TRANSACTION))
                                          != MQ_ERROR_IO_TIMEOUT) {
                if (hr != MQ_OK) {
                    log_it(L_ERROR, "An error %ld occured receiving a message from queue", hr);
                    return -3;
                }
                debug_if(l_mpvar[1].ulVal > 8, L_NOTICE, "MSMQ: processing %lu bytes in 1 pass", l_mpvar[1].ulVal);
                debug_if(g_debug_reactor, L_DEBUG, "Received msg: %p len %lu", *(void **)l_body, l_mpvar[1].ulVal);
                if (a_esocket->callbacks.queue_ptr_callback) {
                    for (long shift = 0; shift < (long)l_mpvar[1].ulVal; shift += sizeof(void*)) {
                        l_queue_ptr = *(void **)(l_body + shift);
                        a_esocket->callbacks.queue_ptr_callback(a_esocket, l_queue_ptr);
                    }
                }
            }
#elif defined DAP_EVENTS_CAPS_KQUEUE
        l_queue_ptr = (void*) a_esocket->kqueue_event_catched_data.data;
        if(g_debug_reactor)
            log_it(L_INFO,"Queue ptr received %p ptr on input", l_queue_ptr);
        if(a_esocket->callbacks.queue_ptr_callback)
            a_esocket->callbacks.queue_ptr_callback (a_esocket, l_queue_ptr);
#else
#error "No Queue fetch mechanism implemented on your platform"
#endif
        } else {
#ifdef DAP_EVENTS_CAPS_KQUEUE
            void * l_queue_ptr = a_esocket->kqueue_event_catched_data.data;
            size_t l_queue_ptr_size = a_esocket->kqueue_event_catched_data.size;
            if(g_debug_reactor)
                log_it(L_INFO,"Queue received %zd bytes on input", l_queue_ptr_size);

            a_esocket->callbacks.queue_callback(a_esocket, l_queue_ptr, l_queue_ptr_size);
#elif !defined(DAP_OS_WINDOWS)
            size_t l_read = read(a_esocket->socket, a_esocket->buf_in, a_esocket->buf_in_size_max );
#endif
        }
    }else{
        log_it(L_ERROR, "Queue socket %"DAP_FORMAT_SOCKET" accepted data but callback is NULL ", a_esocket->socket);
        return -2;
    }
    return 0;
}


/**
 * @brief dap_events_socket_create_type_event_mt
 * @param a_w
 * @param a_callback
 * @return
 */
dap_events_socket_t * dap_events_socket_create_type_event_mt(dap_worker_t * a_w, dap_events_socket_callback_event_t a_callback)
{
    dap_events_socket_t * l_es = dap_context_create_event(NULL, a_callback);
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

    dap_events_socket_t * l_es = dap_context_create_event(NULL, a_callback);
    // If no worker - don't assign
    if (a_w)
        dap_worker_add_events_socket_unsafe(a_w, l_es);
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
        log_it(L_ERROR, "Event socket %"DAP_FORMAT_SOCKET" accepted data but callback is NULL ", a_esocket->socket);
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
static int wait_send_socket(SOCKET a_sockfd, long timeout_ms)
{
    struct timeval l_tv;
    l_tv.tv_sec = timeout_ms / 1000;
    l_tv.tv_usec = (timeout_ms % 1000) * 1000;

    fd_set l_outfd;
    FD_ZERO(&l_outfd);
    FD_SET(a_sockfd, &l_outfd);

    while (1) {
#ifdef DAP_OS_WINDOWS
        int l_res = select(1, NULL, &l_outfd, NULL, &l_tv);
#else
        int l_res = select(a_sockfd + 1, NULL, &l_outfd, NULL, &l_tv);
#endif
        if (l_res == 0) {
            //log_it(L_DEBUG, "socket %d timed out", a_sockfd)
            return -2;
        }
        if (l_res == -1) {
            if (errno == EINTR)
                continue;
            log_it(L_DEBUG, "socket %"DAP_FORMAT_SOCKET" waiting errno=%d", a_sockfd, errno);
            return l_res;
        }
        break;
    };

    if (FD_ISSET(a_sockfd, &l_outfd))
        return 0;

    return -1;
}

#ifndef DAP_EVENTS_CAPS_AIO

/**
 * @brief dap_events_socket_buf_thread
 * @param arg
 * @return
 */
static void *dap_events_socket_buf_thread(void *arg)
{
    dap_events_socket_buf_item_t *l_item = (dap_events_socket_buf_item_t *)arg;
    if (!l_item)
        pthread_exit(0);
    int l_res = 0;
    int l_count = 0;
    SOCKET l_sock = INVALID_SOCKET;
    while (l_res < 1 && l_count++ < 3) {
#if defined(DAP_EVENTS_CAPS_QUEUE_PIPE2)
        l_sock = l_item->es->fd2;
#elif defined(DAP_EVENTS_CAPS_QUEUE_MQUEUE)
        l_sock = l_item->es->mqd;
#endif
        // wait max 5 min
        l_res = wait_send_socket(l_sock, 300000);
        if (l_res == 0) {
            dap_events_socket_queue_ptr_send(l_item->es, l_item->arg);
            break;
        }
    }
    if (l_res != 0)
        log_it(L_WARNING, "Lost data bulk in events socket buf thread");

    DAP_DELETE(l_item);
    pthread_exit(0);
    return NULL;
}

static void add_ptr_to_buf(dap_events_socket_t * a_es, void* a_arg)
{
static atomic_uint_fast64_t l_thd_count;
int     l_rc;
pthread_t l_thread;
dap_events_socket_buf_item_t *l_item;

    atomic_fetch_add(&l_thd_count, 1);                                      /* Count an every call of this routine */

    if ( !(l_item = DAP_NEW(dap_events_socket_buf_item_t)) )                /* Allocate new item - argument for new thread */
    {
        log_it (L_ERROR, "[#%"DAP_UINT64_FORMAT_U"] No memory for new item, errno=%d,  drop: a_es: %p, a_arg: %p",
                atomic_load(&l_thd_count), errno, a_es, a_arg);
        return;
    }

    l_item->es = a_es;
    l_item->arg = a_arg;

    if ( (l_rc = pthread_create(&l_thread, &s_attr_detached /* @RRL: #6157 */, dap_events_socket_buf_thread, l_item)) )
    {
        log_it(L_ERROR, "[#%"DAP_UINT64_FORMAT_U"] Cannot start thread, drop a_es: %p, a_arg: %p, rc: %d",
                 atomic_load(&l_thd_count), a_es, a_arg, l_rc);
        return;
    }

    debug_if(g_debug_reactor, L_DEBUG, "[#%"DAP_UINT64_FORMAT_U"] Created thread %"DAP_UINT64_FORMAT_x", a_es: %p, a_arg: %p",
             atomic_load(&l_thd_count), l_thread, a_es, a_arg);
}
#endif

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
        EV_SET(&l_event,a_es_input->socket+arc4random()  , EVFILT_USER,EV_ADD | EV_ONESHOT, NOTE_FFNOP | NOTE_TRIGGER ,0, l_es_w_data);
        if(l_es->context)
            l_ret=kevent(l_es->context->kqueue_fd,&l_event,1,NULL,0,NULL);
        else
            l_ret=-100;
        if(l_ret != -1 ){
            return 0;
        }else{
            log_it(L_ERROR,"Can't send message in queue, code %d", errno);
            DAP_DELETE(l_es_w_data);
            return l_ret;
        }
    }else{
        log_it(L_ERROR,"No pipe_out pointer for queue socket, possible created wrong");
        return -2;
    }

#elif defined(DAP_EVENTS_CAPS_AIO)
    return dap_events_socket_queue_ptr_send(a_es_input->pipe_out,a_arg);
#else
    void * l_arg = a_arg;
    return dap_events_socket_write_unsafe(a_es_input, &l_arg, sizeof(l_arg))
            == sizeof(l_arg) ? 0 : -1;
#endif
}

/**
 * @brief dap_events_socket_send_event
 * @param a_es
 * @param a_arg
 */
int dap_events_socket_queue_ptr_send( dap_events_socket_t *a_es, void *a_arg)
{
    int l_ret = -1024, l_errno=0;

    if (g_debug_reactor)
        log_it(L_DEBUG,"Sent ptr %p to esocket queue %p (%d)", a_arg, a_es, a_es? a_es->fd : -1);

#if defined(DAP_EVENTS_CAPS_QUEUE_PIPE2)
#if defined (DAP_EVENTS_CAPS_AIO)
    struct queue_ptr_aio * l_ptr_aio = DAP_NEW_Z(struct queue_ptr_aio);
    l_ptr_aio->self = l_ptr_aio;
    l_ptr_aio->ptr = a_arg;
    l_ptr_aio->aiocb = DAP_NEW_Z(struct aiocb);
    l_ptr_aio->aiocb->aio_fildes = a_es->fd2;
    l_ptr_aio->aiocb->aio_buf = l_ptr_aio;
    l_ptr_aio->aiocb->aio_nbytes = sizeof(*l_ptr_aio);
    l_ret =  aio_write(l_ptr_aio->aiocb) == 0? sizeof(a_arg) : 0;
#else
    if ((l_ret = write(a_es->fd2, &a_arg, sizeof(a_arg)) == sizeof(a_arg))) {
        debug_if(g_debug_reactor, L_NOTICE, "send %d bytes to pipe", l_ret);
        return 0;
    }
    l_errno = errno;
    char l_errbuf[128] = { '\0' };
    strerror_r(l_errno, l_errbuf, sizeof(l_errbuf));
    log_it(L_ERROR, "Can't send ptr to pipe:\"%s\" code %d", l_errbuf, l_errno);
    return l_errno;
#endif
    l_errno = errno;

#elif defined (DAP_EVENTS_CAPS_QUEUE_MQUEUE)
    assert(a_es);
    assert(a_es->mqd);
    //struct timespec tmo = {0};
    //tmo.tv_sec = 7 + time(NULL);
    if (!mq_send(a_es->mqd, (const char*)&a_arg, sizeof(a_arg), 0)) {
        debug_if (g_debug_reactor, L_DEBUG,"Sent ptr %p to esocket queue %p (%d)", a_arg, a_es, a_es? a_es->fd : -1);
        return 0;
    }
    switch (l_errno = errno) {
    case EINVAL:
    case EINTR:
    case EWOULDBLOCK:
        log_it(L_ERROR, "Can't send ptr to queue (err %d), will be resent again in a while...", l_errno);
        struct mq_attr l_attr = { 0 };
        mq_getattr(a_es->mqd, &l_attr);
        log_it(L_ERROR, "Number of pending messages: %ld", l_attr.mq_curmsgs);
        add_ptr_to_buf(a_es, a_arg);
        return l_errno;
    default: {
        char l_errbuf[128] = { '\0' };
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        log_it(L_ERROR, "Can't send ptr to queue:\"%s\" code %d", l_errbuf, l_errno);
        return l_errno;
    }}
#if defined (DAP_EVENTS_CAPS_AIO)
    struct aiocb l_aio_op = {0};
    struct queue_ptr_aio * l_ptr_aio = DAP_NEW(struct queue_ptr_aio);
    l_ptr_aio->self = l_ptr_aio;
    l_ptr_aio->ptr = a_arg;
    l_aio_op.aio_fildes = a_es->mqd;
    l_aio_op.aio_buf = l_ptr_aio;
    l_aio_op.aio_nbytes = sizeof(*l_ptr_aio);
    l_ret =  aio_write(&l_aio_op) == 0? sizeof(a_arg) : 0;
    l_errno = errno;
#else
    l_ret = mq_send(a_es->mqd, (const char *)&a_arg, sizeof (a_arg), 0);
    l_errno = errno;
    if ( l_ret == EPERM){
        log_it(L_ERROR,"No permissions to send data in mqueue");
    }

    if (l_errno == EINVAL || l_errno == EINTR || l_errno == ETIMEDOUT)
        l_errno = EAGAIN;
    if (l_ret == 0)
        l_ret = sizeof(a_arg);
    else if (l_ret > 0)
        l_ret = -l_ret;
#endif

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
        log_it(L_ERROR, "An error occured on sending message to queue, errno: %ld", hr);
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
    EV_SET(&l_event,a_es->socket+arc4random()  , EVFILT_USER,EV_ADD | EV_ONESHOT, NOTE_FFNOP | NOTE_TRIGGER ,0, l_es_w_data);
    int l_n;
    if(a_es->pipe_out){ // If we have pipe out - we send events directly to the pipe out kqueue fd
        if(a_es->pipe_out->context){
            if( g_debug_reactor) log_it(L_DEBUG, "Sent kevent() with ptr %p to pipe_out worker on esocket %d",a_arg,a_es);
            l_n = kevent(a_es->pipe_out->context->kqueue_fd,&l_event,1,NULL,0,NULL);
        }
        else {
            log_it(L_WARNING,"Trying to send pointer in pipe out queue thats not assigned to any worker or proc thread");
            l_n = 0;
            DAP_DELETE(l_es_w_data);
        }
    }else if(a_es->context){
        l_n = kevent(a_es->context->kqueue_fd,&l_event,1,NULL,0,NULL);
        if( g_debug_reactor) log_it(L_DEBUG, "Sent kevent() with ptr %p to worker on esocket %d",a_arg,a_es);
    }else {
        log_it(L_WARNING,"Trying to send pointer in queue thats not assigned to any worker or proc thread");
        l_n = 0;
        DAP_DELETE(l_es_w_data);
    }

    if(l_n != -1 ){
        return 0;
    } else {
        l_errno = errno;
        log_it(L_ERROR,"Sending kevent error code %d", l_errno);
        return l_errno;
    }

#else
#error "Not implemented dap_events_socket_queue_ptr_send() for this platform"
#endif
#if defined(DAP_EVENTS_CAPS_AIO_THREADS)

    if (l_ret == sizeof(a_arg) ){
        return 0;
    }else{
        // Try again
        if(l_errno == EAGAIN || l_errno == EWOULDBLOCK ){
            add_ptr_to_buf(a_es, a_arg);
            return 0;
        }else {
            char l_errbuf[128];
            strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
            log_it(L_ERROR, "Can't send ptr to queue:\"%s\" code %d", l_errbuf, l_errno);
            return l_errno;
        }
    }
#else
    if(l_ret == sizeof(a_arg) )
        return 0;
    else{
        char l_errbuf[128];
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        log_it(L_ERROR,"Send queue ptr error: \"%s\" code %d", l_errbuf, l_errno);
        return l_errno;
    }
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

    EV_SET(&l_event,a_es->socket, EVFILT_USER, EV_ADD | EV_ONESHOT , NOTE_FFNOP | NOTE_TRIGGER ,(intptr_t) a_es->socket, l_es_w_data);

    int l_n;

    if(a_es->pipe_out){ // If we have pipe out - we send events directly to the pipe out kqueue fd
        if(a_es->pipe_out->context)
            l_n = kevent(a_es->pipe_out->context->kqueue_fd,&l_event,1,NULL,0,NULL);
        else {
            log_it(L_WARNING,"Trying to send pointer in pipe out queue thats not assigned to any worker or proc thread");
            l_n = -1;
        }
    }else if(a_es->context)
        l_n = kevent(a_es->context->kqueue_fd,&l_event,1,NULL,0,NULL);
    else
        l_n = -1;

    if(l_n == -1){
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
void dap_events_socket_delete_mt(dap_worker_t * a_worker, dap_events_socket_uuid_t a_es_uuid)
{
    dap_events_socket_uuid_t * l_es_uuid_ptr= DAP_NEW_Z(dap_events_socket_uuid_t);
    *l_es_uuid_ptr = a_es_uuid;

    int l_ret= dap_events_socket_queue_ptr_send( a_worker->queue_es_delete, l_es_uuid_ptr );
    if( l_ret != 0 ){
        log_it(L_ERROR, "Queue send returned %d", l_ret);
        DAP_DELETE(l_es_uuid_ptr);
    }
}

/**
 * @brief dap_events_socket_wrap2
 * @param a_server
 * @param a_sock
 * @param a_callbacks
 * @return
 */
dap_events_socket_t * dap_events_socket_wrap2( dap_server_t *a_server, int a_sock, dap_events_socket_callbacks_t *a_callbacks )
{
    assert( a_callbacks );
    assert( a_server );

    //log_it( L_DEBUG,"Dap event socket wrapped around %d sock", a_sock );
    dap_events_socket_t * l_es = DAP_NEW_Z( dap_events_socket_t ); if (!l_es) return NULL;

    l_es->socket = a_sock;
    l_es->server = a_server;
    l_es->uuid = dap_uuid_generate_uint64();
    if (a_callbacks)
        l_es->callbacks = *a_callbacks;
    l_es->buf_out_size_max = l_es->buf_in_size_max = DAP_EVENTS_SOCKET_BUF;
    l_es->buf_in = a_callbacks->timer_callback ? NULL : DAP_NEW_Z_SIZE(byte_t, l_es->buf_in_size_max+1);
    l_es->buf_out = a_callbacks->timer_callback ? NULL : DAP_NEW_Z_SIZE(byte_t, l_es->buf_out_size_max+1);
    l_es->buf_in_size = l_es->buf_out_size = 0;
    l_es->flags = DAP_SOCK_READY_TO_READ;
    l_es->last_time_active = l_es->last_ping_request = time( NULL );

    return l_es;
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
        int l_kqueue_fd = a_esocket->context? a_esocket->context->kqueue_fd : -1;
        if( l_kqueue_fd>0 ){
            int l_kevent_ret = kevent(l_kqueue_fd,&l_event,1,NULL,0,NULL);
            int l_errno = errno;
            if ( l_kevent_ret == -1 && l_errno != EINPROGRESS ){
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
    dap_context_poll_update(a_esocket);
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

    if ( a_is_ready )
        a_esocket->flags |= DAP_SOCK_READY_TO_WRITE;
    else
        a_esocket->flags ^= DAP_SOCK_READY_TO_WRITE;

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
        int l_kqueue_fd = a_esocket->context? a_esocket->context->kqueue_fd : -1;
        if( l_kqueue_fd>0 ){
            int l_kevent_ret=kevent(l_kqueue_fd,&l_event,1,NULL,0,NULL);
            int l_errno = errno;
            if ( l_kevent_ret == -1 && l_errno != EINPROGRESS && l_errno != ENOENT ){
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
    dap_context_poll_update(a_esocket);
#endif

}


/**
 * @brief s_remove_and_delete_unsafe_delayed_delete_callback
 * @param arg
 * @return
 */
bool s_remove_and_delete_unsafe_delayed_delete_callback(void * a_arg)
{
    dap_worker_t * l_worker = dap_worker_get_current();
    dap_events_socket_uuid_w_data_t * l_es_handler = (dap_events_socket_uuid_w_data_t*) a_arg;
    assert(l_es_handler);
    assert(l_worker);
    dap_events_socket_t * l_es;
    if( (l_es = dap_context_find(l_worker->context, l_es_handler->esocket_uuid)) != NULL)
        //dap_events_socket_remove_and_delete_unsafe(l_es,l_es_handler->value == 1);
        dap_events_socket_remove_and_delete_unsafe( l_es, l_es_handler->value == 1);
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

    dap_worker_t * l_worker = a_es->context->worker;
    dap_context_remove(a_es);
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

    //log_it( L_DEBUG, "es is going to be removed from the lists and free the memory (0x%016X)", a_es );
    dap_context_remove(a_es);

    if( a_es->callbacks.delete_callback )
        a_es->callbacks.delete_callback( a_es, NULL ); // Init internal structure

    //log_it( L_DEBUG, "dap_events_socket wrapped around %d socket is removed", a_es->socket );
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
    DAP_DEL_Z(a_esocket->remote_addr_str6)
    DAP_DEL_Z(a_esocket->hostaddr)
    DAP_DEL_Z(a_esocket->service)

    DAP_DEL_Z( a_esocket )
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
 * @brief dap_events_socket_write
 * @param a_es_uuid
 * @param a_data
 * @param a_data_size
 * @param a_callback_success
 * @param a_callback_error
 * @return
 */
size_t dap_events_socket_write(dap_events_socket_uuid_t a_es_uuid, const void * a_data, size_t a_data_size,
                               dap_events_socket_callback_t a_callback_success,
                               dap_events_socket_callback_error_t a_callback_error, void * a_arg)
{
   dap_context_t * l_context = dap_context_current();
   if(l_context){ // We found it
       dap_events_socket_t * l_queue;
       // TODO complete things
   }
   return 0;
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
        log_it(L_ERROR, "wite mt: wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg);
        return 0;
    }
    return  l_data_size;
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
        log_it(L_ERROR, "write f inter: wasn't send pointer to queue input: code %d", l_ret);
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
 * @brief dap_events_socket_write Write data to the client
 * @param a_es Esocket instance
 * @param a_data Pointer to data
 * @param a_data_size Size of data to write
 * @return Number of bytes that were placed into the buffer
 */
size_t dap_events_socket_write_unsafe(dap_events_socket_t *a_es, const void * a_data, size_t a_data_size)
{
    if (a_es->flags & DAP_SOCK_SIGNAL_CLOSE)
        return 0;
    if ( (a_es->buf_out_size + a_data_size) > a_es->buf_out_size_max) {
        if ((a_es->buf_out_size_max + a_data_size) > DAP_EVENTS_SOCKET_BUF_LIMIT) {
            log_it(L_ERROR, "Write esocket (%p) buffer overflow size=%zu/max=%zu", a_es, a_es->buf_out_size_max, (size_t)DAP_EVENTS_SOCKET_BUF_LIMIT);
            return 0;
        } else {
            size_t l_new_size = a_es->buf_out_size_max * 2;
            if (l_new_size > DAP_EVENTS_SOCKET_BUF_LIMIT)
                l_new_size = DAP_EVENTS_SOCKET_BUF_LIMIT;
            a_es->buf_out = DAP_REALLOC(a_es->buf_out, l_new_size);
            a_es->buf_out_size_max = l_new_size;
        }
     }
     a_data_size = ((a_es->buf_out_size + a_data_size) < a_es->buf_out_size_max) ? a_data_size : (a_es->buf_out_size_max - a_es->buf_out_size);
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
    if ( a_data_size < a_es->buf_in_size)
    {
        memcpy(a_data, a_es->buf_in, a_data_size);
        memmove(a_es->buf_in, a_es->buf_in + a_data_size, a_es->buf_in_size - a_data_size);
    } else {
        if ( a_data_size > a_es->buf_in_size )
            a_data_size = a_es->buf_in_size;

        memcpy(a_data, a_es->buf_in, a_data_size);
    }

    a_es->buf_in_size -= a_data_size;

    return a_data_size;
}


/**
 * @brief dap_events_socket_shrink_client_buf_in Shrink input buffer (shift it left)
 * @param cl Client instance
 * @param shrink_size Size on wich we shrink the buffer with shifting it left
 */
void dap_events_socket_shrink_buf_in(dap_events_socket_t * a_es, size_t shrink_size)
{
    if ( (!shrink_size) || (!a_es->buf_in_size) )
        return;                                                             /* Nothing to do - OK */

    if (a_es->buf_in_size > shrink_size)
        memmove(a_es->buf_in , a_es->buf_in + shrink_size, a_es->buf_in_size -= shrink_size);
    else {
        //log_it(WARNING,"Shrinking size of input buffer on amount bigger than actual buffer's size");
        a_es->buf_in_size = 0;
    }
}


/*
 *  DESCRIPTION: Insert specified data data block at beging of the <buf_out> area.
 *      If there is not a room for inserting - no <buf_out> is changed.
 *
 *  INPUTS:
 *      cl:         A events socket context area
 *      data:       A buffer with data to be inserted
 *      data_sz:    A size of the data in the buffer
 *
 *  IMPLICITE OUTPUTS:
 *      a_es->buf_out
 *      a_es->buf_out_sz
 *
 *  RETURNS:
 *      0:          SUCCESS
 *      -ENOMEM:    No room for data to be inserted
 */
size_t dap_events_socket_insert_buf_out(dap_events_socket_t * a_es, void *a_data, size_t a_data_size)
{
    if ( (!a_data_size) || (!a_data) )
        return  0;                                                          /* Nothing to do - OK */

    if ( (a_es->buf_out_size_max - a_es->buf_in_size) < a_data_size )
        return  -ENOMEM;                                                    /* No room for data to be inserted */

    memmove(a_es->buf_out + a_data_size, a_es->buf_out, a_es->buf_in_size); /* Move existing data to right */
    memcpy(a_es->buf_out, a_data, a_data_size);                             /* Place new data at begin of the buffer */
    a_es->buf_in_size += a_data_size;                                       /* Ajust buffer's data lenght */

    return  a_data_size;
}
