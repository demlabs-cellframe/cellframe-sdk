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
#pragma once
#ifndef DAP_OS_WINDOWS
#include "unistd.h"
typedef int SOCKET;
#define closesocket close
#define INVALID_SOCKET  -1  // for win32 =  (SOCKET)(~0)
#define SOCKET_ERROR    -1  // for win32 =  (-1)
#else
#include <ws2tcpip.h>
#include <mq.h>
#endif

#include <pthread.h>
#include "uthash.h"
#include "dap_common.h"
#include "dap_math_ops.h"

#define DAP_EVENTS_SOCKET_MAX 8194

// Caps for different platforms
#if defined (DAP_OS_ANDROID)
    #define DAP_EVENTS_CAPS_POLL
    #define DAP_EVENTS_CAPS_PIPE_POSIX
    #define DAP_EVENTS_CAPS_QUEUE_PIPE2
    #define DAP_EVENTS_CAPS_EVENT_EVENTFD
    #include <netinet/in.h>
    #include <sys/eventfd.h>
    #include <unistd.h>
    #include <sys/un.h>
#elif defined(DAP_OS_LINUX)
    //#define DAP_EVENTS_CAPS_EPOLL
    #define DAP_EVENTS_CAPS_POLL
    #define DAP_EVENTS_CAPS_PIPE_POSIX
    #define DAP_EVENTS_CAPS_QUEUE_PIPE2
    #define DAP_EVENTS_CAPS_EVENT_EVENTFD
    #include <netinet/in.h>
    #include <sys/un.h>
    #include <sys/eventfd.h>
    #include <mqueue.h>
    #include <sys/un.h>
#elif defined (DAP_OS_BSD)
    #define DAP_EVENTS_CAPS_KQUEUE
    #define DAP_EVENTS_CAPS_PIPE_POSIX
    #define DAP_EVENTS_CAPS_EVENT_KEVENT
    #define DAP_EVENTS_CAPS_QUEUE_KEVENT
    #include <netinet/in.h>
    #include <sys/un.h>
    #include <sys/event.h>
    #include <sys/un.h>
#elif defined (DAP_OS_UNIX)
    #define DAP_EVENTS_CAPS_POLL
    #define DAP_EVENTS_CAPS_PIPE_POSIX
    #define DAP_EVENTS_CAPS_EVENT_PIPE
    #define DAP_EVENTS_CAPS_QUEUE_SOCKETPAIR
    #include <netinet/in.h>
    #include <sys/un.h>
#elif defined (DAP_OS_WINDOWS)
    //#define DAP_EVENTS_CAPS_WEPOLL
    #define MSG_DONTWAIT 0
    #define MSG_NOSIGNAL 0
    #define DAP_EVENTS_CAPS_IOCP
    #ifndef INET_ADDRSTRLEN
        #define INET_ADDRSTRLEN     16
    #endif
    #ifndef INET6_ADDRSTRLEN
        #define INET6_ADDRSTRLEN    46
    #endif
typedef struct queue_entry {
    SLIST_ENTRY entry;
    size_t size;
    void *data;
} queue_entry_t;
#endif

#if defined(DAP_EVENTS_CAPS_WEPOLL)
#define DAP_EVENTS_CAPS_EPOLL
#define EPOLL_HANDLE HANDLE
#include "wepoll.h"
#elif defined (DAP_EVENTS_CAPS_IOCP)
#include <mswsock.h>
#define MAX_IOCP_ENTRIES 255 // Maximum count of IOCP entries to fetch at once
#elif defined (DAP_EVENTS_CAPS_EPOLL)
#include <sys/epoll.h>
#define EPOLL_HANDLE  int
#elif defined (DAP_EVENTS_CAPS_POLL)
#include <poll.h>
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
#ifndef EVFILT_EMPTY
#define EVFILT_EMPTY -13
#endif
#endif

#define BIT( x ) ( 1 << x )
#define DAP_SOCK_READY_TO_READ      BIT( 0 )
#define DAP_SOCK_READY_TO_WRITE     BIT( 1 )
#define DAP_SOCK_SIGNAL_CLOSE       BIT( 2 )
#define DAP_SOCK_CONNECTING         BIT( 3 )    // When connection happens this flag is armed for outgoing connections until its establish the connection
#define DAP_SOCK_REASSIGN_ONCE      BIT( 4 )    // This usable for FlowControl to prevent multiple reassigment
//#define DAP_SOCK_DROP_WRITE_IF_ZERO BIT( 5 )    // Drop down WRITE flag from socket if reach zero bytes in output buffer
#ifdef DAP_EVENTS_CAPS_IOCP
#define DAP_SOCK_KEEP_INHERITOR     BIT( 6 )
#define FLAG_KEEP_INHERITOR(f)  (f & DAP_SOCK_KEEP_INHERITOR)
#endif
// If set - queue limited to sizeof(void*) size of data transmitted
#define DAP_SOCK_FILE_MAPPED       BIT( 7 )
#define DAP_SOCK_QUEUE_PTR         BIT( 8 )

#define FLAG_CLOSE(f)           (f & DAP_SOCK_SIGNAL_CLOSE)
#define FLAG_READ_NOCLOSE(f)    (!(f & DAP_SOCK_SIGNAL_CLOSE) && (f & DAP_SOCK_READY_TO_READ))
#define FLAG_WRITE_NOCLOSE(f)   (!(f & DAP_SOCK_SIGNAL_CLOSE) && (f & DAP_SOCK_READY_TO_WRITE))


typedef struct dap_events_socket dap_events_socket_t;
typedef struct dap_worker dap_worker_t;
typedef struct dap_context dap_context_t;

typedef struct dap_server dap_server_t;

typedef size_t (*dap_events_socket_clear_buf)(char*, size_t);

typedef void (*dap_events_socket_callback_t) (dap_events_socket_t *,void * ); // Callback for specific client operations
typedef bool (*dap_events_socket_write_callback_t)(dap_events_socket_t *, void *); // Callback for write client operation
typedef void (*dap_events_socket_callback_error_ptr_t) (dap_events_socket_t *, int, void * ); // Callback for specific client operations
typedef void (*dap_events_socket_callback_error_t) (dap_events_socket_t *, int ); // Callback for specific client operations
typedef void (*dap_events_socket_callback_queue_t) (dap_events_socket_t *,const void * , size_t); // Callback for specific client operations
typedef void (*dap_events_socket_callback_event_t) (dap_events_socket_t *, uint64_t); // Callback for specific client operations
typedef void (*dap_events_socket_callback_pipe_t) (dap_events_socket_t *,const void * , size_t); // Callback for specific client operations
typedef void (*dap_events_socket_callback_queue_ptr_t) (dap_events_socket_t *, void *); // Callback for specific client operations
typedef void (*dap_events_socket_callback_timer_t) (dap_events_socket_t * ); // Callback for specific client operations
typedef void (*dap_events_socket_callback_accept_t) (dap_events_socket_t *, SOCKET, struct sockaddr_storage *); // Callback for accept of new connection
typedef void (*dap_events_socket_callback_connected_t) (dap_events_socket_t * ); // Callback for connected client connection
typedef void (*dap_events_socket_worker_callback_t) (dap_events_socket_t *,dap_worker_t * ); // Callback for specific client operations
#ifdef DAP_EVENTS_CAPS_IOCP
typedef ULONG (*pfn_RtlNtStatusToDosError)(NTSTATUS s);
typedef enum per_io_type {
    io_call     = 'c',  // Callback
    io_read     = 'r',  // Read from es
    io_write    = 'w'   // Write to es
} per_io_type_t;

extern LPFN_ACCEPTEX             pfnAcceptEx;
extern LPFN_GETACCEPTEXSOCKADDRS pfnGetAcceptExSockaddrs;
extern LPFN_CONNECTEX            pfnConnectEx;
extern LPFN_DISCONNECTEX         pfnDisconnectEx;
extern pfn_RtlNtStatusToDosError pfnRtlNtStatusToDosError;
#endif

typedef struct dap_events_socket_callbacks {
    union{ // Specific callbacks
        dap_events_socket_callback_connected_t connected_callback;          /* Connected callback for client socket */
        dap_events_socket_callback_accept_t accept_callback;                /* Accept callback for listening socket */
        dap_events_socket_callback_event_t event_callback;                  /* Event callback for listening socket */
        dap_events_socket_callback_queue_t queue_callback;                  /* Queue callback for listening socket */
        dap_events_socket_callback_queue_ptr_t queue_ptr_callback;          /* queue_ptr callback for listening socket */
    };

    dap_events_socket_callback_timer_t timer_callback;                      /* Timer callback for listening socket */
    dap_events_socket_callback_t new_callback;                              /* Create new client callback */
    dap_events_socket_callback_t delete_callback;                           /* Delete client callback */
    dap_events_socket_callback_t read_callback;                             /* Read function */
    dap_events_socket_write_callback_t write_callback;                      /* Write function */
    dap_events_socket_callback_t write_finished_callback;                   /* Called on completion Write operation */
    dap_events_socket_callback_error_t error_callback;                      /* Error processing function */

    dap_events_socket_worker_callback_t worker_assign_callback;             /* After successful worker assign */
    dap_events_socket_worker_callback_t worker_unassign_callback;           /* After successful worker unassign */

    void *arg;                                                              /* Callbacks argument */
} dap_events_socket_callbacks_t;

#define DAP_STREAM_PKT_FRAGMENT_SIZE    (16 * 1024)
#ifdef DAP_TPS_TEST
#define DAP_STREAM_PKT_SIZE_MAX         (128 * 1024 * 1024)
#else
#define DAP_STREAM_PKT_SIZE_MAX         (4 * 1024 * 1024)
#endif
#define DAP_EVENTS_SOCKET_BUF_SIZE      (DAP_STREAM_PKT_FRAGMENT_SIZE * 16)
#define DAP_EVENTS_SOCKET_BUF_LIMIT     DAP_STREAM_PKT_SIZE_MAX
#define DAP_QUEUE_MAX_MSGS              1024

typedef enum {
    DESCRIPTOR_TYPE_SOCKET_CLIENT = 0,
    DESCRIPTOR_TYPE_SOCKET_LOCAL_CLIENT,
    DESCRIPTOR_TYPE_SOCKET_LISTENING,
    DESCRIPTOR_TYPE_SOCKET_LOCAL_LISTENING,
    DESCRIPTOR_TYPE_SOCKET_UDP,
    DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL,
    DESCRIPTOR_TYPE_FILE,
    DESCRIPTOR_TYPE_PIPE,
    DESCRIPTOR_TYPE_QUEUE,
    /* all above are readable/writeable */
    DESCRIPTOR_TYPE_TIMER,
    DESCRIPTOR_TYPE_EVENT
} dap_events_desc_type_t;


// To transfer esocket link with some pre-sized data
typedef struct dap_events_socket_w_data{
    struct dap_events_socket * esocket;
    union{
        byte_t * data;
        void * ptr;
        uint64_t value;
    };
    size_t size;
} dap_events_socket_w_data_t;

typedef uint64_t dap_events_socket_uuid_t;
#define DAP_FORMAT_ESOCKET_UUID "0x%08" DAP_UINT64_FORMAT_X
#define DAP_HOSTADDR_STRLEN     0x100

typedef struct dap_events_socket_uuid_ctrl {
    dap_events_socket_uuid_t uuid;
    dap_worker_t *worker;
} dap_events_socket_uuid_ctrl_t;

typedef struct dap_events_socket {
    union {
        SOCKET socket;
        int fd;
#if defined(DAP_EVENTS_CAPS_QUEUE_MQUEUE)
        mqd_t mqd;
    };
    uint32_t mqd_id;
#elif defined(DAP_EVENTS_CAPS_IOCP)
    };
    HANDLE h;
#else
    };
#endif
    u_short port;
    union {
        SOCKET socket2;
        int fd2;
    };


    dap_events_desc_type_t type;
    dap_events_socket_uuid_t uuid; // Unique UID
    // Related sockets (be careful - possible problems, delete them before )
    dap_events_socket_t ** workers_es; // If not NULL - on every worker must be present
    size_t workers_es_size;           //  events socket with same socket

    // Flags. TODO  - rework in bool fields
    uint32_t flags;
    bool no_close;
    atomic_bool is_initalized;
    bool was_reassigned; // Was reassigment at least once

    byte_t *buf_in, *buf_out;
    dap_events_socket_clear_buf cb_buf_cleaner;



#ifdef DAP_EVENTS_CAPS_IOCP
    DWORD   
#else
    size_t
#endif
        buf_in_size,    buf_in_size_max,
        buf_out_size,   buf_out_size_max;

    dap_events_socket_t * pipe_out; // Pipe socket with data for output
#if defined(DAP_EVENTS_CAPS_QUEUE_PIPE2)
    pthread_rwlock_t buf_out_lock;
#endif
    struct sockaddr_storage addr_storage;
    // Remote address, port and others
    union {
#ifdef DAP_OS_UNIX
        struct sockaddr_un remote_path;
        struct sockaddr_un listener_path; // Path to UNIX socket
#endif
    };

    union {
        char remote_addr_str[DAP_HOSTADDR_STRLEN];
        char listener_addr_str[DAP_HOSTADDR_STRLEN];
    };
    union {
        uint16_t  remote_port;
        uint16_t  listener_port;
        mode_t  permission;
    };

    // Links to related objects
    dap_context_t *context;
    dap_worker_t *worker;
    dap_server_t *server; // If this socket assigned with server

    // Platform specific things
#ifdef DAP_EVENTS_CAPS_EPOLL
    uint32_t ev_base_flags;
    struct epoll_event ev;
#elif defined (DAP_EVENTS_CAPS_POLL)
    short poll_base_flags;
    uint32_t poll_index; // index in poll array on worker
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
    struct kevent kqueue_event;
    struct kevent *kqueue_event_catched;

    dap_events_socket_w_data_t kqueue_event_catched_data;

    short kqueue_base_filter;
    unsigned short kqueue_base_flags;
    unsigned int kqueue_base_fflags;

    int64_t kqueue_data;
#elif defined DAP_EVENTS_CAPS_IOCP
    uint_fast16_t pending_read : 1, pending_write : 15;
#endif

    dap_events_socket_callbacks_t callbacks;

    time_t time_connection;
    time_t last_time_active;
    time_t last_ping_request;

    void *_inheritor; // Inheritor data to specific client type, usualy states for state machine
    void *_pvt; //Private section, different for different types
    UT_hash_handle hh, hh2; // Handle for local CPU storage on worker or proc_thread AND for total amount
} dap_events_socket_t; // Node of bidirectional list of clients
typedef dap_events_socket_t dap_esocket_t;

#define SSL(a) (a ? (WOLFSSL *) (a)->_pvt : NULL)

typedef struct dap_events_socket_uuid_w_data{
    dap_events_socket_uuid_t esocket_uuid;
    struct {
        uint64_t value; // some custom data
        void * ptr;
    };
} dap_events_socket_uuid_w_data_t;

extern const char *s_socket_type_to_str[];

typedef struct dap_events_socket_handler_hh{
    dap_events_socket_t * esocket;
    dap_events_socket_uuid_t uuid;
    uint32_t worker_id;
    UT_hash_handle hh;
} dap_events_socket_handler_hh_t;

#ifdef DAP_EVENTS_CAPS_IOCP
/* Callback invoked on per-i/o basis */
typedef void (*dap_per_io_func)(dap_context_t*, OVERLAPPED*);
typedef struct dap_overlapped {
    OVERLAPPED ol;
    char op, buf[];
} dap_overlapped_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

unsigned int dap_new_es_id();
int dap_events_socket_init(void); //  Init clients module
void dap_events_socket_deinit(void); // Deinit clients module

dap_events_socket_t * dap_events_socket_create(dap_events_desc_type_t a_type, dap_events_socket_callbacks_t* a_callbacks);
dap_events_socket_t * dap_events_socket_create_type_queue_ptr_mt(dap_worker_t * a_w, dap_events_socket_callback_queue_ptr_t a_callback);
int dap_events_socket_queue_proc_input_unsafe(dap_events_socket_t * a_esocket);

dap_events_socket_t * dap_events_socket_create_type_event_unsafe(dap_worker_t * a_w, dap_events_socket_callback_event_t a_callback);
dap_events_socket_t * dap_events_socket_create_type_event_mt(dap_worker_t * a_w, dap_events_socket_callback_event_t a_callback);
void dap_events_socket_event_proc_input_unsafe(dap_events_socket_t *a_esocket);

dap_events_socket_t * dap_events_socket_create_type_pipe_unsafe(dap_worker_t * a_w, dap_events_socket_callback_t a_callback, uint32_t a_flags);
dap_events_socket_t * dap_events_socket_create_type_pipe_mt(dap_worker_t * a_w, dap_events_socket_callback_t a_callback, uint32_t a_flags);

dap_events_socket_t * dap_events_socket_queue_ptr_create_input(dap_events_socket_t* a_es);
int dap_events_socket_queue_ptr_send_to_input( dap_events_socket_t * a_es, void* a_arg);

int dap_events_socket_event_signal( dap_events_socket_t * a_es, uint64_t a_value);

dap_events_socket_t *dap_events_socket_wrap_no_add(SOCKET a_sock, dap_events_socket_callbacks_t *a_callbacks);
dap_events_socket_t *dap_events_socket_wrap_listener(dap_server_t *a_server, SOCKET a_sock, dap_events_socket_callbacks_t *a_callbacks);

void dap_events_socket_assign_on_worker_mt(dap_events_socket_t * a_es, struct dap_worker * a_worker);
void dap_events_socket_reassign_between_workers_mt(dap_worker_t * a_worker_old, dap_events_socket_t * a_es, dap_worker_t * a_worker_new);
void dap_events_socket_reassign_between_workers_unsafe(dap_events_socket_t * a_es, dap_worker_t * a_worker_new);

size_t dap_events_socket_write_unsafe(dap_events_socket_t *a_es, const void *a_data, size_t a_data_size);
DAP_PRINTF_ATTR(2, 3) ssize_t dap_events_socket_write_f_unsafe(dap_events_socket_t *a_es, const char *a_format, ...);

// MT variants less
void dap_events_socket_set_readable_mt(dap_worker_t * a_w, dap_events_socket_uuid_t a_es_uuid, bool a_is_ready);
void dap_events_socket_set_writable_mt(dap_worker_t * a_w, dap_events_socket_uuid_t a_es_uuid, bool a_is_ready);

// Universal variant thats trying to detect context, if found uses _inter if not uses _mt
size_t dap_events_socket_write(dap_events_socket_uuid_t a_es_uuid, const void * a_data, size_t a_data_size,
                               dap_events_socket_callback_t a_callback_success,
                               dap_events_socket_callback_error_t a_callback_error, void * a_arg);


size_t dap_events_socket_write_mt(dap_worker_t * a_w, dap_events_socket_uuid_t a_es_uuid, void * a_data, size_t a_data_size);
DAP_PRINTF_ATTR(3, 4) size_t dap_events_socket_write_f_mt(dap_worker_t * a_w, dap_events_socket_uuid_t a_es_uuid, const char * a_format,...);
void dap_events_socket_delete_unsafe( dap_events_socket_t * a_esocket , bool a_preserve_inheritor);
void dap_events_socket_remove_and_delete_unsafe( dap_events_socket_t *a_es, bool preserve_inheritor );
#ifndef DAP_EVENTS_CAPS_IOCP

void dap_events_socket_assign_on_worker_inter(dap_events_socket_t * a_es_input, dap_events_socket_t * a_es);
size_t dap_events_socket_write_inter(dap_events_socket_t * a_es_input, dap_events_socket_uuid_t a_es_uuid, const void * a_data, size_t a_data_size);
DAP_PRINTF_ATTR(3, 4) size_t dap_events_socket_write_f_inter(dap_events_socket_t * a_es_input, dap_events_socket_uuid_t a_es_uuid,const char * a_format,...);

void dap_events_socket_set_readable_unsafe(dap_events_socket_t * sc,bool is_ready);
void dap_events_socket_set_writable_unsafe(dap_events_socket_t * sc,bool is_ready);
int dap_events_socket_queue_ptr_send( dap_events_socket_t * a_es, void* a_arg);
#endif

void dap_events_socket_remove_and_delete_mt( dap_worker_t * a_w, dap_events_socket_uuid_t a_es_uuid);

// Delayed removed
void dap_events_socket_remove_and_delete_unsafe_delayed( dap_events_socket_t *a_es, bool a_preserve_inheritor);

// Just close socket descriptor
void dap_events_socket_descriptor_close(dap_events_socket_t *a_socket);

void dap_events_socket_remove_from_worker_unsafe( dap_events_socket_t *a_es, dap_worker_t * a_worker);

// Buffer functions
void    dap_events_socket_shrink_buf_in(dap_events_socket_t * a_es, size_t shrink_size);
DAP_STATIC_INLINE size_t dap_events_socket_get_free_buf_size(dap_events_socket_t *a_es) { return a_es->buf_out_size_max - a_es->buf_out_size; }
size_t  dap_events_socket_pop_from_buf_in(dap_events_socket_t *sc, void * data, size_t data_size);
size_t  dap_events_socket_insert_buf_out(dap_events_socket_t * a_es, void *a_data, size_t a_data_size);

DAP_STATIC_INLINE const char *dap_events_socket_get_type_str(dap_events_socket_t *a_es)
{
    if (!a_es)
        return "CORRUPTED";
    switch (a_es->type) {
    case DESCRIPTOR_TYPE_SOCKET_CLIENT:         return "CLIENT";
    case DESCRIPTOR_TYPE_SOCKET_LOCAL_CLIENT:   return "LOCAL_CLIENT";
    case DESCRIPTOR_TYPE_SOCKET_LISTENING:      return "SERVER";
    case DESCRIPTOR_TYPE_SOCKET_LOCAL_LISTENING:return "LOCAL_SERVER";
    case DESCRIPTOR_TYPE_SOCKET_UDP:            return "CLIENT_UDP";
    case DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL:     return "CLIENT_SSL";
    case DESCRIPTOR_TYPE_FILE:                  return "FILE";
    case DESCRIPTOR_TYPE_PIPE:                  return "PIPE";
    case DESCRIPTOR_TYPE_QUEUE:                 return "QUEUE";
    case DESCRIPTOR_TYPE_TIMER:                 return "TIMER";
    case DESCRIPTOR_TYPE_EVENT:                 return "EVENT";
    default:                                    return "UNKNOWN";
    }
}

DAP_INLINE int dap_close_socket(SOCKET s) {
    return
#ifdef DAP_OS_WINDOWS
    closesocket(s);
#else
    close(s);
#endif
}

#ifdef DAP_EVENTS_CAPS_IOCP

DAP_STATIC_INLINE void dap_overlapped_free(dap_overlapped_t *ol) {
    if (!ol) return;
    if (ol->ol.hEvent)
        CloseHandle(ol->ol.hEvent);
    DAP_DELETE(ol);
}
void dap_events_socket_set_readable_unsafe_ex       (dap_events_socket_t*, bool, dap_overlapped_t*);
void dap_events_socket_set_writable_unsafe_ex       (dap_events_socket_t*, bool, size_t, dap_overlapped_t*);
int dap_events_socket_queue_data_send               (dap_events_socket_t*, const void*, size_t);

#define dap_events_socket_set_readable_unsafe(es, flag)         dap_events_socket_set_readable_unsafe_ex(es, flag, NULL)
#define dap_events_socket_set_writable_unsafe(es, flag)         dap_events_socket_set_writable_unsafe_ex(es, flag, 0, NULL)
#define dap_events_socket_queue_ptr_send(es, arg)               dap_events_socket_queue_data_send(es, arg, 0)

#endif

#ifdef DAP_EVENTS_CAPS_WEPOLL
DAP_STATIC_INLINE int dap_recvfrom(SOCKET s, void* buf_in, size_t buf_size) {
    struct sockaddr_in l_dummy;
    socklen_t l_size = sizeof(l_dummy);
    char l_signal;
    return recvfrom(s, buf_in && buf_size ? (char*)buf_in : &l_signal,
                    buf_in && buf_size ? buf_size : sizeof(char),
                    0, (struct sockaddr*)&l_dummy, &l_size);

}

DAP_STATIC_INLINE int dap_sendto(SOCKET s, u_short port, void* buf_out, size_t buf_out_size) {
    struct sockaddr_in l_addr = { .sin_family = AF_INET, .sin_port = port, .sin_addr = {{ .S_addr = htonl(INADDR_LOOPBACK) }} };
    return sendto(s, buf_out && buf_out_size ? (char*)buf_out : "\0",
                  buf_out && buf_out_size ? buf_out_size : sizeof(char),
                  MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *)&l_addr, sizeof(struct sockaddr_in));

}
#endif


#ifdef __cplusplus
}
#endif
