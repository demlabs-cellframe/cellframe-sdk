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
#include <pthread.h>
#include "uthash.h"

#include "dap_common.h"

#define DAP_EVENTS_SOCKET_MAX 8194

#ifndef _WIN32
typedef int SOCKET;
#define closesocket close
#define INVALID_SOCKET  -1  // for win32 =  (SOCKET)(~0)
#define SOCKET_ERROR    -1  // for win32 =  (-1)
#endif

// Caps for different platforms
#if defined (DAP_OS_ANDROID)
#define DAP_EVENTS_CAPS_POLL
#define DAP_EVENTS_CAPS_PIPE_POSIX
#define DAP_EVENTS_CAPS_QUEUE_PIPE2
#define DAP_EVENTS_CAPS_EVENT_EVENTFD
#include <netinet/in.h>
#include <sys/eventfd.h>
#include <unistd.h>
#elif defined(DAP_OS_LINUX)
//    #define DAP_EVENTS_CAPS_EPOLL
    #define DAP_EVENTS_CAPS_POLL
    #define DAP_EVENTS_CAPS_PIPE_POSIX
    //#define DAP_EVENTS_CAPS_QUEUE_PIPE2
    #define DAP_EVENTS_CAPS_QUEUE_MQUEUE
    #define DAP_EVENTS_CAPS_EVENT_EVENTFD
    #include <netinet/in.h>
    #include <sys/eventfd.h>
    #include <mqueue.h>
#elif defined (DAP_OS_UNIX)
    #define DAP_EVENTS_CAPS_KQUEUE
    #define DAP_EVENTS_CAPS_PIPE_POSIX
    #define DAP_EVENTS_CAPS_EVENT_KEVENT
    #define DAP_EVENTS_CAPS_QUEUE_SOCKETPAIR
    #include <netinet/in.h>
#elif defined (DAP_OS_WINDOWS)
    #define DAP_EVENTS_CAPS_WEPOLL
    #define DAP_EVENTS_CAPS_EPOLL
    #define DAP_EVENTS_CAPS_QUEUE_WEVENT
    #define DAP_EVENTS_CAPS_EVENT_WEVENT
    //#define DAP_EVENTS_CAPS_PIPE_POSIX
    #define DAP_EVENTS_CAPS_MSMQ
    #define INET_ADDRSTRLEN     16
    #define INET6_ADDRSTRLEN    46
#include <mq.h>
#include <ws2tcpip.h>
#define MSG_DONTWAIT 0
#define MSG_NOSIGNAL 0
#endif

#if defined(DAP_EVENTS_CAPS_WEPOLL)
#define EPOLL_HANDLE  HANDLE
#include "wepoll.h"
#elif defined (DAP_EVENTS_CAPS_EPOLL)
#include <sys/epoll.h>
#define EPOLL_HANDLE  int
#elif defined (DAP_EVENTS_CAPS_POLL)
#include <poll.h>
#endif

#define BIT( x ) ( 1 << x )
#define DAP_SOCK_READY_TO_READ     BIT( 0 )
#define DAP_SOCK_READY_TO_WRITE    BIT( 1 )
#define DAP_SOCK_SIGNAL_CLOSE      BIT( 2 )
#define DAP_SOCK_CONNECTING         BIT( 3 ) // When connection happens this flag is armed for outgoing connections until its establish the connection
#define DAP_SOCK_REASSIGN_ONCE     BIT( 4 )   // This usable for FlowControl to prevent multiple reassigment

// If set - queue limited to sizeof(void*) size of data transmitted
#define DAP_SOCK_QUEUE_PTR         BIT( 8 )

typedef struct dap_events dap_events_t;
typedef struct dap_events_socket dap_events_socket_t;
typedef struct dap_worker dap_worker_t;
typedef struct dap_proc_thread dap_proc_thread_t ;

typedef struct dap_server dap_server_t;
typedef void (*dap_events_socket_callback_t) (dap_events_socket_t *,void * ); // Callback for specific client operations
typedef void (*dap_events_socket_callback_error_t) (dap_events_socket_t *, int ); // Callback for specific client operations
typedef void (*dap_events_socket_callback_queue_t) (dap_events_socket_t *,const void * , size_t); // Callback for specific client operations
typedef void (*dap_events_socket_callback_event_t) (dap_events_socket_t *, uint64_t); // Callback for specific client operations
typedef void (*dap_events_socket_callback_pipe_t) (dap_events_socket_t *,const void * , size_t); // Callback for specific client operations
typedef void (*dap_events_socket_callback_queue_ptr_t) (dap_events_socket_t *, void *); // Callback for specific client operations
typedef void (*dap_events_socket_callback_timer_t) (dap_events_socket_t * ); // Callback for specific client operations
typedef void (*dap_events_socket_callback_accept_t) (dap_events_socket_t * , int, struct sockaddr* ); // Callback for accept of new connection
typedef void (*dap_events_socket_callback_connected_t) (dap_events_socket_t * ); // Callback for connected client connection
typedef void (*dap_events_socket_worker_callback_t) (dap_events_socket_t *,dap_worker_t * ); // Callback for specific client operations

typedef struct dap_events_socket_callbacks {
    union{ // Specific callbacks
        dap_events_socket_callback_connected_t connected_callback; // Connected callback for client socket
        dap_events_socket_callback_accept_t accept_callback; // Accept callback for listening socket
        dap_events_socket_callback_event_t event_callback; // Event callback for listening socket
        dap_events_socket_callback_queue_t queue_callback; // Queue callback for listening socket
        dap_events_socket_callback_queue_ptr_t queue_ptr_callback; // queue_ptr callback for listening socket
    };

    dap_events_socket_callback_timer_t timer_callback; // Timer callback for listening socket
    dap_events_socket_callback_t new_callback; // Create new client callback
    dap_events_socket_callback_t delete_callback; // Delete client callback
    dap_events_socket_callback_t read_callback; // Read function
    dap_events_socket_callback_t write_callback; // Write function
    dap_events_socket_callback_error_t error_callback; // Error processing function

    dap_events_socket_worker_callback_t worker_assign_callback; // After successful worker assign
    dap_events_socket_worker_callback_t worker_unassign_callback; // After successful worker unassign

} dap_events_socket_callbacks_t;

#define DAP_EVENTS_SOCKET_BUF 100000

typedef enum {
    DESCRIPTOR_TYPE_SOCKET_CLIENT = 0,
    DESCRIPTOR_TYPE_SOCKET_UDP,
    DESCRIPTOR_TYPE_SOCKET_LISTENING,
    DESCRIPTOR_TYPE_QUEUE,
    DESCRIPTOR_TYPE_PIPE,
    DESCRIPTOR_TYPE_TIMER,
    DESCRIPTOR_TYPE_EVENT,
    DESCRIPTOR_TYPE_FILE
} dap_events_desc_type_t;

typedef struct dap_events_socket {
    union {
#ifdef DAP_OS_WINDOWS
        SOCKET socket;
#else
        int socket;
#endif
        int fd;
#if defined(DAP_EVENTS_CAPS_QUEUE_MQUEUE)
        mqd_t mqd;
    };
    uint32_t mqd_id;
#elif defined DAP_EVENTS_CAPS_MSMQ
    };
    QUEUEHANDLE mqh, mqh_recv;
    u_int mq_num;
    u_short port;
    HANDLE ev_timeout, ev_recv;
#endif

#if defined DAP_EVENTS_CAPS_PIPE_POSIX
    int fd2;
#endif
    dap_events_desc_type_t type;
    // Related sockets (be careful - possible problems, delete them before )
    dap_events_socket_t ** workers_es; // If not NULL - on every worker must be present
    size_t workers_es_size;           //  events socket with same socket

    // Flags. TODO  - rework in bool fields
    uint32_t  flags;
    bool no_close;
    atomic_bool is_initalized;
    bool was_reassigned; // Was reassigment at least once

    uint32_t buf_out_zero_count;

    // Input section
        //uint8_t buf_in[DAP_EVENTS_SOCKET_BUF+1]; // Internal buffer for input data
        //char buf_in_str[DAP_EVENTS_SOCKET_BUF+1];
    byte_t  *buf_in;
    size_t buf_in_size_max; //  size of alloced buffer
        //char    *buf_in_str;
    size_t buf_in_size; // size of data that is in the input buffer

    // Output section

    //byte_t buf_out[DAP_EVENTS_SOCKET_BUF+1]; // Internal buffer for output data
    byte_t *buf_out;
    size_t buf_out_size; // size of data that is in the output buffer
    size_t buf_out_size_max; // max size of data
    dap_events_socket_t * pipe_out; // Pipe socket with data for output

    // Stored string representation
    //char hostaddr[1024]; // Address
    //char service[128];
    char *hostaddr;
    char *service;

    // Remote address, port and others
    struct sockaddr_in remote_addr;
    //char remote_addr_str[INET_ADDRSTRLEN];
    //char remote_addr_str6[INET6_ADDRSTRLEN];
    char *remote_addr_str;
    char *remote_addr_str6;
    short remote_port;


    // Links to related objects
    dap_events_t *events;
    dap_worker_t *worker;
    dap_proc_thread_t * proc_thread; // If assigned on dap_proc_thread_t object
    dap_server_t *server; // If this socket assigned with server

    // Platform specific things
#ifdef DAP_EVENTS_CAPS_EPOLL
    uint32_t ev_base_flags;
    struct epoll_event ev;
#elif defined (DAP_EVENTS_CAPS_POLL)
    short poll_base_flags;
    uint32_t poll_index; // index in poll array on worker
#endif

    dap_events_socket_callbacks_t callbacks;

    time_t time_connection;
    time_t last_time_active;
    time_t last_ping_request;

    void *_inheritor; // Inheritor data to specific client type, usualy states for state machine
    void *_pvt; //Private section, different for different types
    struct dap_events_socket * me; // pointer on itself
    UT_hash_handle hh;
    UT_hash_handle hh_worker; // Handle for local CPU storage on worker
} dap_events_socket_t; // Node of bidirectional list of clients


#ifdef __cplusplus
extern "C" {
#endif

int dap_events_socket_init(); //  Init clients module
void dap_events_socket_deinit(); // Deinit clients module

dap_events_socket_t * dap_events_socket_create(dap_events_desc_type_t a_type, dap_events_socket_callbacks_t* a_callbacks);

dap_events_socket_t * dap_events_socket_create_type_queue_ptr_unsafe(dap_worker_t * a_w, dap_events_socket_callback_queue_ptr_t a_callback);
dap_events_socket_t * dap_events_socket_create_type_queue_ptr_mt(dap_worker_t * a_w, dap_events_socket_callback_queue_ptr_t a_callback);
int dap_events_socket_queue_proc_input_unsafe(dap_events_socket_t * a_esocket);

dap_events_socket_t * dap_events_socket_create_type_event_unsafe(dap_worker_t * a_w, dap_events_socket_callback_event_t a_callback);
dap_events_socket_t * dap_events_socket_create_type_event_mt(dap_worker_t * a_w, dap_events_socket_callback_event_t a_callback);
void dap_events_socket_event_proc_input_unsafe(dap_events_socket_t *a_esocket);

dap_events_socket_t * dap_events_socket_create_type_pipe_unsafe(dap_worker_t * a_w, dap_events_socket_callback_t a_callback, uint32_t a_flags);
dap_events_socket_t * dap_events_socket_create_type_pipe_mt(dap_worker_t * a_w, dap_events_socket_callback_t a_callback, uint32_t a_flags);

dap_events_socket_t * dap_events_socket_queue_ptr_create_input(dap_events_socket_t* a_es);
int dap_events_socket_queue_ptr_send_to_input( dap_events_socket_t * a_es, void* a_arg);
int dap_events_socket_queue_ptr_send( dap_events_socket_t * a_es, void* a_arg);


int dap_events_socket_event_signal( dap_events_socket_t * a_es, uint64_t a_value);

void dap_events_socket_delete_unsafe( dap_events_socket_t * a_esocket , bool a_preserve_inheritor);

dap_events_socket_t *dap_events_socket_wrap_no_add( dap_events_t *a_events,
                                            int a_sock, dap_events_socket_callbacks_t *a_callbacks );
dap_events_socket_t * dap_events_socket_wrap2( dap_server_t *a_server, struct dap_events *a_events,
                                            int a_sock, dap_events_socket_callbacks_t *a_callbacks );

void dap_events_socket_assign_on_worker_mt(dap_events_socket_t * a_es, struct dap_worker * a_worker);
void dap_events_socket_assign_on_worker_inter(dap_events_socket_t * a_es_input, dap_events_socket_t * a_es);

void dap_events_socket_reassign_between_workers_mt(dap_worker_t * a_worker_old, dap_events_socket_t * a_es, dap_worker_t * a_worker_new);
void dap_events_socket_reassign_between_workers_unsafe(dap_events_socket_t * a_es, dap_worker_t * a_worker_new);

dap_events_socket_t * dap_events_socket_find_unsafe(int sock, struct dap_events * sh); // Find client by socket

size_t dap_events_socket_pop_from_buf_in(dap_events_socket_t *sc, void * data, size_t data_size);

// Non-MT functions
bool dap_events_socket_check_unsafe(dap_worker_t * a_worker,dap_events_socket_t * a_es);
void dap_events_socket_set_readable_unsafe(dap_events_socket_t * sc,bool is_ready);
void dap_events_socket_set_writable_unsafe(dap_events_socket_t * sc,bool is_ready);
void dap_events_socket_worker_poll_update_unsafe(dap_events_socket_t * a_esocket);


size_t dap_events_socket_write_unsafe(dap_events_socket_t *sc, const void * data, size_t data_size);
size_t dap_events_socket_write_f_unsafe(dap_events_socket_t *sc, const char * format,...);

// MT variants less
void dap_events_socket_set_readable_mt(dap_worker_t * a_w, dap_events_socket_t * a_es,bool a_is_ready);
void dap_events_socket_set_writable_mt(dap_worker_t * a_w, dap_events_socket_t * a_es,bool a_is_ready);

size_t dap_events_socket_write_mt(dap_worker_t * a_w, dap_events_socket_t *a_es, const void * a_data, size_t a_data_size);
size_t dap_events_socket_write_f_mt(dap_worker_t * a_w, dap_events_socket_t *a_es, const char * a_format,...);

size_t dap_events_socket_write_inter(dap_events_socket_t * a_es_input, dap_events_socket_t *a_es, const void * a_data, size_t a_data_size);
size_t dap_events_socket_write_f_inter(dap_events_socket_t * a_es_input, dap_events_socket_t *a_es, const char * a_format,...);

void dap_events_socket_remove_and_delete_mt( dap_worker_t * a_w, dap_events_socket_t* a_es);
void dap_events_socket_remove_and_delete_unsafe( dap_events_socket_t *a_es, bool preserve_inheritor );

void dap_events_socket_remove_from_worker_unsafe( dap_events_socket_t *a_es, dap_worker_t * a_worker);
void dap_events_socket_shrink_buf_in(dap_events_socket_t * cl, size_t shrink_size);

#ifdef DAP_OS_WINDOWS
extern inline int dap_recvfrom(SOCKET s, void* buf_in, size_t buf_size);
extern inline int dap_sendto(SOCKET s, u_short port, void* buf_in, size_t buf_size);
#endif


#ifdef __cplusplus
}
#endif
