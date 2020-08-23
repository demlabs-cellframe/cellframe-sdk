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
//  assert(a_events);
  assert(a_callbacks);

  dap_events_socket_t *ret = DAP_NEW_Z( dap_events_socket_t );

  ret->socket = a_sock;
  ret->events = a_events;
  memcpy(&ret->callbacks, a_callbacks, sizeof(ret->callbacks) );
  ret->flags = DAP_SOCK_READY_TO_READ;

#if defined(DAP_EVENTS_CAPS_EPOLL)
    ret->ev_base_flags = EPOLLERR | EPOLLRDHUP | EPOLLHUP;
#endif

  log_it( L_DEBUG,"Dap event socket wrapped around %d sock a_events = %X", a_sock, a_events );

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
    dap_worker_add_events_socket(a_es,a_worker);
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
 * @brief dap_events_socket_create_type_queue
 * @param a_w
 * @param a_callback
 * @param a_buf_in_size
 * @return
 */
dap_events_socket_t * dap_events_socket_create_type_pipe(dap_worker_t * a_w, dap_events_socket_callback_t a_callback)
{
    dap_events_socket_t * l_es = DAP_NEW_Z(dap_events_socket_t);
    l_es->type = DESCRIPTOR_TYPE_PIPE;
    l_es->worker = a_w;
    l_es->events = a_w->events;
    l_es->callbacks.read_callback = a_callback; // Arm event callback
    l_es->ev_base_flags = EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP;

    int l_pipe[2];
    int l_errno;
    char l_errbuf[128];
    if( pipe(l_pipe) < 0 ){
        l_errno = errno;
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        log_it( L_ERROR, "Error detected, can't create pipe(): '%s' (%d)", l_errbuf, l_errno);
        DAP_DELETE(l_es);
        return NULL;
    }else
        log_it(L_DEBUG, "Created one-way unnamed bytestream pipe %d->%d", l_pipe[0], l_pipe[1]);
    l_es->fd = l_pipe[0];
    l_es->fd2 = l_pipe[1];

    dap_events_socket_assign_on_worker_unsafe(l_es,a_w);
    return  l_es;
}

/**
 * @brief dap_events_socket_create_type_queue
 * @param a_w
 * @param a_callback
 * @return
 */
dap_events_socket_t * dap_events_socket_create_type_queue(dap_worker_t * a_w, dap_events_socket_callback_t a_callback )
{
    dap_events_socket_t * l_es = DAP_NEW_Z(dap_events_socket_t);
    l_es->type = DESCRIPTOR_TYPE_QUEUE;
    l_es->worker = a_w;
    l_es->events = a_w->events;
    l_es->callbacks.queue_callback = a_callback; // Arm event callback
    l_es->ev_base_flags = EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP;

#ifdef DAP_EVENTS_CAPS_EVENT_PIPE2
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
    }else
        log_it(L_DEBUG, "Created one-way unnamed packet pipe %d->%d", l_pipe[0], l_pipe[1]);
    l_es->fd = l_pipe[0];
    l_es->fd2 = l_pipe[1];
#endif


    dap_events_socket_assign_on_worker_unsafe(l_es,a_w);
    return  l_es;
}

/**
 * @brief dap_events_socket_send_event
 * @param a_es
 * @param a_arg
 */
void dap_events_socket_queue_send( dap_events_socket_t * a_es, void* a_arg)
{
#if defined(DAP_EVENTS_CAPS_EVENT_PIPE2)
    write( a_es->fd2, &a_arg,sizeof(a_arg));
#endif
}

/**
 * @brief dap_events_socket_queue_on_remove_and_delete
 * @param a_es
 */
void dap_events_socket_queue_on_remove_and_delete(dap_events_socket_t* a_es)
{
    dap_events_socket_queue_send( a_es->worker->queue_es_delete, a_es );
}



/**
 * @brief dap_events_socket_create_after
 * @param a_es
 */
void dap_events_socket_create_after( dap_events_socket_t *a_es )
{
  if ( a_es->callbacks.new_callback )
    a_es->callbacks.new_callback( a_es, NULL ); // Init internal structure

  a_es->last_time_active = a_es->last_ping_request = time( NULL );

  dap_worker_add_events_socket_auto( a_es );


  a_es->worker->event_sockets_count ++;

  pthread_rwlock_wrlock( &a_es->events->sockets_rwlock );
  HASH_ADD_INT( a_es->events->sockets, socket, a_es );
  pthread_rwlock_unlock( &a_es->events->sockets_rwlock );

  a_es->ev.events = EPOLLIN | EPOLLERR;
  a_es->ev.data.ptr = a_es;

  if ( epoll_ctl( a_es->worker->epoll_fd, EPOLL_CTL_ADD, a_es->socket, &a_es->ev ) == 1 )
    log_it( L_CRITICAL, "Can't add event socket's handler to epoll_fd" );

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

  log_it( L_DEBUG,"Dap event socket wrapped around %d sock", a_sock );
  dap_events_socket_t * ret = DAP_NEW_Z( dap_events_socket_t );

  ret->socket = a_sock;
  ret->events = a_events;
  ret->server = a_server;
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
void dap_events_socket_set_writable_unsafe( dap_events_socket_t *sc, bool is_ready )
{
    if ( is_ready == (bool)(sc->flags & DAP_SOCK_READY_TO_WRITE) ) {
        return;
    }

    if ( is_ready )
        sc->flags |= DAP_SOCK_READY_TO_WRITE;
    else
        sc->flags ^= DAP_SOCK_READY_TO_WRITE;

    int events = sc->ev_base_flags | EPOLLERR;

    if( sc->flags & DAP_SOCK_READY_TO_READ )
        events |= EPOLLIN;

    if( sc->flags & DAP_SOCK_READY_TO_WRITE )
        events |= EPOLLOUT;

    sc->ev.events = events;

    if ( epoll_ctl(sc->worker->epoll_fd, EPOLL_CTL_MOD, sc->socket, &sc->ev) ){
        int l_errno = errno;
        char l_errbuf[128];
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        log_it(L_ERROR,"Can't update write client socket state in the epoll_fd: \"%s\" (%d)", l_errbuf, l_errno);
    }
}

/**
 * @brief dap_events_socket_remove Removes the client from the list
 * @param sc Connection instance
 */
void dap_events_socket_delete_unsafe( dap_events_socket_t *a_es, bool preserve_inheritor )
{
    if ( !a_es )
        return;

    log_it( L_DEBUG, "es is going to be removed from the lists and free the memory (0x%016X)", a_es );
    dap_events_socket_remove_from_worker_unsafe(a_es, a_es->worker);

    pthread_rwlock_wrlock( &a_es->events->sockets_rwlock );
    if(!dap_events_socket_find_unsafe(a_es->socket, a_es->events)){
        log_it( L_ERROR, "dap_events_socket 0x%x already deleted", a_es);
        return ;
    }

    if(a_es->events->sockets)
        HASH_DEL( a_es->events->sockets, a_es );
    pthread_rwlock_unlock( &a_es->events->sockets_rwlock );

    log_it( L_DEBUG, "dap_events_socket wrapped around %d socket is removed", a_es->socket );

    if( a_es->callbacks.delete_callback )
        a_es->callbacks.delete_callback( a_es, NULL ); // Init internal structure

    if ( a_es->_inheritor && !preserve_inheritor )
        DAP_DELETE( a_es->_inheritor );

    if ( a_es->socket && a_es->socket != -1) {
#ifdef _WIN32
        closesocket( a_es->socket );
#else
        close( a_es->socket );
#ifdef DAP_EVENTS_CAPS_EVENT_PIPE2
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
    if ( epoll_ctl( a_worker->epoll_fd, EPOLL_CTL_DEL, a_es->socket, &a_es->ev) == -1 )
        log_it( L_ERROR,"Can't remove event socket's handler from the epoll_fd" );
    else
        log_it( L_DEBUG,"Removed epoll's event from dap_worker #%u", a_worker->id );
    a_worker->event_sockets_count--;
    if(a_worker->sockets)
        HASH_DELETE(hh_worker,a_worker->sockets, a_es);
}

/**
 * @brief dap_events_socket_remove_and_delete
 * @param a_es
 * @param preserve_inheritor
 */
void dap_events_socket_remove_and_delete_mt( dap_events_socket_t *a_es )
{
    dap_events_socket_queue_send( a_es->worker->queue_es_delete, a_es );
}

/**
 * @brief dap_events_socket_set_readable_mt
 * @param sc
 * @param is_ready
 */
void dap_events_socket_set_readable_mt(dap_events_socket_t * a_es,bool is_ready)
{
    dap_events_socket_mgs_t * l_msg = DAP_NEW_Z(dap_events_socket_mgs_t);
    l_msg->esocket = a_es;
    if (is_ready)
        l_msg->flags_set = DAP_SOCK_READY_TO_READ;
    else
        l_msg->flags_unset = DAP_SOCK_READY_TO_READ;
    if (write(a_es->fd, l_msg,sizeof (l_msg)) != sizeof (l_msg) ){
        log_it(L_ERROR, "Wasn't send pointer to queue");
        DAP_DELETE(l_msg);
    }

}

/**
 * @brief dap_events_socket_set_writable_mt
 * @param sc
 * @param is_ready
 */
void dap_events_socket_set_writable_mt(dap_events_socket_t * a_es,bool is_ready)
{
    dap_events_socket_mgs_t * l_msg = DAP_NEW_Z(dap_events_socket_mgs_t);
    l_msg->esocket = a_es;
    if (is_ready)
        l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    else
        l_msg->flags_unset = DAP_SOCK_READY_TO_WRITE;
    if (write(a_es->fd, l_msg,sizeof (l_msg)) != sizeof (l_msg) ){
        log_it(L_ERROR, "Wasn't send pointer to queue");
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
size_t dap_events_socket_write_mt(dap_events_socket_t *a_es, const void * data, size_t l_data_size)
{
    dap_events_socket_mgs_t * l_msg = DAP_NEW_Z(dap_events_socket_mgs_t);
    l_msg->esocket = a_es;
    l_msg->data = DAP_NEW_SIZE(void,l_data_size);
    l_msg->data_size = l_data_size;
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    memcpy( l_msg->data, data, l_data_size);

    if (write(a_es->fd, l_msg,sizeof (l_msg)) != sizeof (l_msg) ){
        log_it(L_ERROR, "Wasn't send pointer to queue");
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
size_t dap_events_socket_write_f_mt(dap_events_socket_t *a_es, const char * format,...)
{
    va_list ap;
    va_start(ap,format);
    int l_data_size = dap_vsnprintf(NULL,0,format,ap);
    if (l_data_size <0 ){
        log_it(L_ERROR,"Can't write out formatted data '%s' with values",format);
        return 0;
    }
    l_data_size++; // To calc trailing zero
    dap_events_socket_mgs_t * l_msg = DAP_NEW_Z(dap_events_socket_mgs_t);
    l_msg->esocket = a_es;
    l_msg->data = DAP_NEW_SIZE(void,l_data_size);
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    l_data_size = dap_vsnprintf(l_msg->data,0,format,ap);
    if (l_data_size <0 ){
        log_it(L_ERROR,"Can't write out formatted data '%s' with values",format);
        DAP_DELETE(l_msg);
        return 0;
    }
    l_data_size++;
    l_msg->data_size = l_data_size;
    if (write(a_es->fd, l_msg,sizeof (l_msg)) != sizeof (l_msg) ){
        log_it(L_ERROR, "Wasn't send pointer to queue");
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
    log_it(L_DEBUG,"dap_events_socket_write_f %u sock", sc->socket );

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
