/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include "common.h"
#include "dap_events.h"
#ifdef dap_SERVER
#include "dap_server.h"
#endif
#include "dap_events_socket.h"

#define LOG_TAG "dap_events_socket"

/**
 * @brief dap_events_socket_init Init clients module
 * @return Zero if ok others if no
 */
int dap_events_socket_init()
{
    log_it(L_NOTICE,"Initialized socket client module");
    return 0;
}

/**
 * @brief dap_events_socket_deinit Deinit clients module
 */
void dap_events_socket_deinit()
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
dap_events_socket_t * dap_events_socket_wrap_no_add(struct dap_events * a_events,
                                            int a_sock, dap_events_socket_callbacks_t * a_callbacks)
{
    assert(a_events);
    assert(a_callbacks);
    log_it(L_DEBUG,"Sap event socket wrapped around %d sock", a_sock);
    dap_events_socket_t * ret = dap_NEW_Z(dap_events_socket_t);
    ret->socket = a_sock;
    ret->events = a_events;
    ret->callbacks = a_callbacks;
    ret->_ready_to_read=true;
    return ret;
}

/**
 * @brief dap_events_socket_create_after
 * @param a_es
 */
void dap_events_socket_create_after(dap_events_socket_t * a_es)
{
    if(a_es->callbacks->new_callback)
        a_es->callbacks->new_callback(a_es,NULL); // Init internal structure

    pthread_rwlock_wrlock(&a_es->events->sockets_rwlock);
    a_es->last_ping_request = time(NULL);
    HASH_ADD_INT(a_es->events->sockets, socket, a_es);
    pthread_rwlock_unlock(&a_es->events->sockets_rwlock);

    dap_worker_add_events_socket(a_es);
}

/**
 * @brief dap_events_socket_wrap
 * @param a_events
 * @param w
 * @param s
 * @param a_callbacks
 * @return
 */
dap_events_socket_t * dap_events_socket_wrap2(dap_server_t * a_server, struct dap_events * a_events,
                                            int a_sock, dap_events_socket_callbacks_t * a_callbacks)
{
    assert(a_events);
    assert(a_callbacks);
    assert(a_server);
    log_it(L_DEBUG,"Sap event socket wrapped around %d sock", a_sock);
    dap_events_socket_t * ret = dap_NEW_Z(dap_events_socket_t);
    ret->socket = a_sock;
    ret->events = a_events;
    ret->callbacks = a_callbacks;
#ifdef dap_SERVER
    ret->server = a_server;
#endif
    ret->_ready_to_read=true;
    ret->is_pingable = true;

    pthread_rwlock_wrlock(&a_events->sockets_rwlock);
    ret->last_ping_request = time(NULL);
    HASH_ADD_INT(a_events->sockets, socket, ret);
    pthread_rwlock_unlock(&a_events->sockets_rwlock);
    if(a_callbacks->new_callback)
        a_callbacks->new_callback(ret,NULL); // Init internal structure
    return ret;
}

/**
 * @brief dap_events_socket_find
 * @param sock
 * @param sh
 * @return
 */
dap_events_socket_t * dap_events_socket_find(int sock, struct dap_events * a_events)
{
    dap_events_socket_t * ret = NULL;
    pthread_rwlock_rdlock(&a_events->sockets_rwlock);
    HASH_FIND_INT(a_events->sockets, &sock, ret);
    pthread_rwlock_unlock(&a_events->sockets_rwlock);
    return ret;
}

/**
 * @brief dap_events_socket_ready_to_read
 * @param sc
 * @param isReady
 */
void dap_events_socket_set_readable(dap_events_socket_t * sc,bool is_ready)
{
    if(is_ready != sc->_ready_to_read){
        struct epoll_event ev={0};
        ev.events = EPOLLERR;
        sc->_ready_to_read=is_ready;
        if(sc->_ready_to_read)
            ev.events  |= EPOLLIN;
        if(sc->_ready_to_write)
            ev.events |= EPOLLOUT;

        ev.data.fd=sc->socket;
        if (epoll_ctl(sc->dap_worker->epoll_fd, EPOLL_CTL_MOD, sc->socket, &ev) == -1) {
            log_it(L_ERROR,"Can't update read client socket state in the epoll_fd");
        }else
            dap_events_thread_wake_up(&sc->events->proc_thread);
    }
}

/**
 * @brief dap_events_socket_ready_to_write
 * @param sc
 * @param isReady
 */
void dap_events_socket_set_writable(dap_events_socket_t * sc,bool is_ready)
{
    if(is_ready != sc->_ready_to_write){
        struct epoll_event ev={0};
        ev.events = EPOLLERR ;
        sc->_ready_to_write=is_ready;
        if(sc->_ready_to_read)
            ev.events |= EPOLLIN;
        if(sc->_ready_to_write)
            ev.events |= EPOLLOUT;
        ev.data.fd=sc->socket;
        if (epoll_ctl(sc->dap_worker->epoll_fd, EPOLL_CTL_MOD, sc->socket, &ev) == -1) {
            log_it(L_ERROR,"Can't update write client socket state in the epoll_fd");
        }else
            dap_events_thread_wake_up(&sc->events->proc_thread);
    }

}


/**
 * @brief dap_events_socket_remove Removes the client from the list
 * @param sc Connection instance
 */
void dap_events_socket_delete(dap_events_socket_t *a_es, bool preserve_inheritor)
{
    if (a_es){
        log_it(L_DEBUG, "es is going to be removed from the lists and free the memory (0x%016X)", a_es );
        pthread_rwlock_wrlock(&a_es->events->sockets_rwlock);
        HASH_DEL(a_es->events->sockets, a_es);
        pthread_rwlock_unlock(&a_es->events->sockets_rwlock);
        log_it(L_DEBUG, "dap_events_socket wrapped around %d socket is removed", a_es->socket);

        if(a_es->callbacks->delete_callback)
            a_es->callbacks->delete_callback(a_es, NULL); // Init internal structure

        if(a_es->_inheritor && !preserve_inheritor)
//        if(a_es->_inheritor)
            free(a_es->_inheritor);

        if(a_es->socket){
            close(a_es->socket);
        }
        free(a_es);
	}
}

/**
 * @brief dap_events_socket_write Write data to the client
 * @param sc Conn instance
 * @param data Pointer to data
 * @param data_size Size of data to write
 * @return Number of bytes that were placed into the buffer
 */
size_t dap_events_socket_write(dap_events_socket_t *sc, const void * data, size_t data_size)
{
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
size_t dap_events_socket_write_f(dap_events_socket_t *sc, const char * format,...)
{
    size_t max_data_size = sizeof(sc->buf_out)-sc->buf_out_size;
    va_list ap;
    va_start(ap,format);
    int ret=vsnprintf((char*) sc->buf_out+sc->buf_out_size,max_data_size,format,ap);
    va_end(ap);
    if(ret>0){
        sc->buf_out_size+=ret;
        return ret;
    }else{
        log_it(L_ERROR,"Can't write out formatted data '%s'",format);
        return 0;
    }
}

/**
 * @brief dap_events_socket_read Read data from input buffer
 * @param sc Conn instasnce
 * @param data Pointer to memory where to store the data
 * @param data_size Size of data to read
 * @return Actual bytes number that were read
 */
size_t dap_events_socket_read(dap_events_socket_t *sc, void * data, size_t data_size)
{
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
        void * buf = malloc(buf_size);
        memcpy(buf,cl->buf_in+ shrink_size,buf_size );
        memcpy(cl->buf_in,buf,buf_size);
        cl->buf_in_size=buf_size;
        if (buf)
        	free(buf);
    }else{
        //log_it(WARNING,"Shrinking size of input buffer on amount bigger than actual buffer's size");
        cl->buf_in_size=0;
    }

}
