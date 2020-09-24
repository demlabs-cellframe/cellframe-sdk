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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/epoll.h>

#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <signal.h>
#include <sys/timerfd.h>
#include <utlist.h>
#if ! defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#if ! defined (__USE_GNU)
#define __USE_GNU
#endif
#include <sched.h>
#include "dap_common.h"
#include "dap_config.h"
#include "dap_server.h"
#include "dap_worker.h"
#include "dap_events.h"

#define LOG_TAG "dap_server"

static dap_events_socket_t * s_es_server_create(dap_events_t * a_events, int a_sock,
                                             dap_events_socket_callbacks_t * a_callbacks, dap_server_t * a_server);

static void s_es_server_accept(dap_events_socket_t *a_es, int a_remote_socket, struct sockaddr* a_remote_addr);
static void s_es_server_error(dap_events_socket_t *a_es, int a_arg);
static void s_es_server_new(dap_events_socket_t *a_es, void * a_arg);
/**
 * @brief dap_server_init
 * @return
 */
int dap_server_init()
{
    log_it(L_NOTICE,"Server module init");
    return 0;
}

/**
 * @brief dap_server_deinit
 */
void dap_server_deinit()
{
}

/**
 * @brief dap_server_delete
 * @param a_server
 */
void dap_server_delete(dap_server_t *a_server)
{
    while (a_server->es_listeners) {
        dap_events_socket_t *l_es = (dap_events_socket_t *)a_server->es_listeners->data;
        dap_events_socket_remove_and_delete_mt(l_es->worker, l_es);
        dap_list_t *l_tmp = a_server->es_listeners;
        a_server->es_listeners = l_tmp->next;
        DAP_DELETE(l_tmp);
    }
    if(a_server->delete_callback)
        a_server->delete_callback(a_server,NULL);
    if( a_server->address )
        DAP_DELETE(a_server->address );
    if( a_server->_inheritor )
        DAP_DELETE( a_server->_inheritor );
    pthread_mutex_destroy(&a_server->started_mutex);
    pthread_cond_destroy(&a_server->started_cond);
    DAP_DELETE(a_server);
}

/**
 * @brief dap_server_new
 * @param a_events
 * @param a_addr
 * @param a_port
 * @param a_type
 * @return
 */
dap_server_t* dap_server_new(dap_events_t *a_events, const char * a_addr, uint16_t a_port, dap_server_type_t a_type, dap_events_socket_callbacks_t *a_callbacks)
{
    assert(a_events);
    dap_server_t *l_server =  DAP_NEW_Z(dap_server_t);

    l_server->socket_listener=-1; // To diff it from 0 fd
    l_server->address = a_addr? strdup( a_addr) : strdup("0.0.0.0"); // If NULL we listen everything
    l_server->port = a_port;
    l_server->type = a_type;

    if(l_server->type == DAP_SERVER_TCP)
        l_server->socket_listener = socket(AF_INET, SOCK_STREAM, 0);
    else if (l_server->type == DAP_SERVER_UDP)
        l_server->socket_listener = socket(AF_INET, SOCK_DGRAM, 0);

    if (l_server->socket_listener < 0) {
        int l_errno = errno;
        log_it (L_ERROR,"Socket error %s (%d)",strerror(l_errno), l_errno);
        DAP_DELETE(l_server);
        return NULL;
    }

    log_it(L_NOTICE,"Listen socket %d created...", l_server->socket_listener);
    int reuse=1;

    if (setsockopt(l_server->socket_listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        log_it(L_WARNING, "Can't set up REUSEADDR flag to the socket");
#ifdef SO_REUSEPORT
    if (setsockopt(l_server->socket_listener, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0)
        log_it(L_WARNING, "Can't set up REUSEPORT flag to the socket");
#endif

//create socket
    l_server->listener_addr.sin_family = AF_INET;
    l_server->listener_addr.sin_port = htons(l_server->port);
    inet_pton(AF_INET, l_server->address, &(l_server->listener_addr.sin_addr));

    if(bind (l_server->socket_listener, (struct sockaddr *) &(l_server->listener_addr), sizeof(l_server->listener_addr)) < 0){
        log_it(L_ERROR,"Bind error: %s",strerror(errno));
        close(l_server->socket_listener);
        DAP_DELETE(l_server);
        return NULL;
    }else{
        log_it(L_INFO,"Binded %s:%u",l_server->address,l_server->port);
        listen(l_server->socket_listener, SOMAXCONN);
    }

    fcntl( l_server->socket_listener, F_SETFL, O_NONBLOCK);
    pthread_mutex_init(&l_server->started_mutex,NULL);
    pthread_cond_init(&l_server->started_cond,NULL);



    dap_events_socket_callbacks_t l_callbacks;
    memset(&l_callbacks,0,sizeof (l_callbacks));
    l_callbacks.new_callback = s_es_server_new;
    l_callbacks.accept_callback = s_es_server_accept;
    l_callbacks.error_callback = s_es_server_error;

    if (a_callbacks) {
        l_callbacks.read_callback = a_callbacks->read_callback;
        l_callbacks.write_callback = a_callbacks->write_callback;
        l_callbacks.error_callback = a_callbacks->error_callback;
    }

    for(size_t l_worker_id = 0; l_worker_id < dap_events_worker_get_count() ; l_worker_id++){
        dap_worker_t *l_w = dap_events_worker_get(l_worker_id);
        assert(l_w);
        dap_events_socket_t * l_es = dap_events_socket_wrap2( l_server, a_events, l_server->socket_listener, &l_callbacks);
        l_server->es_listeners = dap_list_append(l_server->es_listeners, l_es);

        if (l_es) {
            l_es->type = l_server->type == DAP_SERVER_TCP ? DESCRIPTOR_TYPE_SOCKET_LISTENING : DESCRIPTOR_TYPE_SOCKET;
#ifdef DAP_EVENTS_CAPS_EPOLL
            // Prepare for multi thread listening
            l_es->ev_base_flags  = EPOLLET| EPOLLIN | EPOLLEXCLUSIVE;
#endif
            l_es->_inheritor = l_server;
            pthread_mutex_lock(&l_server->started_mutex);
            dap_worker_add_events_socket( l_es, l_w );
            pthread_cond_wait(&l_server->started_cond, &l_server->started_mutex);
            pthread_mutex_unlock(&l_server->started_mutex);
        } else{
            log_it(L_WARNING, "Can't wrap event socket for %s:%u server", a_addr, a_port);
            return NULL;
        }
    }
    return  l_server;
}

/**
 * @brief s_es_server_new
 * @param a_es
 * @param a_arg
 */
static void s_es_server_new(dap_events_socket_t *a_es, void * a_arg)
{
    log_it(L_DEBUG, "Created server socket %p on worker %u", a_es, a_es->worker->id);
    dap_server_t *l_server = (dap_server_t*) a_es->_inheritor;
    pthread_mutex_lock( &l_server->started_mutex);
    pthread_mutex_unlock( &l_server->started_mutex);
    pthread_cond_broadcast( &l_server->started_cond);
}

/**
 * @brief s_es_server_error
 * @param a_es
 * @param a_arg
 */
static void s_es_server_error(dap_events_socket_t *a_es, int a_arg)
{
    (void) a_arg;
    (void) a_es;
    char l_buf[128];
    strerror_r(errno, l_buf, sizeof (l_buf));
    log_it(L_WARNING, "Listening socket error: %s, ", l_buf);
}

/**
 * @brief s_es_server_accept
 * @param a_events
 * @param a_remote_socket
 * @param a_remote_addr
 */
static void s_es_server_accept(dap_events_socket_t *a_es, int a_remote_socket, struct sockaddr *a_remote_addr)
{
    socklen_t a_remote_addr_size = sizeof(*a_remote_addr);
    a_es->buf_in_size = 0; // It should be 1 so we reset it to 0
    //log_it(L_DEBUG, "Server socket %d is active",i);
    dap_server_t * l_server = (dap_server_t*) a_es->_inheritor;
    assert(l_server);

    dap_events_socket_t * l_es_new = NULL;
    log_it(L_DEBUG, "Listening socket (binded on %s:%u) got new incomming connection",l_server->address,l_server->port);
    log_it(L_DEBUG, "Accepted new connection (sock %d from %d)", a_remote_socket, a_es->socket);
    l_es_new = s_es_server_create(a_es->events,a_remote_socket,&l_server->client_callbacks,l_server);
    //l_es_new->is_dont_reset_write_flag = true; // By default all income connection has this flag
    getnameinfo(a_remote_addr,a_remote_addr_size, l_es_new->hostaddr
                , sizeof(l_es_new->hostaddr),l_es_new->service,sizeof(l_es_new->service),
                NI_NUMERICHOST | NI_NUMERICSERV);

    log_it(L_INFO,"Connection accepted from %s (%s)", l_es_new->hostaddr, l_es_new->service );
    dap_worker_add_events_socket_auto(l_es_new);
}


/**
 * @brief s_esocket_new
 * @param a_events
 * @param a_sock
 * @param a_callbacks
 * @param a_server
 * @return
 */
static dap_events_socket_t * s_es_server_create(dap_events_t * a_events, int a_sock,
                                             dap_events_socket_callbacks_t * a_callbacks, dap_server_t * a_server)
{
    dap_events_socket_t * ret = NULL;
    if (a_sock > 0)  {
        // set it nonblock
        //fcntl(a_sock, F_SETFL, O_NONBLOCK);

        ret = dap_events_socket_wrap_no_add(a_events, a_sock, a_callbacks);
        ret->type = DESCRIPTOR_TYPE_SOCKET;
        ret->server = a_server;

    } else {
        log_it(L_CRITICAL,"Accept error: %s",strerror(errno));
    }
    return ret;
}
