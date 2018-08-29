/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>

#define NI_NUMERICHOST	1	/* Don't try to look up hostname.  */
#define NI_NUMERICSERV 2	/* Don't convert port number to name.  */
#define NI_NOFQDN	    4	/* Only return nodename portion.  */
#define NI_NAMEREQD	8	/* Don't return numeric addresses.  */
#define NI_DGRAM	    16	/* Look up UDP service rather than TCP.  */

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

#include "dap_common.h"
#include "dap_server.h"
#include <ev.h>

#define LOG_TAG "dap_server"

static void read_write_cb (struct ev_loop* _loop, struct ev_io* watcher, int revents);

static struct ev_loop* listener_clients_loop;
static ev_async async_watcher;

typedef struct ev_async_data
{
    int client_fd;
    dap_server_t *dap_server;
} ev_async_data_t;

/**
 * @brief dap_server_init Init server module
 * @return Zero if ok others if no
 */
int dap_server_init()
{
    signal(SIGPIPE, SIG_IGN);
    async_watcher.data = malloc(sizeof(ev_async_data_t));

    log_it(L_NOTICE,"Initialized socket server module");

    return 0;
}

/**
 * @brief dap_server_deinit Deinit server module
 */
void dap_server_deinit()
{
}


/**
 * @brief server_new Creates new empty instance of server_t
 * @return New instance
 */
dap_server_t * dap_server_new()
{
    return (dap_server_t*) calloc(1,sizeof(dap_server_t));
}

/**
 * @brief server_delete Deete server instance
 * @param sh Pointer to the server instance
 */
void dap_server_delete(dap_server_t * sh)
{
    dap_server_client_t * dap_cur, * tmp;
    if(sh->address)
        free(sh->address);

    HASH_ITER(hh,sh->clients,dap_cur,tmp)
        dap_client_remove(dap_cur, sh);

    if(sh->server_delete_callback)
        sh->server_delete_callback(sh,NULL);
    free(sh->_inheritor);
    free(sh);
}

int set_nonblock_socket(int fd)
{
    int flags;
    flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}


static void async_cb (EV_P_ ev_async *w, int revents)
{
    int fd = ((ev_async_data_t*)w->data)->client_fd;
    dap_server_t *sh = ((ev_async_data_t*)w->data)->dap_server;

    struct ev_io* w_client = (struct ev_io*) malloc (sizeof(struct ev_io));

    ev_io_init(w_client, read_write_cb, fd, EV_READ);
    ev_io_set(w_client, fd, EV_READ  | EV_WRITE);
    w_client->data = ((ev_async_data_t*)w->data)->dap_server;

    dap_client_create(sh, fd, w_client);

    ev_io_start(listener_clients_loop, w_client);
}

static void read_write_cb (struct ev_loop* loop, struct ev_io* watcher, int revents)
{
    dap_server_t* sh = watcher->data;
    dap_server_client_t* dap_cur = dap_client_find(watcher->fd, sh);

    if ( revents & EV_READ )
    {
        if(dap_cur)
        {
            ssize_t bytes_read = recv(dap_cur->socket,
                                  dap_cur->buf_in + dap_cur->buf_in_size,
                                  sizeof(dap_cur->buf_in) - dap_cur->buf_in_size,
                                  0);
            if(bytes_read > 0)
            {
                dap_cur->buf_in_size_total += bytes_read;
                dap_cur->buf_in_size += bytes_read;
                sh->client_read_callback(dap_cur, NULL);
            }
            else if(bytes_read < 0)
            {
                log_it(L_ERROR,"Bytes read Error %s",strerror(errno));
                dap_cur->signal_close = true;

            }
            else if (bytes_read == 0)
            {
                dap_cur->signal_close = true;
            }
        }
    }

    if( ( revents & EV_WRITE ) || dap_cur->_ready_to_write ) {

        sh->client_write_callback(dap_cur, NULL); // Call callback to process write event

        if(dap_cur->buf_out_size == 0)
        {
            ev_io_set(watcher, watcher->fd, EV_READ);
        }
        else
        {
            for(size_t total_sent = 0; total_sent < dap_cur->buf_out_size;) {
                //log_it(L_DEBUG, "Output: %u from %u bytes are sent ", total_sent, dap_cur->buf_out_size);
                ssize_t bytes_sent = send(dap_cur->socket,
                                      dap_cur->buf_out + total_sent,
                                      dap_cur->buf_out_size - total_sent,
                                      MSG_DONTWAIT | MSG_NOSIGNAL );
                if(bytes_sent < 0) {
                    log_it(L_ERROR, "Some error occured in send() function");
                    break;
                }
                total_sent += bytes_sent;
            }
            dap_cur->buf_out_size_total += dap_cur->buf_out_size;
            dap_cur->buf_out_size = 0;
        }
    }

    if(dap_cur->signal_close)
    {
        log_it(L_INFO, "Close Socket %d", watcher->fd);
        dap_client_remove(dap_cur, sh);
        ev_io_stop(listener_clients_loop, watcher);
        free(watcher);
        return;
    }
}

static void accept_cb (struct ev_loop* loop, struct ev_io* watcher, int revents)
{
    int client_fd = accept(watcher->fd, 0, 0);
    log_it(L_INFO, "Client accept socket %", client_fd);
    if( client_fd < 0 )
        log_it(L_ERROR, "error accept");
    set_nonblock_socket(client_fd);

    ev_async_data_t *ev_data = async_watcher.data;
    ev_data->client_fd = client_fd;
    ev_data->dap_server = watcher->data;

    if ( ev_async_pending(&async_watcher) == false ) { //the event has not yet been processed (or even noted) by the event loop? (i.e. Is it serviced? If yes then proceed to)
        ev_async_send(listener_clients_loop, &async_watcher); //Sends/signals/activates the given ev_async watcher, that is, feeds an EV_ASYNC event on the watcher into the event loop.
    }
}

/**
 * @brief server_listen Create server_t instance and start to listen tcp port with selected address
 * @param addr address
 * @param port port
 * @return
 */
dap_server_t* dap_server_listen(const char * addr, uint16_t port, dap_server_type_t type)
{
    dap_server_t* sh = dap_server_new();

    sh->socket_listener = -111;

    if(type == DAP_SERVER_TCP)
        sh->socket_listener = socket (AF_INET, SOCK_STREAM, 0);

    if (-1 == set_nonblock_socket(sh->socket_listener)) {
        log_it(L_WARNING,"error server socket nonblock");
        exit(EXIT_FAILURE);
    }

    if (sh->socket_listener < 0){
        log_it (L_ERROR,"Socket error %s",strerror(errno));
        dap_server_delete(sh);
        return NULL;
    }

    log_it(L_NOTICE,"Socket created...");

    int reuse = 1;

    if (setsockopt(sh->socket_listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        log_it(L_WARNING, "Can't set up REUSEADDR flag to the socket");
#ifdef SO_REUSEPORT
    if (setsockopt(sh->socket_listener, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0)
        log_it(L_WARNING, "Can't set up REUSEPORT flag to the socket");
#endif

    sh->listener_addr.sin_family = AF_INET;
    sh->listener_addr.sin_port = htons(port);
    inet_pton(AF_INET,addr, &(sh->listener_addr.sin_addr));

    if(bind (sh->socket_listener, (struct sockaddr *) &(sh->listener_addr), sizeof(sh->listener_addr)) < 0) {
        log_it(L_ERROR,"Bind error: %s",strerror(errno));
        dap_server_delete(sh);
        return NULL;
    }else {
        log_it(L_INFO,"Binded %s:%u",addr,port);

        listen(sh->socket_listener, 100000);
        pthread_mutex_init(&sh->mutex_on_hash, NULL);

        return sh;
    }
}

void* thread_loop(void * arg)
{
    (void)arg;
    log_it(L_NOTICE, "Start loop listener socket thread");
    ev_loop(listener_clients_loop, 0);
    return NULL;
}

/**
 * @brief dap_server_loop Main server loop
 * @param sh Server instance
 * @return Zero if ok others if not
 */
int dap_server_loop(dap_server_t * sh)
{
    pthread_t thread;
    listener_clients_loop = ev_loop_new(0);
    async_watcher.data = sh;
    ev_async_init(&async_watcher, async_cb);
    ev_async_start(listener_clients_loop, &async_watcher);
    pthread_create(&thread, NULL, thread_loop, NULL);

    sh->proc_thread.tid = pthread_self();

    struct ev_loop * ev_main_loop = ev_default_loop(0);
    struct ev_io w_accept; w_accept.data = sh;
    ev_io_init(&w_accept, accept_cb, sh->socket_listener, EV_READ);
    ev_io_start(ev_main_loop, &w_accept);
    ev_run(ev_main_loop, 0);

    return 0;
}


/**
 * @brief dap_thread_wake_up
 * @param th
 */
void dap_thread_wake_up(dap_thread_t * th)
{
   //pthread_kill(th->tid,SIGUSR1);
}
