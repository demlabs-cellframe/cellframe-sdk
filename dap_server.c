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
#define NI_NUMERICSERV  2	/* Don't convert port number to name.  */
#define NI_NOFQDN	    4	/* Only return nodename portion.  */
#define NI_NAMEREQD	    8	/* Don't return numeric addresses.  */
#define NI_DGRAM	    16	/* Look up UDP service rather than TCP.  */

#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>

#include "dap_common.h"
#include "dap_server.h"
#include <ev.h>

#define LOG_TAG "server"

static void read_write_cb (struct ev_loop* loop, struct ev_io* watcher, int revents);

static struct ev_loop** listener_clients_loops;

static ev_async* async_watchers;
static dap_server_t * _current_run_server;
static size_t _count_threads = 0;

typedef struct ev_async_data
{
    int client_fd;
    int thread_number;
} ev_async_data_t;

static struct thread_information {
    int thread_number;
    atomic_size_t count_open_connections;
} *thread_inform;

static pthread_mutex_t mutex_set_client_thread_cb;
static pthread_mutex_t mutex_on_cnt_connections;

#define DAP_EV_DATA(a) ((ev_async_data_t*)a->data)

/**
 * @brief dap_server_init Init server module
 * @return Zero if ok others if no
 */
int dap_server_init(size_t count_threads)
{
    _count_threads = count_threads;

    signal(SIGPIPE, SIG_IGN);

    async_watchers = malloc(sizeof(ev_async) * _count_threads);
    listener_clients_loops = malloc(sizeof(struct ev_loop*) * _count_threads);
    thread_inform = malloc (sizeof(struct thread_information) * _count_threads);

    for(size_t i = 0; i < _count_threads; i++)
    {
        thread_inform[i].thread_number = (int)i;
        atomic_init(&thread_inform[i].count_open_connections, 0);
        async_watchers[i].data = malloc(sizeof(ev_async_data_t));
    }

    pthread_mutex_init(&mutex_set_client_thread_cb, NULL);
    pthread_mutex_init(&mutex_on_cnt_connections, NULL);

    log_it(L_NOTICE,"Initialized socket server module");
    dap_client_remote_init();
    return 0;
}

/**
 * @brief dap_server_deinit Deinit server module
 */
void dap_server_deinit()
{
    dap_client_remote_deinit();
    for(size_t i = 0; i < _count_threads; i++)
        free (async_watchers[i].data);

    free(async_watchers);
    free(listener_clients_loops);
    free(thread_inform);
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
    dap_client_remote_t * dap_cur, * tmp;
    if(sh->address)
        free(sh->address);

    HASH_ITER(hh,sh->clients,dap_cur,tmp)
        dap_client_remote_remove(dap_cur, sh);

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

static void set_client_thread_cb (EV_P_ ev_async *w, int revents)
{
    pthread_mutex_lock(&mutex_set_client_thread_cb);

    int fd = DAP_EV_DATA(w)->client_fd;

    struct ev_io* w_client = (struct ev_io*) malloc (sizeof(struct ev_io));

    ev_io_init(w_client, read_write_cb, fd, EV_READ);
    ev_io_set(w_client, fd, EV_READ  | EV_WRITE);
    w_client->data = malloc(sizeof(ev_async_data_t));

    memcpy(w_client->data, w->data, sizeof(ev_async_data_t));

    dap_client_remote_create(_current_run_server, fd, w_client);

    ev_io_start(listener_clients_loops[DAP_EV_DATA(w)->thread_number], w_client);

    pthread_mutex_unlock(&mutex_set_client_thread_cb);
}

static void read_write_cb (struct ev_loop* loop, struct ev_io* watcher, int revents)
{
    dap_client_remote_t* dap_cur = dap_client_remote_find(watcher->fd, _current_run_server);

    if ( revents & EV_READ )
    {
    //    log_it(INFO, "socket read %d thread %d", watcher->fd, thread);
        if(dap_cur)
        {
            ssize_t bytes_read = recv(dap_cur->socket,
                                  dap_cur->buf_in + dap_cur->buf_in_size,
                                  sizeof(dap_cur->buf_in) - dap_cur->buf_in_size,
                                  0);
            if(bytes_read > 0)
            {
                dap_cur->buf_in_size += (size_t)bytes_read;
                dap_cur->upload_stat.buf_size_total += (size_t)bytes_read;
                _current_run_server->client_read_callback(dap_cur,NULL);
            }
            else if(bytes_read < 0)
            {
                log_it(L_ERROR,"Bytes read Error %s",strerror(errno));
                if ( strcmp(strerror(errno),"Resource temporarily unavailable") != 0 )
                    dap_cur->signal_close = true;
            }
            else if (bytes_read == 0)
            {
                dap_cur->signal_close = true;
            }
        }
    }

    if( ( (revents & EV_WRITE) || dap_cur->_ready_to_write ) &&
            dap_cur->signal_close == false ) {

        _current_run_server->client_write_callback(dap_cur, NULL); // Call callback to process write event

        if(dap_cur->buf_out_size == 0)
        {
            ev_io_set(watcher, watcher->fd, EV_READ);
        }
        else
        {
            size_t total_sent = dap_cur->buf_out_offset;
            for(; total_sent < dap_cur->buf_out_size;) {
                //log_it(DEBUG, "Output: %u from %u bytes are sent ", total_sent, dap_cur->buf_out_size);
                ssize_t bytes_sent = send(dap_cur->socket,
                                      dap_cur->buf_out + total_sent,
                                      dap_cur->buf_out_size - total_sent,
                                      MSG_DONTWAIT | MSG_NOSIGNAL );
                if(bytes_sent < 0) {
                    log_it(L_ERROR,"Error occured in send() function %s", strerror(errno));
                    break;
                }
                total_sent += (size_t)bytes_sent;
                dap_cur->download_stat.buf_size_total += (size_t)bytes_sent;
            }

            if(total_sent == dap_cur->buf_out_size) {
                dap_cur->buf_out_offset = dap_cur->buf_out_size  = 0;
            } else {
                dap_cur->buf_out_offset = total_sent;
            }

        }
    }

    if(dap_cur->signal_close)
    {
        log_it(L_INFO, "Close Socket %d", watcher->fd);

        atomic_fetch_sub(&thread_inform[DAP_EV_DATA(watcher)->thread_number].count_open_connections, 1);
        ev_io_stop(listener_clients_loops[DAP_EV_DATA(watcher)->thread_number], watcher);
        dap_client_remote_remove(dap_cur, _current_run_server);
        free(watcher->data); free(watcher);
        return;
    }
}

/**
 * @brief get_thread_min_connections
 * @return number thread which has minimum open connections
 */
static inline uint8_t get_thread_index_min_connections()
{
    uint8_t min = 0;
    for(uint8_t i = 1; i < _count_threads; i++)
    {
        if (atomic_load(&thread_inform[min].count_open_connections) >
             atomic_load(&thread_inform[i].count_open_connections))
        {
            min = i;
        }
    }
    return min;
}

static inline void print_online()
{
    for(uint8_t i = 0; i < _count_threads; i++)
    {
        log_it(L_INFO, "Thread number: %d, count: %d",
               thread_inform[i].thread_number, atomic_load(&thread_inform[i].count_open_connections));
    }
}

static void accept_cb (struct ev_loop* loop, struct ev_io* watcher, int revents)
{
    int client_fd = accept(watcher->fd, 0, 0);
    log_it(L_INFO, "Client accept socket %d", client_fd);
    if( client_fd < 0 )
        log_it(L_ERROR, "error accept");
    set_nonblock_socket(client_fd);

    uint8_t indx_min = get_thread_index_min_connections();
    ev_async_data_t *ev_data = async_watchers[indx_min].data;
    ev_data->client_fd = client_fd;
    ev_data->thread_number = indx_min;

    atomic_fetch_add(&thread_inform[ev_data->thread_number].count_open_connections, 1);

    log_it(L_DEBUG, "Client send to thread %d", ev_data->thread_number);
    if ( ev_async_pending(&async_watchers[ev_data->thread_number]) == false ) { //the event has not yet been processed (or even noted) by the event loop? (i.e. Is it serviced? If yes then proceed to)
        log_it(L_INFO, "ev_async_pending");
        ev_async_send(listener_clients_loops[ev_data->thread_number], &async_watchers[ev_data->thread_number]); //Sends/signals/activates the given ev_async watcher, that is, feeds an EV_ASYNC event on the watcher into the event loop.
    }
    else {
        atomic_fetch_sub(&thread_inform[DAP_EV_DATA(watcher)->thread_number].count_open_connections, 1);
        log_it(L_ERROR, "Ev async error pending");
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
        log_it(L_INFO,"Binded %s:%u", addr, port);
        listen(sh->socket_listener, 100000);
        pthread_mutex_init(&sh->mutex_on_hash, NULL);
        return sh;
    }
}

/**
 * @brief thread_loop
 * @param arg
 * @return
 */
void* thread_loop(void * arg)
{
    log_it(L_NOTICE, "Start loop listener socket thread %d", *(int*)arg);

    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(*(int*)arg, &mask);

    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &mask) != 0)
    {
        log_it(L_CRITICAL, "Error pthread_setaffinity_np() You really have %d or more core in CPU?", *(int*)arg);
        abort();
    }

    ev_loop(listener_clients_loops[*(int*)arg], 0);
    return NULL;
}

/**
 * @brief dap_server_loop Main server loop
 * @param a_server Server instance
 * @return Zero if ok others if not
 */
int dap_server_loop(dap_server_t * a_server)
{
    int thread_arg[_count_threads];
    pthread_t thread_listener[_count_threads];
    struct ev_loop * ev_main_loop = ev_default_loop(0);

    if ( a_server ) {
        for(size_t i = 0; i < _count_threads; i++)
        {
            thread_arg[i] = (int)i;
            listener_clients_loops[i] = ev_loop_new(0);
            async_watchers[i].data = a_server;
            ev_async_init(&async_watchers[i], set_client_thread_cb);
            ev_async_start(listener_clients_loops[i], &async_watchers[i]);
            pthread_create(&thread_listener[i], NULL, thread_loop, &thread_arg[i]);
        }
        _current_run_server = a_server;
        struct ev_io w_accept; w_accept.data = a_server;
        ev_io_init(&w_accept, accept_cb, a_server->socket_listener, EV_READ);
        ev_io_start(ev_main_loop, &w_accept);
    }
    ev_run(ev_main_loop, 0);

    return 0;
}
