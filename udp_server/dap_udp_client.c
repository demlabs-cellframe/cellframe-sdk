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

#include "dap_udp_client.h"
#include <sys/epoll.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <ev.h>
#include "utlist.h"
#include "dap_common.h"
#include "dap_udp_server.h"

#define LOG_TAG "udp_client"

/**
 * @brief get_key Make key for hash table from host and port
 * @return 64 bit Key
 */
uint64_t get_key(unsigned long host,unsigned short port){
    uint64_t key = host;
    key = key << 32;
    key += port;
    return key;
}

/**
 * @brief udp_client_create Create new client and add it to hashmap
 * @param sh Server instance
 * @param host Client host address
 * @param w_client Clients event loop watcher
 * @param port Client port
 * @return Pointer to the new list's node
 */
dap_client_remote_t * dap_udp_client_create(dap_server_t * sh, ev_io* w_client, unsigned long host, unsigned short port)
{
    dap_udp_server_t* udp_server = DAP_UDP_SERVER(sh);
    log_it(L_DEBUG,"Client structure create");

    dap_udp_client_t * inh=DAP_NEW_Z(dap_udp_client_t);
    inh->host_key = get_key(host,port);

    dap_client_remote_t * ret=DAP_NEW_Z(dap_client_remote_t);
    inh->client = ret;
    ret->server = sh;
    ret->watcher_client = w_client;
    ret->signal_close = false;
    ret->_ready_to_read=true;
    ret->_ready_to_write=false;
    ret->_inheritor = inh;
    pthread_mutex_init(&inh->mutex_on_client, NULL);

    pthread_mutex_lock(&udp_server->mutex_on_list);    
    HASH_ADD_INT( udp_server->clients, host_key, inh);
    pthread_mutex_unlock(&udp_server->mutex_on_list);
    if(sh->client_new_callback)
        sh->client_new_callback(ret,NULL); // Init internal structure


    return ret;
}

/**
 * @brief udp_client_get_address Get host address and port of client
 * @param client Pointer to client structure
 * @param host Variable for host address
 * @param host Variable for port
 */
void dap_udp_client_get_address(dap_client_remote_t *client, unsigned long* host,unsigned short* port){
    dap_udp_client_t* udp_client = DAP_UDP_CLIENT(client);    
    *host = udp_client->host_key >> 32;
    *port = udp_client->host_key - (*host<<32);
}

/**
 * @brief udp_client_find Find client structure by host address and port
 * @param sh Server instance
 * @param host Source host address
 * @param port Source port
 * @return Pointer to client or NULL if not found
 */
dap_client_remote_t * dap_udp_client_find(dap_server_t * sh, unsigned long host,unsigned short port)
{
    dap_udp_server_t* udp_server = DAP_UDP_SERVER(sh);
    pthread_mutex_lock(&udp_server->mutex_on_list);
    dap_udp_client_t* inh = NULL;

    uint64_t token = get_key(host,port);
    HASH_FIND_INT(udp_server->clients,&token,inh);
    
    pthread_mutex_unlock(&udp_server->mutex_on_list);
    if(inh == NULL)
        return NULL;
    else
        return inh->client;
}

/**
 * @brief udp_client_ready_to_read Set ready_to_read flag
 * @param sc Client structure
 * @param is_ready Flag value
 */
void dap_udp_client_ready_to_read(dap_client_remote_t * sc,bool is_ready)
{
    if(is_ready != sc->_ready_to_read) {

        uint32_t events = 0;
        sc->_ready_to_read=is_ready;

        if(sc->_ready_to_read)
        {
            events |= EV_READ;
        }

        if(sc->_ready_to_write)
            events |= EV_WRITE;

        ev_io_set(sc->watcher_client, sc->server->socket_listener, events );
    }
}

/**
 * @brief udp_client_ready_to_write Set ready_to_write flag
 * @param sc Client structure
 * @param is_ready Flag value
 */
void dap_udp_client_ready_to_write(dap_client_remote_t * sc,bool is_ready)
{
   // if(is_ready)
   //     add_waiting_client(sc); // Add client to writing queue
    if(is_ready != sc->_ready_to_write) {
        uint32_t events = 0;
        sc->_ready_to_write=is_ready;

        if(sc->_ready_to_read)
            events |= EV_READ;

        if(sc->_ready_to_write)
        {
            events |= EV_WRITE;
        }
        int descriptor = sc->watcher_client->fd;
        ev_io_set(sc->watcher_client, descriptor, events );
    }
}

/**
 * @brief add_waiting_client Add Client to write queue
 * @param client Client instance
 */
void add_waiting_client(dap_client_remote_t* client){
    dap_server_t* sh = client->server;
    dap_udp_server_t* udp_server = DAP_UDP_SERVER(sh);
    dap_udp_client_t* udp_client = DAP_UDP_CLIENT(client);

    pthread_mutex_lock(&udp_server->mutex_on_list);
    dap_udp_client_t* udp_cl, *tmp;
    LL_FOREACH_SAFE(udp_server->waiting_clients,udp_cl,tmp)
        if(udp_cl == udp_client)
        {
            pthread_mutex_unlock(&udp_server->mutex_on_list);
            return;
        }
    LL_APPEND(udp_server->waiting_clients, udp_client);
    pthread_mutex_unlock(&udp_server->mutex_on_list);

}

size_t dap_udp_client_write(dap_client_remote_t *sc, const void * data, size_t data_size){
    size_t size = dap_client_write(sc,data,data_size);
    add_waiting_client(sc);
    return size;
}

size_t dap_udp_client_write_f(dap_client_remote_t *a_client, const char * a_format,...){
    size_t size = 0;
    va_list ap;
    va_start(ap,a_format);
    size =dap_client_write_f(a_client,a_format,ap);
    va_end(ap);
    add_waiting_client(a_client);
    return size;
}

