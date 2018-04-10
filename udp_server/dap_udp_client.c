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
#include "dap_loop.h"
#include "dap_udp_server.h"

#define LOG_TAG "udp_client"


/**
 * @brief udp_client_init Init clients module
 * @return Zero if ok others if no
 */
int dap_udp_client_init()
{
    log_it(L_NOTICE,"Initialized socket client module");
    return 0;
}

/**
 * @brief udp_client_deinit Deinit clients module
 */
void dap_udp_client_deinit()
{

}

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
dap_udp_client_t * dap_udp_client_create(dap_udp_server_t * sh, ev_io* w_client, unsigned long host, unsigned short port)
{
    pthread_mutex_lock(&sh->mutex_on_hash);
    log_it(L_DEBUG,"Client structure create");

    dap_udp_client_t * ret=DAP_NEW_Z(dap_udp_client_t);
    ret->server = sh;
    ret->watcher_client = w_client;
    ret->signal_close = false;
    ret->host_key = get_key(host,port);   
    ret->_ready_to_read=true;
    ret->_ready_to_write=false;
    
    HASH_ADD_INT( sh->clients, host_key, ret);
    if(sh->client_new_callback)
        sh->client_new_callback(ret,NULL); // Init internal structure

    pthread_mutex_unlock(&sh->mutex_on_hash);
    return ret;
}

/**
 * @brief udp_client_get_address Get host address and port of client
 * @param client Pointer to client structure
 * @param host Variable for host address
 * @param host Variable for port
 */
void dap_udp_client_get_address(dap_udp_client_t *client, unsigned long* host,unsigned short* port){    
    *host = client->host_key >> 32;
    *port = client->host_key - (*host<<32);
}

/**
 * @brief udp_client_find Find client structure by host address and port
 * @param sh Server instance
 * @param host Source host address
 * @param port Source port
 * @return Pointer to client or NULL if not found
 */
dap_udp_client_t * dap_udp_client_find(dap_udp_server_t * sh, unsigned long host,unsigned short port)
{
    pthread_mutex_lock(&sh->mutex_on_hash);

    dap_udp_client_t * ret = NULL;
    uint64_t token = get_key(host,port);
    HASH_FIND_INT(sh->clients,&token,ret);
    
    pthread_mutex_unlock(&sh->mutex_on_hash);
    return ret;
}

/**
 * @brief udp_client_read Read data from input buffer
 * @param sc Client instance
 * @param data Pointer to memory where to store the data
 * @param data_size Size of data to read
 * @return Actual bytes number that were read
 */
size_t dap_udp_client_read(dap_udp_client_t *sc, void * data, size_t data_size)
{
    if (data_size < sc->buf_in_size) {
        memcpy(data, sc->buf_in, data_size);
        memmove(data, sc->buf_in + data_size, sc->buf_in_size - data_size);
    } else {
        if (data_size > sc->buf_in_size) {
            data_size = sc->buf_in_size;
        }
        memcpy(data, sc->buf_in, data_size);
    }
    sc->buf_in_size -= data_size;
    return data_size;
}

/**
 * @brief udp_client_ready_to_read Set ready_to_read flag
 * @param sc Client structure
 * @param is_ready Flag value
 */
void dap_udp_client_ready_to_read(dap_udp_client_t * sc,bool is_ready)
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
void dap_udp_client_ready_to_write(dap_udp_client_t * sc,bool is_ready)
{
    if(is_ready)
        add_waiting_client(sc); // Add client to writing queue
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
 * @brief udp_client_remove Removes the client from the hashmap
 * @param sc Client instance
 * @param sh Server instance
 */
void dap_udp_client_remove(dap_udp_client_t *sc, dap_udp_server_t * sh)
{
    pthread_mutex_lock(&sh->mutex_on_hash);

    log_it(L_DEBUG, "Client structure remove");
    HASH_DEL(sc->server->clients,sc);

    if(sc->server->client_delete_callback)
        sc->server->client_delete_callback(sc,NULL); // Init internal structure
    if(sc->_inheritor)
        free(sc->_inheritor);
    free(sc);
    pthread_mutex_unlock(&sh->mutex_on_hash);
}

/**
 * @brief udp_client_write Write data to the client
 * @param sc Client instance
 * @param data Pointer to data
 * @param data_size Size of data to write
 * @return Number of bytes that were placed into the buffer
 */
size_t dap_udp_client_write(dap_udp_client_t *sc, const void * data, size_t data_size)
{
     data_size = ((sc->buf_out_size+data_size)<(sizeof(sc->buf_out)))?data_size:(sizeof(sc->buf_out)-sc->buf_out_size );
     memcpy(sc->buf_out+sc->buf_out_size,data,data_size);
     sc->buf_out_size+=data_size;
     return data_size;
}

/**
 * @brief udp_client_write_f Write formatted text to the client
 * @param a_client Client instance
 * @param a_format Format
 * @return Number of bytes that were placed into the buffer
 */
size_t dap_udp_client_write_f(dap_udp_client_t *a_client, const char * a_format,...)
{
    size_t max_data_size = sizeof(a_client->buf_out)-a_client->buf_out_size;
    va_list ap;
    va_start(ap,a_format);
    int ret=vsnprintf(a_client->buf_out+a_client->buf_out_size,max_data_size,a_format,ap);
    va_end(ap);
    if(ret>0){
        a_client->buf_out_size+=ret;
        return ret;
    }else{
        log_it(L_ERROR,"Can't write out formatted data '%s'",a_format);
        return 0;
    }
}

/**
 * @brief add_waiting_client Add Client to write queue
 * @param client Client instance
 */
void add_waiting_client(dap_udp_client_t* client){
    dap_udp_server_t* serv = client->server;
    LL_APPEND(serv->waiting_clients, client);
}


/**
 * @brief shrink_client_buf_in Shrink input buffer (shift it left)
 * @param cl Client instance
 * @param shrink_size Size on wich we shrink the buffer with shifting it left
 */
void dap_udp_client_shrink_buf_in(dap_udp_client_t * cl, size_t shrink_size)
{
    if((shrink_size==0)||(cl->buf_in_size==0) ){
        return;
    }else if(cl->buf_in_size>shrink_size){
        size_t buf_size=cl->buf_in_size-shrink_size;
        void * buf = malloc(buf_size);
        memcpy(buf,cl->buf_in+ shrink_size,buf_size );
        memcpy(cl->buf_in,buf,buf_size);
        cl->buf_in_size=buf_size;
        free(buf);
    }else {
        cl->buf_in_size=0;
    }

}

