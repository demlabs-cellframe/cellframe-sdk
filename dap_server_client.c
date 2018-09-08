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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ev.h>
#include <arpa/inet.h>

#include "dap_common.h"
#include "dap_server_client.h"
#include "dap_server.h"


#define LOG_TAG "dap_client_remote"

/**
 * @brief dap_client_init Init clients module
 * @return Zero if ok others if no
 */
int dap_server_client_init()
{
    log_it(L_NOTICE,"Initialized socket client module");
    return 0;
}

/**
 * @brief dap_client_deinit Deinit clients module
 */
void dap_server_client_deinit()
{

}

/**
 * @brief _save_ip_and_port
 * @param cl
 */
void _save_ip_and_port(dap_server_client_t * cl)
{
    struct sockaddr_in ip_adr_get;
    socklen_t ip_adr_len;

    getpeername(cl->socket, &ip_adr_get, &ip_adr_len);

    cl->port = ntohs(ip_adr_get.sin_port);
    strcpy(cl->s_ip, inet_ntoa(ip_adr_get.sin_addr));
}

/**
 * @brief dap_client_remote_create Create new client and add it to the list
 * @param sh Server instance
 * @param s Client's socket
 * @return Pointer to the new list's node
 */
dap_server_client_t * dap_client_create(dap_server_t * sh, int s, ev_io* w_client)
{
    pthread_mutex_lock(&sh->mutex_on_hash);

    dap_server_client_t * dsc = DAP_NEW_Z(dap_server_client_t);
    dap_random_string_fill(dsc->id, CLIENT_ID_SIZE);
    dsc->socket = s;
    dsc->server = sh;
    dsc->watcher_client = w_client;
    dsc->_ready_to_read = true;
    _save_ip_and_port(dsc);

    HASH_ADD_INT(sh->clients, socket, dsc);
    if(sh->client_new_callback)
        sh->client_new_callback(dsc, NULL); // Init internal structure

    pthread_mutex_unlock(&sh->mutex_on_hash);
    log_it(L_DEBUG, "Connected client ip: %s port %d", dsc->s_ip, dsc->port);
    //log_it(L_DEBUG, "Create new client. ID: %s", dsc->id);
    return dsc;
}

/**
 * @brief safe_client_remove Removes the client from the list
 * @param sc Client instance
 */
void dap_client_remove(dap_server_client_t *sc, struct dap_server * sh)
{
    pthread_mutex_lock(&sh->mutex_on_hash);

    log_it(L_DEBUG, "Client structure remove");
    HASH_DEL(sc->server->clients,sc);

    if(sc->server->client_delete_callback)
        sc->server->client_delete_callback(sc,NULL); // Init internal structure
    if(sc->_inheritor)
        free(sc->_inheritor);

    if(sc->socket)
        close(sc->socket);
    free(sc);
    pthread_mutex_unlock(&sh->mutex_on_hash);
}

/**
 * @brief dap_client_find
 * @param sock
 * @param sh
 * @return
 */
dap_server_client_t * dap_client_find(int sock, struct dap_server * sh)
{
    dap_server_client_t * ret = NULL;
    pthread_mutex_lock(&sh->mutex_on_hash);
    HASH_FIND_INT(sh->clients, &sock, ret);
    pthread_mutex_unlock(&sh->mutex_on_hash);
    return ret;
}

/**
 * @brief dap_client_ready_to_read
 * @param sc
 * @param isReady
 */
void dap_client_ready_to_read(dap_server_client_t * sc,bool is_ready)
{
    if(is_ready != sc->_ready_to_read) {
        int events = 0;
        sc->_ready_to_read=is_ready;

        if(sc->_ready_to_read)
            events |= EV_READ;

        if(sc->_ready_to_write)
            events |= EV_WRITE;

        ev_io_set(sc->watcher_client, sc->socket, events );
    }
}

/**
 * @brief dap_client_ready_to_write
 * @param sc
 * @param isReady
 */
void dap_client_ready_to_write(dap_server_client_t * sc,bool is_ready)
{
    if(is_ready != sc->_ready_to_write) {
        int events = 0;
        sc->_ready_to_write=is_ready;

        if(sc->_ready_to_read)
            events |= EV_READ;

        if(sc->_ready_to_write)
            events |= EV_WRITE;

        ev_io_set(sc->watcher_client, sc->socket, events );
    }
}

/**
 * @brief dap_client_write Write data to the client
 * @param sc Client instance
 * @param data Pointer to data
 * @param data_size Size of data to write
 * @return Number of bytes that were placed into the buffer
 */
size_t dap_client_write(dap_server_client_t *sc, const void * data, size_t data_size)
{
     data_size = ((sc->buf_out_size+data_size)<(sizeof(sc->buf_out)))?data_size:(sizeof(sc->buf_out)-sc->buf_out_size );
     memcpy(sc->buf_out+sc->buf_out_size,data,data_size);
     sc->buf_out_size+=data_size;
     return data_size;
}

/**
 * @brief dap_client_write_f Write formatted text to the client
 * @param a_client Client instance
 * @param a_format Format
 * @return Number of bytes that were placed into the buffer
 */
size_t dap_client_write_f(dap_server_client_t *a_client, const char * a_format,...)
{
    size_t max_data_size = sizeof(a_client->buf_out)-a_client->buf_out_size;
    va_list ap;
    va_start(ap,a_format);
    int ret=vsnprintf(a_client->buf_out+a_client->buf_out_size,max_data_size,a_format,ap);
    va_end(ap);
    if(ret>0){
        a_client->buf_out_size += (unsigned long)ret;
        return (size_t)ret;
    }else{
        log_it(L_ERROR,"Can't write out formatted data '%s'",a_format);
        return 0;
    }
}

/**
 * @brief dap_client_read Read data from input buffer
 * @param sc Client instasnce
 * @param data Pointer to memory where to store the data
 * @param data_size Size of data to read
 * @return Actual bytes number that were read
 */
size_t dap_client_read(dap_server_client_t *sc, void * data, size_t data_size)
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
 * @brief shrink_client_buf_in Shrink input buffer (shift it left)
 * @param cl Client instance
 * @param shrink_size Size on wich we shrink the buffer with shifting it left
 */
void dap_client_shrink_buf_in(dap_server_client_t * cl, size_t shrink_size)
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
