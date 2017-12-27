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

#include <sys/epoll.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include "common.h"
#include "dap_loop.h"
#include "dap_client.h"
#include <ev.h>
#define LOG_TAG "client"


/**
 * @brief dap_client_init Init clients module
 * @return Zero if ok others if no
 */
int dap_client_init()
{
    log_it(NOTICE,"Initialized socket client module");
    return 0;
}

/**
 * @brief dap_client_deinit Deinit clients module
 */
void dap_client_deinit()
{

}

/**
 * @brief safe_client_create Create new client and add it to the list
 * @param sh Server instance
 * @param s Client's socket
 * @return Pointer to the new list's node
 */
dap_client_t * dap_client_create(dap_server_t * sh, int s, ev_io* w_client)
{
    pthread_mutex_lock(&sh->mutex_on_hash);
    log_it(DEBUG,"Client structure create");

    dap_client_t * ret=(dap_client_t *) calloc(1,sizeof(dap_client_t));
    ret->socket=s;
    ret->server=sh;
    ret->watcher_client = w_client;
    ret->_ready_to_read=true;

    HASH_ADD_INT( sh->clients, socket, ret);

    if(sh->client_new_callback)
        sh->client_new_callback(ret,NULL); // Init internal structure

    pthread_mutex_unlock(&sh->mutex_on_hash);
    return ret;
}

/**
 * @brief dap_client_find
 * @param sock
 * @param sh
 * @return
 */
dap_client_t * dap_client_find(int sock, struct dap_server * sh)
{
    pthread_mutex_lock(&sh->mutex_on_hash);
    dap_client_t * ret=NULL;
    HASH_FIND_INT(sh->clients,&sock,ret);
    pthread_mutex_unlock(&sh->mutex_on_hash);
    return ret;
}

/**
 * @brief dap_client_ready_to_read
 * @param sc
 * @param isReady
 */
void dap_client_ready_to_read(dap_client_t * sc,bool is_ready)
{
    if(is_ready != sc->_ready_to_read) {

        uint32_t events = 0;
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
void dap_client_ready_to_write(dap_client_t * sc,bool is_ready)
{
    if(is_ready != sc->_ready_to_write) {

        uint32_t events = 0;
        sc->_ready_to_write=is_ready;

        if(sc->_ready_to_read)
            events |= EV_READ;

        if(sc->_ready_to_write)
            events |= EV_WRITE;

        ev_io_set(sc->watcher_client, sc->socket, events );
    }

}


/**
 * @brief safe_client_remove Removes the client from the list
 * @param sc Client instance
 */
void dap_client_remove(dap_client_t *sc, struct dap_server * sh)
{
    pthread_mutex_lock(&sh->mutex_on_hash);

    log_it(DEBUG, "Client structure remove");
    HASH_DEL(sc->server->clients,sc);

    if(sc->server->client_delete_callback)
        sc->server->client_delete_callback(sc,NULL); // Init internal structure
    if(sc->internal)
        free(sc->internal);

    if(sc->socket)
        close(sc->socket);
    free(sc);
    pthread_mutex_unlock(&sh->mutex_on_hash);
}

/**
 * @brief dap_client_write Write data to the client
 * @param sc Client instance
 * @param data Pointer to data
 * @param data_size Size of data to write
 * @return Number of bytes that were placed into the buffer
 */
size_t dap_client_write(dap_client_t *sc, const void * data, size_t data_size)
{
     data_size = ((sc->buf_out_size+data_size)<(sizeof(sc->buf_out)))?data_size:(sizeof(sc->buf_out)-sc->buf_out_size );
     memcpy(sc->buf_out+sc->buf_out_size,data,data_size);
     sc->buf_out_size+=data_size;
     return data_size;
}

/**
 * @brief dap_client_write_f Write formatted text to the client
 * @param sc Client instance
 * @param format Format
 * @return Number of bytes that were placed into the buffer
 */
size_t dap_client_write_f(dap_client_t *sc, const char * format,...)
{
    size_t max_data_size = sizeof(sc->buf_out)-sc->buf_out_size;
    va_list ap;
    va_start(ap,format);
    int ret=vsnprintf(sc->buf_out+sc->buf_out_size,max_data_size,format,ap);
    va_end(ap);
    if(ret>0){
        sc->buf_out_size+=ret;
        return ret;
    }else{
        log_it(ERROR,"Can't write out formatted data '%s'",format);
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
size_t dap_client_read(dap_client_t *sc, void * data, size_t data_size)
{
	
	printf("Size of package: %d\n", (int)data_size);
	// дамп пакета
	hexdump(data, data_size);

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
void dap_client_shrink_buf_in(dap_client_t * cl, size_t shrink_size)
{
    if((shrink_size==0)||(cl->buf_in_size==0) ){
        //log_it(WARNING, "DBG_#003");
        return;
    }else if(cl->buf_in_size>shrink_size){
        size_t buf_size=cl->buf_in_size-shrink_size;
        void * buf = malloc(buf_size);
        memcpy(buf,cl->buf_in+ shrink_size,buf_size );
        memcpy(cl->buf_in,buf,buf_size);
        cl->buf_in_size=buf_size;
        //log_it(WARNING, "DBG_#004");
        free(buf);
    }else {
        //log_it(WARNING, "DBG_#005");
        cl->buf_in_size=0;
    }

}
