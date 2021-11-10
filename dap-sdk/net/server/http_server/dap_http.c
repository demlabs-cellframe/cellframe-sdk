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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <time.h>
#endif

#include <pthread.h>

#include "dap_common.h"
#include "dap_server.h"
#include "dap_events_socket.h"
#include "dap_http.h"
#include "dap_http_header.h"
#include "dap_http_client.h"

#define LOG_TAG "http"


/**
 * @brief dap_http_init // Init HTTP module
 * @return Zero if ok others if not
 */
int dap_http_init( )
{
    if ( dap_http_header_init() != 0 ) { // Init submodule for headers manipulations
        log_it(L_CRITICAL,"Can't init HTTP headers processing submodule");
        return -1;
    }

    if ( dap_http_client_init() !=0 ) { // Init submodule for HTTP client event processing
        log_it(L_CRITICAL,"Can't init HTTP client submodule");
        return -2;
    }

    log_it( L_NOTICE, "Initialized HTTP server module" );
    return 0;
}

/**
 * @brief dap_http_deinit Deinit HTTP module
 */
void dap_http_deinit()
{
    dap_http_header_deinit( );
    dap_http_client_deinit( );
}


/**
 * @brief dap_server_http_init   Init HTTP server
 * @param a_server               Server instance
 * @param a_server_name          Server name
 * @return 0 if ok lesser number if error
 */
int dap_http_new( dap_server_t *a_server, const char * a_server_name )
{
    a_server->_inheritor = DAP_NEW_Z(dap_http_t);

    dap_http_t *l_http = DAP_HTTP( a_server );

    l_http->server = a_server;
    strncpy( l_http->server_name, a_server_name, sizeof(l_http->server_name)-1 );

    a_server->client_callbacks.new_callback    = dap_http_client_new;
    a_server->client_callbacks.delete_callback = dap_http_client_delete;
    a_server->client_callbacks.read_callback   = dap_http_client_read;
    a_server->client_callbacks.write_callback  = dap_http_client_write;
    a_server->client_callbacks.error_callback  = dap_http_client_error;

    return 0;
}

/**
 * @brief dap_http_delete Clear dap_http structure in the internal data field of dap_server_t instance
 * @param sh Server's instance
 * @param arg Non-used argument
 */
void dap_http_delete( dap_server_t *a_server, void * a_arg )
{
    (void) a_arg;
    dap_http_t *l_http = DAP_HTTP( a_server );
    dap_http_url_proc_t *l_url_proc, *l_tmp;

    HASH_ITER( hh, l_http->url_proc ,l_url_proc, l_tmp ) {
        HASH_DEL(l_http->url_proc, l_url_proc);
        if( l_url_proc->_inheritor )
            DAP_DELETE(l_url_proc->_inheritor );
        DAP_DELETE(l_url_proc );
    }
}


/**
 * @brief dap_http_add_proc             Add custom procesor for the HTTP server
 * 
 * @param a_http                        Server's instance
 * @param a_url_path                    Part of URL to be processed
 * @param a_inheritor                   Internal data specific to the current URL processor
 * @param a_new_callback                additional callback function
 * 
 * Called in s_queue_add_es_callback    
 * if ( ! l_es_new->is_initalized ){
        if (l_es_new->callbacks.new_callback)
            l_es_new->callbacks.new_callback(l_es_new, NULL);
        l_es_new->is_initalized = true;
    }
 * @param a_delete_callback             callback which is called, when HTTP server object is deleted
 * @param a_headers_read_callback       Callback for read HTTP headers callback
 * @param a_headers_write_callback      Callback for write HTTP headers callback
 * @param a_data_read_callback          Callback for read in DATA state
 * @param a_data_write_callback         Callback for write in DATA state
 * @param a_error_callback              Callback for error processing
 * @note 
 * data_read_callback is called, when headers is finished in body request, and next part of 
 * body request contains remaining part of buffer. If data contains only in header, a_data_read_callback is not called.
 * @return dap_http_url_proc_t* 
 */
dap_http_url_proc_t * dap_http_add_proc(dap_http_t *a_http, const char *a_url_path, void *a_inheritor
                      ,dap_http_client_callback_t a_new_callback
                      ,dap_http_client_callback_t a_delete_callback
                      ,dap_http_client_callback_t a_headers_read_callback
                      ,dap_http_client_callback_t a_headers_write_callback
                      ,dap_http_client_callback_t a_data_read_callback
                      ,dap_http_client_callback_t a_data_write_callback
                      ,dap_http_client_callback_error_t a_error_callback

                      )
{
    dap_http_url_proc_t *l_url_proc = DAP_NEW_Z(dap_http_url_proc_t);

    strncpy( l_url_proc->url, a_url_path, sizeof(l_url_proc->url)-1 );

    l_url_proc->new_callback    = a_new_callback;
    l_url_proc->delete_callback = a_delete_callback;

    l_url_proc->data_read_callback = a_data_read_callback;
    l_url_proc->data_write_callback = a_data_write_callback;
    l_url_proc->headers_read_callback = a_headers_read_callback;
    l_url_proc->headers_write_callback = a_headers_write_callback;
    l_url_proc->error_callback = a_error_callback;

    l_url_proc->_inheritor = a_inheritor;
    pthread_rwlock_init(& l_url_proc->cache_rwlock, NULL);

    HASH_ADD_STR( a_http->url_proc, url, l_url_proc );

    log_it( L_DEBUG, "Added URL processor for '%s' path", l_url_proc->url );
    return l_url_proc;
}

