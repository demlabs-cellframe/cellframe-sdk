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
#include "dap_client_remote.h"
#include "dap_http.h"
#include "dap_http_header.h"
#include "dap_http_client.h"

#define LOG_TAG "dap_http"


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
 * @brief dap_server_http_init Init HTTP server
 * @param sh Server instance
 * @return 0 if ok lesser number if error
 */
int dap_http_new( dap_server_t *sh, const char * server_name )
{
  sh->_inheritor = calloc( 1, sizeof(dap_http_t) );

  dap_http_t *shttp = DAP_HTTP( sh );

  shttp->server = sh;
  strncpy( shttp->server_name, server_name, sizeof(shttp->server_name)-1 );

  sh->client_new_callback    = dap_http_client_new;
  sh->client_delete_callback = dap_http_client_delete;
  sh->client_read_callback   = dap_http_client_read;
  sh->client_write_callback  = dap_http_client_write;
  sh->client_error_callback  = dap_http_client_error;

  return 0;
}

/**
 * @brief dap_http_delete Clear dap_http structure in the internal data field of dap_server_t instance
 * @param sh Server's instance
 * @param arg Non-used argument
 */
void dap_http_delete( dap_server_t *sh, void * arg )
{
  (void) arg;
  (void) sh;
  dap_http_t *shttp = DAP_HTTP( sh );
  dap_http_url_proc_t *up, *tmp;

  HASH_ITER( hh, shttp->url_proc ,up, tmp ) {
    HASH_DEL(shttp->url_proc, up);
    if( up->_inheritor )
      free( up->_inheritor );
    free( up );
  }
}


/**
 * @brief dap_http_add_proc  Add custom procesor for the HTTP server
 * @param sh                Server's instance
 * @param url_path          Part of URL to be processed
 * @param read_callback     Callback for read in DATA state
 * @param write_callback    Callback for write in DATA state
 * @param error_callback    Callback for error processing
 */
void dap_http_add_proc(dap_http_t *sh, const char *url_path, void *internal
                      ,dap_http_client_callback_t new_callback
                      ,dap_http_client_callback_t delete_callback
                      ,dap_http_client_callback_t headers_read_callback
                      ,dap_http_client_callback_t headers_write_callback
                      ,dap_http_client_callback_t data_read_callback
                      ,dap_http_client_callback_t data_write_callback
                      ,dap_http_client_callback_t error_callback

                      )
{
  dap_http_url_proc_t *up = (dap_http_url_proc_t *) calloc( 1, sizeof(dap_http_url_proc_t) );

  strncpy( up->url, url_path, sizeof(up->url)-1 );

  up->new_callback    = new_callback;
  up->delete_callback = delete_callback;

  up->data_read_callback = data_read_callback;
  up->data_write_callback = data_write_callback;
  up->headers_read_callback = headers_read_callback;
  up->headers_write_callback = headers_write_callback;
  up->error_callback = error_callback;

  up->_inheritor = internal;

  HASH_ADD_STR( sh->url_proc, url, up );

  log_it( L_DEBUG, "Added URL processor for '%s' path", up->url );
}


