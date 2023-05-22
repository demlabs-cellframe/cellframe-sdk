/*
* Authors:
* Dmitrii Gerasimov <naeper@demlabs.net>
* DeM Labs Inc.   https://demlabs.net
* Cellframe https://cellframe.net
* Copyright  (c) 2017-2020
* All rights reserved.

This file is part of DAP the open source project.

DAP is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

DAP is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

See more details here <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifndef _WIN32
#include <sys/queue.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif

#include <pthread.h>

#include "utlist.h"
#include "json.h"

#include "dap_common.h"
#include "dap_config.h"
#include "dap_worker.h"
#include "dap_events.h"
#include "dap_proc_thread.h"
#include "dap_http.h"
#include "dap_http_client.h"
#include "dap_http_simple.h"
#include "dap_enc_key.h"
#include "dap_http_user_agent.h"


#include "../enc_server/include/dap_enc_ks.h"
#include "../enc_server/include/dap_enc_http.h"

#include "http_status_code.h"

#define LOG_TAG "dap_http_simple"

static void s_http_client_new( dap_http_client_t *a_http_client, void *arg );
static void s_http_client_delete( dap_http_client_t *a_http_client, void *arg );
static void s_http_simple_delete( dap_http_simple_t *a_http_simple);

static void s_http_client_headers_read( dap_http_client_t *cl_ht, void *arg );
static void s_http_client_data_read( dap_http_client_t * cl_ht, void *arg );
static void s_http_client_data_write( dap_http_client_t * a_http_client, void *a_arg );
static bool s_proc_queue_callback(dap_proc_thread_t * a_thread, void *a_arg );

typedef struct dap_http_simple_url_proc {

  dap_http_simple_callback_t proc_callback;
  size_t reply_size_max;

} dap_http_simple_url_proc_t;

//typedef struct tailq_entry {

//  dap_http_simple_t *cl_sh;
//  TAILQ_ENTRY(tailq_entry) entries;

//} tailq_entry_t;

//TAILQ_HEAD(, tailq_entry) tailq_head;

///DAP_HTTP_SIMPLE_REQUEST_MAX

typedef struct user_agents_item {
  dap_http_user_agent_ptr_t user_agent;
  /* This is instead of "struct foo *next" */
  struct user_agents_item *next;
} user_agents_item_t;

static user_agents_item_t *user_agents_list = NULL;
static int is_unknown_user_agents_pass = 0;

#define DAP_HTTP_SIMPLE_URL_PROC(a) ((dap_http_simple_url_proc_t*) (a)->_inheritor)

static void _free_user_agents_list( void );

int dap_http_simple_module_init( )
{
    return 0;
}

void dap_http_simple_module_deinit( void )
{
    _free_user_agents_list( );
}

/**
 * @brief dap_http_simple_proc_add Add simple HTTP processor
 * @param a_http HTTP server instance
 * @param a_url_path URL path
 * @param a_reply_size_max Maximum reply size
 * @param a_callback Callback for data processing
 */
struct dap_http_url_proc * dap_http_simple_proc_add( dap_http_t *a_http, const char *a_url_path, size_t a_reply_size_max, dap_http_simple_callback_t a_callback )
{
    dap_http_simple_url_proc_t *l_url_proc = DAP_NEW_Z( dap_http_simple_url_proc_t );

    l_url_proc->proc_callback = a_callback;
    l_url_proc->reply_size_max = a_reply_size_max;

    return dap_http_add_proc( a_http, a_url_path,
                     l_url_proc, // Internal structure
                     NULL, // Contrustor
                     s_http_client_delete, //  Destructor
                     s_http_client_headers_read, NULL, // Headers read, write
                     s_http_client_data_read, s_http_client_data_write, // Data read, write
                     NULL); // errror
}

static void _free_user_agents_list()
{
  user_agents_item_t *elt, *tmp;
  LL_FOREACH_SAFE( user_agents_list, elt, tmp ) {
    LL_DELETE( user_agents_list, elt );
    dap_http_user_agent_delete( elt->user_agent );
    free( elt );
  }
}

static int s_is_user_agent_supported( const char *user_agent )
{
  int result = is_unknown_user_agents_pass;
  dap_http_user_agent_ptr_t find_agent = dap_http_user_agent_new_from_str( user_agent );

  if ( find_agent == NULL )
    return result;

  const char* find_agent_name = dap_http_user_agent_get_name( find_agent );

  user_agents_item_t *elt;
  LL_FOREACH( user_agents_list, elt ) {

    const char* user_agent_name = dap_http_user_agent_get_name( elt->user_agent );

    if ( strcmp(find_agent_name, user_agent_name) == 0) {
      if(dap_http_user_agent_versions_compare(find_agent, elt->user_agent) >= 0) {
        result = true;
        goto END;
      }
      else {
        result = false;
        goto END;
      }
    }
  }

END:
  dap_http_user_agent_delete( find_agent );
  return result;
}


int dap_http_simple_set_supported_user_agents( const char *user_agents, ... )
{
  va_list argptr;
  va_start( argptr, user_agents );

  const char* str = user_agents;

//  log_it(L_DEBUG,"dap_http_simple_set_supported_user_agents");
//  Sleep(300);

  while ( str != NULL )
  {
    dap_http_user_agent_ptr_t user_agent = dap_http_user_agent_new_from_str( str );

    if ( user_agent == NULL ) {
      log_it(L_ERROR, "Can't parse user agent string");
      va_end(argptr);
       _free_user_agents_list();
       return 0;
    }

    user_agents_item_t *item = calloc( 1, sizeof (user_agents_item_t) );

    item->user_agent = user_agent;
    LL_APPEND( user_agents_list, item );

    str = va_arg( argptr, const char * );
  }

  va_end( argptr );

  return 1;
}

// if this function was called. We checking version only supported user-agents
// other will pass automatically ( and request with without user-agents field too )
void dap_http_simple_set_pass_unknown_user_agents(int pass)
{
    is_unknown_user_agents_pass = pass;
}

inline static bool s_is_supported_user_agents_list_setted()
{
  user_agents_item_t * tmp;
  int cnt = 0;
  LL_COUNT(user_agents_list, tmp, cnt);

  return cnt;
}

static void s_esocket_worker_write_callback(dap_worker_t *a_worker, void *a_arg) {
    dap_http_simple_t *l_http_simple = (dap_http_simple_t*)a_arg;
    dap_events_socket_t *l_es = dap_worker_esocket_find_uuid(a_worker, l_http_simple->http_client_uuid);
    if (!l_es) {
        debug_if(g_debug_reactor, L_INFO, "Esocket 0x%"DAP_UINT64_FORMAT_x" is already deleted", l_http_simple->http_client_uuid);
        dap_http_client_t *l_http_client = l_http_simple->http_client;
        if (l_http_client) {
            debug_if(g_debug_reactor, L_INFO, "l_ht_client:%p", l_http_simple);


            while (l_http_client->in_headers)
                dap_http_header_remove(&l_http_client->in_headers, l_http_client->in_headers);
            while (l_http_client->out_headers)
                dap_http_header_remove(&l_http_client->out_headers, l_http_client->out_headers);

            DAP_DELETE(l_http_client);
        }

        DAP_DEL_Z(l_http_simple->request);
        DAP_DEL_Z(l_http_simple->reply);
        DAP_DELETE(l_http_simple);
        return;
    }
    l_es->_inheritor = l_http_simple->http_client; // Back to the owner
    dap_http_client_write(l_es, NULL);
}

inline static void s_write_data_to_socket(dap_proc_thread_t *a_thread, dap_http_simple_t * a_simple) {
    dap_http_client_out_header_generate(a_simple->http_client);
    a_simple->http_client->state_write = DAP_HTTP_CLIENT_STATE_START;
    dap_proc_thread_worker_exec_callback(a_thread, a_simple->worker->id, s_esocket_worker_write_callback, a_simple);
}

static void s_copy_reply_and_mime_to_response( dap_http_simple_t *a_simple )
{
  if( !a_simple->reply_size )
    return  log_it( L_WARNING, " cl_sh->reply_size equal 0" );

  a_simple->http_client->out_content_length = a_simple->reply_size;
  strcpy( a_simple->http_client->out_content_type, a_simple->reply_mime );
  return;
}

inline static void s_write_response_bad_request( dap_http_simple_t * a_http_simple,
                                               const char* error_msg )
{
//  log_it(L_DEBUG,"_write_response_bad_request");
//  Sleep(300);

  struct json_object *jobj = json_object_new_object( );
  json_object_object_add( jobj, "error", json_object_new_string(error_msg) );

  log_it( L_DEBUG, "error message %s",  json_object_to_json_string(jobj) );
  a_http_simple->http_client->reply_status_code = Http_Status_BadRequest;

  const char* json_str = json_object_to_json_string( jobj );
  dap_http_simple_reply(a_http_simple, (void*) json_str,
                          (size_t) strlen(json_str) );

  strcpy( a_http_simple->reply_mime, "application/json" );

  s_copy_reply_and_mime_to_response( a_http_simple );

  json_object_put( jobj ); // free obj
}

/**
 * @brief dap_http_simple_proc Execute procession callback and switch to write state
 * @param cl_sh HTTP simple client instance
 */
static bool s_proc_queue_callback(dap_proc_thread_t *a_thread, void *a_arg) {
    (void) a_thread;
    log_it(L_DEBUG, "dap http simple proc");
    dap_http_simple_t *l_http_simple = (dap_http_simple_t*)a_arg;
    http_status_code_t return_code = (http_status_code_t)0;
    if(s_is_supported_user_agents_list_setted() == true) {
        dap_http_header_t *header = dap_http_header_find(l_http_simple->http_client->in_headers, "User-Agent");
        if (!header && !is_unknown_user_agents_pass) {
            const char error_msg[] = "Not found User-Agent HTTP header";
            s_write_response_bad_request(l_http_simple, error_msg);
            s_write_data_to_socket(a_thread, l_http_simple);
            return true;
        }

        if(header)
            if(s_is_user_agent_supported(header->value) == false) {
                log_it(L_DEBUG, "Not supported user agent in request: %s", header->value);
                const char* error_msg = "User-Agent version not supported. Update your software";
                s_write_response_bad_request(l_http_simple, error_msg);
                s_write_data_to_socket(a_thread, l_http_simple);
                return true;
            }
    }

    DAP_HTTP_SIMPLE_URL_PROC(l_http_simple->http_client->proc)->proc_callback(l_http_simple, &return_code);

    if(return_code) {
        log_it(L_DEBUG, "Request was processed well return_code=%d", return_code);
        l_http_simple->http_client->reply_status_code = (uint16_t)return_code;
        s_copy_reply_and_mime_to_response(l_http_simple);
    } else {
        log_it(L_ERROR, "Request was processed with ERROR");
        l_http_simple->http_client->reply_status_code = Http_Status_InternalServerError;
    }
    s_write_data_to_socket(a_thread, l_http_simple);
    return true;
}

static void s_http_client_delete( dap_http_client_t *a_http_client, void *arg )
{
    dap_http_simple_t * l_http_simple = DAP_HTTP_SIMPLE(a_http_client);
    if (l_http_simple) {
        DAP_DEL_Z(l_http_simple->request);
        DAP_DEL_Z(l_http_simple->reply);
    }
}

static void s_http_client_headers_read( dap_http_client_t *a_http_client, void *a_arg )
{
    (void) a_arg;
    a_http_client->_inheritor = DAP_NEW_Z(dap_http_simple_t);
    dap_http_simple_t *l_http_simple = DAP_HTTP_SIMPLE(a_http_client);


    l_http_simple->esocket = a_http_client->esocket;
    l_http_simple->http_client_uuid = a_http_client->esocket->uuid;
    l_http_simple->http_client = a_http_client;
    l_http_simple->worker = a_http_client->esocket->worker;
    l_http_simple->reply_size_max = DAP_HTTP_SIMPLE_URL_PROC( a_http_client->proc )->reply_size_max;
    l_http_simple->reply = DAP_NEW_Z_SIZE(uint8_t, l_http_simple->reply_size_max );

//    Made a temporary solution to handle simple CORS requests.
//    This is necessary in order to be able to request information using JavaScript obtained from another source.
    dap_http_header_t* l_header_origin = dap_http_header_find(a_http_client->in_headers, "Origin");
    if (l_header_origin){
        dap_http_header_add(&a_http_client->out_headers, "Access-Control-Allow-Origin", -1, "*", -1);
    }


    if( a_http_client->in_content_length ) {
        // dbg if( a_http_client->in_content_length < 3){
        if( a_http_client->in_content_length > 0){
            l_http_simple->request_size_max = a_http_client->in_content_length + 1;
            l_http_simple->request = DAP_NEW_Z_SIZE(void, l_http_simple->request_size_max);
            if(!l_http_simple->request){
                l_http_simple->request_size_max = 0;
                log_it(L_ERROR, "Too big content-length %zu in request", a_http_client->in_content_length);
            }
        }
        else
            log_it(L_ERROR, "Not defined content-length %zu in request", a_http_client->in_content_length);
    } else {
        log_it( L_DEBUG, "No data section, execution proc callback" );
        dap_events_socket_set_readable_unsafe(a_http_client->esocket, false);
        //DAP_HTTP_SIMPLE(a_http_client)->http_client_uuid = a_http_client->esocket->uuid;
        a_http_client->esocket->_inheritor = NULL;
        dap_proc_queue_add_callback_inter_ext( l_http_simple->worker->proc_queue_input, s_proc_queue_callback, l_http_simple, DAP_QUE$K_PRI_HIGH);
    }
}

static void s_http_client_data_write(dap_http_client_t * a_http_client, void *a_arg)
{
    (void) a_arg;
    dap_http_simple_t *l_http_simple = DAP_HTTP_SIMPLE( a_http_client );
    if ( l_http_simple->reply_sent >= a_http_client->out_content_length ) {
        log_it(L_INFO, "All the reply (%zu) is sent out", a_http_client->out_content_length );
        a_http_client->esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
    } else {
        l_http_simple->reply_sent += dap_events_socket_write_unsafe( a_http_client->esocket,
                                                  l_http_simple->reply + l_http_simple->reply_sent,
                                                  a_http_client->out_content_length - l_http_simple->reply_sent);
    }
}

void s_http_client_data_read( dap_http_client_t *a_http_client, void * a_arg )
{
    int *ret = (int *)a_arg;

    //log_it(L_DEBUG,"dap_http_simple_data_read");
    //  Sleep(300);

    dap_http_simple_t *l_http_simple = DAP_HTTP_SIMPLE(a_http_client);
    if(!l_http_simple){
        a_http_client->esocket->buf_in = 0;
        a_http_client->esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
        log_it( L_WARNING, "No http_simple object in read callback, close connection" );
        return;
    }

    size_t bytes_to_read = (a_http_client->esocket->buf_in_size + l_http_simple->request_size) < a_http_client->in_content_length ?
                            a_http_client->esocket->buf_in_size : ( a_http_client->in_content_length - l_http_simple->request_size );

    if( bytes_to_read ) {
        // Oops! The client sent more data than write in the CONTENT_LENGTH header
        if(l_http_simple->request_size + bytes_to_read > l_http_simple->request_size_max){
            log_it(L_WARNING, "Oops! Client sent more data length=%zu than in content-length=%zu in request", l_http_simple->request_size + bytes_to_read, a_http_client->in_content_length);
            l_http_simple->request_size_max = l_http_simple->request_size + bytes_to_read + 1;
            // increase input buffer
            l_http_simple->request = DAP_REALLOC(l_http_simple->request, l_http_simple->request_size_max);
        }
        if(l_http_simple->request){// request_byte=request
            memcpy( l_http_simple->request + l_http_simple->request_size, a_http_client->esocket->buf_in, bytes_to_read );
            l_http_simple->request_size += bytes_to_read;
        }
    }
    *ret = (int) a_http_client->esocket->buf_in_size;
    if( l_http_simple->request_size >= a_http_client->in_content_length ) {

        // bool isOK=true;
        log_it( L_INFO,"Data for http_simple_request collected" );
        dap_events_socket_set_readable_unsafe(a_http_client->esocket, false);
        //DAP_HTTP_SIMPLE(a_http_client)->http_client_uuid = a_http_client->esocket->uuid;
        a_http_client->esocket->_inheritor = NULL;
        dap_proc_queue_add_callback_inter_ext( l_http_simple->worker->proc_queue_input , s_proc_queue_callback, l_http_simple, DAP_QUE$K_PRI_HIGH);
    }
}


/**
 * @brief dap_http_simple_reply Add data to the reply buffer
 * @param shs HTTP simple client instance
 * @param data
 * @param data_size
 */
size_t dap_http_simple_reply(dap_http_simple_t *a_http_simple, void *a_data, size_t a_data_size )
{
size_t l_data_copy_size;

    if ( !a_http_simple->reply )
        return  log_it(L_ERROR, "HTTP's Simple reply buffer is NULL"), 0;

    l_data_copy_size = MIN ( (a_http_simple->reply_size_max - a_http_simple->reply_size),  a_data_size);

    if ( !l_data_copy_size )
        return  log_it(L_ERROR, "No free space in the HTTP's Simple reply buffer"), 0;

    memcpy(a_http_simple->reply + a_http_simple->reply_size, a_data, l_data_copy_size );

    a_http_simple->reply_size += l_data_copy_size;

    return l_data_copy_size;
}

/**
 * @brief dap_http_simple_make_cache_from_reply
 * @param a_http_simple
 * @param a_ts_expire
 */
dap_http_cache_t * dap_http_simple_make_cache_from_reply(dap_http_simple_t * a_http_simple, time_t a_ts_expire  )
{
    // Because we call it from callback, we have no headers ready for output
    s_copy_reply_and_mime_to_response(a_http_simple);
    a_http_simple->http_client->reply_status_code = 200;
    dap_http_client_out_header_generate(a_http_simple->http_client);
    return dap_http_cache_update(a_http_simple->http_client->proc,
                                 a_http_simple->reply,
                                 a_http_simple->reply_size,
                                 a_http_simple->http_client->out_headers,NULL,
                                  200, a_ts_expire);
}

/**
 * @brief dap_http_simple_reply_f
 * @param shs
 * @param data
 */
size_t dap_http_simple_reply_f(dap_http_simple_t * shs, const char * data, ... )
{
  char buf[4096];
  va_list va;
  int vret;

  va_start(va,data);
  vret = dap_vsnprintf( buf, sizeof(buf) - 1, data, va );
  va_end(va);

  if ( vret > 0 )
    return dap_http_simple_reply( shs, buf, vret );
  else
    return 0;
}


/* Key Expired deprecated code */

//    bool key_is_expiried = false;

//    dap_enc_key_t * key = dap_enc_ks_find_http(cl_sh->http);
//    if(key){
//        if( key->last_used_timestamp && ( (time(NULL) - key->last_used_timestamp  )
//                                          > s_TTL_session_key ) ) {

//            enc_http_delegate_t * dg = enc_http_request_decode(cl_sh);

//            if( dg == NULL ) {
//                log_it(L_ERROR, "dg is NULL");
//                return NULL;
//            }

//            log_it(L_WARNING, "Key has been expiried");
//            strcpy(cl_sh->reply_mime,"text/plain");
//            enc_http_reply_f(dg,"Key has been expiried");
//            enc_http_reply_encode(cl_sh,dg);
//            enc_http_delegate_delete(dg);
//            key_is_expiried = true;
//        } else{
//            key->last_used_timestamp = time(NULL);
//        }
//    }
