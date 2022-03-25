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
#include <string.h>
#include <ctype.h>

#ifndef _WIN32
#include <libgen.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif

#include <pthread.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_events_socket.h"

#include "dap_http.h"
#include "http_status_code.h"

#include "dap_http_header.h"
#include "dap_http_client.h"

#define LOG_TAG "dap_http_client"

static bool s_request_line_parse( dap_http_client_t *cl_ht, char *buf, size_t buf_length );
static bool s_debug_http = false;

/**
 * @brief dap_http_client_init Init HTTP client module
 * @return  Zero if ok others if not
 */
int dap_http_client_init( )
{
    log_it(L_NOTICE,"Initialized HTTP client module");
    s_debug_http = dap_config_get_item_bool_default(g_config,"general","debug_http",false);
    return 0;
}

/**
 * @brief dap_http_client_deinit Deinit HTTP client module
 */
void dap_http_client_deinit( )
{
  log_it(L_INFO,"HTTP client module deinit");
}

/**
 * @brief dap_http_client_new Creates HTTP client's internal structure
 * @param a_esocket ESocket instance
 * @param a_arg Additional argument (usualy not used)
 */
void dap_http_client_new( dap_events_socket_t *a_esocket, void *a_arg )
{
    (void) a_arg;


    a_esocket->_inheritor = DAP_NEW_Z( dap_http_client_t );

    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT( a_esocket );
    l_http_client->esocket = a_esocket;
    l_http_client->http = DAP_HTTP( a_esocket->server );
    l_http_client->state_read = DAP_HTTP_CLIENT_STATE_START;
    l_http_client->state_write = DAP_HTTP_CLIENT_STATE_NONE;

    return;
}

/**
 * @brief dap_http_client_delete
 * @param a_esocket HTTP Client instance's esocket
 * @param a_arg Additional argument (usualy not used)
 */
void dap_http_client_delete( dap_events_socket_t * a_esocket, void *a_arg )
{
    (void) a_arg;
    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT( a_esocket );
    if (l_http_client == NULL){ // Client is in proc callback in another thread so we don't delete it
        return;
    }
    while( l_http_client->in_headers )
        dap_http_header_remove( &l_http_client->in_headers, l_http_client->in_headers );

    while( l_http_client->out_headers )
        dap_http_header_remove( &l_http_client->out_headers, l_http_client->out_headers );

    if( l_http_client->proc ) {
        if( l_http_client->proc->delete_callback ) {
          l_http_client->proc->delete_callback( l_http_client, NULL );
        }
    }
    DAP_DEL_Z(l_http_client->_inheritor)
}


/**
 * @brief detect_end_of_line Detect end of line, return position of its end (with \n symbols)
 * @param buf Input buffer
 * @param max_size Maximum size of this buffer minus 1 (for terminating zero)
 * @return position of the end of line
 */

#if 1
static int detect_end_of_line( const char *a_buf, size_t a_max_size )
{
  size_t i;

  for( i = 0; i < a_max_size; i++ ) {
    if ( a_buf[i] == '\n' ) {
      return i;
    }
  }

  return -1;
}
#endif

static char  *z_basename( char *path, uint32_t len )
{
  if ( !len )
    len = strlen( path );

  if ( len < 2 )
    return path;

  char *ptr = path + len - 1;

  while( ptr > path ) {
    if ( *ptr == '/' ) {
      ++ptr;
      break;
    }
    --ptr;
  }
    
  return ptr;
}

static int32_t  z_dirname( char *path, uint32_t len )
{
  if ( !len )
    len = strlen( path );

  if ( len < 2 )
    return 0;

  char *ptr = path + len - 1;

  while( ptr > path ) {
    if ( *ptr == '/' ) {
      break;
    }
    --ptr;
  }

  len = (uint32_t)(ptr - path);
  if ( len  )
    path[ len ] = 0;

  return len;
}

static int32_t  z_rootdirname( char *path, uint32_t len )
{
  if ( !len )
    len = strlen( path );

  if ( len < 2 )
    return 0;

  char *ptr = path + 1;

  while( ptr < path + len ) {
    if ( *ptr == '/' ) {
      break;
    }
    ++ptr;
  }

  uint32_t len2 = (uint32_t)(ptr - path);
  if ( len2 == len )
    return 0;

  path[ len2 ] = 0;
    
  return len2;
}

/**
 * @brief s_request_line_parse
 * @param a_http_client
 * @param a_buf
 * @param a_buf_length
 * @return
 */
static bool s_request_line_parse( dap_http_client_t *a_http_client, char *a_buf, size_t a_buf_length )
{
  size_t l_pos;
  size_t l_pos_kw_begin = 0;

  enum parse_state { PS_START = 0, PS_ACTION = 1, PS_URL = 2, PS_TYPE = 3, PS_VER_MAJOR = 4, PS_VER_MINOR = 5 }  l_parse_state = PS_ACTION;

  log_it( L_NOTICE, "dap_http_request_line_parse" );

  for( l_pos = 0; l_pos < a_buf_length; l_pos ++ ) {

    if ( a_buf[l_pos] == '\n' )
      break;

    if ( a_buf[l_pos] == ' ' || a_buf[l_pos] == '\t' ) {

      switch( l_parse_state ) {
      case PS_ACTION:
      {
        size_t c_size = l_pos - l_pos_kw_begin;
        if ( c_size + 1 > sizeof(a_http_client->action) )
          c_size = sizeof( a_http_client->action ) - 1;

        memcpy( a_http_client->action, a_buf + l_pos_kw_begin, c_size );
        a_http_client->action[c_size] = 0;
        log_it( L_WARNING, "Input: action '%s' pos=%u pos_kw_begin=%u", a_http_client->action, (uint32_t)l_pos, (uint32_t)l_pos_kw_begin );

        l_parse_state = PS_URL;
        l_pos_kw_begin = l_pos + 1;
      }
      break;

      case PS_URL:
      {
        size_t c_size = l_pos - l_pos_kw_begin;
        if ( c_size + 1 > sizeof(a_http_client->action) )
          c_size = sizeof( a_http_client->url_path ) - 1;

        memcpy( a_http_client->url_path, a_buf + l_pos_kw_begin, c_size );
        a_http_client->url_path[c_size] = 0;
        log_it( L_WARNING, "Input: url '%s' pos=%u pos_kw_begin=%u", a_http_client->url_path, (uint32_t)l_pos, (uint32_t)l_pos_kw_begin );
        l_parse_state = PS_TYPE;
        l_pos_kw_begin = l_pos + 1;
        break;
      }
      break;

      default:
      break;
      }
    }
  } // for

  if ( l_pos_kw_begin < a_buf_length && l_parse_state == PS_TYPE ) {

    size_t l_c_size;

    char *end = memchr( a_buf + l_pos_kw_begin, '/', a_buf_length - l_pos_kw_begin );

    if ( end && end < a_buf + a_buf_length ) {

      l_c_size = end - (a_buf + l_pos_kw_begin);
      //TODO get version here
      //end = memchr( buf + pos_kw_begin, '/', buf_length - pos_kw_begin );

    }
    else
      l_c_size = a_buf_length - l_pos_kw_begin;

    if ( l_c_size + 1 > sizeof(a_http_client->in_content_type) )
       l_c_size = sizeof(a_http_client->in_content_type) - 1;

    memcpy( a_http_client->in_content_type, a_buf + l_pos_kw_begin, l_c_size );
    a_http_client->in_content_type[l_c_size] = 0;

    log_it( L_WARNING, "Input: type '%s' pos=%u pos_kw_begin=%u", a_http_client->in_content_type, (uint32_t)l_pos, (uint32_t)l_pos_kw_begin );
  }

  return a_http_client->url_path[0] && a_http_client->action[0];
}

/**
 * @brief s_report_error_and_restart
 * @param a_esocket
 * @param a_http_client
 */
static inline void s_report_error_and_restart( dap_events_socket_t *a_esocket, dap_http_client_t *a_http_client )
{
    a_esocket->buf_in_size = 0;
    a_http_client->state_read = DAP_HTTP_CLIENT_STATE_NONE;

    dap_events_socket_set_readable_unsafe( a_http_client->esocket, false );
    dap_events_socket_set_writable_unsafe( a_http_client->esocket, true );

    a_http_client->reply_status_code = 505;
    strcpy( a_http_client->reply_reason_phrase, "Error" );
    a_http_client->state_write = DAP_HTTP_CLIENT_STATE_START;

    return;
}

/**
 * @brief dap_http_client_read
 * @param cl HTTP Client instance
 * @param arg Additional argument (usualy not used)
 */
void dap_http_client_read( dap_events_socket_t *a_esocket, void *a_arg )
{
    UNUSED(a_arg);
    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT( a_esocket );

//  log_it( L_DEBUG, "dap_http_client_read..." );
    do{
        if(s_debug_http)
            log_it( L_DEBUG, "HTTP client in state read %d taked bytes in input %"DAP_UINT64_FORMAT_U, l_http_client->state_read, a_esocket->buf_in_size );
        switch( l_http_client->state_read ) {
            case DAP_HTTP_CLIENT_STATE_START: { // Beginning of the session. We try to detect
                char l_buf_line[4096];
                char  *peol;
                uint32_t eol;

                if (!(peol = (char*)memchr(a_esocket->buf_in, 10, a_esocket->buf_in_size))) { /// search LF
                    peol = (char*)memchr(a_esocket->buf_in, 13, a_esocket->buf_in_size);
                }

                if (peol) {
                    eol = peol - (char*)a_esocket->buf_in;
                    if (eol <= 0) {
                        eol = a_esocket->buf_in_size - 2;
                    }
                } else {
                    log_it( L_WARNING, "Single-line, possibly trash, input detected");
                    eol = a_esocket->buf_in_size - 2;
                }

                // Check the number of bytes preparing to be copied to l_buf_line
                if ( eol + 3 >= sizeof(l_buf_line) ) {
                    log_it( L_WARNING,"Too big line in request, more than %"DAP_UINT64_FORMAT_U" symbols - thats very strange", sizeof(l_buf_line) - 3 );
                    s_report_error_and_restart( a_esocket, l_http_client );
                    break;
                }

                memcpy( l_buf_line, a_esocket->buf_in, eol + 1 ); // copy with LF

                dap_events_socket_shrink_buf_in( a_esocket, eol + 1 );
                l_buf_line[ eol + 2 ] = 0; // null terminate

                // parse http_request_line
                if ( !s_request_line_parse(l_http_client, l_buf_line, eol + 1) ) {
                    log_it( L_WARNING, "Input: Wrong request line '%s'", l_buf_line );
                    s_report_error_and_restart( a_esocket, l_http_client );
                    break;
                }

                char *l_query_string;
                if( (l_query_string = strchr(l_http_client->url_path, '?')) != NULL ) {
                    size_t len_after = MIN(strlen( l_query_string + 1 ), sizeof (l_http_client->url_path)-1);

                    if ( len_after ) {
                        if( len_after > (sizeof(l_http_client->in_query_string) - 1) ){
                            len_after = sizeof(l_http_client->in_query_string) - 1;
                        }

                        if ( strstr(l_query_string, "HTTP/1.1") ){
                            strncpy( l_http_client->in_query_string, l_query_string + 1, len_after - 8 );
                        }else{
                            strncpy( l_http_client->in_query_string,l_query_string + 1, len_after );
                        }

                        if ( l_http_client->in_query_string[strlen(l_http_client->in_query_string) - 1] == ' ' ){
                            l_http_client->in_query_string[strlen(l_http_client->in_query_string) - 1] = 0;
                        }
                        l_query_string[0] = 0;
                    }
                }

                log_it( L_INFO, "Input: %s request for %s document (query string '%s')", l_http_client->action, l_http_client->url_path, l_http_client->in_query_string[0] ? l_http_client->in_query_string : ""  );

                dap_http_url_proc_t *url_proc;
                int32_t tpos = z_dirname( l_http_client->url_path, 0 );
                HASH_FIND_STR( l_http_client->http->url_proc, l_http_client->url_path, url_proc );  // Find URL processor
                l_http_client->proc = url_proc;

                if ( tpos ){
                    l_http_client->url_path[ tpos ] = '/';
                }
                char *ptr = z_basename( l_http_client->url_path, 0 );
                memmove( l_http_client->url_path, ptr, strlen(ptr) + 1 );

                if ( url_proc ) {
                    l_http_client->state_read = DAP_HTTP_CLIENT_STATE_HEADERS;
                    // Check if present cache
                    pthread_rwlock_rdlock(&l_http_client->proc->cache_rwlock);
                    dap_http_cache_t * l_http_cache = l_http_client->proc->cache;
                    if(l_http_cache){
                        if ( ! l_http_cache->ts_expire || l_http_cache->ts_expire >= time(NULL) ){
                            l_http_client->out_headers = dap_http_headers_dup(l_http_cache->headers);
                            l_http_client->out_content_length = l_http_cache->body_size;
                            l_http_client->reply_status_code = l_http_cache->response_code;
                            if(l_http_cache->response_phrase)
                                strncpy(l_http_client->reply_reason_phrase,l_http_cache->response_phrase,sizeof (l_http_client->reply_reason_phrase)-1);

                            if(s_debug_http)
                                log_it(L_DEBUG,"%"DAP_FORMAT_SOCKET" Out: prepare cached headers", l_http_client->esocket->socket);

                        }else if (l_http_cache){
                            pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                            pthread_rwlock_wrlock(&l_http_client->proc->cache_rwlock);
                            dap_http_cache_delete(l_http_cache);
                            l_http_client->proc->cache = NULL;
                            l_http_cache = NULL;
                        }
                    }
                    if (l_http_cache == NULL){
                        pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                        // Call client constructor
                        if(l_http_client->proc->new_callback)
                            l_http_client->proc->new_callback(l_http_client, NULL);
                    }else
                        pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);

                } else {
                    log_it( L_WARNING, "Input: unprocessed URL request %s is rejected", l_http_client->url_path );
                    s_report_error_and_restart( a_esocket, l_http_client );
                    break;
                }
            } break;

            case DAP_HTTP_CLIENT_STATE_HEADERS: { // Parse input headers
                char l_buf_line[4096];
                char  *l_str_eol;
                uint32_t l_eol_pos;

                if ( !(l_str_eol = (char *)memchr(a_esocket->buf_in, 10, a_esocket->buf_in_size)) ) { /// search LF
                    log_it( L_WARNING, "DAP_HTTP_CLIENT_STATE_HEADERS: no LF" );
                    s_report_error_and_restart( a_esocket, l_http_client );
                    break;
                }

                l_eol_pos = l_str_eol - (char*)a_esocket->buf_in;
                // Check the number of bytes preparing to be copied to l_buf_line
                if(l_eol_pos >= sizeof(l_buf_line)) {
                    l_eol_pos = sizeof(l_buf_line) - 1;
                }
                int parse_ret;
                memcpy( l_buf_line, a_esocket->buf_in, l_eol_pos + 1 );
                l_buf_line[l_eol_pos-1] = 0;

                parse_ret = dap_http_header_parse( l_http_client, l_buf_line );

                if( parse_ret < 0 ){
                    log_it( L_WARNING, "Input: not a valid header '%s'", l_buf_line );
                }else if ( parse_ret == 1 ) {
                    log_it( L_INFO, "Input: HTTP headers are over" );
                    if ( l_http_client->proc->access_callback ) {
                        bool isOk = true;
                        l_http_client->proc->access_callback( l_http_client, &isOk );
                        if ( !isOk ) {
                            log_it( L_NOTICE, "Access restricted" );
                            s_report_error_and_restart( a_esocket, l_http_client );
                        }
                    }

                    pthread_rwlock_rdlock(&l_http_client->proc->cache_rwlock);
                    if ( l_http_client->proc->cache == NULL &&  l_http_client->proc->headers_read_callback ) {
                        pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                        l_http_client->proc->headers_read_callback( l_http_client, NULL );
                    }else{
                        pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                        if(s_debug_http)
                            log_it(L_DEBUG, "Cache is present, don't call underlaying callbacks");
                    }
                    // If no headers callback we go to the DATA processing
                    if( l_http_client->in_content_length ) {
                        if(s_debug_http)
                            log_it( L_DEBUG, "headers -> DAP_HTTP_CLIENT_STATE_DATA" );
                        l_http_client->state_read = DAP_HTTP_CLIENT_STATE_DATA;
                    }else{ // No data, its over
                        l_http_client->state_write=DAP_HTTP_CLIENT_STATE_START;
                        dap_events_socket_set_writable_unsafe(a_esocket, true);
                    }
                }
                dap_events_socket_shrink_buf_in( a_esocket, l_eol_pos + 1 );
            } break;
            case DAP_HTTP_CLIENT_STATE_DATA:{
                size_t read_bytes = 0;
                if(s_debug_http)
                    log_it(L_DEBUG, "dap_http_client_read: DAP_HTTP_CLIENT_STATE_DATA");
                pthread_rwlock_rdlock(&l_http_client->proc->cache_rwlock);
                if ( l_http_client->proc->cache == NULL && l_http_client->proc->data_read_callback ) {
                    pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                    l_http_client->proc->data_read_callback( l_http_client, &read_bytes );
                    dap_events_socket_shrink_buf_in( a_esocket, read_bytes );
                } else {
                    pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                    a_esocket->buf_in_size = 0;
                    l_http_client->state_write=DAP_HTTP_CLIENT_STATE_START;
                    dap_events_socket_set_writable_unsafe(a_esocket, true);
                }
            } break;
            case DAP_HTTP_CLIENT_STATE_NONE: {
                a_esocket->buf_in_size = 0;
            } break;
        } // switch
    } while (a_esocket->buf_in_size);
//  log_it( L_DEBUG, "dap_http_client_read...exit" );
//  Sleep(100);
}

/**
 * @brief dap_http_client_write Process write event
 * @param a_esocket HTTP Client instance's esocket
 * @param a_arg Additional argument (usualy not used)
 */
void dap_http_client_write( dap_events_socket_t * a_esocket, void *a_arg )
{
    //  log_it( L_DEBUG, "dap_http_client_write..." );

    (void) a_arg;
    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT( a_esocket );
    //log_it(L_WARNING,"HTTP client write callback in state %d",l_http_client->state_write);

    switch( l_http_client->state_write ) {
        case DAP_HTTP_CLIENT_STATE_NONE:
            return;
        case DAP_HTTP_CLIENT_STATE_START:{
            if ( l_http_client->proc ){
                // We check out_headers because if they are - we send only cached headers and don't call headers_write_callback at all
                if ( l_http_client->out_headers==NULL && l_http_client->proc->headers_write_callback ){
                        l_http_client->proc->headers_write_callback( l_http_client, NULL );
                        dap_http_client_out_header_generate( l_http_client );
                }else if (l_http_client->out_headers){
                    l_http_client->reply_status_code = Http_Status_OK; // Cached data are always OK... for now.
                    //TODO: make cached reply status code
                }
            }
            char buf[1024];
            time_t current_time = time( NULL );
            dap_time_to_str_rfc822( buf, sizeof(buf), current_time );

            dap_http_header_add( &l_http_client->out_headers,"Date", buf );

            log_it( L_INFO," HTTP response with %u status code", l_http_client->reply_status_code );
            dap_events_socket_write_f_unsafe(a_esocket, "HTTP/1.1 %u %s\r\n",l_http_client->reply_status_code, l_http_client->reply_reason_phrase[0] ?
                            l_http_client->reply_reason_phrase : http_status_reason_phrase(l_http_client->reply_status_code) );
            dap_events_socket_set_writable_unsafe(a_esocket, true);
            l_http_client->state_write = DAP_HTTP_CLIENT_STATE_HEADERS;
        } break;

        case DAP_HTTP_CLIENT_STATE_HEADERS: {
            dap_http_header_t *hdr = l_http_client->out_headers;
            if ( hdr == NULL ) {
                log_it(L_DEBUG, "Output: headers are over (reply status code %hu content_lentgh %zu)",
                       l_http_client->reply_status_code, l_http_client->out_content_length);
                dap_events_socket_write_f_unsafe(a_esocket, "\r\n");
                dap_events_socket_set_writable_unsafe(a_esocket, true);
                if ( l_http_client->out_content_length || l_http_client->out_content_ready ) {
                    l_http_client->state_write=DAP_HTTP_CLIENT_STATE_DATA;
                } else {
                    log_it( L_DEBUG, "Nothing to output" );
                    l_http_client->state_write = DAP_HTTP_CLIENT_STATE_NONE;
                    dap_events_socket_set_writable_unsafe( a_esocket, false );
                    a_esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
                }
                dap_events_socket_set_readable_unsafe( a_esocket, true );
            } else {
                //log_it(L_DEBUG,"Output: header %s: %s",hdr->name,hdr->value);
                dap_events_socket_write_f_unsafe(a_esocket, "%s: %s\r\n", hdr->name, hdr->value);
                dap_events_socket_set_writable_unsafe(a_esocket, true);
                dap_http_header_remove( &l_http_client->out_headers, hdr );
            }
        } break;
        case DAP_HTTP_CLIENT_STATE_DATA:{
            if ( l_http_client->proc ){
                pthread_rwlock_rdlock(&l_http_client->proc->cache_rwlock);
                if  ( ( l_http_client->proc->cache == NULL &&
                        l_http_client->proc->data_write_callback )
                    ){
                    if (l_http_client->proc->cache){
                        pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                        pthread_rwlock_wrlock(&l_http_client->proc->cache_rwlock);
                        dap_http_cache_delete(l_http_client->proc->cache);
                        l_http_client->proc->cache = NULL;
                        if(s_debug_http)
                            log_it(L_NOTICE,"Cache expired and dropped out");
                    }else if (s_debug_http)
                        log_it(L_DEBUG, "No cache so we call write callback");

                    pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                    l_http_client->proc->data_write_callback( l_http_client, NULL );
                }else if(l_http_client->proc->cache) {
                    size_t l_to_send=l_http_client->proc->cache->body_size-l_http_client->out_cache_position ;
                    size_t l_sent = dap_events_socket_write_unsafe(l_http_client->esocket,
                                                   l_http_client->proc->cache->body+l_http_client->out_cache_position,
                                                   l_to_send );
                    if(l_sent){
                        if ( l_http_client->out_cache_position + l_sent >= l_http_client->proc->cache->body_size ){ // All is sent
                            if(s_debug_http)
                                log_it(L_DEBUG,"Out %"DAP_FORMAT_SOCKET" All cached data over, signal to close connection", l_http_client->esocket->socket);
                            l_http_client->esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
                            l_http_client->state_write = DAP_HTTP_CLIENT_STATE_NONE;
                            dap_events_socket_set_writable_unsafe( a_esocket, false );
                        }else
                            l_http_client->out_cache_position += l_sent;
                    }
                    pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                }
            }else{
                log_it(L_WARNING, "No http proc, nothing to write");
            }
        }
        break;
  }
}

/**
 * @brief dap_http_client_out_header_generate Produce general headers
 * @param cl_ht HTTP client instance
 */
void dap_http_client_out_header_generate(dap_http_client_t *a_http_client)
{
    char buf[1024];

    if ( a_http_client->reply_status_code == 200 ) {
        if (s_debug_http)
            log_it(L_DEBUG, "Out headers generate for sock %"DAP_FORMAT_SOCKET, a_http_client->esocket->socket);
        if ( a_http_client->out_last_modified ) {
            dap_time_to_str_rfc822( buf, sizeof(buf), a_http_client->out_last_modified );
            dap_http_header_add( &a_http_client->out_headers, "Last-Modified", buf );
        }
        if ( a_http_client->out_content_type[0] ) {
            dap_http_header_add(&a_http_client->out_headers,"Content-Type",a_http_client->out_content_type);
            log_it(L_DEBUG,"Output: Content-Type = '%s'",a_http_client->out_content_type);
        }
        if ( a_http_client->out_content_length ) {
            dap_snprintf(buf,sizeof(buf),"%zu",a_http_client->out_content_length);
            dap_http_header_add(&a_http_client->out_headers,"Content-Length",buf);
            log_it(L_DEBUG,"output: Content-Length = %zu",a_http_client->out_content_length);
        }
    }else
        if (s_debug_http)
            log_it(L_WARNING, "Out headers: nothing generate for sock %"DAP_FORMAT_SOCKET", http code %d", a_http_client->esocket->socket,
                   a_http_client->reply_status_code);

    if ( a_http_client->out_connection_close || !a_http_client->keep_alive )
        dap_http_header_add( &a_http_client->out_headers, "Connection","Close" );

    dap_http_header_add( &a_http_client->out_headers, "Server-Name", a_http_client->http->server_name );

    log_it( L_DEBUG,"Output: Headers generated" );
}

/**
 * @brief dap_http_client_error Process errors
 * @param cl HTTP Client instance
 * @param arg Additional argument (usualy not used)
 */
void dap_http_client_error( dap_events_socket_t *cl, int arg )
{
  (void) arg;

  log_it( L_NOTICE, "dap_http_client_error" );

  dap_http_client_t *cl_ht = DAP_HTTP_CLIENT( cl );
  if (cl_ht){
      if ( cl_ht->proc )
        if ( cl_ht->proc->error_callback )
          cl_ht->proc->error_callback( cl_ht, arg );
  }
}
