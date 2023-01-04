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

#include "dap_time.h"
#include "dap_http.h"
#include "http_status_code.h"

#include "dap_http_header.h"
#include "dap_http_client.h"

#define LOG_TAG "dap_http_client"

static bool s_request_line_parse( dap_http_client_t *cl_ht, char *buf, size_t buf_length );
static bool s_debug_http = false;

static const char *dap_http_client_state_str[] = {
    [DAP_HTTP_CLIENT_STATE_NONE]    = "None",
    [DAP_HTTP_CLIENT_STATE_START]   = "Start",
    [DAP_HTTP_CLIENT_STATE_HEADERS] = "Headers",
    [DAP_HTTP_CLIENT_STATE_DATA]    = "Data"
};

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
    l_http_client->socket_num = a_esocket->socket;

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
    DAP_DEL_Z(l_http_client->_inheritor);
}


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

  a_http_client->url_path[0] = a_http_client->action[0] = '\0';

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
        if ( c_size + 1 > sizeof(a_http_client->url_path) ) {
            log_it(L_ERROR, "Too long URL with size %zu is truncated", c_size);
            c_size = sizeof( a_http_client->url_path ) - 1;
        }

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

#define	CRLF    "\r\n"
#define	CR    '\r'
#define	LF    '\n'


void dap_http_client_read( dap_events_socket_t *a_esocket, void *a_arg )
{
UNUSED(a_arg);
dap_http_client_t *l_http_client = DAP_HTTP_CLIENT( a_esocket );
byte_t *l_cp;
size_t  l_len;
int     l_rc;

    unsigned l_iter_count = 0;
    do {
        debug_if(s_debug_http, L_DEBUG, "l_http_client: %p, state %s, buf_in_size: %"DAP_UINT64_FORMAT_U,
                 l_http_client, dap_http_client_state_str[l_http_client->state_read], a_esocket->buf_in_size );

        switch( l_http_client->state_read )
        {
            case DAP_HTTP_CLIENT_STATE_START:                          /* Beginning of the session. We try to detect CRLF */
            {
                if ( !(a_esocket->buf_in_size > 3) )                    /* Too short to be true ... */
                    break;
                                                                        /* CR ? */
                if ( !(l_cp = memchr(a_esocket->buf_in, CR, a_esocket->buf_in_size)) )
                    break;

                if ( !(l_len = (l_cp - a_esocket->buf_in)) )/* First char in the buffer ? */
                {
                    log_it( L_ERROR, "LF at begin of the start line - garbage ?");
                    s_report_error_and_restart( a_esocket, l_http_client );
                    break;
                }

                if ( l_len >= a_esocket->buf_in_size )                  /* Last char in the buffer ? */
                    break;                                              /* Wee need to get LF !!! */


                if ( *(l_cp + 1) != LF )                           /* LF ? */
                {
                    log_it( L_ERROR, "Start line is not terminated by CRLF, drop and restart input scanner");
                    s_report_error_and_restart( a_esocket, l_http_client );
                    break;
                }

                l_len += 2;                                             /* Count CRLF */

                // parse http_request_line
                if ( !s_request_line_parse(l_http_client, (char *) a_esocket->buf_in, l_len) ) {
                    log_it( L_WARNING, "Input: Wrong request line '%.*s'", (int)l_len, a_esocket->buf_in);
                    s_report_error_and_restart( a_esocket, l_http_client );
                    break;
                }

                dap_events_socket_shrink_buf_in( a_esocket, l_len);     /* Shrink start line from input buffer over CRLF !!! */

                char *l_query_string = memchr(l_http_client->url_path, '?', sizeof(l_http_client->url_path));
                if (l_query_string++) {
                    size_t len_after = MIN(strnlen(l_query_string, l_http_client->url_path - l_query_string),
                                           sizeof(l_http_client->in_query_string) - 1);

                    if ( len_after ) {
                        l_query_string[len_after] = '\0';
                        char *l_pos = strstr(l_query_string, "HTTP/1.1");
                        //Search for the first occurrence.
                        if (l_pos-- && *l_pos == ' ')
                            strncpy(l_http_client->in_query_string, l_query_string, len_after - (l_pos - l_query_string));
                        else
                            strncpy( l_http_client->in_query_string, l_query_string, len_after);
                        size_t l_in_query_len = strlen(l_http_client->in_query_string);
                        if (l_in_query_len && l_http_client->in_query_string[l_in_query_len - 1] == ' ' ){
                            l_http_client->in_query_string[l_in_query_len - 1] = 0;
                        }
                        *(l_query_string - 1) = 0;
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
                            debug_if(s_debug_http, L_DEBUG,"%"DAP_FORMAT_SOCKET" Out: prepare cached headers", l_http_client->esocket->socket);

                        } else {
                            pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                            pthread_rwlock_wrlock(&l_http_client->proc->cache_rwlock);
                            dap_http_cache_delete(l_http_cache);
                            l_http_client->proc->cache = NULL;
                            l_http_cache = NULL;
                        }
                        pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                    } else {
                        pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                        // Call client constructor
                        if(l_http_client->proc->new_callback)
                            l_http_client->proc->new_callback(l_http_client, NULL);
                    }
                } else {
                    log_it( L_WARNING, "Input: unprocessed URL request %s is rejected", l_http_client->url_path );
                    s_report_error_and_restart( a_esocket, l_http_client );
                    break;
                }
            } break;

            case DAP_HTTP_CLIENT_STATE_HEADERS: { // Parse input headers
                if ( a_esocket->buf_in_size < 2 ) {
                    log_it( L_WARNING, "DAP_HTTP_CLIENT_STATE_HEADERS: not enough data to be processed" );
                    s_report_error_and_restart( a_esocket, l_http_client );
                    break;
                }

                if ( !(l_cp = memchr(a_esocket->buf_in, CR, a_esocket->buf_in_size)) ) { /* search for CR */
                    log_it( L_WARNING, "DAP_HTTP_CLIENT_STATE_HEADERS: no CR" );
                    s_report_error_and_restart( a_esocket, l_http_client );
                    break;
                }

                if ( l_cp == a_esocket->buf_in + a_esocket->buf_in_size
                            || *(l_cp + 1) != LF ) {
                    log_it( L_WARNING, "DAP_HTTP_CLIENT_STATE_HEADERS: no LF" );
                    s_report_error_and_restart( a_esocket, l_http_client );
                    break;
                }

                l_len = l_cp - a_esocket->buf_in;          /* Length of the HTTP header line without the CRLF terminator */

                l_rc = dap_http_header_parse( l_http_client, (char *) a_esocket->buf_in, l_len );

                if( l_rc < 0 ){
                    log_it( L_WARNING, "Input: not a valid header '%.*s'", (int)l_len, a_esocket->buf_in );
                }else if ( l_rc == 1 ) {
                    log_it( L_INFO, "Input: HTTP headers are over" );
                    if ( l_http_client->proc->access_callback ) {
                        bool isOk = true;
                        l_http_client->proc->access_callback( l_http_client, &isOk );
                        if ( !isOk ) {
                            log_it( L_NOTICE, "Access restricted" );
                            s_report_error_and_restart( a_esocket, l_http_client );
                            break;
                        }
                    }

                    pthread_rwlock_rdlock(&l_http_client->proc->cache_rwlock);
                    if ( l_http_client->proc->cache == NULL &&  l_http_client->proc->headers_read_callback ) {
                        pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                        l_http_client->proc->headers_read_callback( l_http_client, NULL );
                    }else{
                        pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                        debug_if(s_debug_http, L_DEBUG, "Cache is present, don't call underlaying callbacks");
                    }
                    // If no headers callback we go to the DATA processing
                    if( l_http_client->in_content_length ) {
                        debug_if(s_debug_http, L_DEBUG, "headers -> DAP_HTTP_CLIENT_STATE_DATA" );
                        l_http_client->state_read = DAP_HTTP_CLIENT_STATE_DATA;
                    }else{ // No data, its over
                        l_http_client->state_write=DAP_HTTP_CLIENT_STATE_START;
                        if (l_http_client->proc->cache)
                            dap_http_client_write(a_esocket, NULL);
                    }
                }

                l_len += 2;                                             /* Count CRLF */
                dap_events_socket_shrink_buf_in( a_esocket, l_len  );
            } break;

            case DAP_HTTP_CLIENT_STATE_DATA:{
                size_t read_bytes = 0;
                pthread_rwlock_rdlock(&l_http_client->proc->cache_rwlock);
                if ( l_http_client->proc->cache == NULL && l_http_client->proc->data_read_callback ) {
                    pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                    l_http_client->proc->data_read_callback( l_http_client, &read_bytes );
                    dap_events_socket_shrink_buf_in( a_esocket, read_bytes );
                } else {
                    pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                    a_esocket->buf_in_size = 0;
                    l_http_client->state_write=DAP_HTTP_CLIENT_STATE_START;
                    dap_http_client_write(a_esocket, NULL);
                }

                debug_if(s_debug_http, L_DEBUG, "l_http_client:%p, read_bytes: %zu",  l_http_client, read_bytes);
            } break;

            case DAP_HTTP_CLIENT_STATE_NONE: {
                a_esocket->buf_in_size = 0;
            } break;
        } // switch
        if (l_iter_count++ > 1000) {
            log_it(L_ERROR, "Indefinite loop in DAP HTTP client read");
            s_report_error_and_restart( a_esocket, l_http_client );
            break;
        }
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
UNUSED(a_arg);
size_t  l_len = 0;
char l_buf[1024];

    debug_if(s_debug_http ,L_DEBUG, "Entering: a_esocket: %p, a_arg: %p", a_esocket, a_arg);

    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT( a_esocket );

    if ( !l_http_client )
        return  log_it( L_ERROR, "dap_http_client_t context is NULL");

    debug_if(s_debug_http ,  L_WARNING, "HTTP client write callback in state %d", l_http_client->state_write);

    switch( l_http_client->state_write ) {
        case DAP_HTTP_CLIENT_STATE_NONE:
        default:
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
            time_t current_time = time( NULL );
            l_len = dap_time_to_str_rfc822( l_buf, sizeof(l_buf), current_time );

            dap_http_header_add( &l_http_client->out_headers, "Date", 4, l_buf, l_len );

            log_it( L_INFO," HTTP response with %u status code", l_http_client->reply_status_code );
            dap_events_socket_write_f_unsafe(a_esocket, "HTTP/1.1 %u %s\r\n",l_http_client->reply_status_code, l_http_client->reply_reason_phrase[0] ?
                            l_http_client->reply_reason_phrase : http_status_reason_phrase(l_http_client->reply_status_code) );
            l_http_client->state_write = DAP_HTTP_CLIENT_STATE_HEADERS;
        } break;

        case DAP_HTTP_CLIENT_STATE_HEADERS: {
            dap_http_header_t *hdr = l_http_client->out_headers;
            if ( hdr == NULL ) {
                log_it(L_DEBUG, "Output: headers are over (reply status code %hu content_lentgh %zu)",
                       l_http_client->reply_status_code, l_http_client->out_content_length);
                dap_events_socket_write_f_unsafe(a_esocket, "\r\n");
                if ( l_http_client->out_content_length || l_http_client->out_content_ready ) {
                    l_http_client->state_write=DAP_HTTP_CLIENT_STATE_DATA;
                } else {
                    log_it( L_DEBUG, "Nothing to output" );
                    l_http_client->state_write = DAP_HTTP_CLIENT_STATE_NONE;
                    dap_events_socket_set_writable_unsafe( a_esocket, false );
                    a_esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
                    break;
                }
                dap_events_socket_set_readable_unsafe( a_esocket, true );
            } else {
                //log_it(L_DEBUG,"Output: header %s: %s",hdr->name,hdr->value);
                dap_events_socket_write_f_unsafe(a_esocket, "%s: %s\r\n", hdr->name, hdr->value);
                dap_http_header_remove( &l_http_client->out_headers, hdr );
            }
        } break;

        case DAP_HTTP_CLIENT_STATE_DATA: {
            if (l_http_client->proc && l_http_client->proc->data_write_callback) {
                pthread_rwlock_wrlock(&l_http_client->proc->cache_rwlock);
                if (!l_http_client->proc->cache) {
                    debug_if(s_debug_http, L_DEBUG, "No cache so we call write callback");
                    pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                    l_http_client->proc->data_write_callback( l_http_client, NULL );
                    if (l_http_client->esocket->flags & DAP_SOCK_SIGNAL_CLOSE)
                        l_http_client->state_write = DAP_HTTP_CLIENT_STATE_NONE;
                } else {
                    size_t l_to_send=l_http_client->proc->cache->body_size-l_http_client->out_cache_position ;
                    size_t l_sent = dap_events_socket_write_unsafe(l_http_client->esocket,
                                                   l_http_client->proc->cache->body+l_http_client->out_cache_position,
                                                   l_to_send );
                    if (!l_sent || l_http_client->out_cache_position + l_sent >= l_http_client->proc->cache->body_size) { // All is sent
                        if (!l_sent)
                            debug_if(s_debug_http, L_ERROR, "Can't send data to socket");
                        else
                            debug_if(s_debug_http, L_DEBUG, "Out %"DAP_FORMAT_SOCKET" All cached data over, signal to close connection",
                                     l_http_client->esocket->socket);
                        l_http_client->esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
                        l_http_client->state_write = DAP_HTTP_CLIENT_STATE_NONE;
                    } else
                        l_http_client->out_cache_position += l_sent;
                    pthread_rwlock_unlock(&l_http_client->proc->cache_rwlock);
                }
            } else {
                log_it(L_WARNING, "No http proc, nothing to write");
                l_http_client->esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
                l_http_client->state_write = DAP_HTTP_CLIENT_STATE_NONE;
            }
        } return;
    }
    dap_http_client_write(a_esocket, a_arg);
}

/**
 * @brief dap_http_client_out_header_generate Produce general headers
 * @param cl_ht HTTP client instance
 */
void dap_http_client_out_header_generate(dap_http_client_t *a_http_client)
{
char l_buf[1024];
size_t  l_len;

    if ( a_http_client->reply_status_code == 200 ) {
        debug_if(s_debug_http, L_DEBUG, "Out headers generate for sock %"DAP_FORMAT_SOCKET, a_http_client->socket_num);
        if ( a_http_client->out_last_modified ) {
            l_len = dap_time_to_str_rfc822( l_buf, sizeof(l_buf), a_http_client->out_last_modified );
            dap_http_header_add( &a_http_client->out_headers, "Last-Modified", -1, l_buf, l_len );
        }
        if ( a_http_client->out_content_type[0] ) {
            dap_http_header_add(&a_http_client->out_headers,"Content-Type", -1, a_http_client->out_content_type, -1);
            log_it(L_DEBUG,"Output: Content-Type = '%s'", a_http_client->out_content_type);
        }
        if ( a_http_client->out_content_length ) {
            dap_snprintf(l_buf,sizeof(l_buf),"%zu",a_http_client->out_content_length);
            dap_http_header_add(&a_http_client->out_headers, "Content-Length",-1, l_buf, -1);
            log_it(L_DEBUG,"output: Content-Length = %zu", a_http_client->out_content_length);
        }
    }else
        debug_if(s_debug_http, L_WARNING, "Out headers: nothing generate for sock %"DAP_FORMAT_SOCKET", http code %d", a_http_client->socket_num,
                   a_http_client->reply_status_code);

    if ( a_http_client->out_connection_close || !a_http_client->keep_alive )
        dap_http_header_add( &a_http_client->out_headers, "Connection", -1, "Close", -1 );

    dap_http_header_add( &a_http_client->out_headers, "Server-Name", -1, a_http_client->http->server_name, -1 );

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
