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
#include "dap_events_socket.h"

#include "dap_http.h"
#include "http_status_code.h"

#include "dap_http_header.h"
#include "dap_http_client.h"

#define LOG_TAG "dap_http_client"

/**
 * @brief dap_http_client_init Init HTTP client module
 * @return  Zero if ok others if not
 */
int dap_http_client_init( )
{
  log_it(L_NOTICE,"Initialized HTTP client module");
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
 * @param cl HTTP Client instance
 * @param arg Additional argument (usualy not used)
 */
void dap_http_client_new( dap_events_socket_t *cl, void *arg )
{
    (void) arg;


    cl->_inheritor = DAP_NEW_Z( dap_http_client_t );

    dap_http_client_t *cl_ht = DAP_HTTP_CLIENT( cl );
    cl_ht->esocket = cl;
    cl_ht->http = DAP_HTTP( cl->server );
    cl_ht->state_read = DAP_HTTP_CLIENT_STATE_START;
    cl_ht->state_write = DAP_HTTP_CLIENT_STATE_NONE;

    return;
}

/**
 * @brief dap_http_client_delete
 * @param cl HTTP Client instance
 * @param arg Additional argument (usualy not used)
 */
void dap_http_client_delete( dap_events_socket_t * cl, void *arg )
{
    dap_http_client_t *cl_ht = DAP_HTTP_CLIENT( cl );
    if (cl_ht == NULL){ // Client is in proc callback in another thread so we don't delete it
        return;
    }
    while( cl_ht->in_headers )
        dap_http_header_remove( &cl_ht->in_headers, cl_ht->in_headers );

    while( cl_ht->out_headers )
        dap_http_header_remove( &cl_ht->out_headers, cl_ht->out_headers );

    if( cl_ht->proc ) {
        if( cl_ht->proc->delete_callback ) {
          cl_ht->proc->delete_callback( cl_ht, NULL );
        }
    }
    DAP_DEL_Z(cl_ht->_inheritor)

  (void) arg;
}


/**
 * @brief detect_end_of_line Detect end of line, return position of its end (with \n symbols)
 * @param buf Input buffer
 * @param max_size Maximum size of this buffer minus 1 (for terminating zero)
 * @return position of the end of line
 */

#if 1
int detect_end_of_line( const char *buf, size_t max_size )
{
  size_t i;

  for( i = 0; i < max_size; i++ ) {
    if ( buf[i] == '\n' ) {
      return i;
    }
  }

  return -1;
}
#endif

char  *z_basename( char *path, uint32_t len )
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

int32_t  z_dirname( char *path, uint32_t len )
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

int32_t  z_rootdirname( char *path, uint32_t len )
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
 * @brief dap_http_request_line_parse
 * @param cl_ht
 * @param buf
 * @param buf_length
 * @return
 */
bool dap_http_request_line_parse( dap_http_client_t *cl_ht, char *buf, size_t buf_length )
{
  size_t pos;
  size_t pos_kw_begin = 0;

  enum parse_state { PS_START = 0, PS_ACTION = 1, PS_URL = 2, PS_TYPE = 3, PS_VER_MAJOR = 4, PS_VER_MINOR = 5 }  p_st = PS_ACTION;

  log_it( L_NOTICE, "dap_http_request_line_parse" );

  for( pos = 0; pos < buf_length; pos ++ ) {

    if ( buf[pos] == '\n' )
      break;

    if ( buf[pos] == ' ' || buf[pos] == '\t' ) {

      switch( p_st ) {
      case PS_ACTION:
      {
        size_t c_size = pos - pos_kw_begin;
        if ( c_size + 1 > sizeof(cl_ht->action) )
          c_size = sizeof( cl_ht->action ) - 1;

        memcpy( cl_ht->action, buf + pos_kw_begin, c_size );
        cl_ht->action[c_size] = 0;
        log_it( L_WARNING, "Input: action '%s' pos=%u pos_kw_begin=%u", cl_ht->action, (uint32_t)pos, (uint32_t)pos_kw_begin );

        p_st = PS_URL;
        pos_kw_begin = pos + 1;
      }
      break;

      case PS_URL:
      {
        size_t c_size = pos - pos_kw_begin;
        if ( c_size + 1 > sizeof(cl_ht->action) )
          c_size = sizeof( cl_ht->url_path ) - 1;

        memcpy( cl_ht->url_path, buf + pos_kw_begin, c_size );
        cl_ht->url_path[c_size] = 0;
        log_it( L_WARNING, "Input: url '%s' pos=%lu pos_kw_begin=%lu", cl_ht->url_path, (uint32_t)pos, (uint32_t)pos_kw_begin );
        p_st = PS_TYPE;
        pos_kw_begin = pos + 1;
        break;
      }
      break;

      default:
      break;
      }
    }
  } // for

  if ( pos_kw_begin < buf_length && p_st == PS_TYPE ) {

    size_t c_size;

    char *end = memchr( buf + pos_kw_begin, '/', buf_length - pos_kw_begin );

    if ( end && end < buf + buf_length ) {

      c_size = end - (buf + pos_kw_begin);
      //TODO get version here
      //end = memchr( buf + pos_kw_begin, '/', buf_length - pos_kw_begin );

    }
    else
      c_size = buf_length - pos_kw_begin;

    if ( c_size + 1 > sizeof(cl_ht->in_content_type) )
       c_size = sizeof(cl_ht->in_content_type) - 1;

    memcpy( cl_ht->in_content_type, buf + pos_kw_begin, c_size );
    cl_ht->in_content_type[c_size] = 0;

    log_it( L_WARNING, "Input: type '%s' pos=%lu pos_kw_begin=%lu", cl_ht->in_content_type, (uint32_t)pos, (uint32_t)pos_kw_begin );
  }

  return cl_ht->url_path[0] && cl_ht->action[0];
}

/**
 * @brief s_report_error_and_restart
 * @param cl
 * @param cl_ht
 */
static inline void s_report_error_and_restart( dap_events_socket_t *cl, dap_http_client_t *cl_ht )
{
  cl->buf_in_size = 0;
  cl_ht->state_read = DAP_HTTP_CLIENT_STATE_NONE;

  dap_events_socket_set_readable_unsafe( cl_ht->esocket, false );
  dap_events_socket_set_writable_unsafe( cl_ht->esocket, true );

  cl_ht->reply_status_code = 505;
  strcpy( cl_ht->reply_reason_phrase, "Error" );
  cl_ht->state_write = DAP_HTTP_CLIENT_STATE_START;

  return;
}

/**
 * @brief dap_http_client_read
 * @param cl HTTP Client instance
 * @param arg Additional argument (usualy not used)
 */
void dap_http_client_read( dap_events_socket_t *a_esocket, void *arg )
{
    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT( a_esocket );

//  log_it( L_DEBUG, "dap_http_client_read..." );
    do{
        //log_it( L_DEBUG, "HTTP client in state read %d taked bytes in input %lu", l_http_client->state_read, a_esocket->buf_in_size );
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

                if ( eol + 3 >= sizeof(l_buf_line) ) {
                    log_it( L_WARNING,"Too big line in request, more than %llu symbols - thats very strange", sizeof(l_buf_line) - 3 );
                    s_report_error_and_restart( a_esocket, l_http_client );
                    break;
                }

                memcpy( l_buf_line, a_esocket->buf_in, eol + 1 ); // copy with LF

                dap_events_socket_shrink_buf_in( a_esocket, eol + 1 );
                l_buf_line[ eol + 2 ] = 0; // null terminate

                // parse http_request_line
                if ( !dap_http_request_line_parse(l_http_client, l_buf_line, eol + 1) ) {
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
                            strncpy( l_http_client->in_query_string, l_query_string + 1, len_after - 11 );
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

                    if ( l_http_client->proc->headers_read_callback ) {
                        l_http_client->proc->headers_read_callback( l_http_client, NULL );
                    }

                    // If no headers callback we go to the DATA processing
                    if( l_http_client->in_content_length ) {
                        //log_it( L_DEBUG, "headers -> DAP_HTTP_CLIENT_STATE_DATA" );
                        l_http_client->state_read = DAP_HTTP_CLIENT_STATE_DATA;
                    }
                }
                dap_events_socket_shrink_buf_in( a_esocket, l_eol_pos + 1 );
            } break;
            case DAP_HTTP_CLIENT_STATE_DATA:{
                size_t read_bytes = 0;
                //log_it(L_DEBUG, "dap_http_client_read: DAP_HTTP_CLIENT_STATE_DATA");
                if ( l_http_client->proc->data_read_callback ) {
                    l_http_client->proc->data_read_callback( l_http_client, &read_bytes );
                    dap_events_socket_shrink_buf_in( a_esocket, read_bytes );
                } else {
                    log_it( L_WARNING, "data_read callback is NULL in DAP_HTTP_CLIENT_STATE_DATA" );
                    a_esocket->buf_in_size = 0;
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
 * @param cl HTTP Client instance
 * @param arg Additional argument (usualy not used)
 */
void dap_http_client_write( dap_events_socket_t * cl, void *arg )
{
    //  log_it( L_DEBUG, "dap_http_client_write..." );

    (void) arg;
    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT( cl );
    //log_it(L_WARNING,"HTTP client write callback in state %d",l_http_client->state_write);

    switch( l_http_client->state_write ) {
        case DAP_HTTP_CLIENT_STATE_NONE:
            return;
        case DAP_HTTP_CLIENT_STATE_START:{
            if ( l_http_client->proc )
                if ( l_http_client->proc->headers_write_callback )
                    l_http_client->proc->headers_write_callback( l_http_client, NULL );

            log_it( L_INFO," HTTP response with %u status code", l_http_client->reply_status_code );
            dap_events_socket_write_f_unsafe(cl, "HTTP/1.1 %u %s\r\n",l_http_client->reply_status_code, l_http_client->reply_reason_phrase[0] ?
                            l_http_client->reply_reason_phrase : http_status_reason_phrase(l_http_client->reply_status_code) );
            dap_events_socket_set_writable_unsafe(cl, true);
            dap_http_client_out_header_generate( l_http_client );
            l_http_client->state_write = DAP_HTTP_CLIENT_STATE_HEADERS;
        } break;

        case DAP_HTTP_CLIENT_STATE_HEADERS: {
            dap_http_header_t *hdr = l_http_client->out_headers;
            if ( hdr == NULL ) {
                log_it(L_DEBUG, "Output: headers are over (reply status code %u content_lentgh %u)",
                       l_http_client->reply_status_code, l_http_client->out_content_length);
                dap_events_socket_write_f_unsafe(cl, "\r\n");
                dap_events_socket_set_writable_unsafe(cl, true);
                if ( l_http_client->out_content_length || l_http_client->out_content_ready ) {
                    l_http_client->state_write=DAP_HTTP_CLIENT_STATE_DATA;
                } else {
                    log_it( L_DEBUG, "Nothing to output" );
                    l_http_client->state_write = DAP_HTTP_CLIENT_STATE_NONE;
                    dap_events_socket_set_writable_unsafe( cl, false );
                    cl->flags |= DAP_SOCK_SIGNAL_CLOSE;
                }
                dap_events_socket_set_readable_unsafe( cl, true );
            } else {
                //log_it(L_WARNING,"Output: header %s: %s",hdr->name,hdr->value);
                dap_events_socket_write_f_unsafe(cl, "%s: %s\r\n", hdr->name, hdr->value);
                dap_events_socket_set_writable_unsafe(cl, true);
                dap_http_header_remove( &l_http_client->out_headers, hdr );
            }
        } break;
        case DAP_HTTP_CLIENT_STATE_DATA:
        {
          if ( l_http_client->proc ){
            if ( l_http_client->proc->data_write_callback ){
                l_http_client->proc->data_write_callback( l_http_client, NULL );
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
void dap_http_client_out_header_generate(dap_http_client_t *cl_ht)
{
  char buf[1024];
  time_t current_time = time( NULL );
  dap_time_to_str_rfc822( buf, sizeof(buf), current_time );

  dap_http_header_add( &cl_ht->out_headers,"Date", buf );

  if ( cl_ht->reply_status_code == 200 ) {

    if ( cl_ht->out_last_modified ) {
      dap_time_to_str_rfc822( buf, sizeof(buf), cl_ht->out_last_modified );
      dap_http_header_add( &cl_ht->out_headers, "Last-Modified", buf );
    }
    if ( cl_ht->out_content_type[0] ) {
      dap_http_header_add(&cl_ht->out_headers,"Content-Type",cl_ht->out_content_type);
      log_it(L_DEBUG,"output: Content-Type = '%s'",cl_ht->out_content_type);
    }
    if ( cl_ht->out_content_length ) {
      dap_snprintf(buf,sizeof(buf),"%llu",(unsigned long long)cl_ht->out_content_length);
      dap_http_header_add(&cl_ht->out_headers,"Content-Length",buf);
      log_it(L_DEBUG,"output: Content-Length = %llu",cl_ht->out_content_length);
    }
  }

  if ( cl_ht->out_connection_close || !cl_ht->keep_alive )
    dap_http_header_add( &cl_ht->out_headers, "Connection","Close" );

  dap_http_header_add( &cl_ht->out_headers, "Server-Name", cl_ht->http->server_name );

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
