/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2021
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif

#include <pthread.h>
#include <utlist.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_events_socket.h"
#include "dap_http_client.h"
#include "dap_http_header.h"

#define LOG_TAG "http_header"


/**
 * @brief dap_http_header_init Init module
 * @return Zero if ok others if not
 */
int dap_http_header_init( )
{
  log_it( L_NOTICE, "Initialized HTTP headers module" );
  return 0;
}

/**
 * @brief dap_http_header_deinit Deinit module
 */
void dap_http_header_deinit()
{
  log_it( L_INFO, "HTTP headers module deinit" );
}


/**
 * @brief dap_http_header_parse Parse string with HTTP header
 * @param top Top of list with HTTP header structures
 * @param str String to parse
 * @return Zero if parsed well -1 if it wasn't HTTP header 1 if its "\r\n" string
 */
#define	CRLF    "\r\n"
#define	CR    '\r'
#define	LF    '\n'


int dap_http_header_parse(
            struct dap_http_client *a_cl_ht,
                        const char *a_str,
                        size_t      a_str_len
        )
{
char    l_name[DAP_HTTP$SZ_FIELD_NAME], l_value[DAP_HTTP$SZ_FIELD_VALUE], *l_cp;
size_t  l_len, l_name_len, l_value_len;

    if ( !a_str_len )
        return 1;

    if ( (a_str_len >= 2) && (*a_str == CR) && (*(a_str + 1) == LF) )
        return 1;

    /* We expect to see: <field_name>':'<white_space><field_value>CRLF */
    if ( !(l_cp = memchr(a_str, ':', a_str_len)) )
        return  log_it(L_ERROR,"Input: Wasn't found ':' symbol in the header"), -EINVAL;

    l_name_len = l_cp - a_str;
    l_name_len = MIN(l_name_len, sizeof(l_name) - 1);
    memcpy(l_name, a_str, l_name_len);
    l_name[l_name_len] = '\0';

    l_cp += 2;                                                          /* Skip ':'<white_space>' ??? */
    l_value_len  = a_str_len - (l_cp - a_str);                          /* <value_len> - rest of input buffer */
    l_value_len = MIN(l_value_len, sizeof(l_value)  - 1);
    memcpy(l_value, l_cp, l_value_len);
    l_value[l_value_len] = '\0';

#ifdef  DAP_SYS_DEBUG
    log_it(L_DEBUG, "[0:%d]='%.*s', [0:%d]='%.*s'", l_name_len, l_name_len, l_name, l_value_len, l_value_len, l_value);
#endif


    if( !strcmp(l_name, "Connection"))
        {
        if ( !strcmp(l_value, "Keep-Alive") )
        {
            log_it(L_INFO, "Input: Keep-Alive connection detected");
            a_cl_ht->keep_alive = true;
        }
    }
    else if ( !strcmp(l_name,"Content-Type") )
    {
        l_len = MIN(l_value_len, sizeof(a_cl_ht->in_content_type) - 1);
        memcpy( a_cl_ht->in_content_type, l_value, l_len );
        a_cl_ht->in_content_type[ l_len] = '\0';
    }
    else if( !strcmp(l_name, "Content-Length") ) {
        a_cl_ht->in_content_length = atoi( l_value );
    }
    else  if( !strcmp(l_name,"Cookie") ) {
        l_len = MIN(l_value_len, sizeof(a_cl_ht->in_cookie) - 1);
        memcpy(a_cl_ht->in_cookie,l_value, l_len);
        a_cl_ht->in_cookie[l_len] = '\0';
    }

    dap_http_header_add(&a_cl_ht->in_headers, l_name, l_name_len, l_value, l_value_len);
    return 0;
}



/**
 * @brief http_header_add Add HTTP header to the HTTP server instance
 * @param sh HTTP server instance
 * @param name  Header's name
 * @param value Header's value
 * @return Pointer to the new HTTP header's structure
 */
dap_http_header_t *dap_http_header_add(
                    dap_http_header_t **a_top,
                           const char *a_name,
                            size_t      a_name_len,
                            const char *a_value,
                            size_t      a_value_len
                                       )
{
    dap_http_header_t *l_new_header = DAP_NEW_Z(dap_http_header_t);
    assert(l_new_header);

    if ( (long)a_name_len == -1 )
        l_new_header->name_len = strnlen(a_name, DAP_HTTP$SZ_FIELD_NAME);
    else l_new_header->name_len = MIN(a_name_len, DAP_HTTP$SZ_FIELD_NAME);

    memcpy(l_new_header->name, a_name, l_new_header->name_len);

    if ( (long)a_value_len == -1 )
        l_new_header->value_len = strnlen(a_value, DAP_HTTP$SZ_FIELD_VALUE);
    else  l_new_header->value_len = MIN(a_value_len, DAP_HTTP$SZ_FIELD_VALUE);

    memcpy(l_new_header->value, a_value, l_new_header->value_len);

    DL_APPEND(*a_top, l_new_header);
    return l_new_header;

}


/**
 * @brief dap_http_out_header_add_f Add header to the output queue with format-filled string
 * @param ht HTTP client instance
 * @param name Header name
 * @param value Formatted string to header value
 * @param ... Arguments for formatted string
 * @return
 */
dap_http_header_t * dap_http_out_header_add_f(dap_http_client_t *ht, const char *a_name, const char *a_format,...)
{
va_list ap;
dap_http_header_t * ret;
char l_buf[DAP_HTTP$SZ_FIELD_VALUE];
size_t  l_len;


    va_start(ap,a_format);
    l_len = dap_vsnprintf(l_buf, sizeof(l_buf) - 1, a_format, ap);
    ret = dap_http_header_add(&ht->out_headers, a_name, -1, l_buf, l_len);
    va_end(ap);

    return ret;
}

/**
 * @brief dap_http_header_remove Removes header from the list
 * @param dap_hdr HTTP header
 */
void dap_http_header_remove(dap_http_header_t **a_top, dap_http_header_t *a_hdr)
{
    DL_DELETE(*a_top, a_hdr);
    DAP_DELETE(a_hdr);

}

void print_dap_http_headers(dap_http_header_t * top)
{
    dap_http_header_t * ret;
    log_it(L_DEBUG, "Print HTTP headers");
    for(ret=top; ret; ret=ret->next) {
        log_it(L_DEBUG, "%s: %s", ret->name, ret->value);
    }
}

/**
 * @brief dap_http_header_find Looks or the header with specified name
 * @param top Top of the list
 * @param name Name of the header
 * @return NULL if not found or pointer to structure with found item
 */
dap_http_header_t *dap_http_header_find( dap_http_header_t *top, const char *name )
{
  dap_http_header_t *ret;

  for( ret = top; ret; ret = ret->next )
    if( strcmp(ret->name, name) == 0 )
      return ret;

  return ret;
}

/**
 * @brief dap_http_headers_dup
 * @param a_top
 * @return
 */
dap_http_header_t * dap_http_headers_dup(dap_http_header_t * a_top)
{
    dap_http_header_t * l_hdr=NULL, * l_ret = NULL;
    DL_FOREACH(a_top,l_hdr){
        dap_http_header_t * l_hdr_copy = DAP_NEW_Z(dap_http_header_t);

        memcpy(l_hdr_copy->name, l_hdr->name, l_hdr_copy->name_len = l_hdr->name_len);
        memcpy(l_hdr_copy->value, l_hdr->value, l_hdr_copy->value_len = l_hdr->value_len);

        DL_APPEND(l_ret,l_hdr_copy);
    }
    return l_ret;
}
