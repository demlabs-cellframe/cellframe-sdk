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
#include <ctype.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_events_socket.h"
#include "dap_http_client.h"
#include "dap_http_header.h"

#define LOG_TAG "http_header"

extern  int s_debug_http;                                                   /* Should be declared in the dap_http_client.c */

#define $STRINI(a)  (a), sizeof((a))-1
struct ht_field {
    int     ht_field_code;                                                  /* Digital HTTP Code, see HTTP_FLD$K_* constants */
    char    name [128];                                                     /* Name of the HTTP Field */
    size_t  namelen;                                                        /* Length of the field */

} ht_fields [HTTP_FLD$K_EOL + 1] = {
    {HTTP_FLD$K_CONNECTION,     $STRINI("Connection")},
    {HTTP_FLD$K_CONTENT_TYPE,   $STRINI("Content-Type")},
    {HTTP_FLD$K_CONTENT_LEN,    $STRINI("Content-Length")},
    {HTTP_FLD$K_COOKIE,         $STRINI("Cookie")},

    {-1, {0}, 0},                                                           /* End-of-list marker, dont' touch!!! */
};
#undef  $STRINI



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

int dap_http_header_parse(dap_http_client_t *cl_ht, const char *ht_line, size_t ht_line_len)
{
char *l_cp, *l_pname, *l_pval;
size_t l_strlen, l_len, l_namelen, l_valuelen;
struct ht_field *l_ht;
dap_http_header_t *l_new_header;

    debug_if(s_debug_http, L_DEBUG, "Parse header string (%zu octets) : '%.*s'",  ht_line_len, (int) ht_line_len, ht_line);

    /* Check for HTTP End-Of-Header sequence */
    if ( (ht_line_len == 2) && (*ht_line == CR) && ( *(ht_line + 1) == LF) )
        return  1;


    /*
     * "Content-Type: application/x-www-form-urlencoded"
     */
    if ( ((l_strlen = ht_line_len) < 4) )
        return  log_it(L_ERROR, "Too short HTTP header field line: '%.*s'", (int) l_strlen, ht_line), -1;


    if ( !(l_cp = memchr(ht_line, ':', l_strlen)) )                         /* Try to find separator (':') */
        return  log_it(L_ERROR, "Illformed HTTP header field line: '%.*s'", (int) l_strlen, ht_line), -1;

    l_pname = (char *) ht_line;
    l_namelen = l_cp - ht_line;

    debug_if(s_debug_http, L_DEBUG, "HTTP header field: '%.*s'", (int) l_namelen, l_pname);

    /*
     * So at this moment we known start and end of a field name, so we can try to recognize it
     * against a set of interested fields
     */
    for ( l_ht = ht_fields; l_ht->namelen; l_ht++)
        {
            if ( l_namelen == l_ht->namelen )
                if ( !memcmp(l_pname, l_ht->name, l_namelen) )
                    break;
            }


    if ( l_ht->namelen )
        debug_if(s_debug_http, L_DEBUG, "Interested HTTP header field: '%.*s'", (int) l_namelen, l_pname);

    /*
     * <l_ht> point to has been recognized field.
     * So, at this point we are ready to extract a value part of the string
     */
    l_pval = l_cp + 1;                                                      /* Skip ':' */
    l_len = l_strlen - (l_pval - ht_line);                                  /* Compute a length of data after ':' */
    for (; isspace(*l_pval) && l_len; l_pval++, l_len-- );                  /* Skip possible whitespaces on begin ... */

    l_valuelen = l_len > 2 ? l_len - 2 : 0;                                                /* Exclude CRLF at end of HTTP header field */

    switch (l_ht->ht_field_code )
    {
        case    HTTP_FLD$K_CONNECTION:
            cl_ht->keep_alive = !strncasecmp(l_pval, "Keep-Alive", l_valuelen);
            break;

        case    HTTP_FLD$K_CONTENT_TYPE:
            memcpy( cl_ht->in_content_type, l_pval, l_len = MIN(l_valuelen, sizeof(cl_ht->in_content_type) - 1) );
            cl_ht->in_content_type[l_valuelen] = '\0';
            break;

        case    HTTP_FLD$K_CONTENT_LEN:
            {
            char digit[32] = {0};
            memcpy(digit, l_pval, MIN(l_valuelen, sizeof(digit) - 1));
            cl_ht->in_content_length = atoi( digit );
        }
            break;

        case    HTTP_FLD$K_COOKIE:
            memcpy(cl_ht->in_cookie, l_pval, l_len = MIN(l_valuelen, sizeof(cl_ht->in_cookie) - 1) );
            cl_ht->in_cookie[l_valuelen] = '\0';
            break;
    }


    /* Make new Attribute-Value element to be added into the list of HTTP header fields */
    if ( !(l_new_header = DAP_NEW_Z(dap_http_header_t)) )                   /* Allocate memory for new AV pair */
        return log_it(L_ERROR, "No memory for new AV element: '%.*s'/'%.*s'",
                        (int) l_namelen, l_pname, (int) l_valuelen, l_pval), -ENOMEM;

    l_new_header->name = DAP_CALLOC(l_namelen + 1, sizeof(char));
    memcpy(l_new_header->name, l_pname, l_new_header->namesz = l_namelen);

    l_new_header->value = DAP_CALLOC(l_valuelen + 1, sizeof(char));
    memcpy(l_new_header->value, l_pval, l_new_header->valuesz = l_valuelen);

    DL_APPEND(cl_ht->in_headers, l_new_header);

    return 0;
}



/**
 * @brief http_header_add Add HTTP header to the HTTP server instance
 * @param sh HTTP server instance
 * @param name  Header's name
 * @param value Header's value
 * @return Pointer to the new HTTP header's structure
 */
dap_http_header_t *dap_http_header_add(dap_http_header_t **a_top, const char *a_name, const char *a_value)
{
    dap_http_header_t *l_new_header = DAP_NEW_Z(dap_http_header_t);
    l_new_header->name = dap_strdup(a_name);
    l_new_header->value = dap_strdup(a_value);
    DL_APPEND(*a_top, l_new_header);
    return l_new_header;

}


struct dap_http_header* dap_http_out_header_add(dap_http_client_t *ht, const char *name, const char *value)
{
    return dap_http_header_add(&ht->out_headers,name,value);
}


/**
 * @brief dap_http_out_header_add_f Add header to the output queue with format-filled string
 * @param ht HTTP client instance
 * @param name Header name
 * @param value Formatted string to header value
 * @param ... Arguments for formatted string
 * @return
 */
dap_http_header_t * dap_http_out_header_add_f(dap_http_client_t *ht, const char *name, const char *value, ...)
{
    va_list ap;
    dap_http_header_t * ret;
    char buf[1024];
    va_start(ap,value);
    dap_vsnprintf(buf,sizeof(buf)-1,value,ap);
    ret=dap_http_out_header_add(ht,name,buf);
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
    DAP_DELETE(a_hdr->name);
    DAP_DELETE(a_hdr->value);
    DAP_DELETE(a_hdr);

}

void print_dap_http_headers(dap_http_header_t * a_ht)
{
    debug_if (s_debug_http, L_DEBUG, "Print HTTP headers");

    for(; a_ht; a_ht = a_ht->next)
        debug_if (s_debug_http, L_DEBUG, "%s: %s", a_ht->name, a_ht->value);
}

/**
 * @brief dap_http_header_find Looks or the header with specified name
 * @param top Top of the list
 * @param name Name of the header
 * @return NULL if not found or pointer to structure with found item
 */
dap_http_header_t *dap_http_header_find( dap_http_header_t *ht, const char *name )
{
    for(; ht; ht = ht->next)
        if( strcmp(ht->name, name) == 0 )
            return ht;

    return  NULL;
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
        l_hdr_copy->name = dap_strdup(l_hdr->name);
        l_hdr_copy->value = dap_strdup(l_hdr->value);
        DL_APPEND(l_ret,l_hdr_copy);
    }

    return l_ret;
}
