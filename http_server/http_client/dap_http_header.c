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
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "dap_common.h"
#include "dap_client.h"
#include "dap_http_client.h"
#include "dap_http_header.h"

#define LOG_TAG "http_header"


/**
 * @brief dap_http_header_init Init module
 * @return Zero if ok others if not
 */
int dap_http_header_init()
{
    log_it(L_NOTICE, "Initialized HTTP headers module");
    return 0;
}

/**
 * @brief dap_http_header_deinit Deinit module
 */
void dap_http_header_deinit()
{
    log_it(L_INFO, "HTTP headers module deinit");
}


/**
 * @brief dap_http_header_parse Parse string with HTTP header
 * @param top Top of list with HTTP header structures
 * @param str String to parse
 * @return Zero if parsed well -1 if it wasn't HTTP header 1 if its "\r\n" string
 */
int dap_http_header_parse(struct dap_http_client * cl_ht, const char * str)
{

    char name[256], value[1024];

    size_t str_len=strlen(str);
    //sn=sscanf(str,"%255s: %1023s\r\n",name,value);
    size_t pos;
    if( str_len==0 )
        return 1;

    //log_it(L_DEBUG, "Parse header string '%s'",str);
    for(pos=1; pos<str_len;pos++)
        if(str[pos]==':'){
            size_t name_len;
            name_len=pos;
            if(name_len>(sizeof(name)-1) )
                name_len=(sizeof(name)-1);
            strncpy(name,str,name_len);
            name[name_len]='\0';

       //     log_it(L_DEBUGUG, "Found name '%s'",name);
            pos+=2;
            size_t value_len=str_len-pos;
            if(value_len>(sizeof(value)-1))
                value_len=(sizeof(value)-1);
            strncpy(value,str+pos,value_len);
            value[value_len]='\0';
           // log_it(L_DEBUGUG, "Found value '%s'",value);

            if(strcmp(name,"Connection")==0){
                if(strcmp(value,"Keep-Alive")==0){
                    log_it(L_INFO, "Input: Keep-Alive connection detected");
                    cl_ht->keep_alive=true;
                }
            }else if(strcmp(name,"Content-Type")==0){
                strncpy(cl_ht->in_content_type,value,sizeof(cl_ht->in_content_type));
            }else if(strcmp(name,"Content-Length")==0){
                cl_ht->in_content_length =atoi(value);
            }else  if(strcmp(name,"Cookie")==0){
                strncpy(cl_ht->in_cookie,value,sizeof(cl_ht->in_cookie));
            }


            //log_it(L_DEBUG, "Input: Header\t%s '%s'",name,value);

            dap_http_header_add(&cl_ht->in_headers,name,value);
            return 0;
        }


    log_it(L_ERROR,"Input: Wasn't found ':' symbol in the header");
    return -1;
}



/**
 * @brief http_header_add Add HTTP header to the HTTP server instance
 * @param sh HTTP server instance
 * @param name  Header's name
 * @param value Header's value
 * @return Pointer to the new HTTP header's structure
 */
dap_http_header_t* dap_http_header_add(dap_http_header_t ** top, const char*name, const char * value)
{
    dap_http_header_t * nh = (dap_http_header_t*) calloc(1,sizeof(dap_http_header_t));
  //  log_it(L_DEBUG,"Added header %s",name);
    nh->name=strdup(name);
    nh->value=strdup(value);
    nh->next=*top;
    if(*top)
        (*top)->prev=nh;
    *top=nh;
    return nh;
}


struct dap_http_header* dap_http_out_header_add(dap_http_client_t * ht, const char*name, const char * value)
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
dap_http_header_t * dap_http_out_header_add_f(dap_http_client_t * ht, const char*name, const char * value,...)
{
    va_list ap;
    dap_http_header_t * ret;
    char buf[1024];
    va_start(ap,value);
    vsnprintf(buf,sizeof(buf)-1,value,ap);
    ret=dap_http_out_header_add(ht,name,buf);
    va_end(ap);
    return ret;
}

/**
 * @brief dap_http_header_remove Removes header from the list
 * @param dap_hdr HTTP header
 */
void dap_http_header_remove(dap_http_header_t ** top, dap_http_header_t * hdr )
{
    if(hdr->prev)
        hdr->prev=hdr->next;
    else
        *top=hdr->next;

    if(hdr->next)
        hdr->next->prev=hdr->prev;
    free(hdr->name);
    free(hdr->value);
}

/**
 * @brief dap_http_header_find Looks or the header with specified name
 * @param top Top of the list
 * @param name Name of the header
 * @return NULL if not found or pointer to structure with found item
 */
dap_http_header_t * dap_http_header_find(dap_http_header_t * top, const char*name)
{
    dap_http_header_t * ret;
    for(ret=top; ret; ret=ret->next)
        if(strcmp(ret->name,name)==0)
            return ret;
    return ret;
}
