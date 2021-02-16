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
#include "utlist.h"
#include "dap_http.h"
#include "dap_http_cache.h"

#define LOG_TAG "http_cache"

/**
 * @brief dap_http_cache_update
 * @param a_url_proc
 * @param a_body
 * @param a_body_size
 * @param a_headers
 * @param a_response_phrase
 * @param a_respoonse_code
 * @param ts_expire
 * @return
 */
dap_http_cache_t * dap_http_cache_update(struct dap_http_url_proc * a_url_proc, const byte_t * a_body, size_t a_body_size,
                                         dap_http_header_t * a_headers, const char * a_response_phrase, int a_respoonse_code,
                                         time_t a_ts_expire )
{
    dap_http_cache_t * l_ret = DAP_NEW_Z(dap_http_cache_t);
    if(a_body_size){
        l_ret->body = DAP_NEW_SIZE(byte_t,a_body_size);
        memcpy(l_ret->body,a_body,a_body_size);
        l_ret->body_size = a_body_size;
    }
    l_ret->headers =  dap_http_headers_dup( a_headers);


    l_ret->ts_expire = a_ts_expire;
    l_ret->url_proc = a_url_proc;
    if(a_response_phrase)
        l_ret->response_phrase = strdup(a_response_phrase);
    l_ret->response_code = a_respoonse_code;

    //Here we cut off 'Date' header because we add it new on each cached request
    dap_http_header_t * l_hdr_date= dap_http_header_find(l_ret->headers,"Date");
    if(l_hdr_date)
        dap_http_header_remove(&l_ret->headers,l_hdr_date);


    // Reset current cache for url_proc and replace with our own
    pthread_rwlock_wrlock(&a_url_proc->cache_rwlock);
    dap_http_cache_delete(a_url_proc->cache);
    a_url_proc->cache = l_ret;
    pthread_rwlock_unlock(&a_url_proc->cache_rwlock);
    return l_ret;
}

/**
 * @brief dap_http_cache_delete
 * @param a_http_cache
 */
void dap_http_cache_delete(dap_http_cache_t * a_http_cache)
{
   if (a_http_cache){
       if(a_http_cache->body)
           DAP_DELETE(a_http_cache->body);
       dap_http_header_t *l_hdr=NULL, *l_tmp=NULL;

       DL_FOREACH_SAFE(a_http_cache->headers,l_hdr,l_tmp){
           DL_DELETE(a_http_cache->headers,l_hdr);
           if(l_hdr->name)
               DAP_DELETE(l_hdr->name);
           if(l_hdr->value)
               DAP_DELETE(l_hdr->value);
           DAP_DELETE(l_hdr);
       }
       DAP_DELETE(a_http_cache);
   }
}
