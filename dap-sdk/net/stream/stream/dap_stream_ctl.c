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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#endif

#include "dap_common.h"

#include "dap_stream.h"

#include "dap_enc_http.h"
#include "dap_enc_key.h"

#include "dap_http.h"
#include "dap_http_client.h"
#include "dap_events_socket.h"
#include "dap_http_simple.h"

#include "dap_stream_session.h"
#include "dap_stream_ctl.h"
#include "http_status_code.h"
#include "dap_enc_ks.h"

#define LOG_TAG "dap_stream_ctl"

const char* connection_type_str[] =
{
        [STEAM_SESSION_HTTP] = "http",
        [STREAM_SESSION_UDP] = "udp"
};

#define DAPMP_VERSION 13
bool stream_check_proto_version(unsigned int ver);
void s_proc(struct dap_http_simple *cl_st, void * arg);

static struct {
    size_t size;
    dap_enc_key_type_t type;
} s_socket_forward_key;

/**
 * @brief stream_ctl_init Initialize stream control module
 * @return Zero if ok others if not
 */
int dap_stream_ctl_init()
{
    s_socket_forward_key.size = 32; // Why do we set it, not autodeceting?
    s_socket_forward_key.type = dap_stream_get_preferred_encryption_type();

    return 0;
}

/**
 * @brief stream_ctl_deinit Deinit stream control module
 */
void dap_stream_ctl_deinit()
{

}

/**
 * @brief stream_ctl_add_proc Add stream control url processor
 * @param sh HTTP server instance
 * @param url URL string
 */
void dap_stream_ctl_add_proc(struct dap_http * sh, const char * url)
{
     dap_http_simple_proc_add(sh,url,14096,s_proc);
}


/**
 * @brief s_proc Process CTL request
 * @param cl_st HTTP server instance
 * @param arg Not used
 */
void s_proc(struct dap_http_simple *a_http_simple, void * a_arg)
{
    http_status_code_t * return_code = (http_status_code_t*)a_arg;

   // unsigned int proto_version;
    dap_stream_session_t * ss=NULL;
   // unsigned int action_cmd=0;
    bool l_new_session = false;

    enc_http_delegate_t *l_dg = enc_http_request_decode(a_http_simple);

    if(l_dg){
        size_t l_channels_str_size = sizeof(ss->active_channels);
        char l_channels_str[sizeof(ss->active_channels)];
        dap_enc_key_type_t l_enc_type = s_socket_forward_key.type;
        size_t l_enc_key_size = 32;
        int l_enc_headers = 0;
        bool l_is_legacy=true;
        char * l_tok_tmp = l_dg->url_path;
        char * l_tok = strtok_r(l_dg->url_path, ",",&l_tok_tmp)   ;
        do {
            char * l_subtok_tmp = NULL;
            char * l_subtok_name = strtok_r(l_tok, "=",&l_subtok_tmp);
            char * l_subtok_value = strtok_r(NULL, "=",&l_subtok_tmp);
            if (l_subtok_value){
                //log_it(L_DEBUG, "tok = %s value =%s",l_subtok_name,l_subtok_value);
                if ( strcmp(l_subtok_name,"channels")==0 ){
                    strncpy(l_channels_str,l_subtok_value,sizeof (l_channels_str)-1);
                    //log_it(L_DEBUG,"Param: channels=%s",l_channels_str);
                }else if(strcmp(l_subtok_name,"enc_type")==0){
                    l_enc_type = atoi(l_subtok_value);
                    //log_it(L_DEBUG,"Param: enc_type=%s",dap_enc_get_type_name(l_enc_type));
                    l_is_legacy = false;
                }else if(strcmp(l_subtok_name,"enc_key_size")==0){
                    l_enc_key_size = (size_t) atoi(l_subtok_value);
                    if (l_enc_key_size > l_dg->request_size )
                        l_enc_key_size = 32;
                    //log_it(L_DEBUG,"Param: enc_type=%s",dap_enc_get_type_name(l_enc_type));
                    l_is_legacy = false;
                }else if(strcmp(l_subtok_name,"enc_headers")==0){
                    l_enc_headers = atoi(l_subtok_value);
                    //log_it(L_DEBUG,"Param: enc_headers=%d",l_enc_headers);
                }
            }
            l_tok = strtok_r(NULL, ",",&l_tok_tmp)   ;
        } while(l_tok);
        l_new_session = true;
        if(l_is_legacy){
            log_it(L_INFO, "legacy encryption mode used (OAES)");
            l_enc_type = DAP_ENC_KEY_TYPE_OAES;
            l_new_session = true;
        }else
            log_it(L_DEBUG,"Encryption type %s (enc headers %d)",dap_enc_get_type_name(l_enc_type), l_enc_headers);

        if(l_new_session){
            ss = dap_stream_session_pure_new();
            strncpy(ss->active_channels, l_channels_str, l_channels_str_size);
            char *key_str = calloc(1, KEX_KEY_STR_SIZE+1);
            dap_random_string_fill(key_str, KEX_KEY_STR_SIZE);
            ss->key = dap_enc_key_new_generate( l_enc_type, key_str, KEX_KEY_STR_SIZE,
                                               NULL, 0, s_socket_forward_key.size);
            dap_http_header_t *l_hdr_key_id = dap_http_header_find(a_http_simple->http_client->in_headers, "KeyID");
            if (l_hdr_key_id) {
                dap_enc_ks_key_t *l_ks_key = dap_enc_ks_find(l_hdr_key_id->value);
                if (!l_ks_key) {
                    log_it(L_WARNING, "Key with ID %s not found", l_hdr_key_id->value);
                    *return_code = Http_Status_BadRequest;
                    return;
                }
                ss->acl = l_ks_key->acl_list;
            }
            if (l_is_legacy)
                enc_http_reply_f(l_dg,"%u %s",ss->id, key_str);
            else
                enc_http_reply_f(l_dg,"%u %s %u %d %d",ss->id, key_str, DAP_PROTOCOL_VERSION, l_enc_type, l_enc_headers);
            *return_code = Http_Status_OK;

            log_it(L_INFO," New stream session %u initialized",ss->id);

            free(key_str);
        }else{
            log_it(L_ERROR,"Wrong request: \"%s\"",l_dg->in_query);
            *return_code = Http_Status_BadRequest;
            return;
        }

        enc_http_reply_encode(a_http_simple,l_dg);
        enc_http_delegate_delete(l_dg);
    }else{
        log_it(L_ERROR,"No encryption layer was initialized well");
        *return_code = Http_Status_BadRequest;
    }
}


bool stream_check_proto_version(unsigned int ver)
{
    return ver<=DAPMP_VERSION;
}
