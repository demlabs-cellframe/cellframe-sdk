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
#include "dap_client_remote.h"
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
int dap_stream_ctl_init(dap_enc_key_type_t socket_forward_key_type,
                        size_t socket_forward_key_size)
{
    s_socket_forward_key.type = socket_forward_key_type;
    s_socket_forward_key.size = socket_forward_key_size;
    log_it(L_NOTICE,"Initialized stream control module");
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
        if(l_dg->url_path && strlen(l_dg->url_path) < 30 &&
                sscanf(l_dg->url_path, "stream_ctl,channels=%s", l_channels_str) == 1) {
            l_new_session = true;
        }
        else if(strcmp(l_dg->url_path, "socket_forward" ) == 0) {
            l_channels_str[0]  = '\0';
            l_new_session = true;
        }
        /* }else if (strcmp(dg->url_path,"stream_ctl")==0) {
            l_new_session = true;
        }*/
        else{
            log_it(L_ERROR,"ctl command unknown: %s",l_dg->url_path);
            enc_http_delegate_delete(l_dg);
            *return_code = Http_Status_MethodNotAllowed;
            return;
        }
        if(l_new_session){

            ss = dap_stream_session_pure_new();
            strncpy(ss->active_channels, l_channels_str, l_channels_str_size);
            char *key_str = calloc(1, KEX_KEY_STR_SIZE+1);
            dap_random_string_fill(key_str, KEX_KEY_STR_SIZE);
            ss->key = dap_enc_key_new_generate( s_socket_forward_key.type, key_str, KEX_KEY_STR_SIZE,
                                               NULL, 0, s_socket_forward_key.size);
            dap_http_header_t *l_hdr_key_id = dap_http_header_find(a_http_simple->http->in_headers, "KeyID");
            if (l_hdr_key_id) {
                dap_enc_ks_key_t *l_ks_key = dap_enc_ks_find(l_hdr_key_id->value);
                ss->acl = l_ks_key->acl_list;
            }
            enc_http_reply_f(l_dg,"%u %s",ss->id,key_str);
            *return_code = Http_Status_OK;

            log_it(L_INFO," New stream session %u initialized",ss->id);

            free(key_str);
        }else{
            log_it(L_ERROR,"Wrong request: \"%s\"",l_dg->in_query);
            *return_code = Http_Status_BadRequest;
        }

        unsigned int conn_t = 0;
        char *ct_str = strstr(l_dg->in_query, "connection_type");
        if (ct_str)
        {
            sscanf(ct_str, "connection_type=%u", &conn_t);
            if (conn_t < 0 || conn_t >= STREAM_SESSION_END_TYPE)
            {
                log_it(L_WARNING,"Error connection type : %i",conn_t);
                conn_t = STEAM_SESSION_HTTP;
            }

            if (ss)
            {
                ss->conn_type = conn_t;
            }

        }

        log_it(L_INFO,"setup connection_type: %s", connection_type_str[conn_t]);

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
