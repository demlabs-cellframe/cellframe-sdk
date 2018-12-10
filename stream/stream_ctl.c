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

#include <stdbool.h>
#include <string.h>
#include "dap_common.h"

#include "stream.h"

#include "dap_enc_http.h"
#include "dap_enc_key.h"

#include "dap_http.h"
#include "dap_http_client.h"
#include "dap_client_remote.h"
#include "dap_http_simple.h"

#include "http_status_code.h"

#include "stream_session.h"
#include "stream_ctl.h"

#define LOG_TAG "stream_ctl"

const char* connection_type_str[] =
{
		[STEAM_SESSION_HTTP] = "http",
		[STREAM_SESSION_UDP] = "udp"
};

#define DAPMP_VERSION 13
bool stream_check_proto_version(unsigned int ver);
void stream_ctl_proc(struct dap_http_simple *cl_st, void * arg);

/**
 * @brief stream_ctl_init Initialize stream control module
 * @return Zero if ok others if not
 */
int stream_ctl_init()
{
    log_it(L_NOTICE,"Initialized stream control module");
    return 0;
}

/**
 * @brief stream_ctl_deinit Deinit stream control module
 */
void stream_ctl_deinit()
{

}

/**
 * @brief stream_ctl_add_proc Add stream control url processor
 * @param sh HTTP server instance
 * @param url URL string
 */
void stream_ctl_add_proc(struct dap_http * sh, const char * url)
{
     dap_http_simple_proc_add(sh,url,4096,stream_ctl_proc);
}


/**
 * @brief stream_ctl_headers_read Process CTL request
 * @param cl_st HTTP server instance
 * @param arg Not used
 */
void stream_ctl_proc(struct dap_http_simple *cl_st, void * arg)
{
    http_status_code_t * return_code = (http_status_code_t*)arg;

	unsigned int db_id=0;
   // unsigned int proto_version;
	dap_stream_session_t * ss=NULL;
   // unsigned int action_cmd=0;
    bool l_new_session = false;

    enc_http_delegate_t *dg = enc_http_request_decode(cl_st);

    if(dg){
        if (strcmp(dg->url_path,"socket_forward")==0){
            l_new_session = true;
        }else if (strcmp(dg->url_path,"stream_ctl")==0) {
            l_new_session = true;
        }else{
            log_it(L_ERROR,"ctl command unknown: %s",dg->url_path);
            enc_http_delegate_delete(dg);
            *return_code = Http_Status_MethodNotAllowed;
            return;
        }
        if(l_new_session){

            ss = dap_stream_session_pure_new();
            char *key_str = calloc(1, KEX_KEY_STR_SIZE);
            dap_random_string_fill(key_str, KEX_KEY_STR_SIZE);
            ss->key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_IAES, key_str, strlen(key_str), NULL, 0, 0);
            enc_http_reply_f(dg,"%u %s",ss->id,key_str);
            *return_code = Http_Status_OK;

            log_it(L_INFO," New stream session %u initialized",ss->id);

            free(key_str);
        }else{
            log_it(L_ERROR,"Wrong request: \"%s\"",dg->in_query);
            *return_code = Http_Status_BadRequest;
        }

        unsigned int conn_t = 0;
        char *ct_str = strstr(dg->in_query, "connection_type");
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

        enc_http_reply_encode(cl_st,dg);
        enc_http_delegate_delete(dg);
    }else{
        log_it(L_ERROR,"No encryption layer was initialized well");
        *return_code = Http_Status_BadRequest;
    }
}


bool stream_check_proto_version(unsigned int ver)
{
    return ver<=DAPMP_VERSION;
}
