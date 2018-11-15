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
#include <stdint.h>
#include "dap_common.h"

#include "dap_http.h"
#include "dap_http_client.h"
#include "dap_http_simple.h"

#include "dap_enc.h"
#include "dap_enc_ks.h"
#include "dap_enc_key.h"
#include "dap_enc_iaes.h"
#include "dap_enc_http.h"
#include "dap_enc_base64.h"
#include "dap_enc_msrln.h"


#define LOG_TAG "dap_enc_http"

int enc_http_init()
{
    return 0;
}

void enc_http_deinit()
{
}


/**
 * @brief enc_http_proc Enc http interface
 * @param cl_st HTTP Simple client instance
 * @param arg Pointer to bool with okay status (true if everything is ok, by default)
 */
void enc_http_proc(struct dap_http_simple *cl_st, void * arg)
{
    log_it(L_DEBUG,"Proc enc http request");
    bool * isOk= (bool*)arg;

    if(strcmp(cl_st->http->url_path,"gd4y5yh78w42aaagh") == 0 ) {

        uint8_t alice_msg[cl_st->request_size];
        size_t decode_len = dap_enc_base64_decode(cl_st->request, cl_st->request_size, alice_msg, DAP_ENC_DATA_TYPE_B64);
        if(decode_len != MSRLN_PKA_BYTES) {
            log_it(L_WARNING, "Wrong http_enc request. Key not equal MSRLN_PKA_BYTES");
            *isOk=false;
            return;
        }

        dap_enc_key_t* msrln_key = dap_enc_key_new(DAP_ENC_KEY_TYPE_MSRLN);

        msrln_key->gen_bob_shared_key(msrln_key, alice_msg, MSRLN_PKA_BYTES, (void**)&msrln_key->pub_key_data);

        dap_enc_ks_key_t * key_ks = dap_enc_ks_add(NULL);

        char encrypt_msg[DAP_ENC_BASE64_ENCODE_SIZE(msrln_key->pub_key_data_size) + 1];
        size_t encrypt_msg_size = dap_enc_base64_encode(msrln_key->pub_key_data, msrln_key->pub_key_data_size, encrypt_msg, DAP_ENC_DATA_TYPE_B64);
        encrypt_msg[encrypt_msg_size] = '\0';

        key_ks->key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_IAES,
                                               msrln_key->priv_key_data, // shared key
                                               msrln_key->priv_key_data_size,
                                               key_ks->id, DAP_ENC_KS_KEY_ID_SIZE, 0);

        char encrypt_id[DAP_ENC_BASE64_ENCODE_SIZE(DAP_ENC_KS_KEY_ID_SIZE) + 1];

        size_t encrypt_id_size = dap_enc_base64_encode(key_ks->id, DAP_ENC_KS_KEY_ID_SIZE, encrypt_id, DAP_ENC_DATA_TYPE_B64);
        encrypt_id[encrypt_id_size] = '\0';

        dap_http_simple_reply_f(cl_st, "%s %s", encrypt_id, encrypt_msg);

        dap_enc_key_delete(msrln_key);
    } else{
        log_it(L_ERROR,"Wrong path '%s' in the request to enc_http module",cl_st->http->url_path);
        *isOk=false;
    }
}

/**
 * @brief enc_http_add_proc
 * @param sh
 * @param url
 */
void enc_http_add_proc(struct dap_http * sh, const char * url)
{
    dap_http_simple_proc_add(sh,url,40000,enc_http_proc);
}

enc_http_delegate_t *enc_http_request_decode(struct dap_http_simple *cl_st)
{

    dap_enc_key_t * key= dap_enc_ks_find_http(cl_st->http);
    if(key){
        enc_http_delegate_t * dg = DAP_NEW_Z(enc_http_delegate_t);
        dg->key=key;
        dg->http=cl_st->http;
        dg->isOk=true;

        strncpy(dg->action,cl_st->http->action,sizeof(dg->action)-1);
        if(cl_st->http->in_cookie[0])
            dg->cookie=strdup(cl_st->http->in_cookie);

        if(cl_st->request_size){
            //  dg->request=calloc(1,cl_st->request_size+1);
            dg->request_size=dap_enc_decode(key, cl_st->request, cl_st->request_size,&dg->request,DAP_ENC_DATA_TYPE_RAW);
            dg->request_str[dg->request_size] = 0;
            log_it(L_DEBUG,"Request after decode '%s'",dg->request_str);
            // log_it(L_DEBUG,"Request before decode: '%s' after decode '%s'",cl_st->request_str,dg->request_str);
        }

        dap_enc_data_type_t l_enc_type;
        int protocol_version = 21; //TODO: Get protocol version
        if(protocol_version >= 21  )
            l_enc_type = DAP_ENC_DATA_TYPE_B64_URLSAFE;
        else
            l_enc_type = DAP_ENC_DATA_TYPE_B64;

        size_t url_path_size=strlen(cl_st->http->url_path);
        if(url_path_size){
            //    dg->url_path=calloc(1,url_path_size+1);
            dg->url_path_size=dap_enc_decode(key, cl_st->http->url_path,url_path_size,&dg->url_path,l_enc_type);
            dg->url_path[dg->url_path_size] = 0;
            log_it(L_DEBUG,"URL path after decode '%s'",dg->url_path );
            // log_it(L_DEBUG,"URL path before decode: '%s' after decode '%s'",cl_st->http->url_path,dg->url_path );
        }

        size_t in_query_size=strlen(cl_st->http->in_query_string);

        if(in_query_size){
            // dg->in_query=calloc(1,in_query_size+1);
            dg->in_query_size=dap_enc_decode(key, cl_st->http->in_query_string,in_query_size,&dg->in_query,l_enc_type);
            dg->in_query[dg->in_query_size] = 0;
            log_it(L_DEBUG,"Query string after decode '%s'",dg->in_query);
        }
        dg->response = calloc(1,cl_st->reply_size_max+1);
        dg->response_size_max=cl_st->reply_size_max;

        return dg;
    }else{
        log_it(L_WARNING,"No Key was found in the request");
        return NULL;
    }
}

void enc_http_reply_encode(struct dap_http_simple *cl_st,enc_http_delegate_t * dg)
{
    dap_enc_key_t * key = dap_enc_ks_find_http(cl_st->http);
    if( key == NULL ) {
        log_it(L_ERROR, "Can't find http key.");
        return;
    }
    if(dg->response){

        if(cl_st->reply)
            free(cl_st->reply);
        cl_st->reply_size = dap_enc_code(dg->key,dg->response,dg->response_size,&cl_st->reply,DAP_ENC_DATA_TYPE_RAW);
    }

}

void enc_http_delegate_delete(enc_http_delegate_t * dg)
{
    if(dg->cookie)
        free(dg->cookie);
    if(dg->in_query)
        free(dg->in_query);
    if(dg->request)
        free(dg->request);
    if(dg->response)
        free(dg->response);
    if(dg->url_path)
        free(dg->url_path);
    free(dg);
}

size_t enc_http_reply(enc_http_delegate_t * dg, void * data, size_t data_size)
{
    size_t wb= (data_size > (dg->response_size_max - dg->response_size) )? (dg->response_size_max - dg->response_size):data_size;
    memcpy(dg->response+dg->response_size,data,wb);
    dg->response_size+=wb;
    return wb;
}

size_t enc_http_reply_f(enc_http_delegate_t * dg, const char * data, ...)
{
    va_list ap;
    va_start(ap, data);
    int mem_size = vsnprintf(0, 0, data, ap);
    va_end(ap);
    char *buf = (char*)malloc(sizeof(char) * mem_size + 1);
    if(buf) {
        va_start(ap, data);
        vsprintf(buf, data, ap);
        va_end(ap);
        return enc_http_reply(dg,buf,mem_size);
    }else
        log_it(L_ERROR, "Can not memmory allocate");
    return 0;
}

