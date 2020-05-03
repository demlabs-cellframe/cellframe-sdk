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

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <time.h>
#endif

#include <pthread.h>


#include "dap_common.h"

#include "include/dap_http.h"
#include "dap_http_client.h"
#include "include/dap_http_simple.h"

#include "dap_enc.h"
#include "include/dap_enc_ks.h"
#include "dap_enc_key.h"
#include "dap_enc_iaes.h"
#include "include/dap_enc_http.h"
#include "dap_enc_base64.h"
#include "dap_enc_msrln.h"
#include "include/http_status_code.h"
#include <json-c/json.h>


#define LOG_TAG "dap_enc_http"

int enc_http_init()
{
    return 0;
}

void enc_http_deinit()
{

}

static void _enc_http_write_reply(struct dap_http_simple *cl_st,
                                  const char* encrypt_id,
                                  const char* encrypt_msg)
{
    struct json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "encrypt_id", json_object_new_string(encrypt_id));
    json_object_object_add(jobj, "encrypt_msg", json_object_new_string(encrypt_msg));
    const char* json_str = json_object_to_json_string(jobj);
    dap_http_simple_reply(cl_st, (void*) json_str,
                          (size_t) strlen(json_str));
    json_object_put(jobj);
}

void dap_enc_http_json_response_format_enable(bool);
/**
 * @brief enc_http_proc Enc http interface
 * @param cl_st HTTP Simple client instance
 * @param arg Pointer to bool with okay status (true if everything is ok, by default)
 */
void enc_http_proc(struct dap_http_simple *cl_st, void * arg)
{
    log_it(L_DEBUG,"Proc enc http request");
    http_status_code_t * return_code = (http_status_code_t*)arg;

    if(strcmp(cl_st->http->url_path,"gd4y5yh78w42aaagh") == 0 ) {

        uint8_t alice_msg[cl_st->request_size];
        size_t decode_len = dap_enc_base64_decode(cl_st->request, cl_st->request_size, alice_msg, DAP_ENC_DATA_TYPE_B64);
        if(decode_len != MSRLN_PKA_BYTES) {
            log_it(L_WARNING, "Wrong http_enc request. Key not equal MSRLN_PKA_BYTES");
            *return_code = Http_Status_BadRequest;
            return;
        }

        dap_enc_key_t* msrln_key = dap_enc_key_new(DAP_ENC_KEY_TYPE_MSRLN);
        msrln_key->gen_bob_shared_key(msrln_key, alice_msg, MSRLN_PKA_BYTES, (void**)&msrln_key->pub_key_data);

        dap_enc_ks_key_t * key_ks = dap_enc_ks_new();

        char encrypt_msg[DAP_ENC_BASE64_ENCODE_SIZE(msrln_key->pub_key_data_size) + 1];
        size_t encrypt_msg_size = dap_enc_base64_encode(msrln_key->pub_key_data, msrln_key->pub_key_data_size, encrypt_msg, DAP_ENC_DATA_TYPE_B64);
        encrypt_msg[encrypt_msg_size] = '\0';

        key_ks->key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_IAES,
                                               msrln_key->priv_key_data, // shared key
                                               msrln_key->priv_key_data_size,
                                               key_ks->id, DAP_ENC_KS_KEY_ID_SIZE, 0);
        dap_enc_ks_save_in_storage(key_ks);

        char encrypt_id[DAP_ENC_BASE64_ENCODE_SIZE(DAP_ENC_KS_KEY_ID_SIZE) + 1];

        size_t encrypt_id_size = dap_enc_base64_encode(key_ks->id, DAP_ENC_KS_KEY_ID_SIZE, encrypt_id, DAP_ENC_DATA_TYPE_B64);
        encrypt_id[encrypt_id_size] = '\0';

        _enc_http_write_reply(cl_st, encrypt_id, encrypt_msg);

        dap_enc_key_delete(msrln_key);

        *return_code = Http_Status_OK;
    } else{
        log_it(L_ERROR,"Wrong path '%s' in the request to enc_http module",cl_st->http->url_path);
        *return_code = Http_Status_NotFound;
    }
}

/**
 * @brief enc_http_add_proc
 * @param sh
 * @param url
 */
void enc_http_add_proc(struct dap_http * sh, const char * url)
{
    dap_http_simple_proc_add(sh,url,140000,enc_http_proc);
}

/**
 * @brief enc_http_request_decode
 * @param a_http_simple
 * @return
 */
enc_http_delegate_t *enc_http_request_decode(struct dap_http_simple *a_http_simple)
{

    dap_enc_key_t * l_key= dap_enc_ks_find_http(a_http_simple->http);
    if(l_key){
        enc_http_delegate_t * dg = DAP_NEW_Z(enc_http_delegate_t);
        dg->key=l_key;
        dg->http=a_http_simple->http;
       // dg->isOk=true;

        strncpy(dg->action,a_http_simple->http->action,sizeof(dg->action)-1);
        if(a_http_simple->http->in_cookie[0])
            dg->cookie=strdup(a_http_simple->http->in_cookie);

        if(a_http_simple->request_size){
            size_t l_dg_request_size_max = a_http_simple->request_size;
            dg->request= DAP_NEW_SIZE( void , l_dg_request_size_max+1);
            dg->request_size=dap_enc_decode(l_key, a_http_simple->request, a_http_simple->request_size,dg->request,
                                            l_dg_request_size_max, DAP_ENC_DATA_TYPE_RAW);
            dg->request_str[dg->request_size] = 0;
            // log_it(L_DEBUG,"Request after decode '%s'",dg->request_str);
            // log_it(L_DEBUG,"Request before decode: '%s' after decode '%s'",cl_st->request_str,dg->request_str);
        }

        dap_enc_data_type_t l_enc_type;
        int protocol_version = 21; //TODO: Get protocol version
        if(protocol_version >= 21  )
            l_enc_type = DAP_ENC_DATA_TYPE_B64_URLSAFE;
        else
            l_enc_type = DAP_ENC_DATA_TYPE_B64;

        size_t l_url_path_size_max = strlen(a_http_simple->http->url_path);
        if(l_url_path_size_max){
            dg->url_path= DAP_NEW_SIZE(char,l_url_path_size_max+1);
            dg->url_path_size=dap_enc_decode(l_key, a_http_simple->http->url_path,l_url_path_size_max,dg->url_path, l_url_path_size_max, l_enc_type);
            dg->url_path[dg->url_path_size] = 0;
            log_it(L_DEBUG,"URL path after decode '%s'",dg->url_path );
            // log_it(L_DEBUG,"URL path before decode: '%s' after decode '%s'",cl_st->http->url_path,dg->url_path );
        }

        size_t l_in_query_size=strlen(a_http_simple->http->in_query_string);

        if(l_in_query_size){
            dg->in_query= DAP_NEW_SIZE(char, l_in_query_size+1);
            dg->in_query_size=dap_enc_decode(l_key, a_http_simple->http->in_query_string,l_in_query_size,dg->in_query,l_in_query_size,  l_enc_type);
            dg->in_query[dg->in_query_size] = 0;
            log_it(L_DEBUG,"Query string after decode '%s'",dg->in_query);
        }
        dg->response = calloc(1,a_http_simple->reply_size_max+1);
        dg->response_size_max=a_http_simple->reply_size_max;

        return dg;
    }else{
        log_it(L_WARNING,"No Key was found in the request");
        return NULL;
    }
}

/**
 * @brief enc_http_reply_encode
 * @param a_http_simple
 * @param a_http_delegate
 */
void enc_http_reply_encode(struct dap_http_simple *a_http_simple,enc_http_delegate_t * a_http_delegate)
{
    dap_enc_key_t * key = dap_enc_ks_find_http(a_http_simple->http);
    if( key == NULL ) {
        log_it(L_ERROR, "Can't find http key.");
        return;
    }
    if(a_http_delegate->response){

        if(a_http_simple->reply)
            free(a_http_simple->reply);

        size_t l_reply_size_max = dap_enc_code_out_size(a_http_delegate->key,
                                                          a_http_delegate->response_size,
                                                          DAP_ENC_DATA_TYPE_RAW);

        a_http_simple->reply = DAP_NEW_SIZE(void,l_reply_size_max);
        a_http_simple->reply_size = dap_enc_code( a_http_delegate->key,
                                                  a_http_delegate->response, a_http_delegate->response_size,
                                                  a_http_simple->reply, l_reply_size_max,
                                                  DAP_ENC_DATA_TYPE_RAW);
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
    int mem_size = dap_vsnprintf(0, 0, data, ap);

    va_end(ap);
    char *buf = (char*)malloc(sizeof(char) * mem_size + 1);
    if(buf) {
        va_start(ap, data);
        dap_vsprintf(buf, data, ap);
        va_end(ap);
        return enc_http_reply(dg,buf,mem_size);
    }else
        log_it(L_ERROR, "Can not memmory allocate");
    return 0;
}

