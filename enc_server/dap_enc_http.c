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
#include "dap_enc_http.h"
#include "dap_enc_base64.h"
#include "dap_enc_msrln16.h"
//#include "liboqs/kex_rlwe_msrln16/kex_rlwe_msrln16.h"
#include "liboqs/kex_rlwe_msrln16/kex_rlwe_msrln16.h"
#include "liboqs/kex/kex.h"


#define LOG_TAG "dap_enc_http"
#define RSA_KEY_LENGTH 4096
#define AES_KEY_LENGTH 16 // 128 ???

int enc_http_init()
{
   /* BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, my_config.key_public, strlen(my_config.key_public));

    PEM_read_bio_RSAPublicKey( bio, &public_key_server, NULL, NULL);

    BIO_free_all(bio);

    bio = BIO_new(BIO_s_mem());
    BIO_write(bio, my_config.key_private,strlen(my_config.key_private));

    PEM_read_bio_RSAPrivateKey(bio, &private_key_server, NULL, NULL);

    BIO_free_all(bio);

    if(public_key_server && private_key_server)
        return 0;
    else
        return -1;*/
    return 0;

}

void enc_http_deinit()
{
  /*  if(public_key_server)
        RSA_free(public_key_server);
    if(private_key_server)
        RSA_free(private_key_server);*/
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
    if(strcmp(cl_st->http->url_path,"hsd9jslagd92abgjalp9h") == 0 )
    {
        //Stage 1 : generate private key and alice message
        OQS_RAND* rand = OQS_RAND_new(OQS_RAND_alg_urandom_chacha20);
        dap_enc_key_t* key_session = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_RLWE_MSRLN16,16);
        dap_enc_msrln16_key_t* msrln16_key = DAP_ENC_KEY_TYPE_RLWE_MSRLN16(key_session);
        msrln16_key->kex = OQS_KEX_rlwe_msrln16_new(rand);
        uint8_t* out_msg = NULL;
        size_t out_msg_size = 0;
        OQS_KEX_rlwe_msrln16_alice_0(msrln16_key->kex,&msrln16_key->private_key,&out_msg,&out_msg_size);
        dap_enc_ks_key_t * key_ks = dap_enc_ks_add(key_session);

        char *sendMsg = malloc(out_msg_size * 2 + strlen(key_ks->id) * 2 + 1024);
        char encrypt_id[strlen(key_ks->id) * 2];

        dap_enc_base64_encode(key_ks->id,strlen(key_ks->id), encrypt_id,DAP_ENC_STANDARD_B64);

        char* encrypt_msg = malloc(out_msg_size * 2);
        dap_enc_base64_encode(out_msg,out_msg_size, encrypt_msg,DAP_ENC_STANDARD_B64);

        strcpy(sendMsg,encrypt_id);
        strcat(sendMsg," ");
        strcat(sendMsg,encrypt_msg);


        dap_http_simple_reply_f(cl_st,"%s",sendMsg);
        free(encrypt_msg);
        free(sendMsg);

        *isOk=true;
    }else if(strcmp(cl_st->http->url_path,"gd4y5yh78w42aaagh")==0 ){
        if(cl_st->request == NULL) {
            log_it(L_WARNING, "Received an empty request");
            *isOk = false;
            return;
        }
        //Stage 2 : generate bob public key and bob message
        OQS_RAND* rand = OQS_RAND_new(OQS_RAND_alg_urandom_chacha20);
        dap_enc_key_t* key_session = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_RLWE_MSRLN16,16);
        dap_enc_msrln16_key_t* msrln16_key = DAP_ENC_KEY_TYPE_RLWE_MSRLN16(key_session);
        msrln16_key->kex = OQS_KEX_rlwe_msrln16_new(rand);
        dap_enc_ks_key_t * key_ks = dap_enc_ks_add(key_session);

        uint8_t* out_msg = NULL;
        size_t out_msg_size = 0;
        char *msg_index = strchr(cl_st->request,' ');
        int key_size = (void*)msg_index - cl_st->request;
        int msg_size = cl_st->request_size - key_size - 1;
        uint8_t *encoded_msg = malloc(cl_st->request_size);
        dap_enc_base64_decode(cl_st->request,cl_st->request_size,encoded_msg,DAP_ENC_STANDARD_B64);


        OQS_KEX_rlwe_msrln16_bob(msrln16_key->kex,encoded_msg,1824,&out_msg,&out_msg_size,&msrln16_key->public_key,&msrln16_key->public_length);
        aes_key_from_msrln_pub(key_ks->key);

        char encrypt_id[strlen(key_ks->id) * 2];
        dap_enc_base64_encode(key_ks->id,strlen(key_ks->id), encrypt_id,DAP_ENC_STANDARD_B64);

        char* encrypt_msg = malloc(out_msg_size * 2);
        dap_enc_base64_encode(out_msg,out_msg_size, encrypt_msg,DAP_ENC_STANDARD_B64);

        char *sendMsg = malloc(out_msg_size * 2 + strlen(key_ks->id) * 2 + 1024);
        strcpy(sendMsg,encrypt_id);
        strcat(sendMsg," ");
        strcat(sendMsg,encrypt_msg);

        dap_http_simple_reply_f(cl_st,"%s",sendMsg);
        free(encrypt_msg);
        free(sendMsg);
        free(encoded_msg);

        *isOk=true;
    }else if(strcmp(cl_st->http->url_path,"klfdgki45b4jbnjdf5")==0 ){
        //Stage 3 : generate alice public key
        uint8_t* out_msg = NULL;
        size_t out_msg_size = 0;
        char *msg_index = strchr(cl_st->request,' ');
        int key_size = (void*)msg_index - cl_st->request;
        int msg_size = cl_st->request_size - key_size - 1;
        char* encoded_key = malloc(key_size);
        memset(encoded_key,0,key_size);
        uint8_t *encoded_msg = malloc(msg_size);
        dap_enc_base64_decode(cl_st->request,key_size,encoded_key,DAP_ENC_STANDARD_B64);
        dap_enc_base64_decode(msg_index+1,msg_size,encoded_msg,DAP_ENC_STANDARD_B64);
        dap_enc_ks_key_t *ks_key = dap_enc_ks_find(encoded_key);
        dap_enc_msrln16_key_t* msrln16_key = DAP_ENC_KEY_TYPE_RLWE_MSRLN16(ks_key->key);
        OQS_KEX_rlwe_msrln16_alice_1(msrln16_key->kex, msrln16_key->private_key, encoded_msg, 2048,&msrln16_key->public_key,&msrln16_key->public_length);
        aes_key_from_msrln_pub(ks_key->key);
        free(encoded_key);
        free(encoded_msg);

        *isOk=true;

    }else{
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
            dg->request=calloc(1,cl_st->request_size+1);
            dg->request_size=dap_enc_decode(key, cl_st->request, cl_st->request_size,dg->request,DAP_ENC_DATA_TYPE_RAW);
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
            dg->url_path=calloc(1,url_path_size+1);
            dg->url_path_size=dap_enc_decode(key, cl_st->http->url_path,url_path_size,dg->url_path,l_enc_type);
            dg->url_path[dg->url_path_size] = 0;
            log_it(L_DEBUG,"URL path after decode '%s'",dg->url_path );
            // log_it(L_DEBUG,"URL path before decode: '%s' after decode '%s'",cl_st->http->url_path,dg->url_path );
        }

        size_t in_query_size=strlen(cl_st->http->in_query_string);

        if(in_query_size){
            dg->in_query=calloc(1,in_query_size+1);
            dg->in_query_size=dap_enc_decode(key, cl_st->http->in_query_string,in_query_size,dg->in_query,l_enc_type);
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
    if( key == NULL )
    {
        log_it(L_ERROR, "Not find key");
        return;
    }
    if(dg->response){
            const size_t part = 255;
            size_t out_enc_mem_size = (dg->response_size / part + 1) * (RSA_KEY_LENGTH / 8);
#ifdef __GNUC__
            if (__builtin_expect(dg->response_size > part, 0)) {
#else
            if (dg->response_size > part) {
#endif
                //log_it(L_DEBUG, "enc_http_reply_encode RSA WAY 1");
                char *out_enc_buffer = calloc (out_enc_mem_size, sizeof(char));
                size_t copy_size, enc_size = 0;
                size_t end = dg->response_size;
                for (size_t i = 0; i<dg->response_size; i += part) {

                    end = dg->response_size - i;
                    copy_size = (end <= part) ? end : part;

                    if(enc_size > out_enc_mem_size) {
                        log_it(L_WARNING, "Enc size > out_enc_mem_size");
                        char *old = out_enc_buffer;
                        out_enc_buffer = (char*)realloc(out_enc_buffer, out_enc_mem_size * 2);
                        if(!out_enc_buffer) {
                            free(old);
                            log_it(L_ERROR, "Can not memmory allocate");
                            return;
                        }
                        memset(out_enc_buffer + out_enc_mem_size, 0, out_enc_mem_size);
                    }

                    enc_size +=dap_enc_code(dg->key,
                                         dg->response_str + i,
                                         copy_size,
                                         out_enc_buffer + enc_size,
                                         DAP_ENC_DATA_TYPE_RAW);

                }
                cl_st->reply = calloc(1, enc_size);
                cl_st->reply_size = enc_size;
                //log_it(L_INFO, "\n\n\nCOLLECTED DATA is {%s} size={%d}",out_enc_buffer, _enc_size);
                memcpy(cl_st->reply, out_enc_buffer, enc_size);
                free (out_enc_buffer);

            }
            else if(dg->response_size>0){
                //log_it(L_DEBUG, "enc_http_reply_encode RSA WAY 2");
                if(cl_st->reply)
                    free(cl_st->reply);

                if(key->type == DAP_ENC_KEY_TYPE_AES){       //Добавить ключ в dap_enc_key.h ???
                    cl_st->reply=calloc(1, AES_KEY_LENGTH / 8);
                }
                else {
                    cl_st->reply=calloc(1, dg->response_size * 3 + 1);
                }
                cl_st->reply_size = dap_enc_code(dg->key,dg->response,dg->response_size,cl_st->reply,DAP_ENC_DATA_TYPE_RAW);
            }
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

