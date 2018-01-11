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
#include "dap_config.h"

#include "dap_http.h"
#include "dap_http_client.h"
#include "dap_http_simple.h"

#include "dap_enc.h"
#include "dap_enc_ks.h"
#include "dap_enc_key.h"
#include "dap_enc_http.h"

#define LOG_TAG "dap_enc_http"


RSA* public_key_server = NULL;
RSA* private_key_server = NULL;

int enc_http_init()
{
    BIO *bio = BIO_new(BIO_s_mem());
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
        return -1;

}

void enc_http_deinit()
{
    if(public_key_server)
        RSA_free(public_key_server);
    if(private_key_server)
        RSA_free(private_key_server);
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
        rsa_key_t* key_session_pair = enc_key_session_pair_create(cl_st->request,cl_st->request_size);

        enc_key_t* key_session = enc_key_generate(ENC_KEY_RSA_SESSION, key_session_pair);

        dap_enc_ks_key_t * key_ks = dap_enc_ks_add(key_session);

        char *pubKey;
        char *sendMsg = malloc(
                    getStringPubKeyFromRsa(key_session_pair->server_key, &pubKey) * 2 +
                    strlen(key_ks->id) * 2 + 1024);

        char encrypt_id[strlen(key_ks->id) * 2];

        enc_base64_encode(key_ks->id,strlen(key_ks->id), encrypt_id);

        char* encrypt_pubkey = malloc(strlen(pubKey) * 2);
        enc_base64_encode(pubKey,strlen(pubKey), encrypt_pubkey);

        strcpy(sendMsg,encrypt_id);
        strcat(sendMsg," ");
        strcat(sendMsg,encrypt_pubkey);

        unsigned char *sig = (unsigned char *) malloc(512);
        unsigned int sig_len = 0;
        if(RSA_sign(NID_sha256, (unsigned char*) pubKey, 200,
                    sig, &sig_len, private_key_server) != 1) {
            log_it(L_ERROR, "ERROR ENCRYPT");
        }

        char *sig_64_out = (char*) malloc (1024);
        int size_out_base = enc_base64_encode(sig, sig_len, sig_64_out);
        sig_64_out[size_out_base] = '\0';

        strcat(sendMsg," ");
        strcat(sendMsg,sig_64_out);

        char str_sig_len[5];
        strcpy(str_sig_len, itoa(sig_len));

        char encode_str_sig_len[5];
        enc_base64_encode(str_sig_len, strlen(str_sig_len), encode_str_sig_len);

        strcat(sendMsg," ");
        strcat(sendMsg,encode_str_sig_len);

        dap_http_simple_reply_f(cl_st,"%s",sendMsg);

        free(sig);
        free(sig_64_out); free(encrypt_pubkey);
        free(pubKey); free(sendMsg);

        *isOk=true;
    }else if(strcmp(cl_st->http->url_path,"gd4y5yh78w42aaagh")==0 ){
        //log_it(L_INFO, "SEND CONFIG KEY");
         dap_http_simple_reply_f(cl_st,"%s",my_config.key_public);
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
    enc_key_t * key= dap_enc_ks_find_http(cl_st->http);
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
            dg->request_size=enc_decode(key, cl_st->request, cl_st->request_size,dg->request,ENC_DATA_TYPE_RAW);
            log_it(L_DEBUG,"Request after decode '%s'",dg->request_str);
           // log_it(L_DEBUG,"Request before decode: '%s' after decode '%s'",cl_st->request_str,dg->request_str);
        }

        size_t url_path_size=strlen(cl_st->http->url_path);
        if(url_path_size){
            dg->url_path=calloc(1,url_path_size+1);
            dg->url_path_size=enc_decode(key, cl_st->http->url_path,url_path_size,dg->url_path,ENC_DATA_TYPE_B64);
            log_it(L_DEBUG,"URL path after decode '%s'",dg->url_path );
            // log_it(L_DEBUG,"URL path before decode: '%s' after decode '%s'",cl_st->http->url_path,dg->url_path );
        }

        size_t in_query_size=strlen(cl_st->http->in_query_string);

        if(in_query_size){
            dg->in_query=calloc(1,in_query_size+1);
            dg->in_query_size=enc_decode(key, cl_st->http->in_query_string,in_query_size,dg->in_query,ENC_DATA_TYPE_B64);
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
    enc_key_t * key = dap_enc_ks_find_http(cl_st->http);
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

                    enc_size += enc_code(dg->key,
                                         dg->response_str + i,
                                         copy_size,
                                         out_enc_buffer + enc_size,
                                         ENC_DATA_TYPE_RAW);

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

                if(key->type == ENC_KEY_RSA_SESSION){
                    cl_st->reply=calloc(1, RSA_KEY_LENGTH / 8);
                }
                else {
                    cl_st->reply=calloc(1, dg->response_size * 3 + 1);
                }
                cl_st->reply_size = enc_code(dg->key,dg->response,dg->response_size,cl_st->reply,ENC_DATA_TYPE_RAW);
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

