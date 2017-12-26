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
#include <string.h>

#include "enc_key.h"
#include "enc_fnam2.h"

#define LOG_TAG "enc_key"


/**
 * @brief enc_key_session_pair_create
 * @param client_pub_key
 * @param key_len
 * @return
 */
rsa_key_t* enc_key_session_pair_create(const char* client_pub_key, u_int16_t key_len)
{
    rsa_key_t* key_session_pair = (rsa_key_t*)calloc(1, sizeof(rsa_key_t));

    BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, client_pub_key,key_len);
    PEM_read_bio_RSAPublicKey(bio, &key_session_pair->client_public_key, NULL, NULL);
    BIO_free_all(bio);

    if ( key_session_pair->client_public_key == NULL)
    {
        free(key_session_pair);
        log_it(WARNING, "key session pair not create");
        return NULL;
    }

    key_session_pair->server_key = RSA_generate_key(RSA_KEY_LENGTH, PUB_EXP, NULL, NULL);

    if ( key_session_pair->server_key == NULL )
        log_it(ERROR, "Error generate rsa key");

    return key_session_pair;
}



/**
 * @brief enc_key_generate
 * @param v_type
 * @param key_session_pair
 * @return
 */
enc_key_t* enc_key_generate(enc_data_type_t v_type, rsa_key_t* key_session_pair)
{
    switch (v_type) {
    case ENC_KEY_TYPE_RSA: {
            if(key_session_pair == NULL)
            {
                log_it(WARNING, "Error generate enc key, key session pair is NULL");
                return NULL;
            }
            enc_key_t *key = (enc_key_t*)malloc(sizeof(enc_key_t));
            key->enc = (enc_callback_t) enc_rsa_encode;
            key->dec = enc_rsa_decode;
            key->internal = (void*) key_session_pair;
            key->type = ENC_KEY_TYPE_RSA;
            return key;
        }
        break;
    default:
        break;
    }
    return NULL;
}

/**
 * @brief enc_key_create
 * @param key_input_b64
 * @param v_type
 * @return
 */
enc_key_t *enc_key_create(const char * key_input,enc_key_type_t v_type)
{
   enc_key_t * ret= (enc_key_t *) calloc(1,sizeof(enc_key_t) );
   size_t input_size=strlen(key_input);
   switch(v_type){
        case ENC_KEY_TYPE_AES:{
            enc_aes_key_create(ret,key_input);
        }break;
        case ENC_KEY_TYPE_FNAM2:{
           ret->data = (unsigned char*) calloc(1,input_size*2);
           ret->data_size= enc_base64_decode(key_input,input_size,ret->data);
        }break;
   }
   ret->type=v_type;
   return ret;
}

/**
 * @brief enc_key_delete
 * @param key
 */
void enc_key_delete(enc_key_t * key)
{
    free(key->data);
    if(key->type == ENC_KEY_TYPE_AES)
        enc_aes_key_delete(key);
    if(key->internal)
        free(key->internal);
    free(key);
}

