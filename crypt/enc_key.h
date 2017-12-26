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

#ifndef _ENC_KEY_H_
#define _ENC_KEY_H_

#include "enc.h"

#include <stddef.h>
#include "enc_key.h"
typedef enum enc_key_type{ENC_KEY_TYPE_FNAM2, ENC_KEY_TYPE_AES,ENC_KEY_RSA_SESSION} enc_key_type_t;

struct enc_key;
typedef size_t (*enc_callback_t)(struct enc_key *, const void * , const size_t ,void *);

typedef struct enc_key{
    unsigned char * data;
    size_t data_size;
    enc_key_type_t type;

    enc_callback_t enc;
    enc_callback_t dec;

    void * internal;
} enc_key_t;

extern enc_key_t *enc_key_new(size_t key_size,enc_key_type_t key_type);
extern enc_key_t *enc_key_generate(enc_data_type_t v_type, rsa_key_t* key_session_pair);
extern enc_key_t *enc_key_create(const char * key_input,enc_key_type_t v_type);
extern void enc_key_delete(enc_key_t * key);
extern rsa_key_t* enc_key_session_pair_create(const char* client_pub_key, u_int16_t key_len);

#endif
