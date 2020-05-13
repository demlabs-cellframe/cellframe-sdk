/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * Demlabs Limited   https://demlabs.net
 * Sources community https://gitlab.demlabs.net/cellframe/cellframe-sdk/dap-sdk
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "newhope/newhope_cpakem.h"
#include "dap_enc_key.h"


///========================================================================
typedef enum{
    NEWHOPE_TOY = 0, NEWHOPE_1024
}DAP_NEWHOPE_SIGN_SECURITY;

typedef struct {
  DAP_NEWHOPE_SIGN_SECURITY kind;                 /* the kind of ringct20       */
  unsigned char *data;
}newhope_public_key_t;


typedef struct {
  DAP_NEWHOPE_SIGN_SECURITY kind;    //  the kind of Dilithium (i.e. *this* choice of parameters)
} newhope_param_t;

///==========================================================================================
typedef struct {
  DAP_NEWHOPE_SIGN_SECURITY kind;                 /* the kind of ringct20       */
  unsigned char *data;
} newhope_private_key_t;

typedef struct {
  DAP_NEWHOPE_SIGN_SECURITY kind;                      /* the kind of ringct20       */
  unsigned char *sig_data;
  unsigned long long sig_len;
} newhope_signature_t;


void dap_enc_newhope_pke_set_type(DAP_NEWHOPE_SIGN_SECURITY type);

void dap_enc_newhope_kem_key_new(struct dap_enc_key *key);

void dap_enc_newhope_kem_key_new_generate(struct dap_enc_key * key, const void *kex_buf,
                                    size_t kex_size, const void * seed, size_t seed_size,
                                    size_t key_size);

size_t dap_enc_newhope_pbk_enc(struct dap_enc_key * a_key, const void * a_pub,
        size_t a_pub_size, void ** b_pub);
size_t dap_enc_newhope_prk_dec(struct dap_enc_key * a_key, const void *a_priv,
                               size_t b_pub_size, unsigned char *b_pub);
void dap_enc_newhope_kem_key_delete(struct dap_enc_key * key);

//size_t dap_enc_newhope_calc_signature_unserialized_size(void);

//static inline size_t dap_enc_newhope_calc_signagture_size(newhope_signature_t* a_sign)
//{
//    return sizeof(size_t) + sizeof(newhope_kind_t) + a_sign->sig_len + sizeof(unsigned long long);
//}

//uint8_t* dap_enc_newhope_write_signature(newhope_signature_t* a_sign, size_t *a_sign_out);
//newhope_signature_t* dap_enc_newhope_read_signature(uint8_t *a_buf, size_t a_buflen);
//uint8_t* dap_enc_newhope_write_private_key(const newhope_private_key_t* a_private_key, size_t *a_buflen_out);
//uint8_t* dap_enc_newhope_write_public_key(const newhope_public_key_t* a_public_key, size_t *a_buflen_out);
//newhope_private_key_t* dap_enc_newhope_read_private_key(const uint8_t *a_buf, size_t a_buflen);
//newhope_public_key_t* dap_enc_newhope_read_public_key(const uint8_t *a_buf, size_t a_buflen);

