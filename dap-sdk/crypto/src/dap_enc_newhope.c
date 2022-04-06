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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>

#include "dap_enc_newhope.h"
#include "dap_common.h"
#include "rand/dap_rand.h"
#include "newhope/newhope_cpapke.h"
#include "newhope/newhope_params.h"


#define LOG_TAG "dap_enc_newhope_pke"

DAP_NEWHOPE_SIGN_SECURITY _newhope_type = NEWHOPE_1024; // by default


void dap_enc_newhope_pke_set_type(DAP_NEWHOPE_SIGN_SECURITY type)
{
    _newhope_type = type;
}

void dap_enc_newhope_kem_key_new(struct dap_enc_key *key) {

    key->type = DAP_ENC_KEY_TYPE_RLWE_NEWHOPE_CPA_KEM;
    key->enc = NULL;
    key->enc_na = NULL;
    key->dec_na = NULL;
    key->gen_bob_shared_key= dap_enc_newhope_pbk_enc;
    key->gen_alice_shared_key = dap_enc_newhope_prk_dec;
    key->priv_key_data  = NULL;
    key->pub_key_data   = NULL;

}

void dap_enc_newhope_kem_key_new_generate(struct dap_enc_key * a_key, const void *kex_buf,
        size_t kex_size, const void * seed, size_t seed_size,
        size_t key_size)
{
    UNUSED(kex_buf);
    UNUSED(key_size);
    UNUSED(seed);
    DAP_NEWHOPE_SIGN_SECURITY newhope_type = NEWHOPE_1024;
    dap_enc_newhope_pke_set_type(newhope_type);


    a_key->priv_key_data_size = sizeof(newhope_private_key_t);
    a_key->pub_key_data_size = sizeof(newhope_public_key_t);
    a_key->priv_key_data = DAP_NEW_SIZE(uint8_t, a_key->priv_key_data_size);
    a_key->pub_key_data = DAP_NEW_SIZE(uint8_t, a_key->pub_key_data_size);
    newhope_private_key_t *sk = (newhope_private_key_t *)a_key->priv_key_data;
    newhope_public_key_t  *pk = (newhope_public_key_t  *)a_key->pub_key_data;
    sk->kind = newhope_type;
    sk->data = DAP_NEW_SIZE(uint8_t, NEWHOPE_CPAPKE_SECRETKEYBYTES);
    pk->kind = newhope_type;
    pk->data = DAP_NEW_SIZE(uint8_t, NEWHOPE_CPAPKE_PUBLICKEYBYTES);
    cpapke_keypair(pk->data, sk->data);
    return;
}

/**
 * @brief Сheck whether a memory address is writable or not
 * @param a_p Pointer
 * @param a_len Checked memory size
 * @return True if the memory is writable, otherwise false
 */
bool is_writeable_memory(void *a_p, size_t a_len)
{
    int l_fd = open("/dev/zero", O_RDONLY);
    bool l_writeable;
    if (l_fd < 0)
        return FALSE; // Should not happen
    l_writeable = read(l_fd, a_p, a_len) == (ssize_t)a_len;
    close(l_fd);
    return l_writeable;
}

size_t dap_enc_newhope_pbk_enc(struct dap_enc_key * a_key, const void * a_pub,
        size_t a_pub_size, void ** a_sendb)
{
    // Check size of the public key
    if(a_pub_size != sizeof (newhope_public_key_t))
    {
        log_it(L_ERROR, "newhope wrong a_pub_size");
        return 0;
    }
    newhope_public_key_t *pk = (newhope_public_key_t*)a_pub;
    // Check the validity of the public key
    if(!pk || (pk->kind != NEWHOPE_1024 && pk->kind != NEWHOPE_TOY) || !is_writeable_memory(pk->data, NEWHOPE_CPAPKE_PUBLICKEYBYTES))
    {
        log_it(L_ERROR, "newhope wrong public key");
        return 0;
    }
    *a_sendb = DAP_NEW_SIZE(uint8_t, NEWHOPE_CPAKEM_CIPHERTEXTBYTES);
            //Bob derives a secret key and creates a response
    uint8_t key_b[NEWHOPE_SYMBYTES];
    crypto_kem_enc(*a_sendb, key_b, pk->data);
    //Save Bob shared key
    a_key->priv_key_data_size = NEWHOPE_SYMBYTES;
    a_key->priv_key_data = DAP_NEW_SIZE(uint8_t, a_key->priv_key_data_size);
    a_key->pub_key_data_size = sizeof(newhope_public_key_t);
    a_key->pub_key_data = DAP_NEW_SIZE(uint8_t, a_key->pub_key_data_size);
    newhope_public_key_t *cur_pk = (newhope_public_key_t*)a_key->pub_key_data;
    cur_pk->data = NULL;
    cur_pk->kind = pk->kind;

    memcpy(a_key->priv_key_data, key_b, a_key->priv_key_data_size);
    return NEWHOPE_CPAKEM_CIPHERTEXTBYTES;
}

size_t dap_enc_newhope_prk_dec(struct dap_enc_key * a_key, const void *a_priv,
                               size_t a_sendb_size, unsigned char *a_sendb)
{
    if(a_sendb_size != NEWHOPE_CPAKEM_CIPHERTEXTBYTES)
    {
        log_it(L_ERROR, "newhope wrong size of ciphertext (Bob send");
        return 0;
    }
    newhope_private_key_t *sk = a_key->priv_key_data;

    uint8_t key_a[NEWHOPE_SYMBYTES];
    uint8_t sendb[NEWHOPE_CPAKEM_CIPHERTEXTBYTES];
    memcpy(sendb, a_sendb, NEWHOPE_CPAKEM_CIPHERTEXTBYTES);
    crypto_kem_dec(key_a, sendb, sk->data);
    DAP_DEL_Z(sk->data);
    a_key->priv_key_data_size = NEWHOPE_SYMBYTES;
    a_key->priv_key_data = DAP_NEW_SIZE(uint8_t,a_key->priv_key_data_size);
    memcpy(a_key->priv_key_data, key_a, a_key->priv_key_data_size);

    return NEWHOPE_SYMBYTES;//return (newhope_crypto_sign_open( (unsigned char *) msg, msg_size, (newhope_signature_t *) signature, a_key->pub_key_data));
}

void dap_enc_newhope_kem_key_delete(struct dap_enc_key * a_key)
{

    newhope_private_key_t *sk = (newhope_private_key_t *)a_key->priv_key_data;
    newhope_public_key_t  *pk = (newhope_public_key_t  *)a_key->pub_key_data;
    if(sk != NULL && a_key->priv_key_data_size != NEWHOPE_SYMBYTES)
        DAP_DEL_Z(sk->data);
    if(pk != NULL)
        DAP_DEL_Z(pk->data);
}

