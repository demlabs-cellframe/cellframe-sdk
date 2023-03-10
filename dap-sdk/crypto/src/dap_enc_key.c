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
#include "dap_common.h"

#include "dap_enc_iaes.h"
#include "dap_enc_oaes.h"
#include "dap_enc_bf.h"
#include "dap_enc_GOST.h"
#include "dap_enc_salsa2012.h"
#include "dap_enc_SEED.h"

#include "dap_enc_msrln.h"
#include "dap_enc_defeo.h"
#include "dap_enc_picnic.h"
#include "dap_enc_bliss.h"
#include "dap_enc_tesla.h"
#include "dap_enc_dilithium.h"
#include "dap_enc_newhope.h"
#include "dap_enc_falcon.h"
#include "dap_enc_ringct20.h"
#include "dap_enc_key.h"

#ifdef DAP_PQLR
#include "dap_pqlr.h"
#include "dap_pqlr_dilithium.h"
#include "dap_pqlr_falcon.h"
#include "dap_pqlr_sphincs.h"
#endif


#undef LOG_TAG
#define LOG_TAG "dap_enc_key"
dap_enc_key_callbacks_t s_callbacks[]={
    /* Symmetric ciphers */
    [DAP_ENC_KEY_TYPE_IAES]={
        .name = "IAES",
        .enc = dap_enc_iaes256_cbc_encrypt,
        .enc_na = dap_enc_iaes256_cbc_encrypt_fast ,
        .dec = dap_enc_iaes256_cbc_decrypt,
        .dec_na = dap_enc_iaes256_cbc_decrypt_fast ,
        .new_callback = dap_enc_aes_key_new,
        .delete_callback = dap_enc_aes_key_delete,
        .new_generate_callback = dap_enc_aes_key_generate,
        .enc_out_size = dap_enc_iaes256_calc_encode_size,
        .dec_out_size = dap_enc_iaes256_calc_decode_max_size
    },

    [DAP_ENC_KEY_TYPE_OAES]={
        .name = "OAES",
        .enc = dap_enc_oaes_encrypt,
        .enc_na = dap_enc_oaes_encrypt_fast ,
        .dec = dap_enc_oaes_decrypt,
        .dec_na = dap_enc_oaes_decrypt_fast ,
        .new_callback = dap_enc_oaes_key_new,
        .delete_callback = dap_enc_oaes_key_delete,
        .new_generate_callback = dap_enc_oaes_key_generate,
        .enc_out_size = dap_enc_oaes_calc_encode_size,
        .dec_out_size = dap_enc_oaes_calc_decode_size
    },

    [DAP_ENC_KEY_TYPE_BF_CBC]={
        .name = "BF_CBC",
        .enc = dap_enc_bf_cbc_encrypt,
        .enc_na = dap_enc_bf_cbc_encrypt_fast ,
        .dec = dap_enc_bf_cbc_decrypt,
        .dec_na = dap_enc_bf_cbc_decrypt_fast ,
        .new_callback = dap_enc_bf_cbc_key_new,
        .delete_callback = dap_enc_bf_key_delete,
        .new_generate_callback = dap_enc_bf_key_generate,
        .enc_out_size = dap_enc_bf_cbc_calc_encode_size,
        .dec_out_size = dap_enc_bf_cbc_calc_decode_max_size
    },

    [DAP_ENC_KEY_TYPE_BF_OFB]={
        .name = "BF_OFB",
        .enc = dap_enc_bf_ofb_encrypt,
        .enc_na = dap_enc_bf_ofb_encrypt_fast ,
        .dec = dap_enc_bf_ofb_decrypt,
        .dec_na = dap_enc_bf_ofb_decrypt_fast ,
        .new_callback = dap_enc_bf_ofb_key_new,
        .delete_callback = dap_enc_bf_key_delete,
        .new_generate_callback = dap_enc_bf_key_generate,
        .enc_out_size = dap_enc_bf_ofb_calc_encode_size,
        .dec_out_size = dap_enc_bf_ofb_calc_decode_size
    },

    [DAP_ENC_KEY_TYPE_GOST_OFB]={
        .name = "GOST_OFB",
        .enc = dap_enc_gost_ofb_encrypt,
        .enc_na = dap_enc_gost_ofb_encrypt_fast ,
        .dec = dap_enc_gost_ofb_decrypt,
        .dec_na = dap_enc_gost_ofb_decrypt_fast ,
        .new_callback = dap_enc_gost_ofb_key_new,
        .delete_callback = dap_enc_gost_key_delete,
        .new_generate_callback = dap_enc_gost_key_generate,
        .enc_out_size = dap_enc_gost_ofb_calc_encode_size,
        .dec_out_size = dap_enc_gost_ofb_calc_decode_size
    },

    [DAP_ENC_KEY_TYPE_KUZN_OFB]={
        .name = "KUZN_OFB",
        .enc = dap_enc_kuzn_ofb_encrypt,
        .enc_na = dap_enc_kuzn_ofb_encrypt_fast ,
        .dec = dap_enc_kuzn_ofb_decrypt,
        .dec_na = dap_enc_kuzn_ofb_decrypt_fast ,
        .new_callback = dap_enc_kuzn_ofb_key_new,
        .delete_callback = dap_enc_gost_key_delete,
        .new_generate_callback = dap_enc_gost_key_generate,
        .enc_out_size = dap_enc_kuzn_ofb_calc_encode_size,
        .dec_out_size = dap_enc_kuzn_ofb_calc_decode_size
    },

    [DAP_ENC_KEY_TYPE_SALSA2012]={
        .name = "SALSA2012",
        .enc = dap_enc_salsa2012_encrypt,
        .enc_na = dap_enc_salsa2012_encrypt_fast ,
        .dec = dap_enc_salsa2012_decrypt,
        .dec_na = dap_enc_salsa2012_decrypt_fast ,
        .new_callback = dap_enc_salsa2012_key_new,
        .delete_callback = dap_enc_salsa2012_key_delete,
        .new_generate_callback = dap_enc_salsa2012_key_generate,
        .enc_out_size = dap_enc_salsa2012_calc_encode_size,
        .dec_out_size = dap_enc_salsa2012_calc_decode_size
    },

    [DAP_ENC_KEY_TYPE_SEED_OFB]={
        .name = "SEED_OFB",
        .enc = dap_enc_seed_ofb_encrypt,
        .enc_na = dap_enc_seed_ofb_encrypt_fast ,
        .dec = dap_enc_seed_ofb_decrypt,
        .dec_na = dap_enc_seed_ofb_decrypt_fast ,
        .new_callback = dap_enc_seed_ofb_key_new,
        .delete_callback = dap_enc_seed_key_delete,
        .new_generate_callback = dap_enc_seed_key_generate,
        .enc_out_size = dap_enc_seed_ofb_calc_encode_size,
        .dec_out_size = dap_enc_seed_ofb_calc_decode_size
    },

    /* Key Exchange Mechanichs */
    [DAP_ENC_KEY_TYPE_MSRLN] = {
        .name = "MSRLN",
        .new_callback = dap_enc_msrln_key_new,
        .delete_callback = dap_enc_msrln_key_delete,
        .new_generate_callback = dap_enc_msrln_key_generate,
        .gen_bob_shared_key = dap_enc_msrln_gen_bob_shared_key,
        .gen_alice_shared_key = dap_enc_msrln_gen_alice_shared_key,
        .new_from_data_public_callback = dap_enc_msrln_key_new_from_data_public
    },

    [DAP_ENC_KEY_TYPE_DEFEO]={
        .name = "DEFEO",
        .gen_bob_shared_key = dap_enc_defeo_gen_bob_shared_key,
        .gen_alice_shared_key = dap_enc_defeo_gen_alice_shared_key,
        .new_callback = dap_enc_defeo_key_new,
        .delete_callback = dap_enc_defeo_key_delete,
        .new_generate_callback = dap_enc_defeo_key_new_generate
    },

    [DAP_ENC_KEY_TYPE_RLWE_NEWHOPE_CPA_KEM]={
        .name = "NEWHOPE_CPA_KEM",
        .gen_bob_shared_key = dap_enc_newhope_pbk_enc,
        .gen_alice_shared_key = dap_enc_newhope_prk_dec,
        .new_callback = dap_enc_newhope_kem_key_new,
        .delete_callback = dap_enc_newhope_kem_key_delete,
        .new_generate_callback = dap_enc_newhope_kem_key_new_generate
    },

    /* Signatures */
    [DAP_ENC_KEY_TYPE_SIG_PICNIC]={
        .name = "PICNIC",
        .enc_na = dap_enc_sig_picnic_get_sign,
        .dec_na = dap_enc_sig_picnic_verify_sign,
        .new_callback = dap_enc_sig_picnic_key_new,
        .gen_key_public_size = dap_enc_picnic_calc_signature_size,
        .delete_callback = dap_enc_sig_picnic_key_delete,
        .new_generate_callback = dap_enc_sig_picnic_key_new_generate
    },

    [DAP_ENC_KEY_TYPE_SIG_BLISS]={
        .name = "SIG_BLISS",
        .sign_get = dap_enc_sig_bliss_get_sign,
        .sign_verify = dap_enc_sig_bliss_verify_sign,
        .new_callback = dap_enc_sig_bliss_key_new,
        .delete_callback = dap_enc_sig_bliss_key_delete,
        .new_generate_callback = dap_enc_sig_bliss_key_new_generate,
        .gen_key_public = dap_enc_sig_bliss_key_pub_output,
        .gen_key_public_size = dap_enc_sig_bliss_key_pub_output_size
    },

    [DAP_ENC_KEY_TYPE_SIG_TESLA]={
        .name = "SIG_TESLA",
        .enc_na = dap_enc_sig_tesla_get_sign,
        .dec_na = dap_enc_sig_tesla_verify_sign,
        .new_callback = dap_enc_sig_tesla_key_new,
        .delete_callback = dap_enc_sig_tesla_key_delete,
        .new_generate_callback = dap_enc_sig_tesla_key_new_generate
    },

    [DAP_ENC_KEY_TYPE_SIG_DILITHIUM]={
        .name = "SIG_DILITHIUM",
        .enc_na = dap_enc_sig_dilithium_get_sign,
        .dec_na = dap_enc_sig_dilithium_verify_sign,
        .new_callback = dap_enc_sig_dilithium_key_new,
        .delete_callback = dap_enc_sig_dilithium_key_delete,
        .new_generate_callback = dap_enc_sig_dilithium_key_new_generate
    },

    [DAP_ENC_KEY_TYPE_SIG_RINGCT20]={
        .name = "SIG_RINGCT20",
        .enc_na = dap_enc_sig_ringct20_get_sign_with_pb_list,//dap_enc_sig_ringct20_get_sign,
        .dec_na = dap_enc_sig_ringct20_verify_sign,
        .dec_na_ext = dap_enc_sig_ringct20_verify_sign_with_pbk_list,
        .new_callback = dap_enc_sig_ringct20_key_new,
        .delete_callback = dap_enc_sig_ringct20_key_delete,
        .new_generate_callback = dap_enc_sig_ringct20_key_new_generate
    },

    [DAP_ENC_KEY_TYPE_SIG_FALCON]={
        .name = "SIG_FALCON",
        .enc_na = dap_enc_sig_falcon_get_sign,
        .dec_na = dap_enc_sig_falcon_verify_sign,
        .new_callback = dap_enc_sig_falcon_key_new,
        .delete_callback = dap_enc_sig_falcon_key_delete,
        .new_generate_callback = dap_enc_sig_falcon_key_new_generate
    }
#ifdef DAP_PQLR
    ,
    [DAP_ENC_KEY_TYPE_PQLR_SIG_DILITHIUM] = {
        .name = "SIG_PQLR_DILITHIUM",
        .enc_na = dap_pqlr_dilithium_create_sign,
        .dec_na = dap_pqlr_dilithium_verify_sign,
        .new_callback = dap_pqlr_dilithium_key_new,
        .delete_callback = dap_pqlr_dilithium_key_delete,
        .new_generate_callback = dap_pqlr_dilithium_key_new_generate
    },

    [DAP_ENC_KEY_TYPE_PQLR_SIG_FALCON] = {
        .name = "SIG_PQLR_FALCON",
        .enc_na = dap_pqlr_falcon_create_sign,
        .dec_na = dap_pqlr_falcon_verify_sign,
        .new_callback = dap_pqlr_falcon_key_new,
        .delete_callback = dap_pqlr_falcon_key_delete,
        .new_generate_callback = dap_pqlr_falcon_key_new_generate
    },

    [DAP_ENC_KEY_TYPE_PQLR_SIG_SPHINCS] = {
        .name = "SIG_PQLR_SPHINCS",
        .enc_na = dap_pqlr_sphincs_create_sign,
        .dec_na = dap_pqlr_sphincs_verify_sign,
        .new_callback = dap_pqlr_sphincs_key_new,
        .delete_callback = dap_pqlr_sphincs_key_delete,
        .new_generate_callback = dap_pqlr_sphincs_key_new_generate
    },

    [DAP_ENC_KEY_TYPE_PQLR_KEM_SABER] = {
        .name = "PQLR_SABER",
    },

    [DAP_ENC_KEY_TYPE_PQLR_KEM_MCELIECE] = {
        .name = "PQLR_MCELIECE"
    },

    [DAP_ENC_KEY_TYPE_PQLR_KEM_NEWHOPE] = {
        .name = "PQLR_NEWHOPE"
    }
#endif
};

const size_t c_callbacks_size = sizeof(s_callbacks) / sizeof(s_callbacks[0]);

/**
 * @brief dap_enc_key_init empty stub
 * @return
 */
int dap_enc_key_init()
{
#ifdef DAP_PQLR
    if (dap_pqlr_init(s_callbacks))
        return -1;
#endif
    return 0;
}

/**
 * @brief dap_enc_key_deinit
 */
void dap_enc_key_deinit()
{
#ifdef DAP_PQLR
    dap_pqlr_deinit();
#endif
}

/**
 * @brief dap_enc_key_serialize_sign
 *
 * @param a_key_type
 * @param a_sign
 * @param a_sign_len [in/out]
 * @return allocates memory with private key
 */
uint8_t* dap_enc_key_serialize_sign(dap_enc_key_type_t a_key_type, uint8_t *a_sign, size_t *a_sign_len)
{
    if (!a_sign_len || !*a_sign_len)
        return NULL;

    switch (a_key_type) {
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        return dap_enc_sig_bliss_write_signature((bliss_signature_t*)a_sign, a_sign_len);
    case DAP_ENC_KEY_TYPE_SIG_TESLA:
        return dap_enc_tesla_write_signature((tesla_signature_t*)a_sign, a_sign_len);
    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
        return dap_enc_dilithium_write_signature((dilithium_signature_t*)a_sign, a_sign_len);
    case DAP_ENC_KEY_TYPE_SIG_FALCON:
        return dap_enc_falcon_write_signature((falcon_signature_t *) a_sign, a_sign_len);
    default:
        return DAP_DUP_SIZE(a_sign, *a_sign_len);
    }
}

/**
 * @brief dap_enc_key_serialize_sign
 *
 * @param a_key_type
 * @param a_sign
 * @param a_sign_len [in/out]
 * @return allocates memory with private key
 */
uint8_t* dap_enc_key_deserialize_sign(dap_enc_key_type_t a_key_type, uint8_t *a_sign, size_t *a_sign_len)
{
    if (!a_sign || !a_sign_len) {
        return NULL;
    }
    uint8_t *l_ret;
    switch (a_key_type) {
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        l_ret = (uint8_t*)dap_enc_sig_bliss_read_signature(a_sign, *a_sign_len);
        *a_sign_len = sizeof(bliss_signature_t);
        break;
    case DAP_ENC_KEY_TYPE_SIG_TESLA:
        l_ret = (uint8_t*)dap_enc_tesla_read_signature(a_sign, *a_sign_len);
        *a_sign_len = sizeof(tesla_signature_t);
        break;
    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
        l_ret = (uint8_t*)dap_enc_dilithium_read_signature(a_sign, *a_sign_len);
        *a_sign_len = sizeof(dilithium_signature_t);
        break;
    case DAP_ENC_KEY_TYPE_SIG_FALCON:
        *a_sign_len = sizeof(falcon_signature_t);
        l_ret = (uint8_t*)dap_enc_falcon_read_signature(a_sign, *a_sign_len);
        break;
    default:
        return DAP_DUP_SIZE(a_sign, *a_sign_len);
    }
    return l_ret;
}

/**
 * @brief dap_enc_key_serialize_priv_key
 *
 * @param a_key
 * @param a_buflen_out
 * @return allocates memory with private key
 */
uint8_t* dap_enc_key_serialize_priv_key(dap_enc_key_t *a_key, size_t *a_buflen_out)
{
    if (!a_key || !a_key->priv_key_data || !a_key->priv_key_data_size) {
        log_it(L_ERROR, "Invalid key");
        return NULL;
    }

    switch (a_key->type) {
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        return a_buflen_out
                ? dap_enc_sig_bliss_write_private_key(a_key->priv_key_data, a_buflen_out)
                : NULL;
    case DAP_ENC_KEY_TYPE_SIG_TESLA:
        return a_buflen_out
                ? dap_enc_tesla_write_private_key(a_key->priv_key_data, a_buflen_out)
                : NULL;
    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
        return a_buflen_out
                ? dap_enc_dilithium_write_private_key(a_key->priv_key_data, a_buflen_out)
                : NULL;
    case DAP_ENC_KEY_TYPE_SIG_FALCON:
        return a_buflen_out
                ? dap_enc_falcon_write_private_key(a_key->priv_key_data, a_buflen_out)
                : NULL;
    default:
        return ({ if (a_buflen_out) *a_buflen_out = a_key->priv_key_data_size;
                  DAP_DUP_SIZE(a_key->priv_key_data, a_key->priv_key_data_size);
                });
    }
}

/**
 * @brief dap_enc_key_serialize_pub_key
 *
 * @param a_key
 * @param a_buflen_out
 * @return allocates memory with private key
 */
uint8_t* dap_enc_key_serialize_pub_key(dap_enc_key_t *a_key, size_t *a_buflen_out)
{
    if (!a_key || !a_key->pub_key_data || !a_key->pub_key_data_size) {
        log_it(L_ERROR, "Invalid key");
        return NULL;
    }

    switch (a_key->type) {
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        return a_buflen_out
                ? dap_enc_sig_bliss_write_public_key(a_key->pub_key_data, a_buflen_out)
                : NULL;
    case DAP_ENC_KEY_TYPE_SIG_TESLA:
        return a_buflen_out
                ? dap_enc_tesla_write_public_key(a_key->pub_key_data, a_buflen_out)
                : NULL;
    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
        return a_buflen_out
                ? dap_enc_dilithium_write_public_key(a_key->pub_key_data, a_buflen_out)
                : NULL;
    case DAP_ENC_KEY_TYPE_SIG_FALCON:
        return a_buflen_out
                ? dap_enc_falcon_write_public_key(a_key->pub_key_data, a_buflen_out)
                : NULL;
    default:
        return ({ if (a_buflen_out) *a_buflen_out = a_key->pub_key_data_size;
                  DAP_DUP_SIZE(a_key->pub_key_data, a_key->pub_key_data_size);
                });
    }
}
/**
 * @brief dap_enc_key_deserialize_priv_key
 *
 * @param a_key
 * @param a_buf
 * @param a_buflen_out
 * @return 0 Ok, -1 error
 */
int dap_enc_key_deserialize_priv_key(dap_enc_key_t *a_key, const uint8_t *a_buf, size_t a_buflen)
{
    if(!a_key || !a_buf || !a_buflen) {
        log_it(L_ERROR, "Invalid params");
        return -2;
    }

    switch (a_key->type) {
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        if((a_key->priv_key_data)) {
            bliss_b_private_key_delete((bliss_private_key_t *) a_key->priv_key_data);
            DAP_DELETE(a_key->pub_key_data);
        }
        a_key->priv_key_data        = (uint8_t*) dap_enc_sig_bliss_read_private_key(a_buf, a_buflen);
        a_key->priv_key_data_size   = a_key->priv_key_data ? sizeof(bliss_private_key_t) : 0;
        break;

    case DAP_ENC_KEY_TYPE_SIG_TESLA:
        tesla_private_key_delete((tesla_private_key_t *) a_key->priv_key_data);
        a_key->priv_key_data        = (uint8_t*) dap_enc_tesla_read_private_key(a_buf, a_buflen);
        a_key->priv_key_data_size   = a_key->priv_key_data ? sizeof(tesla_private_key_t) : 0;
        break;

    case DAP_ENC_KEY_TYPE_SIG_PICNIC:
        DAP_DELETE(a_key->priv_key_data);
        a_key->priv_key_data        = DAP_DUP_SIZE(a_buf, a_buflen);
        a_key->priv_key_data_size   = a_key->priv_key_data ? a_buflen : 0;
        dap_enc_sig_picnic_update(a_key);
        break;

    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
        dilithium_private_key_delete((dilithium_private_key_t *) a_key->priv_key_data);
        a_key->priv_key_data        = (uint8_t*) dap_enc_dilithium_read_private_key(a_buf, a_buflen);
        a_key->priv_key_data_size   = a_key->priv_key_data ? sizeof(dilithium_private_key_t) : 0;
        break;

    case DAP_ENC_KEY_TYPE_SIG_FALCON:
        falcon_private_key_delete((falcon_private_key_t *) a_key->priv_key_data);
        a_key->priv_key_data        = (uint8_t*) dap_enc_falcon_read_private_key(a_buf, a_buflen);
        a_key->priv_key_data_size   = a_key->priv_key_data ? sizeof(falcon_private_key_t) : 0;
        break;

    default:
        DAP_DELETE(a_key->priv_key_data);
        a_key->priv_key_data        = DAP_DUP_SIZE(a_buf, a_buflen);
        a_key->priv_key_data_size   = a_key->priv_key_data ? a_buflen : 0;

    }
    return a_key->priv_key_data_size ? 0 : -1;
}

int dap_enc_key_deserialize_pub_key_old(dap_enc_key_t *a_key, const uint8_t *a_buf, size_t a_buflen)
{
    if(!a_key || !a_buf)
        return -1;
    switch (a_key->type) {
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        if((a_key->pub_key_data)) {
            bliss_b_public_key_delete((bliss_public_key_t *) a_key->pub_key_data);
            DAP_DELETE(a_key->pub_key_data);
        }
        a_key->pub_key_data = (uint8_t*) dap_enc_sig_bliss_read_public_key(a_buf, a_buflen);
        if(!a_key->pub_key_data)
        {
            a_key->pub_key_data_size = 0;
            return -1;
        }
        a_key->pub_key_data_size = sizeof(bliss_public_key_t);
        break;
    case DAP_ENC_KEY_TYPE_SIG_TESLA:
        tesla_public_key_delete((tesla_public_key_t *) a_key->pub_key_data);
        a_key->pub_key_data = (uint8_t*) dap_enc_tesla_read_public_key(a_buf, a_buflen);
        if(!a_key->pub_key_data)
        {
            a_key->pub_key_data_size = 0;
            return -1;
        }
        a_key->pub_key_data_size = sizeof(tesla_public_key_t);
        break;
    case DAP_ENC_KEY_TYPE_SIG_PICNIC:
        DAP_DELETE(a_key->pub_key_data);
        a_key->pub_key_data_size = a_buflen;
        a_key->pub_key_data = DAP_NEW_Z_SIZE(uint8_t, a_key->pub_key_data_size);
        memcpy(a_key->pub_key_data, a_buf, a_key->pub_key_data_size);
        dap_enc_sig_picnic_update(a_key);
        break;
    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
        if ( a_key->pub_key_data )
            dilithium_public_key_delete((dilithium_public_key_t *) a_key->pub_key_data);
        a_key->pub_key_data = (uint8_t*) dap_enc_dilithium_read_public_key_old(a_buf, a_buflen);
        if(!a_key->pub_key_data)
        {
            a_key->pub_key_data_size = 0;
            return -1;
        }
        a_key->pub_key_data_size = sizeof(dilithium_public_key_t);
        break;
    default:
        DAP_DELETE(a_key->pub_key_data);
        a_key->pub_key_data_size = a_buflen;
        a_key->pub_key_data = DAP_NEW_Z_SIZE(uint8_t, a_key->pub_key_data_size);
        memcpy(a_key->pub_key_data, a_buf, a_key->pub_key_data_size);
    }
    return 0;

}

/**
 * @brief dap_enc_key_deserialize_pub_key
 *
 * @param a_key
 * @param a_buf
 * @param a_buflen_out
 * @return 0 Ok, -1 error
 */
int dap_enc_key_deserialize_pub_key(dap_enc_key_t *a_key, const uint8_t *a_buf, size_t a_buflen)
{
    if (!a_key || !a_buflen || !a_buf)
        return -2;

    switch (a_key->type) {
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        if((a_key->pub_key_data)) {
            bliss_b_public_key_delete((bliss_public_key_t *) a_key->pub_key_data);
            DAP_DELETE(a_key->pub_key_data);
        }
        a_key->pub_key_data = (uint8_t*) dap_enc_sig_bliss_read_public_key(a_buf, a_buflen);
        a_key->pub_key_data_size = a_key->pub_key_data ? sizeof(bliss_public_key_t) : 0;
        break;

    case DAP_ENC_KEY_TYPE_SIG_TESLA:
        tesla_public_key_delete((tesla_public_key_t *) a_key->pub_key_data);
        a_key->pub_key_data = (uint8_t*) dap_enc_tesla_read_public_key(a_buf, a_buflen);
        a_key->pub_key_data_size = a_key->pub_key_data ? sizeof(tesla_public_key_t) : 0;
        break;

    case DAP_ENC_KEY_TYPE_SIG_PICNIC:
        DAP_DELETE(a_key->pub_key_data);
        a_key->pub_key_data = DAP_DUP_SIZE(a_buf, a_buflen);
        a_key->pub_key_data_size = a_key->pub_key_data ? a_buflen : 0;
        dap_enc_sig_picnic_update(a_key);
        break;

    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
        if (a_key->pub_key_data)
            dilithium_public_key_delete((dilithium_public_key_t *) a_key->pub_key_data);
        a_key->pub_key_data = (uint8_t*) dap_enc_dilithium_read_public_key(a_buf, a_buflen);
        a_key->pub_key_data_size = a_key->pub_key_data ? sizeof(dilithium_public_key_t) : 0;
        break;

    case DAP_ENC_KEY_TYPE_SIG_FALCON:
        if (a_key->pub_key_data)
            falcon_public_key_delete((falcon_public_key_t *) a_key->pub_key_data);
        a_key->pub_key_data = (uint8_t*) dap_enc_falcon_read_public_key(a_buf, a_buflen);
        a_key->pub_key_data_size = a_key->pub_key_data ? sizeof(falcon_public_key_t) : 0;
        break;

    default:
        DAP_DELETE(a_key->pub_key_data);
        a_key->pub_key_data = DAP_DUP_SIZE(a_buf, a_buflen);
        a_key->pub_key_data_size = a_key->pub_key_data ? a_buflen : 0;
    }
    return a_key->pub_key_data_size ? 0 : -1;
}

/**
 * @brief dap_enc_key_serialize
 * @param key
 * @return allocates dap_enc_key_serialize_t* dont remember use free()
 */
dap_enc_key_serialize_t* dap_enc_key_serialize(dap_enc_key_t * key)
{
    dap_enc_key_serialize_t *result = DAP_NEW_Z(dap_enc_key_serialize_t);
    *result = (dap_enc_key_serialize_t) {
            .priv_key_data_size     = key->priv_key_data_size,
            .pub_key_data_size      = key->pub_key_data_size,
            .last_used_timestamp    = key->last_used_timestamp,
            .inheritor_size         = key->_inheritor_size,
            .type   = key->type,
            .priv_key_data  = DAP_DUP_SIZE(key->priv_key_data, key->priv_key_data_size),
            .pub_key_data   = DAP_DUP_SIZE(key->pub_key_data, key->pub_key_data_size),
            .inheritor      = DAP_DUP_SIZE(key->_inheritor, key->_inheritor_size)
    };
    return result;
}

/**
 * @brief dap_enc_key_dup
 * @param a_key
 * @return
 */
dap_enc_key_t* dap_enc_key_dup(dap_enc_key_t * a_key)
{
    if (!a_key || a_key->type == DAP_ENC_KEY_TYPE_INVALID) {
        return NULL;
    }

    dap_enc_key_t *l_ret = dap_enc_key_new(a_key->type);
    l_ret->priv_key_data = a_key->priv_key_data && a_key->priv_key_data_size
            ? DAP_DUP_SIZE(a_key->priv_key_data, ({ l_ret->priv_key_data_size = a_key->priv_key_data_size; }))
            : NULL;
    l_ret->pub_key_data = a_key->pub_key_data && a_key->pub_key_data_size
            ? DAP_DUP_SIZE(a_key->pub_key_data, ({ l_ret->pub_key_data_size = a_key->pub_key_data_size; }))
            : NULL;
    l_ret->_inheritor =  a_key->_inheritor && a_key->_inheritor_size
            ? DAP_DUP_SIZE(a_key->_inheritor, ({ l_ret->_inheritor_size = a_key->_inheritor_size; }))
            : NULL;

    return l_ret;
}

/**
 * @brief dap_enc_key_deserialize
 * @param buf
 * @param buf_size
 * @return allocates dap_enc_key_t*. Use dap_enc_key_delete for free memory
 */
dap_enc_key_t* dap_enc_key_deserialize(const void *buf, size_t buf_size)
{
    if(buf_size != sizeof (dap_enc_key_serialize_t)) {
        log_it(L_ERROR, "Key can't be deserialized. buf_size(%zu) != sizeof (dap_enc_key_serialize_t)(%zu)",
               buf_size, sizeof (dap_enc_key_serialize_t));
        return NULL;
    }

    const dap_enc_key_serialize_t *in_key = (const dap_enc_key_serialize_t *)buf;
    dap_enc_key_t *result = dap_enc_key_new(in_key->type);
    result->last_used_timestamp     = in_key->last_used_timestamp;
    result->priv_key_data_size      = in_key->priv_key_data_size;
    result->pub_key_data_size       = in_key->pub_key_data_size;
    result->_inheritor_size         = in_key->inheritor_size;
    DAP_DEL_Z(result->priv_key_data);
    DAP_DEL_Z(result->pub_key_data);
    DAP_DEL_Z(result->_inheritor);
    result->priv_key_data   = DAP_DUP_SIZE(in_key->priv_key_data, result->priv_key_data_size);
    result->pub_key_data    = DAP_DUP_SIZE(in_key->pub_key_data, result->pub_key_data_size);
    result->_inheritor      = DAP_DUP_SIZE(in_key->inheritor, in_key->inheritor_size);
    return result;
}

/**
 * @brief dap_enc_key_new
 * @param a_key_type
 * @return
 */
dap_enc_key_t *dap_enc_key_new(dap_enc_key_type_t a_key_type)
{
    if ((size_t)a_key_type >= c_callbacks_size || !s_callbacks[a_key_type].new_callback)
        return NULL;

    dap_enc_key_t *l_ret = DAP_NEW_Z(dap_enc_key_t);
    if (l_ret) {
        s_callbacks[a_key_type].new_callback(l_ret);
        l_ret->type = a_key_type;
        if (!l_ret->enc_na)
            l_ret->enc_na = s_callbacks[a_key_type].enc_na;
        if (!l_ret->dec_na)
            l_ret->dec_na = s_callbacks[a_key_type].dec_na;
    }
    return l_ret;
}

/**
 * @brief dap_enc_key_new_generate
 * @param a_key_type
 * @param kex_buf
 * @param kex_size
 * @param seed
 * @param seed_size
 * @param key_size - can be NULL ( generate size by default )
 * @return
 */
dap_enc_key_t *dap_enc_key_new_generate(dap_enc_key_type_t a_key_type, const void *kex_buf,
                                        size_t kex_size, const void* seed,
                                        size_t seed_size, size_t key_size)
{
    if ((size_t)a_key_type >= c_callbacks_size || !s_callbacks[a_key_type].new_callback)
        return NULL;

    dap_enc_key_t *l_ret = dap_enc_key_new(a_key_type);
    if (l_ret) {
        s_callbacks[a_key_type].new_generate_callback(l_ret, kex_buf, kex_size, seed, seed_size, key_size);
    }
    return l_ret;
}

/**
 * @brief dap_enc_key_update
 * @param a_key_type
 * @return
 */
void dap_enc_key_update(dap_enc_key_t *a_key)
{
    if (!a_key)
        return;

    switch (a_key->type) {
    case DAP_ENC_KEY_TYPE_SIG_PICNIC:
        dap_enc_sig_picnic_update(a_key);
        break;
    case DAP_ENC_KEY_TYPE_SIG_TESLA:
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
    default:
        break;
    }
}

size_t dap_enc_gen_key_public_size (dap_enc_key_t *a_key)
{
    return s_callbacks[a_key->type].gen_key_public_size
            ? s_callbacks[a_key->type].gen_key_public_size(a_key)
            : ({ log_it(L_ERROR, "No callback for key public size calculate"); 0; });
}

int dap_enc_gen_key_public (dap_enc_key_t *a_key, void * a_output)
{
    return s_callbacks[a_key->type].gen_key_public && a_output
            ? s_callbacks[a_key->type].gen_key_public(a_key,a_output)
            : ({ log_it(L_ERROR, "No callback for key public generate action"); -1; });
}

/**
 * @brief dap_enc_key_delete
 * @param a_key
 */
void dap_enc_key_signature_delete(dap_enc_key_type_t a_key_type, uint8_t *a_sig_buf)
{
    switch (a_key_type) {
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        bliss_signature_delete((bliss_signature_t*)a_sig_buf);
        break;
    case DAP_ENC_KEY_TYPE_SIG_TESLA:
        tesla_signature_delete((tesla_signature_t*)a_sig_buf);
        break;
    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
        dilithium_signature_delete((dilithium_signature_t*)a_sig_buf);
        break;
    case DAP_ENC_KEY_TYPE_SIG_FALCON:
        DAP_DEL_Z(((falcon_signature_t *)a_sig_buf)->sig_data);
        break;
    default:
        break;
    }
    DAP_DELETE(a_sig_buf);
}

/**
 * @brief dap_enc_key_delete
 * @param a_key
 */
void dap_enc_key_delete(dap_enc_key_t * a_key)
{
    if(s_callbacks[a_key->type].delete_callback) {
        s_callbacks[a_key->type].delete_callback(a_key);
    } else {
        log_it(L_ERROR, "delete callback is null. Can be leak memory!");
    }

    /* a_key->_inheritor must be cleaned in delete_callback func */
    DAP_DEL_Z(a_key->pub_key_data);
    DAP_DEL_Z(a_key->priv_key_data);
    DAP_DELETE(a_key);
}

size_t dap_enc_key_get_enc_size(dap_enc_key_t * a_key, const size_t buf_in_size)
{
    return s_callbacks[a_key->type].enc_out_size
            ? s_callbacks[a_key->type].enc_out_size(buf_in_size)
            : ({ log_it(L_ERROR, "Can't calculate enc_size for key type %d", a_key->type); 0; });
}

size_t dap_enc_key_get_dec_size(dap_enc_key_t * a_key, const size_t buf_in_size)
{
    return s_callbacks[a_key->type].dec_out_size
            ? s_callbacks[a_key->type].dec_out_size(buf_in_size)
            : ({ log_it(L_ERROR, "Can't calculate dec_size for key type %d", a_key->type); 0; });
}

const char *dap_enc_get_type_name(dap_enc_key_type_t a_key_type)
{
    return a_key_type >= DAP_ENC_KEY_TYPE_NULL && a_key_type < DAP_ENC_KEY_TYPE_SIZE && s_callbacks[a_key_type].name
            ? s_callbacks[a_key_type].name
            : ({ log_it(L_ERROR, "Can't define name of key type %d", a_key_type); NULL; });
}

dap_enc_key_type_t dap_enc_key_type_find_by_name(const char * a_name){
    for (dap_enc_key_type_t i = 0; i < DAP_ENC_KEY_TYPE_SIZE; i++) {
        const char * l_current_key_name = dap_enc_get_type_name(i);
        if(l_current_key_name && !strcmp(a_name, l_current_key_name))
            return i;
    }
    log_it(L_WARNING, "No key type with name %s", a_name);
    return DAP_ENC_KEY_TYPE_INVALID;
}

