/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2023
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <pqlr/sphincs_plus/sphincs_plus.h>
// For version function
#include <pqlr/common/version.h>

#include "dap_common.h"
#include "dap_enc_key.h"
#include "dap_pqlr_sphincs.h"

#define LOG_TAG "pqlr_sphincs"

#define PVT(a)  ((sphincs_plus_t) (a)->_pvt)

/**
 * @brief dap_pqlr_sphincs_key_new
 * @param a_key
 */
void dap_pqlr_sphincs_key_new (dap_enc_key_t *a_key)
{
    a_key->_pvt = sphincs_plus_new(sphincs_plus_parameterset_128f, hashalgo_sha256);

}

/**
 * @brief dap_pqlr_sphincs_key_delete
 * @param a_key
 */
void dap_pqlr_sphincs_key_delete(dap_enc_key_t* a_key)
{
    sphincs_plus_free(PVT(a_key));
}

/**
 * @brief dap_pqlr_sphincs_key_new_generate
 * @param a_key
 * @param a_kex_buf
 * @param a_kex_size
 * @param a_seed
 * @param a_seed_size
 * @param a_key_size
 */
void dap_pqlr_sphincs_key_new_generate( dap_enc_key_t* a_key, const void* a_kex_buf, size_t a_kex_size,
                               const void* a_seed, size_t a_seed_size, size_t a_key_size)
{
    dap_pqlr_sphincs_key_new(a_key->_pvt);
    a_key->priv_key_data_size = sphincs_plus_get_secret_key_bytes_len ( PVT(a_key) );
    a_key->priv_key_data = DAP_NEW_SIZE(void, a_key->priv_key_data_size);

    a_key->pub_key_data_size = sphincs_plus_get_public_key_bytes_len ( PVT(a_key) );
    a_key->pub_key_data = DAP_NEW_SIZE(void, a_key->pub_key_data_size);

    sphincs_plus_generate_keys(PVT(a_key), (byte_t*) a_key->priv_key_data, (byte_t*) a_key->pub_key_data );

}

size_t dap_pqlr_sphincs_calc_signature_size(dap_enc_key_t* a_key)
{
    return sphincs_plus_get_signature_bytes_len(PVT(a_key));
}

/**
 * @brief dap_pqlr_sphincs_create_sign
 * @param a_key
 * @param a_msg
 * @param a_msg_size
 * @param a_signature
 * @param a_signature_size
 * @return
 */
size_t dap_pqlr_sphincs_create_sign(dap_enc_key_t* a_key, const void * a_msg, const size_t a_msg_size,
                  void* a_signature, const size_t a_signature_size)
{
    UNUSED(a_signature_size);
    size_t l_sign_size = sphincs_plus_get_signature_bytes_len(PVT(a_key));

    /*a_signature = DAP_NEW_SIZE(void, l_sign_size);
    if(! a_signature ){
        log_it(L_ERROR, "Out of memory, can't create signature");
        return 0;
    }*/
    if (!a_signature) {
        log_it(L_ERROR, "Invalid signature parameter");
        return 0;
    }
    sphincs_plus_sign(PVT(a_key), (byte_t*) a_key->priv_key_data, a_msg, a_msg_size, a_signature);
    return l_sign_size;
}

/**
 * @brief dap_pqlr_sphincs_verify_sign
 * @param a_key
 * @param a_msg
 * @param a_msg_size
 * @param a_signature
 * @param signature_size
 * @return
 */
size_t dap_pqlr_sphincs_verify_sign( dap_enc_key_t* a_key, const void* a_msg, const size_t a_msg_size, void* a_signature,
                     const size_t signature_size)
{
    return sphincs_plus_verify(PVT(a_key), (byte_t *) a_key->pub_key_data, a_signature, a_msg, a_msg_size);
}
