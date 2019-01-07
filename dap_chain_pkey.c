/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net    https:/gitlab.com/demlabs
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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
#include <string.h>
#include "dap_common.h"
#include "dap_chain_pkey.h"

#define LOG_TAG "chain_key"
dap_chain_pkey_t m_dap_chain_pkey_null={0}; // For sizeof nothing more


/**
 * @brief dap_chain_pkey_enc_get_buf_out_size
 * @param a_pkey
 * @return
 */
size_t dap_chain_pkey_enc_get_buf_out_size(dap_chain_pkey_t * a_pkey)
{
    log_it(L_WARNING,"NOT DEFINED:dap_chain_pkey_enc_get_buf_out_size");
    return 0;
}

/**
 * @brief dap_chain_pkey_enc
 * @param a_type
 * @param a_buf_in
 * @param a_buf_in_size
 * @param a_buf_out
 * @return
 */
int dap_chain_pkey_enc(dap_chain_pkey_t * a_pkey,const void * a_buf_in, uint32_t a_buf_in_size, void * a_buf_out) // 0 if success
{
    log_it(L_WARNING,"NOT DEFINED: dap_chain_pkey_enc");
    return -1;
}

/**
 * @brief dap_chain_pkey_from_enc_key
 * @param a_key
 * @return
 */
dap_chain_pkey_t* dap_chain_pkey_from_enc_key(dap_enc_key_t *a_key)
{
    dap_chain_pkey_t * l_ret = NULL;
    if (a_key->pub_key_data_size > 0 ){
        l_ret = DAP_NEW_Z_SIZE(dap_chain_pkey_t,sizeof(l_ret->header)+ a_key->pub_key_data_size);
        switch (a_key->type) {
            case DAP_ENC_KEY_TYPE_SIG_BLISS:
                l_ret->header.type.type = PKEY_TYPE_SIGN_BLISS ;
            break;
            case DAP_ENC_KEY_TYPE_SIG_PICNIC:
                l_ret->header.type.type = PKEY_TYPE_SIGN_PICNIC ;
            break;
            default:
                log_it(L_WARNING,"No serialization preset");
                DAP_DELETE(l_ret);
                return NULL;
        }
        l_ret->header.size = a_key->pub_key_data_size;
        memcpy(l_ret->pkey,a_key->pub_key_data,a_key->pub_key_data_size);
    }else
        log_it(L_WARNING, "No public key in the input enc_key object");
    return l_ret;
}
