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
#include "dap_pkey.h"

#define LOG_TAG "chain_key"
//static dap_pkey_t m_dap_pkey_null={0}; // For sizeof nothing more


/**
 * @brief 
 * convert encryption key to public key
 * @param a_key dap_enc_key_t encryption key
 * @return dap_pkey_t* 
 */
dap_pkey_t *dap_pkey_from_enc_key(dap_enc_key_t *a_key)
{
    dap_pkey_type_t l_type;
    if (a_key->pub_key_data_size > 0 ){
        switch (a_key->type) {
            case DAP_ENC_KEY_TYPE_SIG_BLISS:
                l_type.type = PKEY_TYPE_SIGN_BLISS; break;
            case DAP_ENC_KEY_TYPE_SIG_TESLA:
                l_type.type = PKEY_TYPE_SIGN_TESLA; break;
            case DAP_ENC_KEY_TYPE_SIG_PICNIC:
                l_type.type = PKEY_TYPE_SIGN_PICNIC; break;
            case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
                l_type.type = PKEY_TYPE_SIGN_DILITHIUM; break;
            default:
                log_it(L_WARNING,"No serialization preset");
                return NULL;
        }
        size_t l_pub_key_size;
        uint8_t *l_pkey = dap_enc_key_serealize_pub_key(a_key, &l_pub_key_size);
        if (!l_pkey) {
            log_it(L_WARNING,"Serialization failed");
            return NULL;
        }
        dap_pkey_t *l_ret = DAP_NEW_SIZE(dap_pkey_t, sizeof(dap_pkey_t) + l_pub_key_size);
        l_ret->header.type = l_type;
        l_ret->header.size = (uint32_t)l_pub_key_size;
        memcpy(&l_ret->pkey, l_pkey, l_pub_key_size);
        DAP_DELETE(l_pkey);
        return l_ret;
    }else{
        log_it(L_WARNING, "No public key in the input enc_key object");
        return NULL;
    }
    return NULL;
}
