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
dap_pkey_t* dap_pkey_from_enc_key(dap_enc_key_t *a_key)
{
    if (a_key->pub_key_data_size > 0 ){
        dap_pkey_t * l_ret = NULL;
        l_ret = DAP_NEW_Z_SIZE(dap_pkey_t,dap_pkey_from_enc_key_output_calc(a_key));
        if( dap_pkey_from_enc_key_output(a_key,l_ret) != 0 ) {
            DAP_DELETE(l_ret);
            return NULL;
        }else
            return l_ret;
    }

    return NULL;
}

/**
 * @brief dap_pkey_from_enc_key_output
 * convert encryption key to public key and placed it in output buffer
 * @param a_key dap_enc_key_t encryption key object
 * @param a_output output data
 * @return result
 */
int dap_pkey_from_enc_key_output(dap_enc_key_t *a_key, void * a_output)
{
    dap_pkey_t * l_output = (dap_pkey_t *) a_output;
    if (a_key->pub_key_data_size > 0 ){
        switch (a_key->type) {
            case DAP_ENC_KEY_TYPE_SIG_BLISS:
                l_output->header.type.type = PKEY_TYPE_SIGN_BLISS ;
            break;
            case DAP_ENC_KEY_TYPE_SIG_TESLA:
                l_output->header.type.type = PKEY_TYPE_SIGN_TESLA ;
            break;
            case DAP_ENC_KEY_TYPE_SIG_PICNIC:
                l_output->header.type.type = PKEY_TYPE_SIGN_PICNIC ;
            break;
            case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
                l_output->header.type.type = PKEY_TYPE_SIGN_DILITHIUM;
            break;

            default:
                log_it(L_WARNING,"No serialization preset");
                return -1;
        }
        l_output->header.size = a_key->pub_key_data_size;
        memcpy(l_output->pkey,a_key->pub_key_data,a_key->pub_key_data_size);
        return 0;
    }else{
        log_it(L_WARNING, "No public key in the input enc_key object");
        return -2;
    }
    return -3;
}


