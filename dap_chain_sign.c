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

#include "dap_common.h"
#include "dap_chain_sign.h"
#include "dap_enc_bliss.h"
#include "dap_enc_tesla.h"
#include "dap_enc_picnic.h"

#define LOG_TAG "dap_chain_sign"

dap_chain_sign_t * s_sign_null = NULL;
bliss_signature_t s_sign_bliss_null = {0};
size_t dap_chain_sign_cals_size(dap_enc_key_t * a_key)
{
    size_t l_sign_size = 0;
    switch (a_key->type){
        case DAP_ENC_KEY_TYPE_SIG_BLISS: l_sign_size = sizeof(s_sign_bliss_null); break;
        case DAP_ENC_KEY_TYPE_SIG_PICNIC: dap_enc_picnic_calc_signature_size(a_key); break;
        default : return 0;

    }
    return sizeof(s_sign_null->header)+ a_key->pub_key_data_size + l_sign_size;
}

int dap_chain_sign_create(dap_enc_key_t *a_key, const void * a_data, const size_t a_data_size, void * a_output )
{
    return 0;
}
