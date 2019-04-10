/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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
#include <stdio.h>
#include <string.h>
#include "dap_chain_datum_coin.h"

dap_chain_datum_token_t s_token_null = {0};

/**
 * @brief dap_chain_datum_token_create_output_calc
 * @param a_key
 * @return
 */
size_t dap_chain_datum_token_create_output_calc(dap_enc_key_t * a_key)
{
    return sizeof (s_token_null.header) + dap_chain_pkey_from_enc_key_output_calc(a_key);
}

/**
 * @brief dap_chain_datum_token_create_output
 * @param a_key
 * @param a_token_id
 * @param a_token_uuid
 * @param a_output
 * @return
 */
int dap_chain_datum_token_create_output(dap_enc_key_t * a_key, uint64_t a_token_id, uint8_t a_token_uuid[16]
                                            , void * a_output)
{
    dap_chain_datum_token_t * l_token = (dap_chain_datum_token_t * ) a_output;
    l_token->header.token_id = a_token_id;
    memcpy(l_token->header.token_uuid,a_token_uuid,sizeof(*a_token_uuid));
    return dap_chain_pkey_from_enc_key_output(a_key,& (l_token->pkey) );
}
