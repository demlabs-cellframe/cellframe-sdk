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
#include "dap_chain_datum_token.h"

/**
 * @brief dap_chain_datum_token_register
 * @param a_token
 */
void dap_chain_datum_token_register(dap_chain_datum_token_t * a_token)
{

}

/**
 * @brief dap_chain_datum_token_get_sign
 * @param a_token
 * @param a_token_size_max
 * @param a_sign_number
 * @return
 */
dap_chain_sign_t * dap_chain_datum_token_get_sign( dap_chain_datum_token_t * a_token, size_t a_token_size_max, uint16_t a_sign_number);

dap_chain_datum_token_t* dap_chain_datum_token_find_by_ticker(const char a_ticker[10] );
dap_chain_datum_token_t* dap_chain_datum_token_find_by_hash(dap_chain_hash_fast_t * a_hash );
