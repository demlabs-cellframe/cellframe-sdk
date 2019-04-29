/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
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

#include <stdint.h>
#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx_out_cond.h"


uint8_t* dap_chain_datum_tx_out_cond_item_get_pkey(dap_chain_tx_out_cond_t *a_tx_out_cond, size_t *a_pkey_size_out)
{
    if(a_tx_out_cond) {
        if(a_pkey_size_out)
            *a_pkey_size_out = a_tx_out_cond->header.pub_key_size;
        return a_tx_out_cond->data;
    }
    return NULL;
}

uint8_t* dap_chain_datum_tx_out_cond_item_get_cond(dap_chain_tx_out_cond_t *a_tx_out_cond, size_t *a_cond_size_out)
{
    if(a_tx_out_cond) {
        if(a_cond_size_out)
            *a_cond_size_out = a_tx_out_cond->header.cond_size;
        return a_tx_out_cond->data + a_tx_out_cond->header.pub_key_size;
    }
    return NULL;
}

