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
#pragma once

#include <stdint.h>
#include <string.h>

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_datum_tx_out.h"
#include "dap_chain_datum_tx_sig.h"
#include "dap_chain_datum_tx_pkey.h"
#include "dap_chain_datum_tx_token.h"

/**
 * Create item dap_chain_tx_token_t
 *
 * return item, NULL Error
 */
dap_chain_tx_token_t* dap_chain_datum_item_token_create(const char *a_name);

/**
 * Create item dap_chain_tx_out_t
 *
 * return item, NULL Error
 */
dap_chain_tx_in_t* dap_chain_datum_item_in_create(dap_chain_hash_fast_t *a_tx_prev_hash, uint32_t a_tx_out_prev_idx);


/**
 * Create item dap_chain_tx_out_t
 *
 * return item, NULL Error
 */
dap_chain_tx_out_t* dap_chain_datum_item_out_create(dap_chain_addr_t *a_addr, uint64_t a_value);

/**
 * Create item dap_chain_tx_sig_t
 *
 * return item, NULL Error
 */
dap_chain_tx_sig_t* dap_chain_datum_item_sign_create(dap_enc_key_t *a_key, const void *a_data, size_t a_data_size);

