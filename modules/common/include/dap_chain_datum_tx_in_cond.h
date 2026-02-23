/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"

/**
 * @brief Special value for receipt_idx meaning "no receipt binding".
 * Used when owner spends their own conditional output (refill/remove operations)
 * where no receipt from service provider is required.
 */
#define DAP_CHAIN_TX_IN_COND_NO_RECEIPT ((uint32_t)-1)

/**
 * @struct dap_chain_tx_in_cond
 * @brief Conditional transaction input - references a previous OUT_COND to spend
 */
typedef struct dap_chain_tx_in_cond {
    struct {
        dap_chain_tx_item_type_t type;           ///< Transaction item type (TX_ITEM_TYPE_IN_COND)
        dap_chain_hash_fast_t tx_prev_hash;      ///< Hash of the previous transaction containing OUT_COND
        uint32_t tx_out_prev_idx DAP_ALIGNED(4); ///< Index of OUT_COND item in previous tx (among TX_ITEM_TYPE_OUT_ALL)
        uint32_t receipt_idx DAP_ALIGNED(4);     ///< Index of receipt in this tx, or DAP_CHAIN_TX_IN_COND_NO_RECEIPT for owner operations
    } DAP_PACKED header; /// Only header's hash is used for verification
} DAP_PACKED dap_chain_tx_in_cond_t;
