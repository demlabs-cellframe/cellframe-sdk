/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "dap_chain_common.h"
#include "dap_hash.h"
#include "uint256.h"

/**
 * @brief UTXO (Unspent Transaction Output) descriptor
 * 
 * Represents an unspent output that can be used as input for new transactions.
 * This is a ledger-level concept - datum layer doesn't know about UTXO.
 */
typedef struct dap_chain_tx_used_out {
    dap_chain_hash_fast_t tx_prev_hash;  // Previous TX hash
    uint32_t tx_out_prev_idx;             // Output index in prev TX
    uint256_t value;                      // Output value
    dap_chain_addr_t addr;                // Address (for validation)
} dap_chain_tx_used_out_t;

