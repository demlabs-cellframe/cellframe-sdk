/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
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

typedef struct dap_chain_tx_out_ext{
    struct {
        dap_chain_tx_item_type_t type;     // Transaction item type - should be TX_ITEM_TYPE_OUT_EXT
        uint256_t value;                   // Number of Datoshis ( DAP/10^8 ) to be transfered
    } DAP_PACKED header;                              // Only header's hash is used for verification
    dap_chain_addr_t addr;                 // Address to transfer to
    const char token[DAP_CHAIN_TICKER_SIZE_MAX]; // Which token is transferred
} DAP_PACKED dap_chain_tx_out_ext_t;
