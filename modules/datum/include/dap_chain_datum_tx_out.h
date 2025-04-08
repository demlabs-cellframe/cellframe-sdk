/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2018
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
#include "dap_time.h"
/**
  * @struct dap_chain_tx_out
  * @brief Transaction item outout
  */
typedef struct dap_chain_tx_out_old {
    struct {
        dap_chain_tx_item_type_t type; ///           @param    type            @brief  Transaction item type
        uint64_t value DAP_ALIGNED(8); ///                       @param    value           @brief  Number of Datoshis ( DAP/10^9 ) to be transfered
    } DAP_PACKED header; /// Only header's hash is used for verification
    dap_chain_addr_t addr; ////
} DAP_PACKED dap_chain_tx_out_old_t;

//256
typedef struct dap_chain_tx_out {
    struct {
        dap_chain_tx_item_type_t type; ///           @param    type            @brief  Transaction item type
        uint256_t value; ///                       @param    value           @brief  Number of Datoshis ( DAP/10^9 ) to be transfered
    } DAP_PACKED header; /// Only header's hash is used for verification
    dap_chain_addr_t addr; ////
} DAP_PACKED dap_chain_tx_out_t;

typedef struct dap_chain_tx_out_ext {
    struct {
        dap_chain_tx_item_type_t type;     // Transaction item type - should be TX_ITEM_TYPE_OUT_EXT
        uint256_t value;                   // Number of Datoshis ( DAP/10^8 ) to be transfered
    } DAP_PACKED header;                              // Only header's hash is used for verification
    dap_chain_addr_t addr;                 // Address to transfer to
    const char token[DAP_CHAIN_TICKER_SIZE_MAX]; // Which token is transferred
} DAP_PACKED dap_chain_tx_out_ext_t;

typedef struct dap_chain_tx_out_std {
    dap_chain_tx_item_type_t type;      // Transaction item type - should be TX_ITEM_TYPE_OUT_STD
    uint8_t version;                    // Output version
    const char token[DAP_CHAIN_TICKER_SIZE_MAX]; // Token to be transferred
    uint256_t value;                    // Number of datoshis ( coin/10^8 ) to be transfered
    dap_chain_addr_t addr;              // Address to transfer to
    dap_time_t ts_unlock;               // Time to unlock for locked out
} DAP_ALIGN_PACKED dap_chain_tx_out_std_t;
