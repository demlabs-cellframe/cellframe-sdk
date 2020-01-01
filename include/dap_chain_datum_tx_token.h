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
#pragma once

#include <stdint.h>
#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"

/**
  * @struct dap_chain_tx_token
  * @brief Token item
  */
typedef struct dap_chain_tx_token{
    struct {
        dap_chain_tx_item_type_t type:8;
        char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
        uint8_t padding; // Padding
        dap_chain_id_t token_emission_chain_id;
        dap_chain_hash_fast_t token_emission_hash;
    } header; /// Only header's hash is used for verification
} DAP_ALIGN_PACKED dap_chain_tx_token_t;


/**
  * @struct dap_chain_tx_token_ext
  * @brief External token swap
  */
typedef struct dap_chain_tx_token_ext{
    struct {
        dap_chain_tx_item_type_t type:8;
        uint8_t version;
        char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
        uint8_t padding1; // Padding
        dap_chain_net_id_t ext_net_id;
        dap_chain_id_t ext_chain_id;
        dap_chain_hash_fast_t ext_tx_hash;
        uint16_t padding2;
        uint16_t ext_tx_out_idx; // Output index
    } header; /// Only header's hash is used for verification
} DAP_ALIGN_PACKED dap_chain_tx_token_ext_t;
