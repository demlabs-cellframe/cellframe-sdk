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
#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
/**
  * @struct dap_chain_tx_item
  * @brief Sections belongs to heading tx section, with inputs, outputs and others tx relatated items
  */

typedef struct dap_chain_tx_in{
    struct {
        dap_chain_tx_item_type_t type; /// @param    type            @brief Transaction item type
        dap_chain_hash_fast_t tx_prev_hash; /// @param tx_prev_hash    @brief Hash of the previous transaction. 0 for generation TX
        uint32_t tx_out_prev_idx; ///      @param   tx_prev_idx     @brief Previous tx_out index. 0 for generation TX
//        dap_sign_type_t sig_type; /// Signature type
//        uint32_t sig_size; /// Signature size
    } header; /// Only header's hash is used for verification
//    uint32_t seq_no; /// Sequence number, out of the header so could be changed during reorganization
//    uint8_t sig[]; /// @param sig @brief raw signatura dat
} DAP_ALIGN_PACKED dap_chain_tx_in_t;

typedef struct list_used_item {
    dap_chain_hash_fast_t tx_hash_fast;
    uint32_t num_idx_out;
    uint8_t padding[4];
    uint64_t value;
//dap_chain_tx_out_t *tx_out;
} list_used_item_t;
