/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
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


#define DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY     0x01
/**
 * @struct dap_chain_tx_out
 * @brief Transaction item out_cond
 */
typedef struct dap_chain_tx_out_cond {
    struct {
        /// Transaction item type
        dap_chain_tx_item_type_t item_type :8;
        /// Condition subtype
        uint8_t subtype;
        /// Number of Datoshis ( DAP/10^9 ) to be reserver for service
        uint64_t value;
        /// When time expires this output could be used only by transaction owner
        dap_chain_time_t ts_expires;
    } header;
    union {
        struct {
            /// Structure with specific for service pay condition subtype
            struct {
                /// Public key hash that could use this conditioned outout
                dap_chain_hash_fast_t pkey_hash;
                /// Service uid that only could be used for this outout
                dap_chain_net_srv_uid_t srv_uid;
                /// Price unit thats used to check price max
                dap_chain_net_srv_price_unit_uid_t unit;
                /// Maximum price per unit
                uint64_t unit_price_max_datoshi;
                 /// Condition parameters size
                uint32_t params_size;
            } DAP_ALIGN_PACKED header;
            uint8_t params[]; // condition parameters, pkey, hash or smth like this
        } DAP_ALIGN_PACKED srv_pay;
    } subtype;
}DAP_ALIGN_PACKED dap_chain_tx_out_cond_t;

uint8_t* dap_chain_datum_tx_out_cond_item_get_params(dap_chain_tx_out_cond_t *a_tx_out_cond, size_t *a_params_size_out);


