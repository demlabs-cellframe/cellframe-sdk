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

typedef enum dap_chain_tx_out_cond_subtype {
    DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY = 0x01,
    DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE = 0x02,
    DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE = 0x03
} dap_chain_tx_out_cond_subtype_t;

DAP_STATIC_INLINE const char *dap_chain_tx_out_cond_subtype_to_str(dap_chain_tx_out_cond_subtype_t a_subtype){
    switch (a_subtype) {
    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY: return "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY";
    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE: return "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE";
    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: return "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE";
    default: return "UNDEFINED";

    }
}

/**
 * @struct dap_chain_tx_out
 * @brief Transaction item out_cond
 */
typedef struct dap_chain_tx_out_cond {
    struct {
        /// Transaction item type
        dap_chain_tx_item_type_t item_type :8;
        /// Condition subtype
        dap_chain_tx_out_cond_subtype_t subtype : 8;
        /// Number of Datoshis ( DAP/10^9 ) to be reserver for service
        uint64_t value;
        /// When time expires this output could be used only by transaction owner
        dap_chain_time_t ts_expires;
    } header;
    union {
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
        } srv_pay;
        struct {
            // Service uid that only could be used for this outout
            dap_chain_net_srv_uid_t srv_uid;
            // Token ticker to change to
            char token[DAP_CHAIN_TICKER_SIZE_MAX];
            // Chain network to change to
            dap_chain_net_id_t net_id;
            // Total amount of datoshi to change to
            uint64_t value;
        } srv_xchange;
        struct {
            // Service uid that only could be used for this outout
            dap_chain_net_srv_uid_t srv_uid;
            // Fee address
            dap_chain_addr_t fee_addr;
            // Fee value in percent
            long double fee_value;
        } srv_stake;
    } subtype;
    uint32_t params_size; // Condition parameters size
    uint8_t params[]; // condition parameters, pkey, hash or smth like this
} DAP_ALIGN_PACKED dap_chain_tx_out_cond_t;
