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
#include "dap_time.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"

enum dap_chain_tx_out_cond_subtype {
    DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED = 0x0,
    DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY = 0x01,
    DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE = 0x02,
    DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE = 0x03,
    DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE = 0x04,
    DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK = 0x06,
    DAP_CHAIN_TX_OUT_COND_SUBTYPE_ALL = 0xFF
};
typedef byte_t dap_chain_tx_out_cond_subtype_t;

DAP_STATIC_INLINE const char *dap_chain_tx_out_cond_subtype_to_str(dap_chain_tx_out_cond_subtype_t a_subtype){
    switch (a_subtype) {
    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY: return "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY";
    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE: return "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE";
    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE: return "DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE";
    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: return "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE";
    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK: return "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK";
    default: {}
    }
    return "UNDEFINED";
}

// Stake lock base flags
// Lock by time
#define DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_BY_TIME           0x00000008
// Create base tx for delegated token
#define DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_CREATE_BASE_TX    0x00000010
// Emit with single lock TX
#define DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_EMIT              0x00000020

/**
 * @struct dap_chain_tx_out
 * @brief Transaction item out_cond
 */
typedef struct dap_chain_tx_out_cond {
    struct {
        /// Transaction item type
        dap_chain_tx_item_type_t item_type;
        /// Condition subtype
        dap_chain_tx_out_cond_subtype_t subtype;
        /// Number of Datoshis ( DAP/10^18 ) to be reserved for service
        uint256_t value;
        byte_t paddding_ext[6];
        /// When time expires this output could be used only by transaction owner
        dap_time_t ts_expires;
        /// Service uid that only could be used for this out
        dap_chain_net_srv_uid_t srv_uid;
#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
        byte_t padding[8];
#endif
    } DAP_ALIGN_PACKED header;
    union {
        /// Structure with specific for service pay condition subtype
        struct {
            /// Public key hash that could use this conditioned outout
            dap_chain_hash_fast_t pkey_hash;
            /// Price unit thats used to check price max
            dap_chain_net_srv_price_unit_uid_t unit;
            /// Maximum price per unit
            uint256_t unit_price_max_datoshi;
        } DAP_ALIGN_PACKED srv_pay;
        struct {
            // Chain network to change from
            dap_chain_net_id_t sell_net_id;
            // Chain network to change to
            dap_chain_net_id_t buy_net_id;
            // Total amount of datoshi to change to
            uint256_t buy_value;
            // Token ticker to change to
            char buy_token[DAP_CHAIN_TICKER_SIZE_MAX];
            // Seller address
            dap_chain_addr_t seller_addr;
        } DAP_ALIGN_PACKED srv_xchange;
        struct {
            // Public key hash of signing certificate combined with net id
            dap_chain_addr_t signing_addr;
            // Node address of signer with this stake
            dap_chain_node_addr_t signer_node_addr;
        } DAP_ALIGN_PACKED srv_stake_pos_delegate;
        struct {
            dap_time_t		time_unlock;
            dap_hash_fast_t	unused;
            uint256_t		reinvest_percent;
            uint32_t		flags;
            byte_t          padding[4];
        } DAP_ALIGN_PACKED srv_stake_lock;
        struct {
            // Nothing here
        } DAP_ALIGN_PACKED fee;
        byte_t free_space[272]; // TODO increase it to 512 with version update
    } DAP_ALIGN_PACKED subtype;
    uint32_t tsd_size; // Condition parameters size
    uint8_t tsd[]; // condition parameters, pkey, hash or smth like this
} DAP_ALIGN_PACKED dap_chain_tx_out_cond_t;
