/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025, All rights reserved.

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

#include <stdint.h>
#include "dap_common.h"
#include "dap_chain_common.h"

typedef struct dap_chain_tx_item_event {
    dap_chain_tx_item_type_t type;          /// @param type             @brief Transaction item type
    uint8_t version;                        /// @param version          @brief Version of the event.
    uint16_t group_size;                    /// @param group_size       @brief Size of the group
    uint16_t event_type;                    /// @param event_type       @brief Event type.
    byte_t group[];                         /// @param group            @brief Event group
} DAP_ALIGN_PACKED dap_chain_tx_item_event_t;

typedef struct dap_chain_tx_event {
    char *group_name;                   /// @param group_name           @brief Event group name
    dap_chain_tx_item_type_t type;      /// @param type                 @brief Transaction item type
    dap_chain_hash_fast_t tx_hash;      /// @param tx_hash              @brief Hash of the transaction.
    dap_chain_hash_fast_t pkey_hash;    /// @param pkey_hash            @brief Hash of the public key.
    uint16_t event_type;                /// @param event_type           @brief Event type.
    void *event_data;                   /// @param event_data           @brief Event data.
    size_t event_data_size;             /// @param event_data_size      @brief Event data size.
} dap_chain_tx_event_t;

#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_STARTED             0x0001
#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_BID_PLACED          0x0002
#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_WON                 0x0003
#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_LOST                0x0004
#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_CANCELLED           0x0005

#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_STARTED_JSON_STR     "auction_started"
#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_BID_PLACED_JSON_STR  "auction_bid_placed"
#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_WON_JSON_STR         "auction_won"
#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_LOST_JSON_STR        "auction_lost"
#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_CANCELLED_JSON_STR   "auction_cancel"