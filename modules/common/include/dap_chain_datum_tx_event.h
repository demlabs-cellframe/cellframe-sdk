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
#include "dap_time.h"
#include "dap_chain_common.h"

#define DAP_CHAIN_TX_EVENT_VERSION                          0x0001

typedef struct dap_chain_tx_item_event {
    dap_chain_tx_item_type_t type;          /// @param type             @brief Transaction item type
    uint8_t version;                        /// @param version          @brief Version of the event.
    uint16_t group_size;                    /// @param group_size       @brief Size of the group
    uint16_t event_type;                    /// @param event_type       @brief Event type.
    dap_time_t timestamp;                   /// @param timestamp        @brief Timestamp of the event.
    byte_t group_name[];                    /// @param group_name       @brief Event group name
} DAP_ALIGN_PACKED dap_chain_tx_item_event_t;

typedef struct dap_chain_tx_event {
    dap_time_t timestamp;               /// @param timestamp            @brief Timestamp of the event.
    char *group_name;                   /// @param group_name           @brief Event group name
    dap_chain_hash_fast_t tx_hash;      /// @param tx_hash              @brief Hash of the transaction.
    dap_chain_hash_fast_t pkey_hash;    /// @param pkey_hash            @brief Hash of the public key.
    uint16_t event_type;                /// @param event_type           @brief Event type.
    void *event_data;                   /// @param event_data           @brief Event data.
    size_t event_data_size;             /// @param event_data_size      @brief Event data size.
} dap_chain_tx_event_t;

#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_STARTED             0x0001
#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_BID_PLACED          0x0002
#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_FINISH              0x0003
#define DAP_CHAIN_TX_EVENT_TYPE_AUCTION_CANCELLED           0x0004

DAP_STATIC_INLINE const char *dap_chain_tx_item_event_type_to_str(uint16_t a_event_type)
{
    switch (a_event_type) {
        case DAP_CHAIN_TX_EVENT_TYPE_AUCTION_STARTED: return "auction_started";
        case DAP_CHAIN_TX_EVENT_TYPE_AUCTION_BID_PLACED: return "auction_bid_placed";
        case DAP_CHAIN_TX_EVENT_TYPE_AUCTION_FINISH: return "auction_finish";  
        case DAP_CHAIN_TX_EVENT_TYPE_AUCTION_CANCELLED: return "auction_cancel";
        default: return "unknown";
    }
}

#define DAP_CHAIN_TX_TSD_TYPE_CUSTOM_DATA                   0x1000
#define DAP_CHAIN_TX_TSD_TYPE_CUSTOM_DATA_JSON_STR          "custom_data"

int dap_chain_datum_tx_item_event_to_json(json_object *a_json_obj, dap_chain_tx_item_event_t *a_event);
int dap_chain_datum_tx_event_to_json(json_object *a_json_obj, dap_chain_tx_event_t *a_event, const char *a_hash_out_type);