/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
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
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_common.h"
#include "dap_time.h"
#include "dap_chain_datum_tx_out_cond.h"

typedef struct dap_chain_net_srv_auctions dap_chain_net_srv_auctions_t;

// Auction states
typedef enum dap_chain_net_srv_auction_state {
    AUCTION_STATE_UNDEFINED = 0,
    AUCTION_STATE_ACTIVE,
    AUCTION_STATE_COMPLETED,
    AUCTION_STATE_CANCELLED
} dap_chain_net_srv_auction_state_t;

// Auction bid structure
typedef struct dap_chain_net_srv_auction_bid {
    dap_chain_hash_fast_t tx_hash;          // Bid transaction hash
    dap_chain_addr_t bidder_addr;           // Bidder's address
    uint64_t amount;                        // Bid amount in CELL
    uint8_t range_end;                      // CellSlot range end (1-8)
    uint8_t lock_months;                    // Token lock period (3-24 months)
    dap_time_t timestamp;                   // Bid timestamp
    struct dap_chain_net_srv_auction_bid *next; // Next bid in list
} dap_chain_net_srv_auction_bid_t;

// Auction structure
typedef struct dap_chain_net_srv_auction {
    dap_chain_hash_fast_t hash;             // Auction hash
    dap_chain_net_srv_auction_state_t state; // Auction state
    dap_time_t start_time;                  // Auction start time
    dap_time_t end_time;                    // Auction end time
    dap_chain_net_srv_auction_bid_t *bids;  // List of bids
    uint32_t bid_count;                     // Number of bids
    struct dap_chain_net_srv_auction *next; // Next auction in list
} dap_chain_net_srv_auction_t;

// Service structure
struct dap_chain_net_srv_auctions {
    dap_chain_net_srv_t *parent;           // Parent service
    dap_chain_net_srv_auction_t *auctions; // List of auctions
    uint32_t auction_count;                // Number of auctions
};

// Service initialization/deinitialization
int dap_chain_net_srv_auctions_init(void);
void dap_chain_net_srv_auctions_deinit(void);

// Service creation/deletion
dap_chain_net_srv_auctions_t *dap_chain_net_srv_auctions_create(dap_chain_net_srv_t *a_srv);
void dap_chain_net_srv_auctions_delete(dap_chain_net_srv_auctions_t *a_auctions);

// Auction management
dap_chain_net_srv_auction_t *dap_chain_net_srv_auctions_find(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_hash);
