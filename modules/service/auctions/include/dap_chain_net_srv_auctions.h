/*
 * Authors:
 * Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2024
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

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_datum_tx_event.h"
#include "dap_chain_wallet_cache.h"
#include "dap_chain_ledger.h"
#include "uthash.h"

// Auction service ID
#define DAP_CHAIN_NET_SRV_AUCTION_ID 0x07

// Forward declarations
typedef struct dap_chain_net_srv_auctions dap_chain_net_srv_auctions_t;

// Auction status enumeration
typedef enum {
    DAP_AUCTION_STATUS_UNKNOWN = 0,
    DAP_AUCTION_STATUS_CREATED = 1,
    DAP_AUCTION_STATUS_ACTIVE = 2,
    DAP_AUCTION_STATUS_ENDED = 3,
    DAP_AUCTION_STATUS_CANCELLED = 4
} dap_auction_status_t;

// Single bid information in auction cache
typedef struct dap_auction_bid_cache_item {
    uint64_t project_id;               // ID of the project this bid is for
    dap_hash_fast_t bid_tx_hash;       // Transaction hash of the bid
    dap_chain_addr_t bidder_addr;      // Address of the bidder
    uint256_t bid_amount;              // Amount of the bid
    uint8_t range_end;                 // Range end (1-8)
    dap_time_t lock_time;              // Lock time in seconds
    dap_time_t created_time;           // When bid was created
    bool is_withdrawn;                 // Whether bid was withdrawn
   
    UT_hash_handle hh;                 // Hash table handle by bid_tx_hash
} dap_auction_bid_cache_item_t;

// Project aggregation in auction
typedef struct dap_auction_project_cache_item {
    uint64_t project_id;               // ID of the project
    char *project_name;                // Name of the project
    uint256_t total_amount;            // Total amount bid for this project
    uint32_t bids_count;               // Number of bids for this project
    uint32_t active_bids_count;        // Number of active (non-withdrawn) bids
    
    UT_hash_handle hh;                 // Hash table handle by project_hash
} dap_auction_project_cache_item_t;

// Auction information in cache
typedef struct dap_auction_cache_item {
    dap_hash_fast_t auction_tx_hash;   // Transaction hash of auction creation
    dap_chain_net_id_t net_id;         // Network ID
    char *guuid;                       // Event group name for this auction
    dap_auction_status_t status;       // Current auction status
    
    // Auction timing
    dap_time_t created_time;           // When auction was created
    dap_time_t start_time;             // When bidding started
    dap_time_t end_time;               // When auction ends/ended
    
    // Auction data - TODO: Define specific auction data structure
    char *description;                 // Auction description (if available)
    uint256_t min_bid_amount;          // Minimum bid amount (if specified)
    
    // Bids tracking
    dap_auction_bid_cache_item_t *bids; // Hash table of bids by bid_tx_hash
    uint32_t bids_count;               // Total number of bids
    uint32_t active_bids_count;        // Number of non-withdrawn bids
    
    // Projects tracking
    dap_auction_project_cache_item_t *projects; // Hash table of projects by project_id
    uint32_t projects_count;           // Number of projects in this auction
    
    // Winner tracking (for ended auctions)
    bool has_winner;                   // Whether auction has determined winner
    uint8_t winners_cnt;               // Number of winners in this auction
    uint32_t *winners_ids;             // Array of winner project IDs from event data
    
    UT_hash_handle hh;                 // Hash handle for table keyed by GUUID
    UT_hash_handle hh_hash;            // Hash handle for table keyed by auction_tx_hash
} dap_auction_cache_item_t;

// Main auction cache structure
typedef struct dap_auction_cache {
    dap_auction_cache_item_t *auctions; // Hash table of auctions keyed by GUUID
    dap_auction_cache_item_t *auctions_by_hash; // Hash table for fast lookup by auction_tx_hash
    uint32_t total_auctions;            // Total number of auctions in cache
    uint32_t active_auctions;           // Number of active auctions
    pthread_rwlock_t cache_rwlock;      // Read-write lock for cache access
} dap_auction_cache_t;

// Auction service structure
struct dap_chain_net_srv_auctions {
    dap_chain_net_srv_t *parent;       // Parent service
    dap_auction_cache_t *cache;         // Auction cache
};

// Project information in auction (for external API)
typedef struct dap_chain_net_srv_auction_project {
    uint64_t project_id;
    char *project_name;
    uint256_t total_amount;
    uint32_t bids_count;
    uint32_t active_bids_count;
} dap_chain_net_srv_auction_project_t;

// Single auction structure (for external API)
typedef struct dap_chain_net_srv_auction {
    dap_hash_fast_t auction_hash;
    char *guuid;                        // Auction GUUID from cache
    dap_auction_status_t status;
    dap_time_t created_time;
    dap_time_t start_time;
    dap_time_t end_time;
    char *description;
    uint32_t bids_count;
    uint32_t projects_count;
    
    // Winner information (if auction ended)
    bool has_winner;                      // Whether auction has determined winner
    uint8_t winners_cnt;                  // Number of winners
    uint32_t *winners_ids;                // Array of winner project IDs
    
    // Projects array (if requested)
    dap_chain_net_srv_auction_project_t *projects;
} dap_chain_net_srv_auction_t;

#ifdef __cplusplus
extern "C" {
#endif

// Service initialization/deinitialization
int dap_chain_net_srv_auctions_init(void);
void dap_chain_net_srv_auctions_deinit(void);

// Register event notification callback for a specific network
// This should be called when new networks are created after auction service initialization
int dap_chain_net_srv_auctions_register_net_callback(dap_chain_net_t *a_net);

// Service management
dap_chain_net_srv_auctions_t *dap_chain_net_srv_auctions_create(dap_chain_net_srv_t *a_srv);
void dap_chain_net_srv_auctions_delete(dap_chain_net_srv_auctions_t *a_auctions);

// Auction cache API
dap_auction_cache_t *dap_auction_cache_create(void);
void dap_auction_cache_delete(dap_auction_cache_t *a_cache);

// Cache manipulation functions
int dap_auction_cache_add_auction(dap_auction_cache_t *a_cache, 
                                  dap_hash_fast_t *a_auction_hash,
                                  dap_chain_net_id_t a_net_id,
                                  const char *a_guuid,
                                  dap_chain_tx_event_data_auction_started_t *a_started_data,
                                  dap_time_t a_tx_timestamp);

int dap_auction_cache_add_bid(dap_auction_cache_t *a_cache,
                              dap_hash_fast_t *a_auction_hash,
                              dap_hash_fast_t *a_bid_hash,
                              dap_chain_addr_t *a_bidder_addr,
                              uint256_t a_bid_amount,
                              dap_time_t a_lock_time,
                              uint64_t a_project_id,
                              const char *a_project_name);

int dap_auction_cache_update_auction_status(dap_auction_cache_t *a_cache,
                                           dap_hash_fast_t *a_auction_hash,
                                           dap_auction_status_t a_new_status);

// New: update auction status by group name
int dap_auction_cache_update_auction_status_by_name(dap_auction_cache_t *a_cache,
                                                   const char *a_guuid,
                                                   dap_auction_status_t a_new_status);

int dap_auction_cache_withdraw_bid(dap_auction_cache_t *a_cache,
                                  dap_hash_fast_t *a_bid_hash);

int dap_auction_cache_set_winners(dap_auction_cache_t *a_cache,
                                 dap_hash_fast_t *a_auction_hash,
                                 uint8_t a_winners_cnt,
                                 uint32_t *a_winners_ids);

// New: set winners by group name
int dap_auction_cache_set_winners_by_name(dap_auction_cache_t *a_cache,
                                         const char *a_guuid,
                                         uint8_t a_winners_cnt,
                                         uint32_t *a_winners_ids);

// Search functions
// Find by auction tx hash
dap_auction_cache_item_t *dap_auction_cache_find_auction(dap_auction_cache_t *a_cache,
                                                         dap_hash_fast_t *a_auction_hash);
// New: find by group name
dap_auction_cache_item_t *dap_auction_cache_find_auction_by_name(dap_auction_cache_t *a_cache,
                                                                 const char *a_guuid);

dap_auction_bid_cache_item_t *dap_auction_cache_find_bid(dap_auction_cache_item_t *a_auction,
                                                         dap_hash_fast_t *a_bid_hash);

dap_auction_project_cache_item_t *dap_auction_cache_find_project(dap_auction_cache_item_t *a_auction,
                                                                 uint64_t a_project_id);

// External API for frontend and CLI
dap_chain_net_srv_auction_t *dap_chain_net_srv_auctions_find(dap_chain_net_t *a_net, 
                                                             dap_chain_hash_fast_t *a_hash);
void dap_chain_net_srv_auction_delete(dap_chain_net_srv_auction_t *a_auction);

// Get list of all auctions (with optional filtering)
dap_list_t *dap_chain_net_srv_auctions_get_list(dap_chain_net_t *a_net, 
                                                dap_auction_status_t a_status_filter, 
                                                bool a_include_projects);

// Get detailed auction information with all projects
dap_chain_net_srv_auction_t *dap_chain_net_srv_auctions_get_detailed(dap_chain_net_t *a_net,
                                                                     dap_chain_hash_fast_t *a_hash);

// Get statistics about auctions
typedef struct {
    uint32_t total_auctions;
    uint32_t active_auctions;
    uint32_t ended_auctions;
    uint32_t cancelled_auctions;
    uint32_t total_bids;
    uint32_t total_projects;
} dap_auction_stats_t;

dap_auction_stats_t *dap_chain_net_srv_auctions_get_stats(dap_chain_net_t *a_net);

// Event fixation callback (for ledger event notifications)
void dap_auction_cache_event_callback(void *a_arg, 
                                      dap_ledger_t *a_ledger,
                                      dap_chain_tx_event_t *a_event,
                                      dap_hash_fast_t *a_tx_hash,
                                      dap_chan_ledger_notify_opcodes_t a_opcode);

// Helper functions
const char *dap_auction_status_to_str(dap_auction_status_t a_status);
dap_auction_status_t dap_auction_status_from_event_type(uint16_t a_event_type);

// Transaction creation functions 
char *dap_chain_net_srv_auction_bid_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_from, const dap_hash_fast_t *a_auction_hash, 
                                uint256_t a_amount, dap_time_t a_lock_time, uint32_t a_project_id, uint256_t a_fee, int *a_ret_code);

char *dap_chain_net_srv_auction_withdraw_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_from, dap_hash_fast_t *a_bid_tx_hash, uint256_t a_fee, uint256_t *a_value, int *a_ret_code);

#ifdef __cplusplus
}
#endif 