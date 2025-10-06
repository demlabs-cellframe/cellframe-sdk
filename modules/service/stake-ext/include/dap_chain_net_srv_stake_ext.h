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

// Stake-ext service ID
#define DAP_CHAIN_NET_SRV_STAKE_EXT_ID 0x07

// Forward declarations
typedef struct dap_chain_net_srv_stake_ext dap_chain_net_srv_stake_ext_t;

typedef enum dap_chain_tx_event_data_time_unit {
    DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_HOURS  = 0,
    DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_DAYS   = 1,
    DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_WEEKS  = 2,
    DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_MONTHS = 3,
} dap_chain_tx_event_data_time_unit_t;

DAP_STATIC_INLINE const char *dap_chain_tx_event_data_time_unit_to_str(dap_chain_tx_event_data_time_unit_t a_time_unit)
{
    switch (a_time_unit) {
    case DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_HOURS: return "hours";
    case DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_DAYS: return "days";
    case DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_WEEKS: return "weeks";
    case DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_MONTHS: return "months";
    default: return "seconds";
    }
}

typedef struct dap_chain_tx_event_data_stake_ext_started {
    uint32_t multiplier;
    dap_time_t duration;
    dap_chain_tx_event_data_time_unit_t time_unit;
    uint32_t calculation_rule_id;
    uint8_t total_positions;
    uint32_t position_ids[];
} DAP_ALIGN_PACKED dap_chain_tx_event_data_stake_ext_started_t;

typedef struct dap_chain_tx_event_data_ended {
    uint8_t winners_cnt;
    uint32_t winners_ids[];
} DAP_ALIGN_PACKED dap_chain_tx_event_data_ended_t;

// Stake-ext status enumeration
typedef enum {
    DAP_STAKE_EXT_STATUS_UNKNOWN = 0,
    DAP_STAKE_EXT_STATUS_EXPIRED = 1,
    DAP_STAKE_EXT_STATUS_ACTIVE = 2,
    DAP_STAKE_EXT_STATUS_ENDED = 3,
    DAP_STAKE_EXT_STATUS_CANCELLED = 4
} dap_stake_ext_status_t;

// Single lock information in stake-ext cache
typedef struct dap_stake_ext_lock_cache_item {
    dap_hash_fast_t lock_tx_hash;       // Transaction hash of the lock
    uint256_t lock_amount;              // Amount of the lock
    uint8_t range_end;                 // Range end (1-8)
    dap_time_t lock_time;              // Lock time in seconds
    dap_time_t created_time;           // When lock was created
    bool is_unlocked;                 // Whether lock was unlocked
   
    UT_hash_handle hh;                 // Hash table handle by lock_tx_hash
} dap_stake_ext_lock_cache_item_t;

// Position aggregation in stake-ext
typedef struct dap_stake_ext_position_cache_item {
    uint64_t position_id;               // ID of the position
    uint256_t total_amount;            // Total amount lock for this position
    uint32_t active_locks_count;        // Number of active (non-unlocked) locks
    dap_stake_ext_lock_cache_item_t *locks;// Hash table of locks by lock_tx_hash  
    UT_hash_handle hh;                 // Hash table handle by position_hash
} dap_stake_ext_position_cache_item_t;

// Stake-ext information in cache
typedef struct dap_stake_ext_cache_item {
    dap_hash_fast_t stake_ext_tx_hash;   // Transaction hash of stake-ext creation
    dap_chain_net_id_t net_id;         // Network ID
    char *guuid;                       // Event group name for this stake-ext
    dap_stake_ext_status_t status;       // Current stake-ext status
    
    // Stake-ext timing
    dap_time_t created_time;           // When stake-ext was created
    dap_time_t start_time;             // When lockding started
    dap_time_t end_time;               // When stake-ext ends/ended
    
    // Stake-ext data - TODO: Define specific stake-ext data structure
    char *description;                 // Stake-ext description (if available)
    uint256_t min_lock_amount;          // Minimum lock amount (if specified)
    
    // locks tracking
    uint32_t locks_count;               // Total number of locks
    uint32_t active_locks_count;        // Number of non-unlocked locks
    
    // Positions tracking
    dap_stake_ext_position_cache_item_t *positions; // Hash table of positions by position_id
    
    // Winner tracking (for ended stake-ext)
    bool has_winner;                   // Whether stake-ext has determined winner
    uint8_t winners_cnt;               // Number of winners in this stake-ext
    uint32_t *winners_ids;             // Array of winner position IDs from event data
    
    UT_hash_handle hh;                 // Hash handle for table keyed by GUUID
    UT_hash_handle hh_hash;            // Hash handle for table keyed by stake_ext_tx_hash
} dap_stake_ext_cache_item_t;

// Main stake-ext cache structure
typedef struct dap_stake_ext_cache {
    dap_stake_ext_cache_item_t *stake_ext; // Hash table of stake-exts keyed by GUUID
    dap_stake_ext_cache_item_t *stake_ext_by_hash; // Hash table for fast lookup by stake_ext_tx_hash
    uint32_t total_stake_ext;            // Total number of stake-exts in cache
    uint32_t active_stake_ext;           // Number of active stake-exts
    pthread_rwlock_t cache_rwlock;      // Read-write lock for cache access
} dap_stake_ext_cache_t;

// Position information in stake-ext (for external API)
typedef struct dap_chain_net_srv_stake_ext_position {
    uint64_t position_id;
    uint256_t total_amount;
    uint32_t locks_count;
    uint32_t active_locks_count;
} dap_chain_net_srv_stake_ext_position_t;

// Single stake-ext structure (for external API)
typedef struct dap_chain_net_srv_stake_ext {
    dap_hash_fast_t stake_ext_hash;
    char *guuid;                        // Stake-ext GUUID from cache
    dap_stake_ext_status_t status;
    dap_time_t created_time;
    dap_time_t start_time;
    dap_time_t end_time;
    char *description;
    uint32_t locks_count;
    uint32_t positions_count;
    
    // Winner information (if stake-ext ended)
    bool has_winner;                      // Whether stake-ext has determined winner
    uint8_t winners_cnt;                  // Number of winners
    uint32_t *winners_ids;                // Array of winner position IDs
    
    // Positions array (if requested)
    dap_chain_net_srv_stake_ext_position_t *positions;
} dap_chain_net_srv_stake_ext_t;

#ifdef __cplusplus
extern "C" {
#endif

// Service initialization/deinitialization
int dap_chain_net_srv_stake_ext_init(void);
void dap_chain_net_srv_stake_ext_deinit(void);

// Register event notification callback for a specific network
// This should be called when new networks are created after stake-ext service initialization
int dap_chain_net_srv_stake_ext_register_net_callback(dap_chain_net_t *a_net);
// Stake-ext cache API
dap_stake_ext_cache_t *dap_chain_net_srv_stake_ext_service_create(void);
void dap_chain_net_srv_stake_ext_service_delete(dap_stake_ext_cache_t *a_cache);

// Cache manipulation functions
int dap_stake_ext_cache_add_stake_ext(dap_stake_ext_cache_t *a_cache, 
                                  dap_hash_fast_t *a_stake_ext_hash,
                                  dap_chain_net_id_t a_net_id,
                                  const char *a_guuid,
                                  dap_chain_tx_event_data_stake_ext_started_t *a_started_data,
                                  dap_time_t a_tx_timestamp);

int dap_stake_ext_cache_add_lock(dap_stake_ext_cache_t *a_cache,
                              dap_hash_fast_t *a_stake_ext_hash,
                              dap_hash_fast_t *a_lock_hash,
                              uint256_t a_lock_amount,
                              dap_time_t a_lock_time,
                              dap_time_t a_created_time,
                              uint64_t a_position_id);

int dap_stake_ext_cache_update_stake_ext_status(dap_stake_ext_cache_t *a_cache,
                                           dap_hash_fast_t *a_stake_ext_hash,
                                           dap_stake_ext_status_t a_new_status);

// New: update stake-ext status by group name
int dap_stake_ext_cache_update_stake_ext_status_by_name(dap_stake_ext_cache_t *a_cache,
                                                   const char *a_guuid,
                                                   dap_stake_ext_status_t a_new_status);

int dap_stake_ext_cache_unlock_lock(dap_stake_ext_position_cache_item_t *a_cache,
                                  dap_hash_fast_t *a_lock_hash);

int dap_stake_ext_cache_set_winners(dap_stake_ext_cache_t *a_cache,
                                 dap_hash_fast_t *a_stake_ext_hash,
                                 uint8_t a_winners_cnt,
                                 uint32_t *a_winners_ids);

// New: set winners by group name
int dap_stake_ext_cache_set_winners_by_name(dap_stake_ext_cache_t *a_cache,
                                         const char *a_guuid,
                                         uint8_t a_winners_cnt,
                                         uint32_t *a_winners_ids);

// Search functions
// Find by stake-ext tx hash
dap_stake_ext_cache_item_t *dap_stake_ext_cache_find_stake_ext(dap_stake_ext_cache_t *a_cache,
                                                         dap_hash_fast_t *a_stake_ext_hash);
// New: find by group name
dap_stake_ext_cache_item_t *dap_stake_ext_cache_find_stake_ext_by_name(dap_stake_ext_cache_t *a_cache,
                                                                 const char *a_guuid);

dap_stake_ext_lock_cache_item_t *dap_stake_ext_cache_find_lock(dap_stake_ext_cache_item_t *a_stake_ext,
                                                         dap_hash_fast_t *a_lock_hash);

dap_stake_ext_position_cache_item_t *dap_stake_ext_cache_find_position(dap_stake_ext_cache_item_t *a_stake_ext,
                                                                 uint64_t a_position_id);

// External API for frontend and CLI
dap_chain_net_srv_stake_ext_t *dap_chain_net_srv_stake_ext_find(dap_chain_net_t *a_net, 
                                                             dap_chain_hash_fast_t *a_hash);
void dap_chain_net_srv_stake_ext_delete(dap_chain_net_srv_stake_ext_t *a_stake_ext);

// Get list of all stake-exts (with optional filtering)
dap_list_t *dap_chain_net_srv_stake_ext_get_list(dap_chain_net_t *a_net, 
                                                dap_stake_ext_status_t a_status_filter, 
                                                bool a_include_positions);

// Get detailed stake-ext information with all positions
dap_chain_net_srv_stake_ext_t *dap_chain_net_srv_stake_ext_get_detailed(dap_chain_net_t *a_net,
                                                                     dap_chain_hash_fast_t *a_hash);

// Get statistics about stake-exts
typedef struct {
    uint32_t total_stake_ext;
    uint32_t active_stake_ext;
    uint32_t ended_stake_ext;
    uint32_t cancelled_stake_ext;
    uint32_t total_locks;
    uint32_t total_positions;
} dap_stake_ext_stats_t;

dap_stake_ext_stats_t *dap_chain_net_srv_stake_ext_get_stats(dap_chain_net_t *a_net);

// Event fixation callback (for ledger event notifications)
void dap_stake_ext_cache_event_callback(void *a_arg, 
                                      dap_ledger_t *a_ledger,
                                      dap_chain_tx_event_t *a_event,
                                      dap_hash_fast_t *a_tx_hash,
                                      dap_chan_ledger_notify_opcodes_t a_opcode);

// Helper functions
const char *dap_stake_ext_status_to_str(dap_stake_ext_status_t a_status);
dap_stake_ext_status_t dap_stake_ext_status_from_event_type(uint16_t a_event_type);

// Transaction creation functions 
char *dap_chain_net_srv_stake_ext_lock_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_from, const dap_hash_fast_t *a_stake_ext_hash, 
                                uint256_t a_amount, dap_time_t a_lock_time, uint32_t a_position_id, uint256_t a_fee, int *a_ret_code);

char *dap_chain_net_srv_stake_ext_unlock_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_from, dap_hash_fast_t *a_lock_tx_hash, uint256_t a_fee, uint256_t *a_value, int *a_ret_code);

byte_t *dap_chain_srv_stake_ext_started_tx_event_create(size_t *a_data_size, uint32_t a_multiplier, dap_time_t a_duration,
    dap_chain_tx_event_data_time_unit_t a_time_unit,
    uint32_t a_calculation_rule_id, uint8_t a_total_positions, uint32_t a_position_ids[]);
byte_t *dap_chain_srv_stake_ext_ended_tx_event_create(size_t *a_data_size, uint8_t a_winners_cnt, uint32_t a_winners_ids[]);

#ifdef __cplusplus
}
#endif 
