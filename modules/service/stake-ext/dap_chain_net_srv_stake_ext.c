/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2022
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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_stake_ext.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_event.h"
#include "dap_chain_ledger.h"
#include "dap_chain_mempool.h"
#include "dap_chain_wallet.h"
#include "dap_config.h"
#include "json-c/json.h"
#include "json_object.h"
#include "uthash.h"
#include "dap_chain_srv.h"

#define LOG_TAG "dap_chain_net_srv_stake_ext"
#define set_ret_code(p,ret_code) if (p) { *p = ret_code;}

// Error codes
enum error_code {
    STAKE_EXT_NO_ERROR = 0,
    NET_ARG_ERROR = 1,
    NET_ERROR = 2,
    STAKE_EXT_HASH_ARG_ERROR = 3,
    STAKE_EXT_HASH_FORMAT_ERROR = 4,
    WALLET_ARG_ERROR = 5,
    WALLET_OPEN_ERROR = 6,
    AMOUNT_ARG_ERROR = 9,
    AMOUNT_FORMAT_ERROR = 10,
    LOCK_ARG_ERROR = 11,
    LOCK_FORMAT_ERROR = 12,
    FEE_ARG_ERROR = 13,
    FEE_FORMAT_ERROR = 14,
    LOCK_TX_HASH_ARG_ERROR = 15,
    LOCK_TX_HASH_FORMAT_ERROR = 16,
    STAKE_EXT_NOT_FOUND_ERROR = 17,
    STAKE_EXT_NOT_ACTIVE_ERROR = 18,
    LOCK_CREATE_ERROR = 19,
    UNLOCK_CREATE_ERROR = 20,
    COMMAND_NOT_RECOGNIZED = 21,
    STAKE_EXT_NAME_ARG_ERROR = 22,
    STAKE_EXT_DURATION_ARG_ERROR = 23,
    STAKE_EXT_DURATION_FORMAT_ERROR = 24,
    STAKE_EXT_END_TIME_ERROR = 25,
    STAKE_EXT_CREATE_ERROR = 26,
    POSITION_ID_ARG_ERROR = 27,
    POSITION_ID_FORMAT_ERROR = 28,
    STAKE_EXT_CACHE_NOT_INITIALIZED = 29,
    POSITION_NOT_FOUND_IN_STAKE_EXT = 30,
    INVALID_EVENT_TYPE_ERROR = 31
};

#ifndef DAP_STAKE_EXT_TEST
// Main stake_ext service structure
struct stake_ext {
    dap_chain_srv_stake_ext_cache_item_t *stake_ext; // Hash table of stake_ext keyed by GUUID
    dap_chain_srv_stake_ext_cache_item_t *stake_ext_by_hash; // Hash table for fast lookup by stake_ext_tx_hash
    uint32_t total_stake_ext;            // Total number of stake_ext in cache
    uint32_t active_stake_ext;           // Number of active stake_ext
    pthread_rwlock_t cache_rwlock;      // Read-write lock for cache access
};
#endif

// Stake_ext cache API
static struct stake_ext *s_stake_ext_service_create(void);
static void s_stake_ext_service_delete(struct stake_ext *a_cache);

// Callbacks
static int s_stake_ext_event_verify(dap_chain_net_id_t a_net_id, const char *a_event_group_name, int a_event_type, void *a_event_data, size_t a_event_data_size, dap_hash_fast_t *a_tx_hash);
static void s_stake_ext_lock_callback_updater(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_out_item);
static void s_stake_ext_unlock_callback_updater(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_prev_out_item);
static int s_stake_ext_lock_callback_verificator(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in,  dap_hash_fast_t *a_tx_in_hash,
                                              dap_chain_tx_out_cond_t *a_prev_cond, bool a_owner, bool a_check_for_apply);
// Event fixation callback (for ledger event notifications)
static void s_stake_ext_cache_event_callback(void *a_arg, dap_ledger_t *a_ledger, dap_chain_tx_event_t *a_event, dap_hash_fast_t *a_tx_hash, dap_ledger_notify_opcodes_t a_opcode);
// Forward declaration for optimization function
static dap_chain_srv_stake_ext_cache_item_t *s_find_stake_ext_by_hash_fast(struct stake_ext *a_cache, const dap_hash_fast_t *a_stake_ext_hash);
static void *s_stake_ext_start_callback(dap_chain_net_id_t a_net_id, dap_config_t *a_config);

// Cache manipulation functions
static int s_stake_ext_cache_add_stake_ext(struct stake_ext *a_cache, 
                                  dap_hash_fast_t *a_stake_ext_hash,
                                  dap_chain_net_id_t a_net_id,
                                  const char *a_guuid,
                                  dap_chain_tx_event_data_stake_ext_started_t *a_started_data,
                                  dap_time_t a_tx_timestamp);

static int s_stake_ext_cache_add_lock(struct stake_ext *a_cache,
                              dap_hash_fast_t *a_stake_ext_hash,
                              dap_hash_fast_t *a_lock_hash,
                              uint256_t a_lock_amount,
                              dap_time_t a_lock_time,
                              dap_time_t a_created_time,
                              uint64_t a_position_id);

static int s_stake_ext_cache_update_stake_ext_status(struct stake_ext *a_cache,
                                           dap_hash_fast_t *a_stake_ext_hash,
                                           dap_chain_srv_stake_ext_status_t a_new_status);

// New: update stake_ext status by group name
static int s_stake_ext_cache_update_stake_ext_status_by_name(struct stake_ext *a_cache,
                                                   const char *a_guuid,
                                                   dap_chain_srv_stake_ext_status_t a_new_status);

static int s_stake_ext_cache_unlock_lock(dap_chain_srv_stake_ext_position_cache_item_t *a_cache,
                                  dap_hash_fast_t *a_lock_hash);

static int s_stake_ext_cache_set_winners(struct stake_ext *a_cache,
                                 dap_hash_fast_t *a_stake_ext_hash,
                                 uint8_t a_winners_cnt,
                                 uint32_t *a_winners_ids);

// New: set winners by group name
static int s_stake_ext_cache_set_winners_by_name(struct stake_ext *a_cache,
                                         const char *a_guuid,
                                         uint8_t a_winners_cnt,
                                         uint32_t *a_winners_ids);

// Search functions
static dap_chain_srv_stake_ext_lock_cache_item_t *s_stake_ext_cache_find_lock(dap_chain_srv_stake_ext_cache_item_t *a_stake_ext, dap_hash_fast_t *a_lock_hash);
static dap_chain_srv_stake_ext_position_cache_item_t *s_stake_ext_cache_find_position(dap_chain_srv_stake_ext_cache_item_t *a_stake_ext, uint64_t a_position_id);

// Find by stake_ext tx hash
static dap_chain_srv_stake_ext_cache_item_t *s_stake_ext_cache_find_stake_ext(struct stake_ext *a_cache, dap_hash_fast_t *a_stake_ext_hash);
// New: find by group name
static dap_chain_srv_stake_ext_cache_item_t *s_stake_ext_cache_find_stake_ext_by_name(struct stake_ext *a_cache, const char *a_guuid);

static int s_com_stake_ext(int argc, char **argv, void **str_reply, int a_version);

#ifdef DAP_STAKE_EXT_TEST
dap_chain_srv_stake_ext_cache_t *dap_chain_srv_stake_ext_cache_create(void) { return s_stake_ext_service_create(); }
void dap_chain_srv_stake_ext_cache_delete(dap_chain_srv_stake_ext_cache_t *a_cache) { return s_stake_ext_service_delete(a_cache); }
int dap_chain_srv_stake_ext_cache_add_stake_ext(dap_chain_srv_stake_ext_cache_t *a_cache, dap_hash_fast_t *a_stake_ext_hash, dap_chain_net_id_t a_net_id, const char *a_guuid, dap_chain_tx_event_data_stake_ext_started_t *a_started_data, dap_time_t a_tx_timestamp)
{ return s_stake_ext_cache_add_stake_ext(a_cache, a_stake_ext_hash, a_net_id, a_guuid, a_started_data, a_tx_timestamp); }
int dap_chain_srv_stake_ext_cache_add_lock(dap_chain_srv_stake_ext_cache_t *a_cache, dap_hash_fast_t *a_stake_ext_hash, dap_hash_fast_t *a_lock_hash, uint256_t a_lock_amount, dap_time_t a_lock_time, dap_time_t a_created_time, uint64_t a_position_id)
{ return s_stake_ext_cache_add_lock(a_cache, a_stake_ext_hash, a_lock_hash, a_lock_amount, a_lock_time, a_created_time, a_position_id); }
int dap_chain_srv_stake_ext_cache_unlock_lock(dap_chain_srv_stake_ext_position_cache_item_t *a_cache, dap_hash_fast_t *a_lock_hash)
{ return s_stake_ext_cache_unlock_lock(a_cache, a_lock_hash); }
dap_chain_srv_stake_ext_cache_item_t *dap_chain_srv_stake_ext_cache_find_stake_ext(dap_chain_srv_stake_ext_cache_t *a_cache, dap_hash_fast_t *a_stake_ext_hash)
{ return s_stake_ext_cache_find_stake_ext(a_cache, a_stake_ext_hash); }
dap_chain_srv_stake_ext_cache_item_t *dap_chain_srv_stake_ext_cache_find_stake_ext_by_name(dap_chain_srv_stake_ext_cache_t *a_cache, const char *a_guuid)
{ return s_stake_ext_cache_find_stake_ext_by_name(a_cache, a_guuid); }
int dap_chain_srv_stake_ext_cache_update_stake_ext_status(dap_chain_srv_stake_ext_cache_t *a_cache, dap_hash_fast_t *a_stake_ext_hash, dap_chain_srv_stake_ext_status_t a_new_status)
{ return s_stake_ext_cache_update_stake_ext_status(a_cache, a_stake_ext_hash, a_new_status); }
dap_chain_srv_stake_ext_lock_cache_item_t *dap_chain_srv_stake_ext_cache_find_lock(dap_chain_srv_stake_ext_cache_item_t *a_stake_ext, dap_hash_fast_t *a_lock_hash)
{ return s_stake_ext_cache_find_lock(a_stake_ext, a_lock_hash); }
dap_chain_srv_stake_ext_position_cache_item_t *dap_chain_srv_stake_ext_cache_find_position(dap_chain_srv_stake_ext_cache_item_t *a_stake_ext, uint64_t a_position_id)
{ return s_stake_ext_cache_find_position(a_stake_ext, a_position_id); }
void dap_chain_srv_stake_ext_cache_event_callback(void *a_arg, dap_ledger_t *a_ledger, dap_chain_tx_event_t *a_event, dap_hash_fast_t *a_tx_hash, dap_ledger_notify_opcodes_t a_opcode)
{ s_stake_ext_cache_event_callback(a_arg, a_ledger, a_event, a_tx_hash, a_opcode); }
#endif


/**
 * @brief Service initialization
 * @return Returns 0 on success
 */
int dap_chain_net_srv_stake_ext_init(void)
{
    // Register verificator for stake_ext lock conditional outputs
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_EXT_LOCK,
                               s_stake_ext_lock_callback_verificator, NULL,
                               s_stake_ext_unlock_callback_updater, s_stake_ext_lock_callback_updater,
                               NULL, NULL);
    
    dap_cli_server_cmd_add ("stake_ext", s_com_stake_ext, "Stake_ext commands", dap_chain_node_cli_cmd_id_from_str("stake_ext"),
                "lock -net <network> -stake_ext <stake_ext_name|tx_hash> -amount <value> -lock_period <3..24> -position <position_id> -fee <value> -w <wallet>\n"
                "\tPlace a lock on an stake_ext for a specific position\n"
                "\t-position: position ID (uint32) for which the lock is made\n\n"
                "unlock -net <network> -lock_tx_hash <hash> -fee <value> -w <wallet>\n"
                "\tUnlock a lock from an stake_ext\n\n"
                "list -net <network> [-active_only] [-positions]\n"
                "\tList all stake_ext or active stake_ext only\n"
                "\t-active_only: show only active stake_ext\n"
                "\t-positions: include basic position information\n\n"
                "info -net <network> -stake_ext <stake_ext_name|tx_hash>\n"
                "\tGet detailed information about a specific stake_ext\n\n"
                "events -net <network> [-stake_ext <stake_ext_name|tx_hash>] [-type <event_type>]\n"
                "\tGet stake_ext events history\n"
                "\t-stake_ext: filter events for specific stake_ext\n"
                "\t-type: filter events for specific type\n\n"
                "stats -net <network>\n"
                "\tGet stake_ext statistics\n\n"
                "create -net <network> -name <stake_ext_name> -duration <duration_hours> -positions <position_list> -fee <value> -w <wallet>\n"
                "\tCreate a new stake_ext\n"
                "\t-name: stake_ext name (string)\n"
                "\t-duration: stake_ext duration in hours\n"
                "\t-positions: comma-separated list of position IDs or names\n"
                "\t-fee: transaction fee\n"
                "\t-w: wallet name\n\n"
                "  Examples:\n"
                "  stake_ext list -net myCellFrame -active_only -positions\n"
                "  stake_ext lock -net myCellFrame -stake_ext <stake_ext_name|tx_hash> -amount 1000 -lock_period 6 -position 1 -fee 0.1 -w myWallet\n"
                "  stake_ext info -net myCellFrame -stake_ext <stake_ext_name|tx_hash>\n"
                "  stake_ext unlock -net myCellFrame -lock_tx_hash <hash> -fee 0.1 -w myWallet\n"
                "  stake_ext events -net myCellFrame -stake_ext <stake_ext_name|tx_hash> -type <event_type>\n"
                "  stake_ext stats -net myCellFrame\n"
                "  stake_ext create -net myCellFrame -name 'Test Stake_ext' -duration 168 -positions '1,2,part3' -fee 0.1 -w myWallet\n\n"
                "  Notes:\n"
                "  - Lock period (3-24 months): how long your tokens are locked\n"
                "  - Each lock has lock period (3-24 months)\n\n"
                "  stake_ext_created - Stake_ext successfully created\n"
                "  stake_ext_cancelled - Stake_ext cancelled\n\n");

    log_it(L_NOTICE, "Stake_ext service initialized successfully with cache monitoring");
    dap_chain_static_srv_callbacks_t l_callbacks = {
        .start = s_stake_ext_start_callback,
        .event_verify = s_stake_ext_event_verify,
    };
    dap_chain_srv_add((dap_chain_srv_uid_t) { .uint64 = DAP_CHAIN_NET_SRV_STAKE_EXT_ID }, "manadged-staking", &l_callbacks);
    return 0;
}

//====================================================================
// STAKE_EXT CACHE IMPLEMENTATION
//====================================================================

/**
 * @brief Create stake_ext cache
 * @return Returns stake_ext cache instance or NULL on error
 */
static struct stake_ext *s_stake_ext_service_create(void)
{
    struct stake_ext *l_cache = DAP_NEW_Z(struct stake_ext);
    if (!l_cache) {
        log_it(L_CRITICAL, "Memory allocation error for stake_ext cache");
        return NULL;
    }
    
    // Initialize read-write lock
    if (pthread_rwlock_init(&l_cache->cache_rwlock, NULL) != 0) {
        log_it(L_ERROR, "Failed to initialize cache rwlock");
        DAP_DELETE(l_cache);
        return NULL;
    }
    
    l_cache->stake_ext = NULL;
    l_cache->stake_ext_by_hash = NULL;    // Initialize secondary hash table
    l_cache->total_stake_ext = 0;
    l_cache->active_stake_ext = 0;
    
    log_it(L_DEBUG, "Stake_ext cache created successfully");
    return l_cache;
}

static void *s_stake_ext_start_callback(dap_chain_net_id_t a_net_id, dap_config_t *a_config)
{
    struct stake_ext *l_stake_ext_service = s_stake_ext_service_create();
    if (!l_stake_ext_service) {
        log_it(L_CRITICAL, "Failed to create stake_ext cache");
        return NULL;
    }
    
    log_it(L_DEBUG, "Stake_ext service created successfully");
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);
    if (!l_net) {
        log_it(L_CRITICAL, "Failed to get network by id");
        return NULL;
    }
    dap_ledger_event_notify_add(l_net->pub.ledger, s_stake_ext_cache_event_callback, NULL);
    log_it(L_DEBUG, "Registered stake_ext event callback for network %s", l_net->pub.name);
    return l_stake_ext_service;
}

static struct stake_ext *s_stake_ext_service_get(dap_chain_net_id_t a_net_id)
{
    struct stake_ext *l_stake_ext_service = dap_chain_srv_get_internal(a_net_id, (dap_chain_srv_uid_t) { .uint64 = DAP_CHAIN_NET_SRV_STAKE_EXT_ID });
    if (!l_stake_ext_service) {
        log_it(L_CRITICAL, "Failed to get stake_ext service");
        return NULL;
    }
    return l_stake_ext_service;
}

/**
 * @brief Delete stake_ext cache and cleanup all data
 * @param a_cache Cache instance to delete
 */
static void s_stake_ext_service_delete(struct stake_ext *a_cache)
{
    if (!a_cache)
        return;
    
    pthread_rwlock_wrlock(&a_cache->cache_rwlock);
    
    // Clean up all stake_ext and their locks and positions
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext, *l_tmp_stake_ext;
    HASH_ITER(hh, a_cache->stake_ext, l_stake_ext, l_tmp_stake_ext) {
        
        // Clean up all positions in this stake_ext
        dap_chain_srv_stake_ext_position_cache_item_t *l_position, *l_tmp_position;
        HASH_ITER(hh, l_stake_ext->positions, l_position, l_tmp_position) {
            HASH_DEL(l_stake_ext->positions, l_position);
            // Clean up all locks in this position
            dap_chain_srv_stake_ext_lock_cache_item_t *l_lock, *l_tmp_lock;
            HASH_ITER(hh, l_position->locks, l_lock, l_tmp_lock) {
                HASH_DEL(l_position->locks, l_lock);
                DAP_DELETE(l_lock);
            }
            DAP_DELETE(l_position);
        }
        
        // Remove stake_ext from both hash tables
        HASH_DELETE(hh, a_cache->stake_ext, l_stake_ext);           // Remove from primary table (by GUUID)
        HASH_DELETE(hh_hash, a_cache->stake_ext_by_hash, l_stake_ext); // Remove from secondary table (by stake_ext_tx_hash)
        
        // Clean up stake_ext data
        DAP_DELETE(l_stake_ext->guuid);
        DAP_DELETE(l_stake_ext->description);
        DAP_DELETE(l_stake_ext->winners_ids);  // Clean up winners array
        DAP_DELETE(l_stake_ext);
    }
    
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    pthread_rwlock_destroy(&a_cache->cache_rwlock);
    DAP_DELETE(a_cache);
    
    log_it(L_DEBUG, "Stake_ext cache deleted");
}

/**
 * @brief Add new stake_ext to cache from stake_ext started event data
 * @param a_cache Cache instance
 * @param a_stake_ext_hash Hash of stake_ext transaction
 * @param a_net_id Network ID
 * @param a_guuid Event group name for this stake_ext
 * @param a_started_data Stake_ext started event data
 * @param a_tx_timestamp Timestamp of the stake_ext transaction
 * @return Returns 0 on success, negative error code otherwise
 */
static int s_stake_ext_cache_add_stake_ext(struct stake_ext *a_cache, 
                                  dap_hash_fast_t *a_stake_ext_hash,
                                  dap_chain_net_id_t a_net_id,
                                  const char *a_guuid,
                                  dap_chain_tx_event_data_stake_ext_started_t *a_started_data,
                                  dap_time_t a_tx_timestamp)
{
    if (!a_cache || !a_stake_ext_hash || !a_guuid)
        return -1;
    
    pthread_rwlock_wrlock(&a_cache->cache_rwlock);
    
    // Check if stake_ext already exists by GUUID (faster than hash iteration)
    dap_chain_srv_stake_ext_cache_item_t *l_existing = NULL;
    HASH_FIND_STR(a_cache->stake_ext, a_guuid, l_existing);
    if (l_existing) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_WARNING, "Stake_ext %s already exists in cache", 
               dap_chain_hash_fast_to_str_static(a_stake_ext_hash));
        return -2;
    }

    // Create new stake_ext cache item
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = DAP_NEW_Z(dap_chain_srv_stake_ext_cache_item_t);
    if (!l_stake_ext) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_CRITICAL, "Memory allocation error for stake_ext cache item");
        return -3;
    }

    // Initialize basic stake_ext data
    *l_stake_ext = (dap_chain_srv_stake_ext_cache_item_t) { .stake_ext_tx_hash.hash = *a_stake_ext_hash,
                                              .net_id = a_net_id,
                                              .created_time = a_tx_timestamp,
                                              .start_time = a_tx_timestamp,
                                              .end_time = a_tx_timestamp,
                                              .guuid = dap_strdup(a_guuid),
                                              .status = DAP_STAKE_EXT_STATUS_ACTIVE
    };

    // Calculate end time from stake_ext started data if provided
    if (a_started_data) {
        switch (a_started_data->time_unit) {
            case DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_HOURS:
                l_stake_ext->end_time = a_tx_timestamp + (a_started_data->duration * 3600);
                break;
            case DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_DAYS:
                l_stake_ext->end_time = a_tx_timestamp + (a_started_data->duration * 24 * 3600);
                break;
            case DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_WEEKS:
                l_stake_ext->end_time = a_tx_timestamp + (a_started_data->duration * 7 * 24 * 3600);
                break;
            case DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_MONTHS:
                l_stake_ext->end_time = a_tx_timestamp + (a_started_data->duration * 30 * 24 * 3600);
                break;
            default:
                // Fallback to seconds
                l_stake_ext->end_time = a_tx_timestamp + a_started_data->duration;
                break;
        }

        // Add positions from the stake_ext started data
        if (a_started_data->total_postions > 0) {
           
            // Create position cache entries for each position ID
            for (uint8_t i = 0; i < a_started_data->total_postions; i++) {
                uint64_t l_position_id = a_started_data->position_ids[i];              
                // Create position cache item
                dap_chain_srv_stake_ext_position_cache_item_t *l_position = NULL;
                HASH_FIND(hh, l_stake_ext->positions, &l_position_id, sizeof(uint64_t), l_position);
                if (l_position) {
                    log_it(L_ERROR, "Position %" DAP_UINT64_FORMAT_U " already exists in stake_ext cache", l_position_id);
                    continue;
                }
                l_position = DAP_NEW_Z(dap_chain_srv_stake_ext_position_cache_item_t);
                if (!l_position) {
                    log_it(L_CRITICAL, "Memory allocation error for position cache item");
                    return -4;
                }
                l_position->position_id = l_position_id;

                // Add to positions hash table
                HASH_ADD(hh, l_stake_ext->positions, position_id, sizeof(uint64_t), l_position);
            }
        }

        const char *l_hash_str = dap_chain_hash_fast_to_str_static(a_stake_ext_hash);
        log_it(L_DEBUG, "Added stake_ext %s with %u positions, duration: %" DAP_UINT64_FORMAT_U " %s", 
               l_hash_str,
               a_started_data->total_postions,
               a_started_data->duration,
               dap_chain_tx_event_data_time_unit_to_str(a_started_data->time_unit));
    }

    // Add to both hash tables for optimal performance
    HASH_ADD_STR(a_cache->stake_ext, guuid, l_stake_ext);  // Primary table by GUUID
    HASH_ADD(hh_hash, a_cache->stake_ext_by_hash, stake_ext_tx_hash.hash_key, sizeof(l_stake_ext->stake_ext_tx_hash.hash_key), l_stake_ext);  // Secondary table by tx hash (aligned key for ARM32)
    a_cache->total_stake_ext++;
    a_cache->active_stake_ext++;
    
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    
    log_it(L_DEBUG, "Added stake_ext %s to cache with ACTIVE status", 
           dap_chain_hash_fast_to_str_static(a_stake_ext_hash));
    return 0;
}

/**
 * @brief Add lock to stake_ext in cache
 * @param a_cache Cache instance
 * @param a_stake_ext_hash Hash of stake_ext transaction
 * @param a_lock_hash Hash of lock transaction
 * @param a_lock_amount Lock amount
 * @param a_lock_time Lock time in seconds
 * @param a_position_id ID of position this lock is for
 * @return Returns 0 on success, negative error code otherwise
 */
static int s_stake_ext_cache_add_lock(struct stake_ext *a_cache,
                              dap_hash_fast_t *a_stake_ext_hash,
                              dap_hash_fast_t *a_lock_hash,
                              uint256_t a_lock_amount,
                              dap_time_t a_lock_time,
                              dap_time_t a_created_time,
                              uint64_t a_position_id)
{
    dap_return_val_if_fail(a_cache && a_lock_hash, -1);
    
    pthread_rwlock_wrlock(&a_cache->cache_rwlock);
    
    // Find stake_ext using ultra-fast O(1) hash lookup
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = s_find_stake_ext_by_hash_fast(a_cache, a_stake_ext_hash);
    if (!l_stake_ext) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_WARNING, "Stake_ext not found in cache for lock add (hash missing or not resolved by name)");
        return -2;
    }
          
    // Find position in stake_ext cache
    dap_chain_srv_stake_ext_position_cache_item_t *l_position = NULL;
    HASH_FIND(hh, l_stake_ext->positions, &a_position_id, sizeof(uint64_t), l_position);
    if (!l_position) {
        log_it(L_ERROR, "Position not found in stake_ext cache for lock add");
        return -4;
    }

    // Create new lock cache item
    dap_chain_srv_stake_ext_lock_cache_item_t *l_lock = DAP_NEW_Z(dap_chain_srv_stake_ext_lock_cache_item_t);
    if (!l_lock) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_CRITICAL, "Memory allocation error for lock cache item");
        return -5;
    }

    // Update position aggregation
    if (SUM_256_256(l_position->total_amount, a_lock_amount, &l_position->total_amount)) {
        log_it(L_ERROR, "Overflow detected when adding lock amount to position total");
    }


    // Initialize lock data
    *l_lock = (dap_chain_srv_stake_ext_lock_cache_item_t) { .lock_tx_hash.hash = *a_lock_hash,
                                             .lock_amount = a_lock_amount,
                                             .lock_time = a_lock_time,
                                             .created_time = a_created_time
                                            };
    
    // Add to stake_ext's locks (use aligned hash_key for uthash)
    HASH_ADD(hh, l_position->locks, lock_tx_hash.hash_key, sizeof(l_lock->lock_tx_hash.hash_key), l_lock);
    l_position->active_locks_count++;
    l_stake_ext->locks_count++;
    l_stake_ext->active_locks_count++;
        
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    
    log_it(L_DEBUG, "Added lock %s to stake_ext %s in cache", 
                        dap_chain_hash_fast_to_str_static(a_lock_hash), dap_chain_hash_fast_to_str_static(a_stake_ext_hash));
    return 0;
}

/**
 * @brief Update stake_ext status in cache
 * @param a_cache Cache instance
 * @param a_stake_ext_hash Hash of stake_ext transaction
 * @param a_new_status New stake_ext status
 * @return Returns 0 on success, negative error code otherwise
 */
static int s_stake_ext_cache_update_stake_ext_status(struct stake_ext *a_cache,
                                           dap_hash_fast_t *a_stake_ext_hash,
                                           dap_chain_srv_stake_ext_status_t a_new_status)
{
    dap_return_val_if_fail(a_cache && a_stake_ext_hash, -1);
    
    pthread_rwlock_wrlock(&a_cache->cache_rwlock);
    
    // Find stake_ext using ultra-fast O(1) hash lookup
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = s_find_stake_ext_by_hash_fast(a_cache, a_stake_ext_hash);
    
    if (!l_stake_ext) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_WARNING, "Stake_ext %s not found in cache for status update", 
               dap_chain_hash_fast_to_str_static(a_stake_ext_hash));
        return -2;
    }
    
    dap_chain_srv_stake_ext_status_t l_old_status = l_stake_ext->status;
    l_stake_ext->status = a_new_status;
    
    // Update active stake_ext counter
    if (l_old_status == DAP_STAKE_EXT_STATUS_ACTIVE && a_new_status != DAP_STAKE_EXT_STATUS_ACTIVE) {
        if (a_cache->active_stake_ext > 0)
            a_cache->active_stake_ext--;
    } else if (l_old_status != DAP_STAKE_EXT_STATUS_ACTIVE && a_new_status == DAP_STAKE_EXT_STATUS_ACTIVE) {
        a_cache->active_stake_ext++;
    }
    
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    
    log_it(L_DEBUG, "Updated stake_ext %s status from %s to %s", 
           dap_chain_hash_fast_to_str_static(a_stake_ext_hash),
           dap_chain_srv_stake_ext_status_to_str(l_old_status),
           dap_chain_srv_stake_ext_status_to_str(a_new_status));
    return 0;
}

/**
 * @brief Mark lock as unlocked in cache
 * @param a_cache Cache instance
 * @param a_lock_hash Hash of lock transaction
 * @return Returns 0 on success, negative error code otherwise
 */
static int s_stake_ext_cache_unlock_lock(dap_chain_srv_stake_ext_position_cache_item_t *a_cache, dap_hash_fast_t *a_lock_hash)
{
    dap_return_val_if_fail(a_cache && a_lock_hash, -1);
    // Find matching lock by parameters from conditional output
    dap_chain_srv_stake_ext_lock_cache_item_t *l_lock = NULL;
    HASH_FIND(hh, a_cache->locks, a_lock_hash, sizeof(dap_hash_fast_t), l_lock);

    if (!l_lock) {
        log_it(L_WARNING, "Lock %s not found in stake_ext cache during lock unlocking",
                dap_chain_hash_fast_to_str_static(a_lock_hash));
        return -2;
    }
    l_lock->is_unlocked = true;
    if (a_cache->active_locks_count > 0)
        a_cache->active_locks_count--;
    log_it(L_DEBUG, "Marked lock %s as unlocked in cache", 
           dap_chain_hash_fast_to_str_static(a_lock_hash));
    return 0;
}

/**
 * @brief Set winners of stake_ext
 * @param a_cache Cache instance
 * @param a_stake_ext_hash Hash of stake_ext transaction
 * @param a_winners_cnt Number of winners
 * @param a_winners_ids Array of winner position IDs
 * @return Returns 0 on success, negative error code otherwise
 */
static int s_stake_ext_cache_set_winners(struct stake_ext *a_cache,
                                 dap_hash_fast_t *a_stake_ext_hash,
                                 uint8_t a_winners_cnt,
                                 uint32_t *a_winners_ids)
{
    dap_return_val_if_fail(a_cache && a_stake_ext_hash && a_winners_ids && a_winners_cnt > 0, -1);
    
    pthread_rwlock_wrlock(&a_cache->cache_rwlock);
    
    // Find stake_ext using ultra-fast O(1) hash lookup
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = s_find_stake_ext_by_hash_fast(a_cache, a_stake_ext_hash);
    
    if (!l_stake_ext) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_WARNING, "Stake_ext %s not found in cache for setting multiple winners", 
               dap_chain_hash_fast_to_str_static(a_stake_ext_hash));
        return -2;
    }
    
    // Clean up previous winners array if exists
    DAP_DELETE(l_stake_ext->winners_ids);
    
    // Set multiple winners information
    l_stake_ext->has_winner = true;
    l_stake_ext->winners_cnt = a_winners_cnt;
    l_stake_ext->winners_ids = DAP_NEW_Z_SIZE(uint32_t, sizeof(uint32_t) * a_winners_cnt);
    if (!l_stake_ext->winners_ids) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_CRITICAL, "Memory allocation error for winners array");
        return -3;
    }
    
    // Copy winners IDs
    memcpy(l_stake_ext->winners_ids, a_winners_ids, sizeof(uint32_t) * a_winners_cnt);
    
    // Log the winners for debugging
    for (uint8_t i = 0; i < a_winners_cnt; i++) {
        log_it(L_DEBUG, "Winner #%u: position ID %u", i + 1, a_winners_ids[i]);
    }
    
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    
    log_it(L_DEBUG, "Set %u winners for stake_ext %s", 
           a_winners_cnt, dap_chain_hash_fast_to_str_static(a_stake_ext_hash));
    
    return 0;
}

/**
 * @brief Find stake_ext in cache
 * @param a_cache Cache instance
 * @param a_stake_ext_hash Hash of stake_ext transaction
 * @return Returns stake_ext cache item or NULL if not found
 */
static dap_chain_srv_stake_ext_cache_item_t *s_stake_ext_cache_find_stake_ext(struct stake_ext *a_cache,
                                                         dap_hash_fast_t *a_stake_ext_hash)
{
    dap_return_val_if_fail(a_cache && a_stake_ext_hash, NULL);
    
    pthread_rwlock_rdlock(&a_cache->cache_rwlock);
    
    // Direct O(1) hash lookup using optimized secondary table
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = s_find_stake_ext_by_hash_fast(a_cache, a_stake_ext_hash);
    
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    return l_stake_ext;
}

/**
 * @brief Fast stake_ext lookup by hash using secondary hash table (O(1) performance)
 * @param a_cache Cache instance
 * @param a_stake_ext_hash Hash of stake_ext transaction
 * @return Returns stake_ext cache item or NULL if not found
 */
static dap_chain_srv_stake_ext_cache_item_t *s_find_stake_ext_by_hash_fast(struct stake_ext *a_cache, const dap_hash_fast_t *a_stake_ext_hash)
{
    if (!a_cache || !a_stake_ext_hash)
        return NULL;
    
    // Direct O(1) hash lookup using secondary table (use raw bytes for aligned search)
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = NULL;
    HASH_FIND(hh_hash, a_cache->stake_ext_by_hash, a_stake_ext_hash->raw, DAP_HASH_FAST_SIZE, l_stake_ext);
    return l_stake_ext;
}

static dap_chain_srv_stake_ext_cache_item_t *s_stake_ext_cache_find_stake_ext_by_name(struct stake_ext *a_cache,
                                                                 const char *a_guuid)
{
    if (!a_cache || !a_guuid)
        return NULL;
    pthread_rwlock_rdlock(&a_cache->cache_rwlock);
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = NULL, *l_tmp_stake_ext = NULL;
    HASH_FIND_STR(a_cache->stake_ext, a_guuid, l_stake_ext);
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    return l_stake_ext;
}

static int s_stake_ext_cache_update_stake_ext_status_by_name(struct stake_ext *a_cache,
                                                   const char *a_guuid,
                                                   dap_chain_srv_stake_ext_status_t a_new_status)
{
    if (!a_cache || !a_guuid)
        return -1;
    pthread_rwlock_wrlock(&a_cache->cache_rwlock);
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = NULL, *l_tmp_stake_ext = NULL;
    HASH_FIND_STR(a_cache->stake_ext, a_guuid, l_stake_ext);
    if (!l_stake_ext) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        return -2;
    }
    dap_chain_srv_stake_ext_status_t l_old_status = l_stake_ext->status;
    l_stake_ext->status = a_new_status;
    if (l_old_status == DAP_STAKE_EXT_STATUS_ACTIVE && a_new_status != DAP_STAKE_EXT_STATUS_ACTIVE) {
        if (a_cache->active_stake_ext > 0)
            a_cache->active_stake_ext--;
    } else if (l_old_status != DAP_STAKE_EXT_STATUS_ACTIVE && a_new_status == DAP_STAKE_EXT_STATUS_ACTIVE) {
        a_cache->active_stake_ext++;
    }
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    log_it(L_DEBUG, "Updated stake_ext '%s' status from %s to %s",
        a_guuid,
           dap_chain_srv_stake_ext_status_to_str(l_old_status),
           dap_chain_srv_stake_ext_status_to_str(a_new_status));
    return 0;
}

/**
 * @brief Find lock in stake_ext
 * @param a_stake_ext Stake_ext cache item
 * @param a_lock_hash Hash of lock transaction
 * @return Returns lock cache item or NULL if not found
 */
static dap_chain_srv_stake_ext_lock_cache_item_t *s_stake_ext_cache_find_lock(dap_chain_srv_stake_ext_cache_item_t *a_stake_ext,
                                                         dap_hash_fast_t *a_lock_hash)
{
    if (!a_stake_ext || !a_lock_hash)
        return NULL;
    
    for (dap_chain_srv_stake_ext_position_cache_item_t *l_position = a_stake_ext->positions; l_position; l_position = l_position->hh.next) {
        dap_chain_srv_stake_ext_lock_cache_item_t *l_lock = NULL;
        HASH_FIND(hh, l_position->locks, a_lock_hash, sizeof(dap_hash_fast_t), l_lock);
        if (l_lock) {
            return l_lock;
        }
    }
    
    return NULL;
}

/**
 * @brief Find position in stake_ext
 * @param a_stake_ext Stake_ext cache item
 * @param a_position_hash Hash of position
 * @return Returns position cache item or NULL if not found
 */
static dap_chain_srv_stake_ext_position_cache_item_t *s_stake_ext_cache_find_position(dap_chain_srv_stake_ext_cache_item_t *a_stake_ext,
                                                                 uint64_t a_position_id)
{
    if (!a_stake_ext || !a_position_id)
        return NULL;
    
    dap_chain_srv_stake_ext_position_cache_item_t *l_position = NULL;
    HASH_FIND(hh, a_stake_ext->positions, &a_position_id, sizeof(uint64_t), l_position);
    
    return l_position;
}

static int s_stake_ext_event_verify(dap_chain_net_id_t a_net_id, const char *a_event_group_name, int a_event_type, void *a_event_data, size_t a_event_data_size, dap_hash_fast_t *a_tx_hash)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);
    dap_return_val_if_fail(l_net && l_net->pub.ledger, -1);
    dap_list_t *l_events = dap_ledger_event_get_list_ex(l_net->pub.ledger, a_event_group_name, false);
    if (!l_events)
        return a_event_type == DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_STARTED ? 0 : -1;
    for (dap_list_t *it = l_events; it; it = it->next) {
        dap_chain_tx_event_t *l_event = (dap_chain_tx_event_t *)it->data;
        if (l_event->event_type == a_event_type &&
                (a_event_type == DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_STARTED ||
                a_event_type == DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_CANCELLED ||
                a_event_type == DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_ENDED))
        {
            log_it(L_WARNING, "Event %s rejected: group '%s' already exists event with type %s (existing tx %s)",
                                            dap_chain_hash_fast_to_str_static(a_tx_hash),
                                            a_event_group_name,
                                            dap_chain_tx_item_event_type_to_str(a_event_type),
                                            dap_chain_hash_fast_to_str_static(&l_event->tx_hash));
            dap_list_free_full(l_events, dap_chain_tx_event_delete);
            return -13;
        }
    }
    dap_list_free_full(l_events, dap_chain_tx_event_delete);
    return 0;
}

/**
 * @brief Event fixation callback for stake_ext monitoring
 * @param a_arg User argument (stake_ext cache)
 * @param a_ledger Ledger instance
 * @param a_event Event data
 * @param a_tx_hash Transaction hash
 * @param a_opcode Operation code (added/deleted)
 */
static void s_stake_ext_cache_event_callback(void *a_arg, 
                                       dap_ledger_t *a_ledger,
                                       dap_chain_tx_event_t *a_event,
                                       dap_hash_fast_t *a_tx_hash,
                                       dap_ledger_notify_opcodes_t a_opcode)
{
    dap_return_if_fail(a_event && a_tx_hash);
    
    // Дополнительный отладочный вывод по входящему событию
    const char *l_group_name = a_event->group_name ? a_event->group_name : "(null)";
    const char *l_opcode_str =
            a_opcode == DAP_LEDGER_NOTIFY_OPCODE_ADDED   ? "ADDED" :
            a_opcode == DAP_LEDGER_NOTIFY_OPCODE_DELETED ? "DELETED" : "UNKNOWN";
    log_it(L_DEBUG, "Stake_ext event received: type=%u opcode=%s tx=%s GUUID=\"%s\" data_size=%zu timestamp=%" DAP_UINT64_FORMAT_U,
           a_event->event_type,
           l_opcode_str,
           dap_chain_hash_fast_to_str_static(&a_event->tx_hash),
           l_group_name,
           a_event->event_data_size,
           a_event->timestamp);
    if (a_event->event_data && a_event->event_data_size) {
        size_t l_preview_len = a_event->event_data_size < 16 ? a_event->event_data_size : 16;
        char l_data_hex[16 * 2 + 1];
        dap_bin2hex(l_data_hex, a_event->event_data, l_preview_len);
        l_data_hex[l_preview_len * 2] = '\0';
        log_it(L_DEBUG, "Stake_ext event data preview (%zu bytes): %s", l_preview_len, l_data_hex);
    }
#ifndef DAP_STAKE_EXT_TEST
    struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(a_ledger->net->pub.id);
#else
    struct stake_ext *l_stake_ext_service = a_arg;
#endif
    if (!l_stake_ext_service) {
        log_it(L_ERROR, "Failed to get stake_ext service");
        return;
    }

    // Handle only stake_ext-related events
    switch (a_event->event_type) {
        case DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_STARTED: {
            log_it(L_DEBUG, "Processing stake_ext started event for %s", 
                   dap_chain_hash_fast_to_str_static(&a_event->tx_hash));
            
            if (a_opcode == DAP_LEDGER_NOTIFY_OPCODE_ADDED) {
                // Parse event data for stake_ext started info
                if (a_event->event_data && a_event->event_data_size >= sizeof(dap_chain_tx_event_data_stake_ext_started_t)) {
                    dap_chain_tx_event_data_stake_ext_started_t *l_started_data = 
                        (dap_chain_tx_event_data_stake_ext_started_t *)a_event->event_data;
                    
                    // Validate buffer size for potential position_ids array access
                    size_t l_required_size = sizeof(dap_chain_tx_event_data_stake_ext_started_t) + 
                                           (l_started_data->total_postions * sizeof(uint32_t));
                    if (a_event->event_data_size < l_required_size) {
                        log_it(L_ERROR, "Event data size %zu is insufficient for %u positions (required: %zu)", 
                               a_event->event_data_size, l_started_data->total_postions, l_required_size);
                        return;
                    }
                    // Check if stake_ext already exists in cache
                    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = s_stake_ext_cache_find_stake_ext(l_stake_ext_service, &a_event->tx_hash);
                    if (l_stake_ext) {
                        // Stake_ext already exists, just ignore double event
                        log_it(L_WARNING, "Stake_ext %s already exists in cache", 
                            dap_chain_hash_fast_to_str_static(&a_event->tx_hash));
                        return;
                    }
                    // Create new stake_ext entry with proper stake_ext started data
                    int l_result = s_stake_ext_cache_add_stake_ext(l_stake_ext_service, &a_event->tx_hash, 
                                                                a_ledger->net->pub.id, a_event->group_name,
                                                                l_started_data, a_event->timestamp);
                    if (l_result != 0) {
                        log_it(L_ERROR, "Failed to add stake_ext %s to cache: %d", 
                                dap_chain_hash_fast_to_str_static(&a_event->tx_hash), l_result);
                        return;
                    }
                        
                    log_it(L_INFO, "Stake_ext %s started with %u positions, duration: %"DAP_UINT64_FORMAT_U" %s", 
                            dap_chain_hash_fast_to_str_static(&a_event->tx_hash),
                            l_started_data->total_postions,
                            l_started_data->duration,
                            dap_chain_tx_event_data_time_unit_to_str(l_started_data->time_unit));
                }
            } else {
                // TODO: Handle deleted stake_ext started event
                log_it(L_DEBUG, "Processing deleted stake_ext started event for %s", 
                       dap_chain_hash_fast_to_str_static(&a_event->tx_hash));
            }
        } break;
        
        case DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_ENDED: {
            log_it(L_DEBUG, "Processing stake_ext ended event for %s", 
                   dap_chain_hash_fast_to_str_static(&a_event->tx_hash));
            
            if (a_opcode == DAP_LEDGER_NOTIFY_OPCODE_ADDED) {
                // Parse event data for winners information
                if (a_event->event_data && a_event->event_data_size >= sizeof(dap_chain_tx_event_data_ended_t)) {
                    dap_chain_tx_event_data_ended_t *l_ended_data = 
                        (dap_chain_tx_event_data_ended_t *)a_event->event_data;
                    
                    // Validate buffer size for winners array access
                    size_t l_required_size = sizeof(dap_chain_tx_event_data_ended_t) + 
                                           (l_ended_data->winners_cnt * sizeof(uint32_t));
                    if (a_event->event_data_size < l_required_size) {
                        log_it(L_ERROR, "Event data size %zu is insufficient for %u winners (required: %zu)", 
                               a_event->event_data_size, l_ended_data->winners_cnt, l_required_size);
                        return;
                    }
                    
                    // Find stake_ext by name and update status + end time efficiently
                    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = s_stake_ext_cache_find_stake_ext_by_name(l_stake_ext_service, a_event->group_name);
                    if (l_stake_ext) {
                        // Update status and counters efficiently (avoid second cache lookup)
                        pthread_rwlock_wrlock(&l_stake_ext_service->cache_rwlock);
                        dap_chain_srv_stake_ext_status_t l_old_status = l_stake_ext->status;
                        l_stake_ext->status = DAP_STAKE_EXT_STATUS_ENDED;
                        l_stake_ext->end_time = a_event->timestamp;
                        
                        // Update active stake_ext counter
                        if (l_old_status == DAP_STAKE_EXT_STATUS_ACTIVE && l_stake_ext_service->active_stake_ext > 0) {
                            l_stake_ext_service->active_stake_ext--;
                        }
                        pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
                        
                        log_it(L_DEBUG, "Updated stake_ext %s status from %s to %s", 
                                dap_chain_hash_fast_to_str_static(&a_event->tx_hash),
                                dap_chain_srv_stake_ext_status_to_str(l_old_status),
                                dap_chain_srv_stake_ext_status_to_str(DAP_STAKE_EXT_STATUS_ENDED));
                    }
                    
                    // Set winners
                    if (l_ended_data->winners_cnt > 0) {
                        const uint32_t *l_winners_ids = (const uint32_t *)((const byte_t *)l_ended_data +
                            offsetof(dap_chain_tx_event_data_ended_t, winners_ids));
                        s_stake_ext_cache_set_winners_by_name(l_stake_ext_service, a_event->group_name,
                                                             l_ended_data->winners_cnt, (uint32_t *)l_winners_ids);
                        
                        log_it(L_INFO, "Stake_ext %s ended with %u winner(s)", 
                                 dap_chain_hash_fast_to_str_static(&a_event->tx_hash),
                                 l_ended_data->winners_cnt);
                        
                        // Log all winners
                        for (uint8_t i = 0; i < l_ended_data->winners_cnt; i++) {
                            log_it(L_DEBUG, "Winner #%u: position ID %u", i + 1, l_winners_ids[i]);
                        }
                    } else {
                        log_it(L_INFO, "Stake_ext %s ended with no winners", 
                                 dap_chain_hash_fast_to_str_static(&a_event->tx_hash));
                    }
                }
            } else {
                // TODO: Handle deleted stake_ext ended event
                log_it(L_DEBUG, "Processing deleted stake_ext ended event for %s", 
                       dap_chain_hash_fast_to_str_static(&a_event->tx_hash));
            }
        } break;
        
        case DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_CANCELLED: {
            log_it(L_DEBUG, "Processing stake_ext cancelled event for %s", a_event->group_name);
            
            if (a_opcode == DAP_LEDGER_NOTIFY_OPCODE_ADDED) {
                // Find stake_ext once and update status + end time efficiently
                dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = s_stake_ext_cache_find_stake_ext_by_name(l_stake_ext_service, a_event->group_name);
                if (l_stake_ext) {
                    // Update status and counters efficiently (avoid second cache lookup)
                    pthread_rwlock_wrlock(&l_stake_ext_service->cache_rwlock);
                    dap_chain_srv_stake_ext_status_t l_old_status = l_stake_ext->status;
                    l_stake_ext->status = DAP_STAKE_EXT_STATUS_CANCELLED;
                    l_stake_ext->end_time = a_event->timestamp;
                    
                    // Update active stake_ext counter
                    if (l_old_status == DAP_STAKE_EXT_STATUS_ACTIVE && l_stake_ext_service->active_stake_ext > 0) {
                        l_stake_ext_service->active_stake_ext--;
                    }
                    pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
                    
                    log_it(L_DEBUG, "Updated stake_ext %s status from %s to %s", 
                           a_event->group_name,
                           dap_chain_srv_stake_ext_status_to_str(l_old_status),
                           dap_chain_srv_stake_ext_status_to_str(DAP_STAKE_EXT_STATUS_CANCELLED));
                } else {
                    log_it(L_DEBUG, "Stake_ext %s not found in cache", 
                           a_event->group_name);
                    return;
                }
            } else {
                // TODO: Handle deleted stake_ext cancelled event
                log_it(L_DEBUG, "Processing deleted stake_ext cancelled event for %s", 
                       dap_chain_hash_fast_to_str_static(&a_event->tx_hash));
            }
        } break;
        
        default:
            // Not an stake_ext event, ignore
            break;
    }
}

/**
 * @brief Convert stake_ext status to string
 * @param a_status Stake_ext status
 * @return Returns string representation of status
 */
const char *dap_chain_srv_stake_ext_status_to_str(dap_chain_srv_stake_ext_status_t a_status)
{
    switch (a_status) {
        case DAP_STAKE_EXT_STATUS_UNKNOWN: return "unknown";
        case DAP_STAKE_EXT_STATUS_EXPIRED: return "expired";
        case DAP_STAKE_EXT_STATUS_ACTIVE: return "active";
        case DAP_STAKE_EXT_STATUS_ENDED: return "ended";
        case DAP_STAKE_EXT_STATUS_CANCELLED: return "cancelled";
        default: return "invalid";
    }
}

/**
 * @brief Convert event type to stake_ext status
 * @param a_event_type Event type
 * @return Returns corresponding stake_ext status
 */
dap_chain_srv_stake_ext_status_t dap_chain_srv_stake_ext_status_from_event_type(uint16_t a_event_type)
{
    switch (a_event_type) {
        case DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_STARTED: return DAP_STAKE_EXT_STATUS_ACTIVE;
        case DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_CANCELLED: return DAP_STAKE_EXT_STATUS_CANCELLED;
        default: return DAP_STAKE_EXT_STATUS_UNKNOWN;
    }
}

/**
 * @brief Service deinitialization
 */
void dap_chain_net_srv_stake_ext_deinit(void)
{
    dap_chain_net_t *l_net = dap_chain_net_iter_start();
    while (l_net) {
        struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(l_net->pub.id);
        if (l_stake_ext_service)
            s_stake_ext_service_delete(l_stake_ext_service);
        l_net = dap_chain_net_iter_next(l_net);
    }
    
    log_it(L_NOTICE, "Stake_ext service deinitialized");
}

static void s_stake_ext_lock_callback_updater(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in,
                                           dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_out_item)
{
    // 1. Extract lock parameters from conditional output
    dap_hash_fast_t l_stake_ext_hash = a_out_item->subtype.srv_stake_ext_lock.stake_ext_hash;
    dap_time_t l_lock_time = a_out_item->subtype.srv_stake_ext_lock.lock_time;
    uint32_t l_position_id = a_out_item->subtype.srv_stake_ext_lock.position_id;

    // 2. Extract lock amount from conditional output value
    uint256_t l_lock_amount = a_out_item->header.value;
    struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(a_ledger->net->pub.id);
    if (!l_stake_ext_service) {
        log_it(L_ERROR, "Failed to get stake_ext service");
        return;
    }

    // 3. Add lock to stake_ext cache
    int l_add_result = s_stake_ext_cache_add_lock(l_stake_ext_service,
                                                    &l_stake_ext_hash,
                                                    a_tx_in_hash,
                                                    l_lock_amount,
                                                    l_lock_time,
                                                    a_tx_in->header.ts_created,
                                                    l_position_id);

    if (l_add_result == 0)
        log_it(L_WARNING, "Failed to add lock %s to stake_ext %s cache (error: %d)", 
                dap_chain_hash_fast_to_str_static(a_tx_in_hash),
                dap_chain_hash_fast_to_str_static(&l_stake_ext_hash),
                l_add_result);

    log_it(L_INFO, "Successfully added lock %s to stake_ext %s cache (position_id=%u, lock_time=%"DAP_UINT64_FORMAT_U", amount=%s)", 
            dap_chain_hash_fast_to_str_static(a_tx_in_hash),
            dap_chain_hash_fast_to_str_static(&l_stake_ext_hash),
            l_position_id,
            l_lock_time,
            dap_uint256_to_char(l_lock_amount, NULL));
}

static void s_stake_ext_unlock_callback_updater(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in,
            dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_prev_out_item)
{
    struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(a_ledger->net->pub.id);
    if (!l_stake_ext_service) {
        log_it(L_ERROR, "Failed to get stake_ext service");
        return;
    }
    uint8_t *l_in_cond = dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL);
    if (!l_in_cond) {
        log_it(L_ERROR, "No stake_ext lock conditional output found in transaction %s", 
                dap_chain_hash_fast_to_str_static(a_tx_in_hash));
        return;
    }
    dap_chain_tx_in_cond_t *l_in_cond_item = (dap_chain_tx_in_cond_t *)l_in_cond;
    dap_hash_fast_t *l_lock_hash = &l_in_cond_item->header.tx_prev_hash;
    log_it(L_DEBUG, "Processing lock unlocking for transaction %s", 
            dap_chain_hash_fast_to_str_static(l_lock_hash));

    // Extract stake_ext hash from conditional output
    dap_hash_fast_t l_stake_ext_hash = a_prev_out_item->subtype.srv_stake_ext_lock.stake_ext_hash;

    pthread_rwlock_wrlock(&l_stake_ext_service->cache_rwlock);

    // Find stake_ext in cache using ultra-fast O(1) hash lookup
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = s_find_stake_ext_by_hash_fast(l_stake_ext_service, &l_stake_ext_hash);
    if (!l_stake_ext) {
        pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
        log_it(L_ERROR, "Stake_ext %s not found in cache during lock unlocking",
                dap_chain_hash_fast_to_str_static(&l_stake_ext_hash));
        return;
    }
    uint64_t l_position_id = a_prev_out_item->subtype.srv_stake_ext_lock.position_id;
    dap_chain_srv_stake_ext_position_cache_item_t *l_position = NULL;
    HASH_FIND(hh, l_stake_ext->positions, &l_position_id, sizeof(uint64_t), l_position);
    if (!l_position) {
        log_it(L_ERROR, "Position %" DAP_UINT64_FORMAT_U " not found in stake_ext cache during lock unlocking", l_position_id);
        return;
    }
    int l_result = s_stake_ext_cache_unlock_lock(l_position, l_lock_hash);

    pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
    log_it(L_INFO, "%s lock %s from stake_ext %s", l_result ? "Failed to unlock" : "Successfully withdrew", 
                                dap_chain_hash_fast_to_str_static(l_lock_hash),
                                dap_chain_hash_fast_to_str_static(&l_stake_ext_hash));
}

/**
 * @brief Verify stake_ext lock conditional output
 * @param a_ledger Ledger instance
 * @param a_cond Conditional output to verify
 * @param a_tx_in Input transaction (unlocking transaction)
 * @param a_owner Whether the transaction is from the owner (who created the lock)
 * @return Returns 0 on success, negative error code otherwise
 */
static int s_stake_ext_lock_callback_verificator(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in,  dap_hash_fast_t *a_tx_in_hash,
                                              dap_chain_tx_out_cond_t *a_prev_cond, bool a_owner, bool a_check_for_apply)
{
    struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(a_ledger->net->pub.id);
    if (!l_stake_ext_service) {
        log_it(L_ERROR, "Failed to get stake_ext service");
        return -11;
    }
    if (!a_prev_cond) {
        log_it(L_WARNING, "NULL conditional output specified");
        return -1;
    }

    // Check if output type is stake_ext lock
    if (a_prev_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_EXT_LOCK) {
        log_it(L_WARNING, "Invalid conditional output subtype (expected stake_ext lock)");
        return -2;
    }

    // Validate position_id 
    uint32_t l_position_id = a_prev_cond->subtype.srv_stake_ext_lock.position_id;
    if (l_position_id == 0) {
        log_it(L_WARNING, "Invalid position_id value 0 (must be > 0)");
        return -4;
    }

    // Only the owner (who created the lock/lock) can unlock funds
    if (!a_owner) {
        log_it(L_WARNING, "Unlocking denied: only the owner who created the lock can unlock funds");
        return -9;
    }

    // 1. In unlocking transaction, find the stake_ext transaction hash from the conditional output
    dap_hash_fast_t l_stake_ext_hash = a_prev_cond->subtype.srv_stake_ext_lock.stake_ext_hash;
    char l_stake_ext_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_stake_ext_hash, l_stake_ext_hash_str, sizeof(l_stake_ext_hash_str));
    
    log_it(L_DEBUG, "Verifying unlocking for stake_ext hash %s by owner", l_stake_ext_hash_str);

    // 2. Find the stake_ext transaction by hash
    dap_chain_datum_tx_t *l_stake_ext_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_stake_ext_hash);
    if (!l_stake_ext_tx) {
        log_it(L_WARNING, "Stake_ext transaction %s not found in ledger", l_stake_ext_hash_str);
        return -4;
    }

    int ret_code = 0;
    dap_time_t l_stake_ext_end_time = 0;
    

    // 3. Check stake_ext status with thread-safe access
    pthread_rwlock_rdlock(&l_stake_ext_service->cache_rwlock);
    
    // Find stake_ext using ultra-fast O(1) hash lookup
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = s_find_stake_ext_by_hash_fast(l_stake_ext_service, &l_stake_ext_hash);
    if (!l_stake_ext) {
        pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
        log_it(L_WARNING, "Stake_ext %s not found in cache", l_stake_ext_hash_str);
        return -7;
    }

    switch (l_stake_ext->status) {

        case DAP_STAKE_EXT_STATUS_CANCELLED: {
            log_it(L_DEBUG, "Unlocking allowed: stake_ext %s was cancelled", l_stake_ext_hash_str);
            ret_code = 0;
        } break;

        case DAP_STAKE_EXT_STATUS_ENDED: {
            // 1. Get position id from lock transaction
            uint32_t l_lock_position = a_prev_cond->subtype.srv_stake_ext_lock.position_id;

            // 2. Check if this position is among the winners
            bool l_is_winner = false;
            if (!l_stake_ext->winners_ids && l_stake_ext->winners_cnt > 0) {
                log_it(L_ERROR, "Inconsistent winner data: count > 0 but no IDs");
                ret_code = -10;
                break;
            }
            if (l_stake_ext->winners_cnt > 0 && l_stake_ext->winners_ids) {
                for (uint32_t i = 0; i < l_stake_ext->winners_cnt; i++) {
                    if (l_stake_ext->winners_ids[i] == l_lock_position) {
                        l_is_winner = true;
                        break;
                    }
                }
            }
            
            dap_chain_tx_in_cond_t *l_tx_in_cond_item = (dap_chain_tx_in_cond_t *)dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL);
            assert(l_tx_in_cond_item);
            dap_hash_fast_t l_lock_tx_hash = l_tx_in_cond_item->header.tx_prev_hash;
            dap_chain_datum_tx_t *l_lock_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_lock_tx_hash);
            assert(l_lock_tx);
            dap_time_t l_lock_time = l_lock_tx->header.ts_created;
            // 3. Make decision about unlock validity
            if (l_is_winner) { // If position is winner, check if lock period expired
                if (l_lock_time > l_stake_ext->end_time) {
                    log_it(L_DEBUG, "Unlocking allowed: stake_ext %s won before lock is made", l_stake_ext_hash_str);
                    ret_code = 0;
                } else {
                    dap_time_t l_current_time = dap_ledger_get_blockchain_time(a_ledger);
                    dap_time_t l_lock_end_time = l_stake_ext->end_time + a_prev_cond->subtype.srv_stake_ext_lock.lock_time;
                    
                    if (l_current_time >= l_lock_end_time) {
                        log_it(L_DEBUG, "Unlocking allowed: stake_ext %s won and lock period expired", l_stake_ext_hash_str);
                        ret_code = 0;
                    } else {
                        log_it(L_WARNING, "Unlocking denied: stake_ext %s won but lock period not expired (current: %"DAP_UINT64_FORMAT_U", lock_end: %"DAP_UINT64_FORMAT_U")", 
                            l_stake_ext_hash_str, l_current_time, l_lock_end_time);
                        ret_code = -7;
                    }
                }
            } else { // If position is not winner
                log_it(L_DEBUG, "Unlocking allowed: position %u in stake_ext %s lost", l_lock_position, l_stake_ext_hash_str);
                ret_code = 0;
            }
        } break;

        case DAP_STAKE_EXT_STATUS_ACTIVE: {
            // For active stake_ext, check if time has expired based on cache data
            dap_time_t l_current_time = dap_ledger_get_blockchain_time(a_ledger);
            if (l_stake_ext->end_time > 0 && l_current_time >= l_stake_ext->end_time + a_prev_cond->subtype.srv_stake_ext_lock.lock_time) {
                log_it(L_DEBUG, "Unlocking allowed: stake_ext %s ended by time", l_stake_ext_hash_str);
                ret_code = 0;
            } else {
                log_it(L_WARNING, "Unlocking denied: stake_ext %s still active", l_stake_ext_hash_str);
                ret_code = -7;
            }
        } break;

        default:
            log_it(L_WARNING, "Stake_ext %s has unknown status %d", l_stake_ext_hash_str, l_stake_ext->status);
            ret_code = -6;
            break;
    }

    pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);

    return ret_code;
}

/**
 * @brief Free stake_ext structure returned by find function
 * @param a_stake_ext Stake_ext structure to free
 */
void dap_chain_net_srv_stake_ext_delete(dap_chain_net_srv_stake_ext_t *a_stake_ext)
{
    dap_return_if_fail(a_stake_ext);
    
    DAP_DEL_Z(a_stake_ext->guuid);
    DAP_DEL_Z(a_stake_ext->description);
    DAP_DEL_Z(a_stake_ext->winners_ids);  // Free winners array   
    DAP_DEL_Z(a_stake_ext->positions);     // Free positions array if present
    
    DAP_DELETE(a_stake_ext);
}

/**
 * @brief Find stake_ext by hash
 * @param a_net Network instance
 * @param a_hash Stake_ext hash
 * @return Returns stake_ext instance or NULL if not found
 */
dap_chain_net_srv_stake_ext_t *dap_chain_net_srv_stake_ext_find(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_hash)
{
    dap_return_val_if_fail(a_net && a_hash, NULL);
    struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(a_net->pub.id);
    if(!l_stake_ext_service)
        return NULL;
    
    // Search in stake_ext cache
    dap_chain_srv_stake_ext_cache_item_t *l_cached_stake_ext = s_stake_ext_cache_find_stake_ext(l_stake_ext_service, a_hash);
    if (!l_cached_stake_ext) {
        log_it(L_DEBUG, "Stake_ext %s not found in cache", dap_chain_hash_fast_to_str_static(a_hash));
        return NULL;
    }
    
    // Create external API structure
    dap_chain_net_srv_stake_ext_t *l_stake_ext = DAP_NEW_Z(dap_chain_net_srv_stake_ext_t);
    if (!l_stake_ext) {
        log_it(L_CRITICAL, "Memory allocation error for stake_ext API structure");
        return NULL;
    }
    
    // Fill stake_ext data from cache
    l_stake_ext->stake_ext_hash = l_cached_stake_ext->stake_ext_tx_hash.hash;
    l_stake_ext->guuid = l_cached_stake_ext->guuid ? dap_strdup(l_cached_stake_ext->guuid) : NULL;
    l_stake_ext->status = l_cached_stake_ext->status;
    l_stake_ext->created_time = l_cached_stake_ext->created_time;
    l_stake_ext->start_time = l_cached_stake_ext->start_time;
    l_stake_ext->end_time = l_cached_stake_ext->end_time;
    l_stake_ext->description = l_cached_stake_ext->description ? dap_strdup(l_cached_stake_ext->description) : NULL;
    l_stake_ext->locks_count = l_cached_stake_ext->locks_count;
    l_stake_ext->positions_count = HASH_COUNT(l_cached_stake_ext->positions);
    
    // Winner information with proper memory management
    l_stake_ext->has_winner = l_cached_stake_ext->has_winner;
    if (l_cached_stake_ext->winners_cnt > 0 && l_cached_stake_ext->winners_ids) {
        l_stake_ext->winners_ids = DAP_NEW_Z_SIZE(uint32_t, sizeof(uint32_t) * l_cached_stake_ext->winners_cnt);
        if (l_stake_ext->winners_ids) {
            l_stake_ext->winners_cnt = l_cached_stake_ext->winners_cnt;
            memcpy(l_stake_ext->winners_ids, l_cached_stake_ext->winners_ids, 
                   sizeof(uint32_t) * l_cached_stake_ext->winners_cnt);
        } else {
            // Memory allocation failed - reset to consistent state
            log_it(L_ERROR, "Failed to allocate memory for winners array");
            l_stake_ext->winners_cnt = 0;
            l_stake_ext->has_winner = false;
        }
    } else {
        l_stake_ext->winners_cnt = 0;
        l_stake_ext->winners_ids = NULL;
    }
    
    if (l_cached_stake_ext->description) {
        l_stake_ext->description = dap_strdup(l_cached_stake_ext->description);
    }
    
    // Positions array is not filled here - use get_detailed for that
    
    log_it(L_DEBUG, "Found stake_ext %s in cache with status %s", 
           dap_chain_hash_fast_to_str_static(a_hash),
           dap_chain_srv_stake_ext_status_to_str(l_stake_ext->status));
    
    return l_stake_ext;
}

//====================================================================
// EXTERNAL API FUNCTIONS
//====================================================================

/**
 * @brief Get detailed stake_ext information with all positions
 * @param a_net Network instance
 * @param a_hash Stake_ext hash
 * @return Returns detailed stake_ext structure or NULL if not found
 */
dap_chain_net_srv_stake_ext_t *dap_chain_net_srv_stake_ext_get_detailed(dap_chain_net_t *a_net,
                                                                     dap_chain_hash_fast_t *a_hash)
{
    dap_return_val_if_fail(a_net && a_hash, NULL);
    struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(a_net->pub.id);
    if(!l_stake_ext_service)
        return NULL;
    
    pthread_rwlock_rdlock(&l_stake_ext_service->cache_rwlock);
    
    // Find stake_ext in cache using ultra-fast O(1) hash lookup
    dap_chain_srv_stake_ext_cache_item_t *l_cached_stake_ext = s_find_stake_ext_by_hash_fast(l_stake_ext_service, a_hash);
    if (!l_cached_stake_ext) {
        pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
        return NULL;
    }
    
    // Create detailed stake_ext structure
    dap_chain_net_srv_stake_ext_t *l_stake_ext = DAP_NEW_Z(dap_chain_net_srv_stake_ext_t);
    if (!l_stake_ext) {
        pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
        return NULL;
    }
    
    // Fill basic stake_ext data
    l_stake_ext->stake_ext_hash = l_cached_stake_ext->stake_ext_tx_hash.hash;
    l_stake_ext->guuid = l_cached_stake_ext->guuid ? dap_strdup(l_cached_stake_ext->guuid) : NULL;
    l_stake_ext->status = l_cached_stake_ext->status;
    l_stake_ext->created_time = l_cached_stake_ext->created_time;
    l_stake_ext->start_time = l_cached_stake_ext->start_time;
    l_stake_ext->end_time = l_cached_stake_ext->end_time;
    l_stake_ext->description = l_cached_stake_ext->description ? dap_strdup(l_cached_stake_ext->description) : NULL;
    l_stake_ext->locks_count = l_cached_stake_ext->locks_count;
    l_stake_ext->positions_count = HASH_COUNT(l_cached_stake_ext->positions);
    
    // Winner information with proper memory management
    l_stake_ext->has_winner = l_cached_stake_ext->has_winner;
    if (l_cached_stake_ext->winners_cnt > 0 && l_cached_stake_ext->winners_ids) {
        l_stake_ext->winners_ids = DAP_NEW_Z_SIZE(uint32_t, sizeof(uint32_t) * l_cached_stake_ext->winners_cnt);
        if (l_stake_ext->winners_ids) {
            l_stake_ext->winners_cnt = l_cached_stake_ext->winners_cnt;
            memcpy(l_stake_ext->winners_ids, l_cached_stake_ext->winners_ids, 
                   sizeof(uint32_t) * l_cached_stake_ext->winners_cnt);
        } else {
            // Memory allocation failed - reset to consistent state
            log_it(L_ERROR, "Failed to allocate memory for winners array in detailed view");
            l_stake_ext->winners_cnt = 0;
            l_stake_ext->has_winner = false;
        }
    } else {
        l_stake_ext->winners_cnt = 0;
        l_stake_ext->winners_ids = NULL;
    }
    
    // Fill positions array
    if (l_stake_ext->positions_count) {
        l_stake_ext->positions = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_net_srv_stake_ext_position_t,
                                                            sizeof(dap_chain_net_srv_stake_ext_position_t) * l_stake_ext->positions_count,
                                                            NULL);
        if (l_stake_ext->positions) {
            uint32_t l_index = 0;
            for (dap_chain_srv_stake_ext_position_cache_item_t *l_position = l_cached_stake_ext->positions; l_position; l_position = l_position->hh.next) {
                if (l_index == l_stake_ext->positions_count) {
                    log_it(L_ERROR, "Positions count mismatch in detailed view (expected %u, got more positions)", l_stake_ext->positions_count);
                    break;
                }
                l_stake_ext->positions[l_index].position_id = l_position->position_id;
                l_stake_ext->positions[l_index].total_amount = l_position->total_amount;
                l_stake_ext->positions[l_index].locks_count = HASH_COUNT(l_position->locks);
                l_stake_ext->positions[l_index].active_locks_count = l_position->active_locks_count; 
                
                l_index++;
            }
        }
    }
    pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
    
    log_it(L_DEBUG, "Retrieved detailed stake_ext %s with %u positions", 
           dap_chain_hash_fast_to_str_static(a_hash), l_stake_ext->positions_count);
    
    return l_stake_ext;
}

/**
 * @brief Get list of stake_ext with optional filtering
 * @param a_net Network instance
 * @param a_status_filter Filter by status (DAP_STAKE_EXT_STATUS_UNKNOWN = no filter)
 * @param a_include_positions Whether to include basic position information
 * @return Returns list of stake_ext (must be freed with dap_list_free)
 */
dap_list_t *dap_chain_net_srv_stake_ext_get_list(dap_chain_net_t *a_net, 
                                                dap_chain_srv_stake_ext_status_t a_status_filter, 
                                                bool a_include_positions)
{
    dap_return_val_if_fail(a_net, NULL);
    struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(a_net->pub.id);
    if(!l_stake_ext_service)
        return NULL;
    
    dap_list_t *l_list = NULL;
    pthread_rwlock_rdlock(&l_stake_ext_service->cache_rwlock);
    
    // Diagnostic: Log current cache state
    log_it(L_INFO, "Getting stake_ext list for network %s, status_filter=%d, include_positions=%s", 
           a_net->pub.name, a_status_filter, a_include_positions ? "true" : "false");
    log_it(L_INFO, "Cache state: total_stake_ext=%u, active_stake_ext=%u, stake_ext_table=%s", 
           l_stake_ext_service->total_stake_ext, l_stake_ext_service->active_stake_ext,
           l_stake_ext_service->stake_ext ? "present" : "NULL");
    
    // Verify cache integrity before iteration
    if (!l_stake_ext_service->stake_ext && l_stake_ext_service->total_stake_ext > 0) {
        log_it(L_ERROR, "Cache corruption detected: NULL stake_ext table but total_stake_ext=%u", 
               l_stake_ext_service->total_stake_ext);
        pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
        return NULL;
    }
    
    // Early exit if no stake_ext in cache
    if (!l_stake_ext_service->stake_ext || l_stake_ext_service->total_stake_ext == 0) {
        log_it(L_INFO, "No stake_ext in cache - returning empty list");
        pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
        return NULL;
    }
    
    uint32_t l_total_found = 0, l_network_matches = 0, l_status_matches = 0;
    
    dap_chain_srv_stake_ext_cache_item_t *l_cached_stake_ext = NULL, *l_tmp_stake_ext = NULL;
        HASH_ITER(hh, l_stake_ext_service->stake_ext, l_cached_stake_ext, l_tmp_stake_ext) {
        l_total_found++;
        
        // Safety check to prevent segfault
        if (!l_cached_stake_ext) {
            log_it(L_ERROR, "NULL stake_ext found during iteration - cache corruption detected");
            continue;
        }
        
        // Filter by network ID
        if (l_cached_stake_ext->net_id.uint64 != a_net->pub.id.uint64) {
            log_it(L_DEBUG, "Stake_ext %s: network mismatch (expected %"DAP_UINT64_FORMAT_U", got %"DAP_UINT64_FORMAT_U")",
                   l_cached_stake_ext->guuid ? l_cached_stake_ext->guuid : "no_name",
                   a_net->pub.id.uint64, l_cached_stake_ext->net_id.uint64);
            continue;
        }
        l_network_matches++;
        
        // Filter by status if specified
        if (a_status_filter != DAP_STAKE_EXT_STATUS_UNKNOWN && 
            l_cached_stake_ext->status != a_status_filter) {
            log_it(L_DEBUG, "Stake_ext %s: status mismatch (expected %d, got %d)",
                   l_cached_stake_ext->guuid ? l_cached_stake_ext->guuid : "no_name",
                   a_status_filter, l_cached_stake_ext->status);
            continue;
        }
        l_status_matches++;
        
        // Create stake_ext structure
        dap_chain_net_srv_stake_ext_t *l_stake_ext = DAP_NEW_Z(dap_chain_net_srv_stake_ext_t);
        if (!l_stake_ext)
            continue;
        
        // Fill basic data
        l_stake_ext->stake_ext_hash = l_cached_stake_ext->stake_ext_tx_hash.hash;
        l_stake_ext->guuid = l_cached_stake_ext->guuid ? dap_strdup(l_cached_stake_ext->guuid) : NULL;
        l_stake_ext->status = l_cached_stake_ext->status;
        l_stake_ext->created_time = l_cached_stake_ext->created_time;
        l_stake_ext->start_time = l_cached_stake_ext->start_time;
        l_stake_ext->end_time = l_cached_stake_ext->end_time;
        l_stake_ext->description = l_cached_stake_ext->description ? dap_strdup(l_cached_stake_ext->description) : NULL;
        l_stake_ext->locks_count = l_cached_stake_ext->locks_count;
        l_stake_ext->positions_count = HASH_COUNT(l_cached_stake_ext->positions);
        
        // Winner information with proper memory management
        l_stake_ext->has_winner = l_cached_stake_ext->has_winner;
        if (l_cached_stake_ext->winners_cnt > 0 && l_cached_stake_ext->winners_ids) {
            l_stake_ext->winners_ids = DAP_NEW_Z_SIZE(uint32_t, sizeof(uint32_t) * l_cached_stake_ext->winners_cnt);
            if (l_stake_ext->winners_ids) {
                l_stake_ext->winners_cnt = l_cached_stake_ext->winners_cnt;
                memcpy(l_stake_ext->winners_ids, l_cached_stake_ext->winners_ids, 
                       sizeof(uint32_t) * l_cached_stake_ext->winners_cnt);
            } else {
                // Memory allocation failed - reset to consistent state
                log_it(L_ERROR, "Failed to allocate memory for winners array in list view");
                l_stake_ext->winners_cnt = 0;
                l_stake_ext->has_winner = false;
            }
        } else {
            l_stake_ext->winners_cnt = 0;
            l_stake_ext->winners_ids = NULL;
        }
        
        // Fill positions array if requested and available
        if (a_include_positions && l_stake_ext->positions_count > 0) {
            l_stake_ext->positions = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_net_srv_stake_ext_position_t,
                                                                sizeof(dap_chain_net_srv_stake_ext_position_t) * l_stake_ext->positions_count,
                                                                NULL);
            if (l_stake_ext->positions) {
                uint32_t l_index = 0;
                dap_chain_srv_stake_ext_position_cache_item_t *l_position, *l_tmp_position;
                HASH_ITER(hh, l_cached_stake_ext->positions, l_position, l_tmp_position) {
                    // Safety check to prevent segfault in nested iteration
                    if (!l_position) {
                        log_it(L_ERROR, "NULL position found during iteration - position cache corruption detected");
                        break;
                    }
                    if (l_index >= l_stake_ext->positions_count)
                        break;
                    
                    l_stake_ext->positions[l_index].position_id = l_position->position_id;
                    l_stake_ext->positions[l_index].total_amount = l_position->total_amount;
                    l_stake_ext->positions[l_index].locks_count = HASH_COUNT(l_position->locks);
                    l_stake_ext->positions[l_index].active_locks_count = l_position->active_locks_count;
                    
                    l_index++;
                }
            } else {
                // Memory allocation failed - log error but continue
                log_it(L_ERROR, "Failed to allocate memory for positions array in list view");
                l_stake_ext->positions_count = 0;
            }
        }
        
        l_list = dap_list_append(l_list, l_stake_ext);
    }
    
    pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
    
    uint32_t l_final_count = dap_list_length(l_list);
    log_it(L_INFO, "Stake_ext filtering results: found=%u, network_matches=%u, status_matches=%u, final_list=%u", 
           l_total_found, l_network_matches, l_status_matches, l_final_count);
    log_it(L_DEBUG, "Retrieved %u stake_ext from cache", l_final_count);
    return l_list;
}

/**
 * @brief Get statistics about stake_ext
 * @param a_net Network instance
 * @return Returns statistics structure (must be freed)
 */
dap_chain_srv_stake_ext_stats_t *dap_chain_net_srv_stake_ext_get_stats(dap_chain_net_t *a_net)
{
    dap_return_val_if_fail(a_net, NULL);
    struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(a_net->pub.id);
    if(!l_stake_ext_service)
        return NULL;
    
    dap_chain_srv_stake_ext_stats_t *l_stats = DAP_NEW_Z(dap_chain_srv_stake_ext_stats_t);
    if (!l_stats)
        return NULL;
    
    pthread_rwlock_rdlock(&l_stake_ext_service->cache_rwlock);
    
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = NULL, *l_tmp_stake_ext = NULL;
    HASH_ITER(hh, l_stake_ext_service->stake_ext, l_stake_ext, l_tmp_stake_ext) {
        // Filter by network ID
        if (l_stake_ext->net_id.uint64 != a_net->pub.id.uint64)
            continue;
        
        l_stats->total_stake_ext++;
        l_stats->total_locks += l_stake_ext->locks_count;
        l_stats->total_positions += HASH_COUNT(l_stake_ext->positions);
        
        switch (l_stake_ext->status) {
            case DAP_STAKE_EXT_STATUS_ACTIVE:
                l_stats->active_stake_ext++;
                break;
            case DAP_STAKE_EXT_STATUS_ENDED:
                l_stats->ended_stake_ext++;
                break;
            case DAP_STAKE_EXT_STATUS_CANCELLED:
                l_stats->cancelled_stake_ext++;
                break;
            default:
                break;
        }
    }
    
    pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
    
    log_it(L_DEBUG, "Stake_ext stats: total=%u, active=%u, ended=%u, cancelled=%u", 
           l_stats->total_stake_ext, l_stats->active_stake_ext, 
           l_stats->ended_stake_ext, l_stats->cancelled_stake_ext);
    
    return l_stats;
} 

/**
 * @brief Create unlock transaction
 * @param a_net Network instance
 * @param a_key_from Wallet key for signing
 * @param a_lock_tx_hash Hash of the lock transaction
 * @param a_fee Validator fee
 * @return Returns transaction hash string or NULL on error
 */
char *dap_chain_net_srv_stake_ext_unlock_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_to, dap_hash_fast_t *a_lock_tx_hash, uint256_t a_fee, uint256_t *a_value, int *a_ret_code)
{
    dap_return_val_if_fail(a_net && a_key_to && a_lock_tx_hash && !IS_ZERO_256(a_fee), NULL);
    struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(a_net->pub.id);
    if (!l_stake_ext_service)
        return NULL;
    
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    if (!l_ledger) {
        log_it(L_ERROR, "Ledger not found");
        set_ret_code(a_ret_code, -101);
        return NULL;
    }

    // 1. Find lock transaction
    dap_chain_datum_tx_t *l_lock_tx = dap_ledger_tx_find_by_hash(l_ledger, a_lock_tx_hash);
    if (!l_lock_tx) {
        log_it(L_ERROR, "Lock transaction not found");
        set_ret_code(a_ret_code, -102);
        return NULL;
    }

    // 2. Find lock output
    int l_out_num = 0;
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_lock_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_EXT_LOCK, &l_out_num);
    if (!l_out_cond) {
        log_it(L_ERROR, "Lock output not found");
        set_ret_code(a_ret_code, -103);
        return NULL;
    }

    if (dap_ledger_tx_hash_is_used_out_item(l_ledger, a_lock_tx_hash, l_out_num, NULL)) {
        log_it(L_ERROR, "Lock transaction is already unlocked");
        set_ret_code(a_ret_code, -104);
        return NULL;
    }

    // 3. Find stake_ext
    dap_hash_fast_t l_stake_ext_hash = l_out_cond->subtype.srv_stake_ext_lock.stake_ext_hash;
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = s_stake_ext_cache_find_stake_ext(l_stake_ext_service, &l_stake_ext_hash);
    if (!l_stake_ext) {
        log_it(L_WARNING, "Stake_ext %s not found in cache", dap_chain_hash_fast_to_str_static(&l_stake_ext_hash));
        set_ret_code(a_ret_code, -105);
        return NULL;
    }
    
    // 4. Verify lock unlocking is allowed
    switch (l_stake_ext->status){
        case DAP_STAKE_EXT_STATUS_ENDED:
        {
            // 1. Get position id from lock transaction
            uint32_t l_lock_position = l_out_cond->subtype.srv_stake_ext_lock.position_id;
            // 2. Get winners from stake_ext ended event

            uint32_t l_winners_count = l_stake_ext->winners_cnt;
            // 3. Check position won or lost
            bool l_is_winner = false;
            for (uint32_t i = 0; i < l_winners_count; i++) {
                if (l_stake_ext->winners_ids[i] == l_lock_position) {
                    l_is_winner = true;
                    break;
                }
            }
            // 4. Make decision about unlocking validity
            if (l_is_winner) { // If position is winner, check if lock period expired
                dap_time_t l_current_time = dap_ledger_get_blockchain_time(l_ledger);
                dap_time_t l_lock_end_time = l_stake_ext->end_time + l_out_cond->subtype.srv_stake_ext_lock.lock_time;
                
                if (l_current_time < l_lock_end_time) {
                    log_it(L_WARNING, "Unlocking denied: stake_ext %s won but lock period not expired (current: %"DAP_UINT64_FORMAT_U", lock_end: %"DAP_UINT64_FORMAT_U")", 
                        dap_chain_hash_fast_to_str_static(&l_stake_ext_hash), l_current_time, l_lock_end_time);
                    set_ret_code(a_ret_code, -106);
                    return NULL;
                }
            } 
            break;
        }
        case DAP_STAKE_EXT_STATUS_ACTIVE:
        {
            dap_time_t l_stake_ext_end_timeout = l_stake_ext->end_time + l_out_cond->subtype.srv_stake_ext_lock.lock_time;
            dap_time_t l_current_time = dap_ledger_get_blockchain_time(l_ledger);
            if (l_current_time < l_stake_ext_end_timeout) {
                log_it(L_DEBUG, "Unlocking debiued: stake_ext %s still active", dap_chain_hash_fast_to_str_static(&l_stake_ext_hash));
                set_ret_code(a_ret_code, -107);
                return NULL;
            }
        }
        default:
            break;
    }

    // 5. Get delegated token and value
    uint256_t l_value_delegated = {};
    uint256_t l_value_transfer = {}; // how many coins to transfer
    dap_list_t *l_list_used_out = NULL;
    char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
    const char *l_ticker_str = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_stake_ext_hash);
    if (!l_ticker_str) {
        log_it(L_ERROR, "Failed to get token ticker");
        set_ret_code(a_ret_code, -108);
        return NULL;
    }

    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_ticker_str);
    dap_chain_datum_token_t *l_delegated_token = dap_ledger_token_ticker_check(l_ledger, l_delegated_ticker_str);

    if (!l_delegated_token) {
        log_it(L_ERROR, "Delegated token not found");
        set_ret_code(a_ret_code, -109);
        return NULL;
    }

    uint256_t l_emission_rate = dap_ledger_token_get_emission_rate(l_ledger, l_delegated_ticker_str);

    if (IS_ZERO_256(l_emission_rate) ||
            MULT_256_COIN(l_out_cond->header.value, l_emission_rate, &l_value_delegated) ||
            IS_ZERO_256(l_value_delegated))
    {
        log_it(L_ERROR, "Failed to get emission rate");
        set_ret_code(a_ret_code, -110);
        return NULL;
    }

    dap_chain_addr_t l_addr = {};
    dap_chain_addr_fill_from_key(&l_addr, a_key_to, a_net->pub.id);

    if (!IS_ZERO_256(l_value_delegated)) {
        l_list_used_out = dap_chain_wallet_get_list_tx_outs_with_val(l_ledger, l_delegated_ticker_str,
                                                                                &l_addr, l_value_delegated, &l_value_transfer);
        if(!l_list_used_out) {
            log_it( L_ERROR, "Nothing to transfer (not enough delegated tokens)");
            set_ret_code(a_ret_code, -111);
            return NULL;
        }
    }

    // 6. Create unlock transaction
    dap_chain_datum_tx_t *l_unlock_tx = dap_chain_datum_tx_create();
    if (!l_unlock_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        set_ret_code(a_ret_code, -112);
        return NULL;
    }

    // add 'in_cond' & 'in' items
    dap_chain_datum_tx_add_in_cond_item(&l_unlock_tx, a_lock_tx_hash, l_out_num, 0);
    
    if (l_list_used_out) {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_unlock_tx, l_list_used_out);
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
        dap_list_free_full(l_list_used_out, NULL);
        l_list_used_out = NULL;
    }

    bool l_is_native = dap_strcmp(l_ticker_str, a_net->pub.native_ticker) == 0;
    uint256_t l_value_pack = l_is_native ? l_out_cond->header.value : uint256_0;    
    dap_chain_addr_t l_addr_fee = {};
    uint256_t l_net_fee = {}, l_fee_transfer = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_addr_fee);
    uint256_t l_fee_pack = a_fee;
    if (l_net_fee_used)
        SUM_256_256(l_fee_pack, l_net_fee, &l_fee_pack);
    if (compare256(l_fee_pack, l_out_cond->header.value) == 1) {
        uint256_t l_value_shortage = {};
        SUBTRACT_256_256(l_fee_pack, l_out_cond->header.value, &l_value_shortage);
        l_list_used_out = dap_chain_wallet_get_list_tx_outs_with_val(l_ledger, l_ticker_str, &l_addr, l_value_shortage, &l_fee_transfer);
        if(!l_list_used_out) {
            log_it( L_ERROR, "Nothing to transfer (not enough coins)");
            set_ret_code(a_ret_code, -111);
            return NULL;
        }
        SUM_256_256(l_value_pack, l_fee_transfer, &l_value_pack);
    }
    if (l_list_used_out) {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_unlock_tx, l_list_used_out);
        assert(EQUAL_256(l_value_to_items, l_fee_transfer));
        dap_list_free_full(l_list_used_out, NULL);
    }

    uint256_t l_value_back = {};
    // add 'out_ext' items
    // Network fee
    if (l_net_fee_used && !dap_chain_datum_tx_add_out_ext_item(&l_unlock_tx, &l_addr_fee, l_net_fee, a_net->pub.native_ticker)) {
        dap_chain_datum_tx_delete(l_unlock_tx);
        log_it(L_ERROR, "Failed to add network fee output");
        set_ret_code(a_ret_code, -113);
        return NULL;
    }

    // Validator's fee
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_unlock_tx, a_fee) != 1) {
        dap_chain_datum_tx_delete(l_unlock_tx);
        log_it(L_ERROR, "Failed to add validator fee");
        set_ret_code(a_ret_code, -114);
        return NULL;
    }
    // coin back
    if (SUBTRACT_256_256(l_value_pack, l_fee_pack, &l_value_back)) {
        dap_chain_datum_tx_delete(l_unlock_tx);
        log_it(L_ERROR, "Failed to calculate coin back");
        set_ret_code(a_ret_code, -115);
        return NULL;
    }
    if(!IS_ZERO_256(l_value_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_unlock_tx, &l_addr, l_value_back, a_net->pub.native_ticker)!=1) {
            dap_chain_datum_tx_delete(l_unlock_tx);
            log_it(L_ERROR, "Failed to add coin back output");
            set_ret_code(a_ret_code, -116);
            return NULL;
        }
    }
    if (!l_is_native && dap_chain_datum_tx_add_out_ext_item(&l_unlock_tx, &l_addr, l_out_cond->header.value, l_ticker_str) != 1) {
        dap_chain_datum_tx_delete(l_unlock_tx);
        log_it(L_ERROR, "Failed to add coin back output");
        set_ret_code(a_ret_code, -116);
        return NULL;
    }
    
    // add burning 'out_ext'
    if (!IS_ZERO_256(l_value_delegated)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_unlock_tx, &c_dap_chain_addr_blank,
                                               l_value_delegated, l_delegated_ticker_str) != 1) {
            dap_chain_datum_tx_delete(l_unlock_tx);
            log_it(L_ERROR, "Failed to add delegated token burn output");
            set_ret_code(a_ret_code, -117);
            return NULL;
        }
        // delegated token coin back
        SUBTRACT_256_256(l_value_transfer, l_value_delegated, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_unlock_tx, &l_addr, l_value_back, l_delegated_ticker_str) != 1) {
                dap_chain_datum_tx_delete(l_unlock_tx);
                log_it(L_ERROR, "Failed to add delegated token coin back output");
                set_ret_code(a_ret_code, -118);
                return NULL;
            }
        }
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_unlock_tx, a_key_to) != 1) {
        dap_chain_datum_tx_delete(l_unlock_tx);
        log_it(L_ERROR, "Failed to sign transaction");
        set_ret_code(a_ret_code, -119);
        return NULL;
    }

    // 13. Create datum and add to mempool
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_unlock_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_unlock_tx, l_tx_size);
    dap_chain_datum_tx_delete(l_unlock_tx);
    
    if (!l_datum) {
        log_it(L_ERROR, "Failed to create transaction datum");
        set_ret_code(a_ret_code, -120);
        return NULL;
    }

    // 14. Add to mempool   
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    
    if (!l_ret) {
        log_it(L_ERROR, "Failed to add stake_ext lock transaction to mempool");
        set_ret_code(a_ret_code, -121);
        return NULL;
    }

    if (a_value)
        *a_value = l_out_cond->header.value;
    log_it(L_INFO, "Successfully created and added stake_ext lock transaction to mempool: %s", l_ret);
    set_ret_code(a_ret_code, 0);
    return l_ret;
}

/**
 * @brief Create stake_ext lock transaction
 * @param a_net Network instance
 * @param a_key_from Encryption key for transaction signing
 * @param a_stake_ext_hash Hash of the stake_ext transaction
 * @param a_amount Lock amount
 * @param a_lock_time Lock time in seconds
 * @param a_position_id Position ID for which the lock is made
 * @param a_fee Transaction fee
 * @param a_ret_code Return code for error handling
 * @return Returns transaction hash string or NULL on error
 */
char *dap_chain_net_srv_stake_ext_lock_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_from, const dap_hash_fast_t *a_stake_ext_hash, 
                                     uint256_t a_amount, dap_time_t a_lock_time, uint32_t a_position_id, uint256_t a_fee, int *a_ret_code)
{
    dap_return_val_if_fail(a_net && a_key_from && a_stake_ext_hash && !IS_ZERO_256(a_amount) && a_position_id != 0, NULL);
    struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(a_net->pub.id);
    if(!l_stake_ext_service)
        return NULL;

    dap_ledger_t *l_ledger = a_net->pub.ledger;
    if (!l_ledger) {
        log_it(L_ERROR, "Ledger not found");
        set_ret_code(a_ret_code, -100);
        return NULL;
    }
    
    pthread_rwlock_rdlock(&l_stake_ext_service->cache_rwlock);
    
    // Find stake_ext using ultra-fast O(1) hash lookup
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext_cache = s_find_stake_ext_by_hash_fast(l_stake_ext_service, a_stake_ext_hash);
    
    if (!l_stake_ext_cache) {
        pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
        log_it(L_ERROR, "Stake_ext %s not found in cache", dap_chain_hash_fast_to_str_static(a_stake_ext_hash));
        set_ret_code(a_ret_code, -102);
        return NULL;
    }
      
    uint64_t l_position_id = a_position_id;
    dap_chain_srv_stake_ext_position_cache_item_t *l_position = NULL;
    HASH_FIND(hh, l_stake_ext_cache->positions, &l_position_id, sizeof(uint64_t), l_position);    
    pthread_rwlock_unlock(&l_stake_ext_service->cache_rwlock);
    if (!l_position) {
        log_it(L_ERROR, "Position ID %u not found in stake_ext", a_position_id);
        set_ret_code(a_ret_code, -104);
        return NULL;
    }

    if (a_lock_time < DAP_SEC_PER_DAY * 30 * 3 || a_lock_time > DAP_SEC_PER_DAY * 30 * 24) {
        log_it(L_ERROR, "Lock time must be between 3 and 24 months");
        set_ret_code(a_ret_code, -103);
        return NULL;
    }

    const char *l_native_ticker = a_net->pub.native_ticker;
    // Derive delegated m-token ticker for this chain (not hardcoded)
    char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] = {};
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_native_ticker);

    // Get emission rate for delegated m-token
    uint256_t l_emission_rate = dap_ledger_token_get_emission_rate(l_ledger, l_delegated_ticker_str);
    if (IS_ZERO_256(l_emission_rate)) {
        log_it(L_ERROR, "Failed to get emission rate for delegated token %s", l_delegated_ticker_str);
        set_ret_code(a_ret_code, -105);
        return NULL;
    }
    dap_chain_addr_t l_addr_from = {};
    dap_chain_addr_fill_from_key(&l_addr_from, a_key_from, a_net->pub.id);

    // 1. Verify stake_ext exists and is valid
    dap_chain_datum_tx_t *l_stake_ext_tx = dap_ledger_tx_find_by_hash(l_ledger, a_stake_ext_hash);
    if (!l_stake_ext_tx) {
        log_it(L_ERROR, "Stake_ext transaction not found");
        set_ret_code(a_ret_code, -106);
        return NULL;
    }

    // Calculate total costs: lock amount + network fee + validator fee
    uint256_t l_net_fee = {}, l_total_cost = a_amount;
    dap_chain_addr_t l_addr_net_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_addr_net_fee);
    
    if (l_net_fee_used) {
        if (SUM_256_256(l_total_cost, l_net_fee, &l_total_cost)) {
            log_it(L_ERROR, "Overflow detected when adding network fee to total cost");
            set_ret_code(a_ret_code, -107);
            return NULL;
        }
    }
    if (SUM_256_256(l_total_cost, a_fee, &l_total_cost)) {
        log_it(L_ERROR, "Overflow detected when adding validator fee to total cost");
        set_ret_code(a_ret_code, -108);
        return NULL;
    }

    // 2. Find UTXOs to cover the total cost (native tokens)
    dap_list_t *l_list_used_out = NULL;
    uint256_t l_value_transfer = {};
    l_list_used_out = dap_chain_wallet_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                              &l_addr_from, l_total_cost, &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_ERROR, "Not enough funds to place lock");
        set_ret_code(a_ret_code, -109);
        return NULL;
    }

    // 3. Create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        dap_list_free_full(l_list_used_out, NULL);
        set_ret_code(a_ret_code, -110);
        return NULL;
    }

    // 4. Add 'in' items (native tokens)
    uint256_t l_value_added = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_added, l_value_transfer)) {
        log_it(L_ERROR, "Failed to add input items");
        dap_chain_datum_tx_delete(l_tx);
        set_ret_code(a_ret_code, -111);
        return NULL;
    }

    // 5. Add 'in_ems' item (emission input for m-tokens)
    dap_chain_id_t l_chain_id = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX)->id;
    dap_hash_fast_t l_blank_hash = {};
    dap_chain_tx_in_ems_t *l_in_ems = dap_chain_datum_tx_item_in_ems_create(l_chain_id, &l_blank_hash, l_delegated_ticker_str);
    if (l_in_ems) {
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_in_ems);
        DAP_DELETE(l_in_ems);
    }

    // 6. Add conditional output (stake_ext lock lock)
    dap_chain_srv_uid_t l_srv_uid = {.uint64 = DAP_CHAIN_NET_SRV_STAKE_EXT_ID};
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_stake_ext_lock(
        l_srv_uid, a_amount, a_stake_ext_hash, a_lock_time, a_position_id, NULL, 0);
    if (!l_out_cond) {
        log_it(L_ERROR, "Failed to create stake_ext lock conditional output");
        dap_chain_datum_tx_delete(l_tx);
        set_ret_code(a_ret_code, -112);
        return NULL;
    }
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out_cond);
    DAP_DELETE(l_out_cond);

    // 7. Add m-tokens output
    // Calculate m-token amount using emission rate
    uint256_t l_mtoken_amount = {};
    if (MULT_256_COIN(a_amount, l_emission_rate, &l_mtoken_amount) || IS_ZERO_256(l_mtoken_amount)) {
        log_it(L_ERROR, "Failed to calculate m-token amount: overflow or zero result");
        dap_chain_datum_tx_delete(l_tx);
        set_ret_code(a_ret_code, -113);
        return NULL;
    }
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_from, l_mtoken_amount, l_delegated_ticker_str) != 1) {
        log_it(L_ERROR, "Failed to add m-tokens output");
        dap_chain_datum_tx_delete(l_tx);
        set_ret_code(a_ret_code, -114);
        return NULL;
    }

    // 8. Add network fee output
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_net_fee, l_net_fee, l_native_ticker) != 1) {
            log_it(L_ERROR, "Failed to add network fee output");
            dap_chain_datum_tx_delete(l_tx);
            set_ret_code(a_ret_code, -115);
            return NULL;
        }
    }

    // 9. Add validator fee
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            log_it(L_ERROR, "Failed to add validator fee");
            dap_chain_datum_tx_delete(l_tx);
            set_ret_code(a_ret_code, -116);
            return NULL;
        }
    }

    // 10. Add change output if needed
    uint256_t l_change = {};
    SUBTRACT_256_256(l_value_transfer, l_total_cost, &l_change);
    if (!IS_ZERO_256(l_change)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_from, l_change, l_native_ticker) != 1) {
            log_it(L_ERROR, "Failed to add change output");
            dap_chain_datum_tx_delete(l_tx);
            set_ret_code(a_ret_code, -117);
            return NULL;
        }
    }
    // 11. Sign transaction
    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        log_it(L_ERROR, "Failed to sign transaction");
        dap_chain_datum_tx_delete(l_tx);
        set_ret_code(a_ret_code, -118);
        return NULL;
    }

    // 12. Create datum and add to mempool
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    dap_chain_datum_tx_delete(l_tx);
    
    if (!l_datum) {
        log_it(L_ERROR, "Failed to create transaction datum");
        set_ret_code(a_ret_code, -119);
        return NULL;
    }

    // 13. Add to mempool
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    
    if (!l_ret) {
        log_it(L_ERROR, "Failed to add stake_ext lock transaction to mempool");
        set_ret_code(a_ret_code, -120);
        return NULL;
    }
    
    log_it(L_INFO, "Successfully created and added stake_ext lock transaction to mempool: %s", l_ret);
    set_ret_code(a_ret_code, 0);
    return l_ret;
}

/**
 * @brief Main stake_ext command handler
 * @param argc Argument count
 * @param argv Arguments array
 * @param str_reply Reply string
 * @param a_version Protocol version
 * @return Error code
 */
static int s_com_stake_ext(int argc, char **argv, void **str_reply, UNUSED_ARG int a_version)
{
    enum {
        CMD_NONE, CMD_LOCK, CMD_UNLOCK, CMD_LIST, CMD_INFO, CMD_EVENTS, CMD_STATS
    };

    int arg_index = 1;
    int cmd_num = CMD_NONE;
    const char *str_tmp = NULL;
    dap_json_t **l_json_arr_reply = (dap_json_t **) str_reply;
    
    // Ensure JSON reply is an array to avoid segfaults on json_object_array_add
    if (!l_json_arr_reply) {
        return -1;
    }
    if (!*l_json_arr_reply || !dap_json_is_array(*l_json_arr_reply)) {
        *l_json_arr_reply = dap_json_array_new();
    }
    
    // Parse command
    if(arg_index >= argc) {
        dap_json_rpc_error_add(*l_json_arr_reply, COMMAND_NOT_RECOGNIZED, "Command not specified");
        return -1;
    }

    str_tmp = argv[arg_index];
    if(!strcmp(str_tmp, "lock"))
        cmd_num = CMD_LOCK;
    else if(!strcmp(str_tmp, "unlock"))
        cmd_num = CMD_UNLOCK;
    else if(!strcmp(str_tmp, "list"))
        cmd_num = CMD_LIST;
    else if(!strcmp(str_tmp, "info"))
        cmd_num = CMD_INFO;
    else if(!strcmp(str_tmp, "events"))
        cmd_num = CMD_EVENTS;
    else if(!strcmp(str_tmp, "stats"))
        cmd_num = CMD_STATS;
    else {
        dap_json_rpc_error_add(*l_json_arr_reply, COMMAND_NOT_RECOGNIZED, "Command %s not recognized", str_tmp);
        return -1;
    }

    arg_index++;

    // Parse network
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &str_tmp);
    if(!str_tmp) {
        dap_json_rpc_error_add(*l_json_arr_reply, NET_ARG_ERROR, "Network not specified");
        return -1;
    }

    dap_chain_net_t *l_net = dap_chain_net_by_name(str_tmp);
    if(!l_net) {
        dap_json_rpc_error_add(*l_json_arr_reply, NET_ERROR, "Network '%s' not found", str_tmp);
        return -1;
    }

    switch(cmd_num) {
        case CMD_LOCK: {
            // Parse stake_ext identifier (GUUID or tx hash)
            const char *l_stake_ext_id_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-stake_ext", &l_stake_ext_id_str);
            if(!l_stake_ext_id_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, STAKE_EXT_HASH_ARG_ERROR, "Stake_ext identifier not specified");
                return -1;
            }

            // Parse wallet
            const char *l_wallet_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-w", &l_wallet_str);
            if(!l_wallet_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, WALLET_ARG_ERROR, "Wallet not specified");
                return -2;
            }

            // Parse amount
            str_tmp = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-amount", &str_tmp);
            if(!str_tmp) {
                dap_json_rpc_error_add(*l_json_arr_reply, AMOUNT_ARG_ERROR, "Amount not specified");
                return -3;
            }
            uint256_t l_amount = dap_chain_balance_scan(str_tmp);
            if(IS_ZERO_256(l_amount)) {
                dap_json_rpc_error_add(*l_json_arr_reply, AMOUNT_FORMAT_ERROR, "Invalid amount format");
                return -4;
            }

            // Parse lock period
            str_tmp = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-lock", &str_tmp);
            if(!str_tmp) {
                dap_json_rpc_error_add(*l_json_arr_reply, LOCK_ARG_ERROR, "Lock period not specified");
                return -5;
            }
            uint8_t l_lock_months = (uint8_t)atoi(str_tmp);
            if(l_lock_months < 3 || l_lock_months > 24) {
                dap_json_rpc_error_add(*l_json_arr_reply, LOCK_FORMAT_ERROR, "Lock period must be between 3 and 24 months");
                return -6;
            }

            // Parse fee
            str_tmp = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-fee", &str_tmp);
            if(!str_tmp) {
                dap_json_rpc_error_add(*l_json_arr_reply, FEE_ARG_ERROR, "Fee not specified");
                return -7;
            }
            uint256_t l_fee = dap_chain_balance_scan(str_tmp);
            if(IS_ZERO_256(l_fee)) {
                dap_json_rpc_error_add(*l_json_arr_reply, FEE_FORMAT_ERROR, "Invalid fee format");
                return -8;
            }

            // Parse position ID
            str_tmp = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-position", &str_tmp);
            if(!str_tmp) {
                dap_json_rpc_error_add(*l_json_arr_reply, POSITION_ID_ARG_ERROR, "Position ID not specified");
                return -9;
            }
            uint32_t l_position_id = (uint32_t)atoi(str_tmp);
            if(l_position_id == 0) {
                dap_json_rpc_error_add(*l_json_arr_reply, POSITION_ID_FORMAT_ERROR, "Invalid position ID format");
                return -10;
            }

            struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(l_net->pub.id);
            if(!l_stake_ext_service) {
                dap_json_rpc_error_add(*l_json_arr_reply, STAKE_EXT_CACHE_NOT_INITIALIZED, "Stake_ext cache not initialized in network %s", l_net->pub.name);
                return -14;
            }

            // Resolve stake_ext: try as hash; if fails, resolve by GUUID from cache
            dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = NULL;
            dap_hash_fast_t l_stake_ext_hash = {};
            bool l_hash_parsed = (dap_chain_hash_fast_from_str(l_stake_ext_id_str, &l_stake_ext_hash) == 0);
            if (l_hash_parsed) {
                l_stake_ext = s_stake_ext_cache_find_stake_ext(l_stake_ext_service, &l_stake_ext_hash);
            } else {
                // Try resolve by GUUID via stake_ext cache
                l_stake_ext = s_stake_ext_cache_find_stake_ext_by_name(l_stake_ext_service, l_stake_ext_id_str);
                if (l_stake_ext)
                    l_stake_ext_hash = l_stake_ext->stake_ext_tx_hash.hash;
            }
            // Check stake_ext is active           
            if (!l_stake_ext) {
                dap_json_rpc_error_add(*l_json_arr_reply, STAKE_EXT_NOT_FOUND_ERROR, "Stake_ext '%s' not found",
                                                                                l_hash_parsed ? dap_hash_fast_to_str_static(&l_stake_ext_hash) : l_stake_ext_id_str);
                return -11;
            }
            if (l_stake_ext->status != DAP_STAKE_EXT_STATUS_ACTIVE) {
                dap_json_rpc_error_add(*l_json_arr_reply, STAKE_EXT_NOT_ACTIVE_ERROR, "Stake_ext is not active");
                return -12;
            }

            // Convert lock period from months to seconds
            dap_time_t l_lock_time = (dap_time_t)l_lock_months * 30 * DAP_SEC_PER_DAY; // months to seconds

            // Open wallet
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
            if (!l_wallet) {
                dap_json_rpc_error_add(*l_json_arr_reply, WALLET_OPEN_ERROR, "Can't open wallet '%s'", l_wallet_str);
                return -13;
            }
            dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);

            // Create stake_ext lock transaction
            int l_ret_code = 0;
            char *l_tx_hash_str = dap_chain_net_srv_stake_ext_lock_create(l_net, l_enc_key, &l_stake_ext_hash, 
                                                         l_amount, l_lock_time, l_position_id, l_fee, &l_ret_code);
            DAP_DELETE(l_enc_key);
            
            // Close wallet
            dap_chain_wallet_close(l_wallet);

            if (l_tx_hash_str) {
                // Success - return transaction hash
                dap_json_t *l_json_obj = dap_json_object_new();
                dap_json_object_add_object(l_json_obj, "command", dap_json_object_new_string("lock"));
                dap_json_object_add_object(l_json_obj, "status", dap_json_object_new_string("success"));
                dap_json_object_add_object(l_json_obj, "tx_hash", dap_json_object_new_string(l_tx_hash_str));
                dap_json_object_add_object(l_json_obj, "stake_ext_tx_hash", dap_json_object_new_string(dap_chain_hash_fast_to_str_static(&l_stake_ext_hash)));
                dap_json_object_add_object(l_json_obj, "stake_ext_name", dap_json_object_new_string(l_stake_ext->guuid));
                const char *l_amount_str = dap_uint256_to_char(l_amount, NULL);
                dap_json_object_add_object(l_json_obj, "amount", dap_json_object_new_string(l_amount_str));
                
                
                const char *l_fee_str = dap_uint256_to_char(l_fee, NULL);
                dap_json_object_add_object(l_json_obj, "fee", dap_json_object_new_string(l_fee_str));
                
                dap_json_object_add_object(l_json_obj, "lock_months", dap_json_object_new_int(l_lock_months));
                dap_json_array_add(*l_json_arr_reply, l_json_obj);
                
                DAP_DELETE(l_tx_hash_str);
            } else {
                // Error creating transaction - handle specific error codes
                const char *l_error_msg = NULL;
                switch (l_ret_code) {
                    case 0:
                        l_error_msg = "Success (unexpected error)";
                        break;
                    case -100:
                        l_error_msg = "Ledger not found";
                        break;
                    case -101:
                        l_error_msg = "Stake_ext cache not initialized";
                        break;
                    case -102:
                        l_error_msg = "Stake_ext not found in cache";
                        break;
                    case -103:
                        l_error_msg = "Lock time must be between 3 and 24 months";
                        break;
                    case -104:
                        l_error_msg = "Position ID not found in stake_ext";
                        break;
                    case -105:
                        l_error_msg = "Failed to get emission rate for delegated token";
                        break;
                    case -106:
                        l_error_msg = "Stake_ext transaction not found";
                        break;
                    case -107:
                        l_error_msg = "Overflow detected when adding network fee to total cost";
                        break;
                    case -108:
                        l_error_msg = "Overflow detected when adding validator fee to total cost";
                        break;
                    case -109:
                        l_error_msg = "Not enough funds to place lock";
                        break;
                    case -110:
                        l_error_msg = "Failed to create transaction";
                        break;
                    case -111:
                        l_error_msg = "Failed to add input items";
                        break;
                    case -112:
                        l_error_msg = "Failed to create stake_ext lock conditional output";
                        break;
                    case -113:
                        l_error_msg = "Failed to calculate m-token amount: overflow or zero result";
                        break;
                    case -114:
                        l_error_msg = "Failed to add m-tokens output";
                        break;
                    case -115:
                        l_error_msg = "Failed to add network fee output";
                        break;
                    case -116:
                        l_error_msg = "Failed to add validator fee";
                        break;
                    case -117:
                        l_error_msg = "Failed to add change output";
                        break;
                    case -118:
                        l_error_msg = "Failed to sign transaction";
                        break;
                    case -119:
                        l_error_msg = "Failed to create transaction datum";
                        break;
                    case -120:
                        l_error_msg = "Failed to add stake_ext lock transaction to mempool";
                        break;
                    default:
                        l_error_msg = "Unknown error occurred";
                        break;
                }
                dap_json_rpc_error_add(*l_json_arr_reply, LOCK_CREATE_ERROR, "Error creating lock transaction: %s (code: %d)", l_error_msg, l_ret_code);
                return -14;
            }
        } break;

        case CMD_UNLOCK: {
            // Parse lock transaction hash
            const char *l_lock_tx_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-lock_tx_hash", &l_lock_tx_hash_str);
            if(!l_lock_tx_hash_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, LOCK_TX_HASH_ARG_ERROR, "Lock transaction hash not specified");
                return -1;
            }

            // Parse wallet
            const char *l_wallet_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-w", &l_wallet_str);
            if(!l_wallet_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, WALLET_ARG_ERROR, "Wallet not specified");
                return -2;
            }

            // Parse fee
            str_tmp = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-fee", &str_tmp);
            if(!str_tmp) {
                dap_json_rpc_error_add(*l_json_arr_reply, FEE_ARG_ERROR, "Fee not specified");
                return -3;
            }
            uint256_t l_fee = dap_chain_balance_scan(str_tmp);
            if(IS_ZERO_256(l_fee)) {
                dap_json_rpc_error_add(*l_json_arr_reply, FEE_FORMAT_ERROR, "Invalid fee format");
                return -4;
            }

            // Open wallet
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
            if (!l_wallet) {
                dap_json_rpc_error_add(*l_json_arr_reply, WALLET_OPEN_ERROR, "Can't open wallet '%s'", l_wallet_str);
                return -5;
            }
            dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);

            dap_hash_fast_t l_lock_tx_hash = {};
            if (dap_chain_hash_fast_from_str(l_lock_tx_hash_str, &l_lock_tx_hash) != 0) {
                dap_json_rpc_error_add(*l_json_arr_reply, LOCK_TX_HASH_FORMAT_ERROR, "Invalid lock transaction hash format");
                DAP_DELETE(l_enc_key);
                dap_chain_wallet_close(l_wallet);
                return -6;
            }
            uint256_t l_value = {};
            int l_ret_code = 0;
            char *l_tx_hash_str = dap_chain_net_srv_stake_ext_unlock_create(l_net, l_enc_key, &l_lock_tx_hash, l_fee, &l_value, &l_ret_code);
            DAP_DELETE(l_enc_key);

            // Close wallet
            dap_chain_wallet_close(l_wallet);

            if (l_ret_code == 0) {
                // Success - return transaction hash
                dap_json_t *l_json_obj = dap_json_object_new();
                dap_json_object_add_object(l_json_obj, "command", dap_json_object_new_string("unlock"));
                dap_json_object_add_object(l_json_obj, "status", dap_json_object_new_string("success"));
                dap_json_object_add_object(l_json_obj, "tx_hash", dap_json_object_new_string(l_tx_hash_str));
                dap_json_object_add_object(l_json_obj, "lock_tx_hash", dap_json_object_new_string(l_lock_tx_hash_str));
                const char *l_value_str; dap_uint256_to_char(l_value, &l_value_str);
                dap_json_object_add_object(l_json_obj, "value", dap_json_object_new_string(l_value_str));
                const char *l_fee_str; dap_uint256_to_char(l_fee, &l_fee_str);
                dap_json_object_add_object(l_json_obj, "fee", dap_json_object_new_string(l_fee_str));
                
                dap_json_array_add(*l_json_arr_reply, l_json_obj);
                
                DAP_DELETE(l_tx_hash_str);
            } else {
                // Error creating transaction - handle specific error codes
                const char *l_error_msg = NULL;
                switch (l_ret_code) {
                    case 0:
                        l_error_msg = "Success (unexpected error)";
                        break;
                    case -101:
                        l_error_msg = "Ledger not found";
                        break;
                    case -102:
                        l_error_msg = "Lock transaction not found";
                        break;
                    case -103:
                        l_error_msg = "Lock output not found";
                        break;
                    case -104:
                        l_error_msg = "Lock transaction is already unlocked";
                        break;
                    case -105:
                        l_error_msg = "Stake_ext not found in cache";
                        break;
                    case -106:
                        l_error_msg = "Unlocking denied: stake_ext won but lock period not expired";
                        break;
                    case -107:
                        l_error_msg = "Unlocking denied: stake_ext still active";
                        break;
                    case -108:
                        l_error_msg = "Failed to get token ticker";
                        break;
                    case -109:
                        l_error_msg = "Delegated token not found";
                        break;
                    case -110:
                        l_error_msg = "Failed to get emission rate";
                        break;
                    case -111:
                        l_error_msg = "Nothing to transfer (not enough delegated tokens)";
                        break;
                    case -112:
                        l_error_msg = "Failed to create transaction";
                        break;
                    case -113:
                        l_error_msg = "Failed to add network fee output";
                        break;
                    case -114:
                        l_error_msg = "Failed to add validator fee";
                        break;
                    case -115:
                        l_error_msg = "Failed to calculate coin back";
                        break;
                    case -116:
                        l_error_msg = "Failed to add coin back output";
                        break;
                    case -117:
                        l_error_msg = "Failed to add delegated token burn output";
                        break;
                    case -118:
                        l_error_msg = "Failed to add delegated token coin back output";
                        break;
                    case -119:
                        l_error_msg = "Failed to sign transaction";
                        break;
                    case -120:
                        l_error_msg = "Failed to create transaction datum";
                        break;
                    case -121:
                        l_error_msg = "Failed to add stake_ext lock transaction to mempool";
                        break;
                    default:
                        l_error_msg = "Unknown error occurred";
                        break;
                }
                dap_json_rpc_error_add(*l_json_arr_reply, UNLOCK_CREATE_ERROR, "Error creating unlock transaction: %s (code: %d)", l_error_msg, l_ret_code);
                return -7;
            }
        } break;

        case CMD_LIST: {
            bool l_active_only = (dap_cli_server_cmd_check_option(argv, arg_index, argc, "-active_only") != -1);
            bool l_include_positions = (dap_cli_server_cmd_check_option(argv, arg_index, argc, "-positions") != -1);
            
            // Get list of stake_ext from cache
            dap_chain_srv_stake_ext_status_t l_status_filter = l_active_only ? DAP_STAKE_EXT_STATUS_ACTIVE : DAP_STAKE_EXT_STATUS_UNKNOWN;
            dap_list_t *l_stake_ext_list = dap_chain_net_srv_stake_ext_get_list(l_net, l_status_filter, l_include_positions);
            
            // Diagnostic: Check returned list
            if (!l_stake_ext_list) {
                log_it(L_INFO, "CMD_LIST: get_list returned NULL");
            } else {
                uint32_t l_list_length = dap_list_length(l_stake_ext_list);
                log_it(L_INFO, "CMD_LIST: get_list returned list with %u items", l_list_length);
            }
            
            dap_json_t *l_json_obj = dap_json_object_new();
            dap_json_object_add_object(l_json_obj, "command", dap_json_object_new_string("list"));
            dap_json_object_add_object(l_json_obj, "status", dap_json_object_new_string("success"));
            dap_json_object_add_object(l_json_obj, "active_only", dap_json_object_new_bool(l_active_only));
            dap_json_object_add_object(l_json_obj, "include_positions", dap_json_object_new_bool(l_include_positions));
            
            // Create stake_ext array
            dap_json_t *l_stake_ext_array = dap_json_array_new();
            uint32_t l_count = 0;
            uint32_t l_processed = 0;
            
            log_it(L_INFO, "CMD_LIST: Starting stake_ext processing loop");
            for (dap_list_t *l_item = l_stake_ext_list; l_item; l_item = dap_list_next(l_item)) {
                l_processed++;
                log_it(L_DEBUG, "CMD_LIST: Processing stake_ext item %u", l_processed);
                
                dap_chain_net_srv_stake_ext_t *l_stake_ext = (dap_chain_net_srv_stake_ext_t *)l_item->data;
                if (!l_stake_ext) {
                    log_it(L_WARNING, "CMD_LIST: Item %u has NULL data", l_processed);
                    continue;
                }
                
                log_it(L_DEBUG, "CMD_LIST: Stake_ext %u: guuid=%s, status=%d", 
                       l_processed, l_stake_ext->guuid ? l_stake_ext->guuid : "NULL", l_stake_ext->status);
                
                dap_json_t *l_stake_ext_obj = dap_json_object_new();
                
                // Basic stake_ext info
                dap_json_object_add_object(l_stake_ext_obj, "hash", 
                    dap_json_object_new_string(dap_chain_hash_fast_to_str_static(&l_stake_ext->stake_ext_hash)));
                if (l_stake_ext->guuid)
                    dap_json_object_add_object(l_stake_ext_obj, "stake_ext_name", dap_json_object_new_string(l_stake_ext->guuid));
                dap_json_object_add_object(l_stake_ext_obj, "status", 
                    dap_json_object_new_string(dap_chain_srv_stake_ext_status_to_str(l_stake_ext->status)));
                
                // Format times as human-readable strings
                char created_time_str[DAP_TIME_STR_SIZE], start_time_str[DAP_TIME_STR_SIZE], end_time_str[DAP_TIME_STR_SIZE];
                dap_time_to_str_rfc822(created_time_str, DAP_TIME_STR_SIZE, l_stake_ext->created_time);
                dap_time_to_str_rfc822(start_time_str, DAP_TIME_STR_SIZE, l_stake_ext->start_time);
                dap_time_to_str_rfc822(end_time_str, DAP_TIME_STR_SIZE, l_stake_ext->end_time);
                dap_json_object_add_object(l_stake_ext_obj, "created_time", dap_json_object_new_string(created_time_str));
                dap_json_object_add_object(l_stake_ext_obj, "start_time", dap_json_object_new_string(start_time_str));
                dap_json_object_add_object(l_stake_ext_obj, "end_time", dap_json_object_new_string(end_time_str));
                dap_json_object_add_object(l_stake_ext_obj, "locks_count", 
                    dap_json_object_new_uint64(l_stake_ext->locks_count));
                dap_json_object_add_object(l_stake_ext_obj, "positions_count", 
                    dap_json_object_new_uint64(l_stake_ext->positions_count));
                
                // Winners information
                if (l_stake_ext->has_winner && l_stake_ext->winners_cnt > 0) {
                    dap_json_t *l_winners_array = dap_json_array_new();
                    for (uint8_t i = 0; i < l_stake_ext->winners_cnt; i++) {
                    dap_json_t *l_winner_obj = dap_json_object_new();
                        dap_json_object_add_object(l_winner_obj, "position_id", 
                            dap_json_object_new_uint64(l_stake_ext->winners_ids[i]));
                        dap_json_array_add(l_winners_array, l_winner_obj);
                    }
                    dap_json_object_add_object(l_stake_ext_obj, "winners", l_winners_array);
                    dap_json_object_add_object(l_stake_ext_obj, "winners_count", 
                        dap_json_object_new_uint64(l_stake_ext->winners_cnt));
                }
                
                // Positions information (if requested and available)
                if (l_include_positions && l_stake_ext->positions && l_stake_ext->positions_count > 0) {
                    dap_json_t *l_positions_array = dap_json_array_new();
                    for (uint32_t i = 0; i < l_stake_ext->positions_count; i++) {
                        dap_json_t *l_position_obj = dap_json_object_new();
                        
                        // Position ID
                        dap_json_object_add_object(l_position_obj, "position_id", dap_json_object_new_uint64(l_stake_ext->positions[i].position_id));
                        
                        // Total amount
                        char *l_total_amount_str = dap_uint256_uninteger_to_char(l_stake_ext->positions[i].total_amount);
                        if (l_total_amount_str) {
                            dap_json_object_add_object(l_position_obj, "total_amount", dap_json_object_new_string(l_total_amount_str));
                            DAP_DELETE(l_total_amount_str);
                        } else {
                            dap_json_object_add_object(l_position_obj, "total_amount", dap_json_object_new_string("0"));
                        }
                        
                        // Total amount in CELL
                        char *l_total_amount_coin_str = dap_uint256_decimal_to_char(l_stake_ext->positions[i].total_amount);
                        if (l_total_amount_coin_str) {
                            dap_json_object_add_object(l_position_obj, "total_amount_coin", dap_json_object_new_string(l_total_amount_coin_str));
                            DAP_DELETE(l_total_amount_coin_str);
                        } else {
                            dap_json_object_add_object(l_position_obj, "total_amount_coin", dap_json_object_new_string("0.0"));
                        }
                        
                        // Locks counts
                        dap_json_object_add_object(l_position_obj, "locks_count", dap_json_object_new_uint64(l_stake_ext->positions[i].locks_count));
                        dap_json_object_add_object(l_position_obj, "active_locks_count", dap_json_object_new_uint64(l_stake_ext->positions[i].active_locks_count));
                        
                        dap_json_array_add(l_positions_array, l_position_obj);
                    }
                    dap_json_object_add_object(l_stake_ext_obj, "positions", l_positions_array);
                }
                
                dap_json_array_add(l_stake_ext_array, l_stake_ext_obj);
                l_count++;
                log_it(L_DEBUG, "CMD_LIST: Successfully added stake_ext %u to JSON array", l_count);
            }
            
            log_it(L_INFO, "CMD_LIST: Processed %u items, added %u stake_ext to JSON array", l_processed, l_count);
            dap_json_object_add_object(l_json_obj, "stake_ext", l_stake_ext_array);
            dap_json_object_add_object(l_json_obj, "count", dap_json_object_new_uint64(l_count));
            dap_json_array_add(*l_json_arr_reply, l_json_obj);
            
            log_it(L_INFO, "CMD_LIST: JSON response prepared with %u stake_ext", l_count);
            
            // Cleanup
            if (l_stake_ext_list) {
                for (dap_list_t *l_item = l_stake_ext_list; l_item; l_item = dap_list_next(l_item)) {
                    dap_chain_net_srv_stake_ext_delete((dap_chain_net_srv_stake_ext_t *)l_item->data);
                }
                dap_list_free(l_stake_ext_list);
            }
        } break;

        case CMD_INFO: {
            // Parse stake_ext ID
            const char *l_stake_ext_id_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-stake_ext", &l_stake_ext_id_str);
            if(!l_stake_ext_id_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, STAKE_EXT_HASH_ARG_ERROR, "Stake_ext hash not specified");
                return -1;
            }

            struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(l_net->pub.id);
            if(!l_stake_ext_service) {
                dap_json_rpc_error_add(*l_json_arr_reply, STAKE_EXT_CACHE_NOT_INITIALIZED, "Stake_ext cache not initialized in network %s", l_net->pub.name);
                return -14;
            }
            dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = NULL;
            dap_hash_fast_t l_stake_ext_hash = {};
            bool l_hash_parsed = (dap_chain_hash_fast_from_str(l_stake_ext_id_str, &l_stake_ext_hash) == 0);
            if (l_hash_parsed) {
                l_stake_ext = s_stake_ext_cache_find_stake_ext(l_stake_ext_service, &l_stake_ext_hash);
            } else {
                // Try resolve by GUUID via stake_ext cache
                l_stake_ext = s_stake_ext_cache_find_stake_ext_by_name(l_stake_ext_service, l_stake_ext_id_str);
                if (l_stake_ext)
                    l_stake_ext_hash = l_stake_ext->stake_ext_tx_hash.hash;
            }
            if(!l_stake_ext) {
                dap_json_rpc_error_add(*l_json_arr_reply, STAKE_EXT_NOT_FOUND_ERROR, "Stake_ext '%s' not found",
                                                                                l_hash_parsed ? dap_hash_fast_to_str_static(&l_stake_ext_hash) : l_stake_ext_id_str);
                return -2;
            }          
            bool l_verbose = (dap_cli_server_cmd_check_option(argv, arg_index, argc, "-verbose") != -1);
            dap_json_t *l_json_obj = dap_json_object_new();
            dap_json_object_add_object(l_json_obj, "command", dap_json_object_new_string("info"));
            dap_json_object_add_object(l_json_obj, "status", dap_json_object_new_string("success"));
            dap_json_object_add_object(l_json_obj, "verbose", dap_json_object_new_bool(l_verbose));
            dap_json_object_add_object(l_json_obj, "stake_ext_tx_hash", dap_json_object_new_string(dap_hash_fast_to_str_static(&l_stake_ext->stake_ext_tx_hash.hash)));
            dap_json_object_add_object(l_json_obj, "stake_ext_name", dap_json_object_new_string(l_stake_ext->guuid));
            
            // Basic stake_ext information
            dap_json_object_add_object(l_json_obj, "stake_ext_status", 
                dap_json_object_new_string(dap_chain_srv_stake_ext_status_to_str(l_stake_ext->status)));
            
            // Format times as human-readable strings
            char info_created_time_str[DAP_TIME_STR_SIZE], info_start_time_str[DAP_TIME_STR_SIZE], info_end_time_str[DAP_TIME_STR_SIZE];
            dap_time_to_str_rfc822(info_created_time_str, DAP_TIME_STR_SIZE, l_stake_ext->created_time);
            dap_time_to_str_rfc822(info_start_time_str, DAP_TIME_STR_SIZE, l_stake_ext->start_time);
            dap_time_to_str_rfc822(info_end_time_str, DAP_TIME_STR_SIZE, l_stake_ext->end_time);
            dap_json_object_add_object(l_json_obj, "created_time", dap_json_object_new_string(info_created_time_str));
            dap_json_object_add_object(l_json_obj, "start_time", dap_json_object_new_string(info_start_time_str));
            dap_json_object_add_object(l_json_obj, "end_time", dap_json_object_new_string(info_end_time_str));
            dap_json_object_add_object(l_json_obj, "locks_count", dap_json_object_new_uint64(l_stake_ext->locks_count));
            dap_json_object_add_object(l_json_obj, "positions_count", dap_json_object_new_uint64(HASH_COUNT(l_stake_ext->positions)));
            
            if (l_stake_ext->description) {
                dap_json_object_add_object(l_json_obj, "description", 
                    dap_json_object_new_string(l_stake_ext->description));
            }
            
            // Winners information
            if (l_stake_ext->has_winner && l_stake_ext->winners_cnt > 0) {
                dap_json_t *l_winners_array = dap_json_array_new();
                for (uint8_t i = 0; i < l_stake_ext->winners_cnt; i++) {
                dap_json_t *l_winner_obj = dap_json_object_new();
                    dap_json_object_add_object(l_winner_obj, "position_id", 
                        dap_json_object_new_uint64(l_stake_ext->winners_ids[i]));
                    dap_json_array_add(l_winners_array, l_winner_obj);
                }
                dap_json_object_add_object(l_json_obj, "winners", l_winners_array);
                dap_json_object_add_object(l_json_obj, "winners_count", 
                    dap_json_object_new_uint64(l_stake_ext->winners_cnt));
            }
            
            // Positions information
            if (l_stake_ext->positions && HASH_COUNT(l_stake_ext->positions) > 0) {
                dap_json_t *l_positions_array = dap_json_array_new();
                
                for (dap_chain_srv_stake_ext_position_cache_item_t *l_position = l_stake_ext->positions; l_position; l_position = l_position->hh.next) {
                    dap_json_t *l_position_obj = dap_json_object_new();
                    dap_json_array_add(l_positions_array, l_position_obj);
                    // Position ID
                    dap_json_object_add_object(l_position_obj, "position_id", dap_json_object_new_uint64(l_position->position_id));
                   
                    const char *l_total_amount_str = dap_uint256_to_char(l_position->total_amount, NULL);
                    dap_json_object_add_object(l_position_obj, "total_amount", dap_json_object_new_string(l_total_amount_str));
                    
                    // Total amount in CELL
                    char *l_total_amount_coin_str = dap_uint256_decimal_to_char(l_position->total_amount);
                    if (l_total_amount_coin_str) {
                        dap_json_object_add_object(l_position_obj, "total_amount_coin", dap_json_object_new_string(l_total_amount_coin_str));
                        DAP_DELETE(l_total_amount_coin_str);
                    } else {
                        dap_json_object_add_object(l_position_obj, "total_amount_coin", dap_json_object_new_string("0.0"));
                    }
                    
                    dap_json_object_add_object(l_position_obj, "locks_count", 
                        dap_json_object_new_uint64(HASH_COUNT(l_position->locks)));
                    dap_json_object_add_object(l_position_obj, "active_locks_count", 
                        dap_json_object_new_uint64(l_position->active_locks_count));
                    if (l_verbose) {
                        dap_json_t *l_locks_array = dap_json_array_new();
                        dap_json_object_add_object(l_position_obj, "locks", l_locks_array);
                        for (dap_chain_srv_stake_ext_lock_cache_item_t *l_lock = l_position->locks; l_lock; l_lock = l_lock->hh.next) {
                            dap_json_t *l_lock_obj = dap_json_object_new();
                            dap_json_array_add(l_locks_array, l_lock_obj);
                            dap_json_object_add_object(l_lock_obj, "lock_tx_hash", dap_json_object_new_string(dap_hash_fast_to_str_static(&l_lock->lock_tx_hash.hash)));
                            dap_json_object_add_object(l_lock_obj, "lock_amount", dap_json_object_new_string(dap_uint256_to_char(l_lock->lock_amount, NULL)));
                            dap_json_object_add_object(l_lock_obj, "lock_time", dap_json_object_new_uint64(l_lock->lock_time));
                            char l_lock_created_time_str[DAP_TIME_STR_SIZE] = {'\0'};
                            dap_time_to_str_rfc822(l_lock_created_time_str, sizeof(l_lock_created_time_str), l_lock->created_time);
                            dap_json_object_add_object(l_lock_obj, "created_time", dap_json_object_new_string(l_lock_created_time_str));
                            dap_json_object_add_object(l_lock_obj, "is_unlocked", dap_json_object_new_bool(l_lock->is_unlocked));
                        }
                    }
                }
                
                dap_json_object_add_object(l_json_obj, "positions", l_positions_array);
            }
            
            dap_json_array_add(*l_json_arr_reply, l_json_obj);

        } break;

        case CMD_EVENTS: {
            // Parse stake_ext ID
            const char *l_stake_ext_id_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-stake_ext", &l_stake_ext_id_str);
            dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = NULL;
            if (!l_stake_ext_id_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, STAKE_EXT_HASH_ARG_ERROR, "Stake_ext hash not specified");
                return -1;
            }
            struct stake_ext *l_stake_ext_service = s_stake_ext_service_get(l_net->pub.id);
            if(!l_stake_ext_service) {
                dap_json_rpc_error_add(*l_json_arr_reply, STAKE_EXT_CACHE_NOT_INITIALIZED, "Stake_ext cache not initialized in network %s", l_net->pub.name);
                return -14;
            }
            dap_hash_fast_t l_stake_ext_hash = {};
            bool l_hash_parsed = (dap_chain_hash_fast_from_str(l_stake_ext_id_str, &l_stake_ext_hash) == 0);
            if (l_hash_parsed)
                l_stake_ext = s_stake_ext_cache_find_stake_ext(l_stake_ext_service, &l_stake_ext_hash);
            else {
                // Try resolve by GUUID via stake_ext cache
                l_stake_ext = s_stake_ext_cache_find_stake_ext_by_name(l_stake_ext_service, l_stake_ext_id_str);
                if (l_stake_ext)
                    l_stake_ext_hash = l_stake_ext->stake_ext_tx_hash.hash;
            }
            if(!l_stake_ext) {
                dap_json_rpc_error_add(*l_json_arr_reply, STAKE_EXT_NOT_FOUND_ERROR, "Stake_ext '%s' not found", l_stake_ext_id_str);
                return -2;
            }
            // Parse optional parameters
            const char *l_event_type = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-type", &l_event_type);

            int l_event_type_int = 0;
            if (l_event_type) {
                l_event_type_int = dap_chain_tx_item_event_type_from_str(l_event_type);
                if (l_event_type_int == -1) {
                    dap_json_rpc_error_add(*l_json_arr_reply, INVALID_EVENT_TYPE_ERROR, "Invalid event type: %s", l_event_type);
                    return -3;
                }
            }

            dap_list_t *l_events = dap_ledger_event_get_list(l_net->pub.ledger, l_stake_ext->guuid);
            
            dap_json_t *l_json_obj = dap_json_object_new();
            dap_json_object_add_object(l_json_obj, "command", dap_json_object_new_string("events"));
            dap_json_object_add_object(l_json_obj, "status", dap_json_object_new_string("success"));
            dap_json_object_add_object(l_json_obj, "stake_ext_name", dap_json_object_new_string(l_stake_ext->guuid));
            dap_json_t *l_events_array = dap_json_array_new();
            for (dap_list_t *it = l_events; it; it = it->next) {
                dap_chain_tx_event_t *l_event = (dap_chain_tx_event_t *)it->data;
                if (l_event_type_int && l_event->event_type != l_event_type_int)
                    continue;
                dap_json_t *l_event_obj = dap_json_object_new();
                dap_json_array_add(l_events_array, l_event_obj);
                dap_chain_datum_tx_event_to_json(l_event_obj, l_event, "hex");
                dap_json_t *l_stake_ext_data = dap_json_object_new();
                dap_json_object_add_object(l_event_obj, "stake_ext_data", l_stake_ext_data);
                switch (l_event->event_type) {
                case DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_STARTED: {
                    dap_chain_tx_event_data_stake_ext_started_t *l_started_data = (dap_chain_tx_event_data_stake_ext_started_t *)l_event->event_data;
                    dap_json_object_add_object(l_stake_ext_data, "multiplier", dap_json_object_new_uint64(l_started_data->multiplier));
                    dap_json_object_add_object(l_stake_ext_data, "duration", dap_json_object_new_uint64(l_started_data->duration));
                    dap_json_object_add_object(l_stake_ext_data, "time_unit", dap_json_object_new_string(dap_chain_tx_event_data_time_unit_to_str(l_started_data->time_unit)));
                    dap_json_object_add_object(l_stake_ext_data, "calculation_rule_id", dap_json_object_new_uint64(l_started_data->calculation_rule_id));
                    dap_json_object_add_object(l_stake_ext_data, "total_postions", dap_json_object_new_uint64(l_started_data->total_postions));
                    dap_json_t *l_positions_array = dap_json_array_new();
                    dap_json_object_add_object(l_stake_ext_data, "positions", l_positions_array);
                    for (uint8_t i = 0; i < l_started_data->total_postions; i++) {
                        dap_json_t *l_position_obj = dap_json_object_new();
                        dap_json_object_add_object(l_position_obj, "position_id", dap_json_object_new_uint64(l_started_data->position_ids[i]));
                        dap_json_array_add(l_positions_array, l_position_obj);
                    }
                } break;
                case DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_ENDED: {
                    dap_chain_tx_event_data_ended_t *l_ended_data = (dap_chain_tx_event_data_ended_t *)l_event->event_data;
                    char l_end_time_str[DAP_TIME_STR_SIZE] = {'\0'};
                    dap_time_to_str_rfc822(l_end_time_str, sizeof(l_end_time_str), l_ended_data->end_time);
                    dap_json_object_add_string(l_stake_ext_data, "end_time", l_end_time_str);
                    dap_json_object_add_object(l_stake_ext_data, "winners_cnt", dap_json_object_new_uint64(l_ended_data->winners_cnt));
                    dap_json_t *l_winners_array = dap_json_array_new();
                    dap_json_object_add_object(l_stake_ext_data, "winners", l_winners_array);
                    for (uint8_t i = 0; i < l_ended_data->winners_cnt; i++) {
                        dap_json_t *l_winner_obj = dap_json_object_new();
                        dap_json_object_add_object(l_winner_obj, "winner_id", dap_json_object_new_uint64(l_ended_data->winners_ids[i]));
                        dap_json_array_add(l_winners_array, l_winner_obj);
                    }
                } break;
                default:
                    dap_json_object_add_object(l_stake_ext_data, "empty", dap_json_object_new());
                    break;
                }
            }
            dap_json_object_add_object(l_json_obj, "events", l_events_array);
            dap_json_array_add(*l_json_arr_reply, l_json_obj);
        } break;

        case CMD_STATS: {
            // Get stake_ext statistics
            dap_chain_srv_stake_ext_stats_t *l_stats = dap_chain_net_srv_stake_ext_get_stats(l_net);
            
            dap_json_t *l_json_obj = dap_json_object_new();
            dap_json_object_add_object(l_json_obj, "command", dap_json_object_new_string("stats"));
            
            if (l_stats) {
                dap_json_object_add_object(l_json_obj, "status", dap_json_object_new_string("success"));
                dap_json_object_add_object(l_json_obj, "total_stake_ext", dap_json_object_new_uint64(l_stats->total_stake_ext));
                dap_json_object_add_object(l_json_obj, "active_stake_ext", dap_json_object_new_uint64(l_stats->active_stake_ext));
                dap_json_object_add_object(l_json_obj, "ended_stake_ext", dap_json_object_new_uint64(l_stats->ended_stake_ext));
                dap_json_object_add_object(l_json_obj, "cancelled_stake_ext", dap_json_object_new_uint64(l_stats->cancelled_stake_ext));
                dap_json_object_add_object(l_json_obj, "total_locks", dap_json_object_new_uint64(l_stats->total_locks));
                dap_json_object_add_object(l_json_obj, "total_positions", dap_json_object_new_uint64(l_stats->total_positions));
                
                DAP_DELETE(l_stats);
            } else {
                dap_json_object_add_object(l_json_obj, "status", dap_json_object_new_string("error"));
                dap_json_object_add_object(l_json_obj, "message", dap_json_object_new_string("Failed to get statistics"));
            }
            
            dap_json_array_add(*l_json_arr_reply, l_json_obj);
        } break;

        default:
            dap_json_rpc_error_add(*l_json_arr_reply, COMMAND_NOT_RECOGNIZED, "Unknown command");
            return -1;
    }

    return 0;
}

static int s_stake_ext_cache_set_winners_by_name(struct stake_ext *a_cache,
                                         const char *a_guuid,
                                         uint8_t a_winners_cnt,
                                         uint32_t *a_winners_ids)
{
    if (!a_cache || !a_guuid || !a_winners_ids || a_winners_cnt == 0)
        return -1;

    pthread_rwlock_wrlock(&a_cache->cache_rwlock);

    // Find stake_ext
    dap_chain_srv_stake_ext_cache_item_t *l_stake_ext = NULL;
    HASH_FIND_STR(a_cache->stake_ext, a_guuid, l_stake_ext);
    if (!l_stake_ext) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_WARNING, "Stake_ext '%s' not found in cache for setting winners", a_guuid);
        return -2;
    }

    // Clean up previous winners array if exists
    DAP_DELETE(l_stake_ext->winners_ids);

    // Set multiple winners information
    l_stake_ext->has_winner = true;
    l_stake_ext->winners_cnt = a_winners_cnt;
    l_stake_ext->winners_ids = DAP_NEW_Z_SIZE(uint32_t, sizeof(uint32_t) * a_winners_cnt);
    if (!l_stake_ext->winners_ids) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_CRITICAL, "Memory allocation error for winners array (by GUUID)");
        return -3;
    }

    memcpy(l_stake_ext->winners_ids, a_winners_ids, sizeof(uint32_t) * a_winners_cnt);

    pthread_rwlock_unlock(&a_cache->cache_rwlock);

    log_it(L_DEBUG, "Set %u winners for stake_ext '%s' (by GUUID)", a_winners_cnt, a_guuid);
    return 0;
}

byte_t *dap_chain_srv_stake_ext_started_tx_event_create(size_t *a_data_size, uint32_t a_multiplier, dap_time_t a_duration,
    dap_chain_tx_event_data_time_unit_t a_time_unit, uint32_t a_calculation_rule_id, uint8_t a_total_postions, uint32_t a_position_ids[])
{
    size_t l_data_size = sizeof(dap_chain_tx_event_data_stake_ext_started_t) + a_total_postions * sizeof(uint32_t);
    dap_chain_tx_event_data_stake_ext_started_t *l_data = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_event_data_stake_ext_started_t, l_data_size, NULL);

    l_data->multiplier = a_multiplier;
    l_data->duration = a_duration;
    l_data->time_unit = a_time_unit;
    l_data->calculation_rule_id = a_calculation_rule_id;
    l_data->total_postions = a_total_postions;
    memcpy(l_data->position_ids, a_position_ids, a_total_postions * sizeof(uint32_t));

    if (a_data_size)
        *a_data_size = l_data_size;

    return (byte_t *)l_data;
}

byte_t *dap_chain_srv_stake_ext_ended_tx_event_create(size_t *a_data_size, dap_time_t a_end_time, uint8_t a_winners_cnt, uint32_t a_winners_ids[])
{
    size_t l_data_size = sizeof(dap_chain_tx_event_data_ended_t) + a_winners_cnt * sizeof(uint32_t);
    dap_chain_tx_event_data_ended_t *l_data = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_event_data_ended_t, l_data_size, NULL);
    l_data->winners_cnt = a_winners_cnt;
    l_data->end_time = a_end_time;
    memcpy(l_data->winners_ids, a_winners_ids, a_winners_cnt * sizeof(uint32_t));

    if (a_data_size)
        *a_data_size = l_data_size;

    return (byte_t *)l_data;
}
