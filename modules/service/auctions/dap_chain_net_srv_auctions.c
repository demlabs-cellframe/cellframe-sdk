/*
 * Authors:
 * AI Assistant & CellFrame Development Team
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame Network https://cellframe.net
 * Copyright  (c) 2025
 * All rights reserved.

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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#include "dap_chain_net_srv_auctions.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_mempool.h"
#include "dap_cli_server.h"
#include "dap_chain_wallet_cache.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_common.h"
#include "dap_strfuncs.h"

#define LOG_TAG "chain_net_auctions"

// ===========================================
// GLOBAL STORAGE
// ===========================================

/// Global auction storage instance
static dap_chain_auction_storage_t s_auction_storage = {0};

/// Service initialization flag
static bool s_auction_service_initialized = false;

// Static function declarations
static int s_cli_auctions(int argc, char **argv, void **a_str_reply, int a_version);
static bool s_tag_check_auctions(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, 
                                 dap_chain_datum_tx_item_groups_t *a_items_grp, 
                                 dap_chain_tx_tag_action_type_t *a_action);

// ===========================================
// BID TRANSACTION COMPOSER IMPLEMENTATION
// ===========================================

/**
 * @brief Create auction bid transaction item
 * 
 * Bid Transaction Composer function that creates a properly formatted
 * auction bid transaction item for inclusion in blockchain transactions.
 */
dap_chain_tx_out_cond_t* dap_chain_auction_bid_cond_create(
    dap_hash_fast_t *a_auction_hash,
    uint8_t a_range_end,
    uint256_t a_bid_amount,
    dap_time_t a_lock_time,
    dap_pkey_t *a_bidder_pkey)
{
    // Input validation
    if (!a_auction_hash || !a_bidder_pkey) {
        log_it(L_ERROR, "Auction hash and bidder public key are required");
        return NULL;
    }

    // Validate bid parameters using existing validation function (range_start = 1 by default)
    dap_chain_auction_bid_error_t l_validation_result = dap_chain_auction_bid_validate_params(
        1, a_range_end, a_bid_amount, a_lock_time);
    
    if (l_validation_result != DAP_CHAIN_AUCTION_BID_OK) {
        log_it(L_ERROR, "Bid parameters validation failed with code %d", l_validation_result);
        return NULL;
    }

    // Create bid data for TSD section
    dap_chain_auction_bid_tsd_t l_bid_data = {
        .auction_hash = *a_auction_hash,
        .range_end = a_range_end,
        .lock_time = a_lock_time,
        .bid_amount = a_bid_amount
    };

    // Create conditional output with auction service
    dap_chain_net_srv_uid_t l_srv_uid = { .uint64 = DAP_CHAIN_NET_SRV_AUCTIONS_ID };
    
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_auction_bid(
        a_bidder_pkey,
        l_srv_uid,
        a_bid_amount,
        uint256_0,  // no unit price max for auctions
        SERV_UNIT_UNDEFINED,
        &l_bid_data,
        sizeof(dap_chain_auction_bid_tsd_t)
    );

    if (!l_out_cond) {
        log_it(L_ERROR, "Failed to create conditional output for auction bid");
        return NULL;
    }

    // Set the correct subtype for auction bids
    l_out_cond->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID;
    
    // Set auction-specific fields in the subtype union
    l_out_cond->subtype.srv_auction_bid.auction_hash = *a_auction_hash;
    l_out_cond->subtype.srv_auction_bid.range_end = a_range_end;
    l_out_cond->subtype.srv_auction_bid.lock_time = a_lock_time;

    log_it(L_DEBUG, "Created auction bid conditional output: range 1-%d, amount %s", 
           a_range_end, dap_chain_balance_to_coins(a_bid_amount));

    return l_out_cond;
}

/**
 * @brief Initialize auction service
 * @return 0 on success, negative error code on failure
 */
int dap_chain_net_srv_auctions_init(void)
{
    if (s_auction_service_initialized) {
        log_it(L_WARNING, "Auction service already initialized");
        return 0;
    }

    // Initialize storage
    if (dap_chain_auction_storage_init() != 0) {
        log_it(L_ERROR, "Failed to initialize auction storage");
        return -1;
    }

    // Register conditional transaction verificator for auction bids
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID, dap_chain_auction_bid_verificator, NULL, NULL);

    // Register CLI commands
    dap_cli_cmd_t *l_auction_cmd = dap_cli_server_cmd_add(
        "auction", s_cli_auctions, "Auction bidding system commands",
        "auction bid -net <net_name> -auction <auction_hash> -range <start>-<end> "
        "-amount <cell_amount> -lock <months> -fee <fee_amount> -w <wallet_name>\n"
        "auction list -net <net_name> [-active_only]\n"
        "auction info -net <net_name> -auction <auction_hash>\n"
        "auction events -net <net_name> [-auction <auction_hash>] [-type <event_type>]\n"
        "auction load -net <net_name>\n"
    );

    if (!l_auction_cmd) {
        log_it(L_ERROR, "Failed to register auction CLI commands");
        dap_chain_auction_storage_deinit();
        return -3;
    }

    // Register service with ledger
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_AUCTIONS_ID };
    dap_ledger_service_add(l_uid, "auction", NULL);

    s_auction_service_initialized = true;
    log_it(L_INFO, "Auction service initialized successfully");
    
    // Note: Auction state loading from events should be done per-network
    // when networks are available during runtime using 'auction load -net <net_name>'
    
    return 0;
}

/**
 * @brief Deinitialize auction service
 */
void dap_chain_net_srv_auctions_deinit(void)
{
    pthread_rwlock_wrlock(&s_auctions_storage.auctions_rwlock);
    
    // Clean up all auctions
    dap_chain_auction_info_t *l_auction, *l_tmp;
    HASH_ITER(hh, s_auctions_storage.auctions, l_auction, l_tmp) {
        HASH_DEL(s_auctions_storage.auctions, l_auction);
        dap_chain_auction_info_free(l_auction);
    }
    
    pthread_rwlock_unlock(&s_auctions_storage.auctions_rwlock);
    pthread_rwlock_destroy(&s_auctions_storage.auctions_rwlock);
    
    log_it(L_INFO, "Auction service deinitialized");
}

/**
 * @brief Calculate bid score using formula: range * bid_amount
 * 
 * The scoring algorithm implements the Cellframe auction rules:
 * - Range is calculated as (range_end - range_start + 1)
 * - Score = range * bid_amount
 * - Higher scores win the auction
 * 
 * Example: 50 CELL bid on range 1-8 gives range=8, score = 8 * 50 = 400
 * 
 * @param a_params Bid parameters containing range and amount
 * @param a_score_out Output calculated score
 * @return 0 on success, negative error code on failure
 */
int dap_chain_auction_bid_calculate_score(const dap_chain_auction_bid_score_params_t *a_params, uint256_t *a_score_out)
{
    if (!a_params || !a_score_out) {
        log_it(L_ERROR, "Invalid parameters for score calculation");
        return DAP_CHAIN_NET_AUCTIONS_ERROR_INVALID_PARAMS;
    }

    // Validate range parameters
    if (a_params->range_start < DAP_CHAIN_AUCTIONS_CELLSLOT_RANGE_MIN || 
        a_params->range_start > DAP_CHAIN_AUCTIONS_CELLSLOT_RANGE_MAX ||
        a_params->range_end < DAP_CHAIN_AUCTIONS_CELLSLOT_RANGE_MIN ||
        a_params->range_end > DAP_CHAIN_AUCTIONS_CELLSLOT_RANGE_MAX ||
        a_params->range_start > a_params->range_end) {
        log_it(L_ERROR, "Invalid range: start=%u, end=%u (must be 1-8 with start <= end)", 
               a_params->range_start, a_params->range_end);
        return DAP_CHAIN_NET_AUCTIONS_ERROR_INVALID_RANGE;
    }

    // Calculate range size: (end - start + 1)
    uint8_t l_range_size = a_params->range_end - a_params->range_start + 1;
    
    // Convert range to uint256_t for multiplication
    uint256_t l_range_uint256 = uint256_from_uint64(l_range_size);
    
    // Calculate score: range * bid_amount
    *a_score_out = uint256_multi(l_range_uint256, a_params->bid_amount);
    
    log_it(L_INFO, "Calculated bid score: range=%u, amount=%s, score=%s", 
           l_range_size, 
           dap_uint256_decimal_to_char(a_params->bid_amount),
           dap_uint256_decimal_to_char(*a_score_out));
    
    return DAP_CHAIN_NET_AUCTIONS_OK;
}

/**
 * @brief Validate auction bid parameters according to Cellframe rules
 * 
 * @param a_range_start Starting range for CellSlot (1-8)
 * @param a_range_end Ending range for CellSlot (1-8)
 * @param a_bid_amount Amount of CELL tokens bid
 * @param a_lock_time Token lock time duration
 * @return dap_chain_auction_bid_error_t Validation result
 */
dap_chain_auction_bid_error_t dap_chain_auction_bid_validate_params(
    uint8_t a_range_start, 
    uint8_t a_range_end, 
    uint256_t a_bid_amount, 
    dap_time_t a_lock_time)
{
    // Validate range parameters
    if (a_range_start < DAP_CHAIN_AUCTION_MIN_RANGE || a_range_start > DAP_CHAIN_AUCTION_MAX_RANGE) {
        log_it(L_ERROR, "Invalid range start: %u (must be %u-%u)", 
               a_range_start, DAP_CHAIN_AUCTION_MIN_RANGE, DAP_CHAIN_AUCTION_MAX_RANGE);
        return DAP_CHAIN_AUCTION_BID_ERROR_INVALID_RANGE;
    }
    
    if (a_range_end < DAP_CHAIN_AUCTION_MIN_RANGE || a_range_end > DAP_CHAIN_AUCTION_MAX_RANGE) {
        log_it(L_ERROR, "Invalid range end: %u (must be %u-%u)", 
               a_range_end, DAP_CHAIN_AUCTION_MIN_RANGE, DAP_CHAIN_AUCTION_MAX_RANGE);
        return DAP_CHAIN_AUCTION_BID_ERROR_INVALID_RANGE;
    }
    
    if (a_range_start > a_range_end) {
        log_it(L_ERROR, "Range start (%u) cannot be greater than range end (%u)", 
               a_range_start, a_range_end);
        return DAP_CHAIN_AUCTION_BID_ERROR_INVALID_RANGE;
    }

    // Validate bid amount
    if (IS_ZERO_256(a_bid_amount)) {
        log_it(L_ERROR, "Bid amount cannot be zero");
        return DAP_CHAIN_AUCTION_BID_ERROR_INSUFFICIENT_AMOUNT;
    }

    // Calculate required minimum based on range and time
    uint8_t l_range_size = a_range_end - a_range_start + 1;
    uint64_t l_months_required = l_range_size * DAP_CHAIN_AUCTION_MONTHS_PER_RANGE;
    
    // Minimum amount: 31.250 CELL for 3 months
    uint256_t l_min_amount_per_3months = uint256_from_uint64(DAP_CHAIN_AUCTION_MIN_CELL_3MONTHS);
    uint256_t l_required_min_amount = {};
    
    // Calculate minimum required: (months_required / 3) * 31.250 CELL
    uint64_t l_multiplier = l_months_required / 3;
    l_required_min_amount = dap_uint256_scan_uint64(l_multiplier);
    MULT_256_256(l_required_min_amount, l_min_amount_per_3months, &l_required_min_amount);
    
    if (compare256(a_bid_amount, l_required_min_amount) < 0) {
        log_it(L_ERROR, "Bid amount %s is below minimum required %s for range %u-%u", 
               dap_chain_balance_to_coins(a_bid_amount),
               dap_chain_balance_to_coins(l_required_min_amount),
               a_range_start, a_range_end);
        return DAP_CHAIN_AUCTION_BID_ERROR_INSUFFICIENT_AMOUNT;
    }

    // Maximum amount: 250.000 CELL for 2 years
    uint256_t l_max_amount = uint256_from_uint64(DAP_CHAIN_AUCTION_MAX_CELL_2YEARS);
    if (compare256(a_bid_amount, l_max_amount) > 0) {
        log_it(L_ERROR, "Bid amount %s exceeds maximum allowed %s", 
               dap_chain_balance_to_coins(a_bid_amount),
               dap_chain_balance_to_coins(l_max_amount));
        return DAP_CHAIN_AUCTION_BID_ERROR_INSUFFICIENT_AMOUNT;
    }

    // Validate lock time
    dap_time_t l_min_lock_time = l_months_required * 30 * 24 * 3600; // Approximate months to seconds
    if (a_lock_time < l_min_lock_time) {
        log_it(L_ERROR, "Lock time %"PRIu64" is too short (minimum %"PRIu64" for range %u-%u)",
               a_lock_time, l_min_lock_time, a_range_start, a_range_end);
        return DAP_CHAIN_AUCTION_BID_ERROR_LOCK_TIME_TOO_SHORT;
    }

    dap_time_t l_max_lock_time = 24 * 30 * 24 * 3600; // 24 months in seconds
    if (a_lock_time > l_max_lock_time) {
        log_it(L_ERROR, "Lock time %"PRIu64" is too long (maximum %"PRIu64")",
               a_lock_time, l_max_lock_time);
        return DAP_CHAIN_AUCTION_BID_ERROR_LOCK_TIME_TOO_LONG;
    }

    return DAP_CHAIN_AUCTION_BID_OK;
}

/**
 * @brief Calculate bid score using Cellframe auction rules
 * 
 * Calculates the score for a bid using the formula: range_end * bid_amount = score
 * (range_start is always 1 for Cellframe auctions)
 * 
 * @param a_range_end Ending range for CellSlot (1-8, range_start always = 1)  
 * @param a_bid_amount Amount of CELL tokens bid
 * @return uint64_t Calculated score, or 0 on error
 */
uint64_t dap_chain_auction_bid_calculate_score(uint8_t a_range_end, uint256_t a_bid_amount)
{
    // Input validation (range_start is always 1)
    if (a_range_end < DAP_CHAIN_AUCTION_MIN_RANGE || a_range_end > DAP_CHAIN_AUCTION_MAX_RANGE) {
        log_it(L_ERROR, "Invalid range end: %u (must be %u-%u)", 
               a_range_end, DAP_CHAIN_AUCTION_MIN_RANGE, DAP_CHAIN_AUCTION_MAX_RANGE);
        return 0;
    }
    
    if (IS_ZERO_256(a_bid_amount)) {
        log_it(L_ERROR, "Bid amount cannot be zero");
        return 0;
    }

    // Calculate range size (always a_range_end since range_start = 1)
    uint8_t l_range_size = a_range_end;
    
    // Convert bid amount to uint64_t for calculation
    // Note: This assumes bid amounts fit in uint64_t, which should be safe for CELL tokens
    uint64_t l_bid_amount_u64 = dap_chain_uint256_to(a_bid_amount);
    
    // Calculate score: range_size * bid_amount
    uint64_t l_score = (uint64_t)l_range_size * l_bid_amount_u64;
    
    // Check for overflow
    if (l_bid_amount_u64 > 0 && l_score / l_bid_amount_u64 != l_range_size) {
        log_it(L_ERROR, "Score calculation overflow detected");
        return 0;
    }

    log_it(L_DEBUG, "Calculated score: range 1-%u (size %u) * amount %s = %"PRIu64,
           a_range_end, l_range_size, 
           dap_chain_balance_to_coins(a_bid_amount), l_score);

    return l_score;
}

// ===========================================
// AUCTION EVENT READING IMPLEMENTATION
// ===========================================

/**
 * @brief Read all auction events from ledger by group
 */
dap_list_t* dap_chain_auction_events_read_all(dap_chain_net_t *a_net)
{
    if (!a_net) {
        log_it(L_ERROR, "Network parameter is NULL");
        return NULL;
    }

    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);
    if (!l_ledger) {
        log_it(L_ERROR, "Cannot find ledger for network %s", a_net->pub.name);
        return NULL;
    }

    // Read all events from auction event group
    dap_list_t *l_events = dap_ledger_event_get_list(l_ledger, DAP_CHAIN_AUCTION_EVENT_GROUP);
    
    log_it(L_INFO, "Read %zu auction events from ledger network %s", 
           dap_list_length(l_events), a_net->pub.name);
    
    return l_events;
}

/**
 * @brief Read auction events for specific auction
 */
dap_list_t* dap_chain_auction_events_read_by_auction(dap_chain_net_t *a_net, dap_hash_fast_t *a_auction_hash)
{
    if (!a_net || !a_auction_hash) {
        log_it(L_ERROR, "Invalid parameters for auction events read");
        return NULL;
    }

    dap_list_t *l_all_events = dap_chain_auction_events_read_all(a_net);
    if (!l_all_events) {
        return NULL;
    }

    dap_list_t *l_filtered_events = NULL;
    
    for (dap_list_t *it = l_all_events; it; it = it->next) {
        dap_chain_tx_event_t *l_event = (dap_chain_tx_event_t*)it->data;
        if (!l_event || !l_event->event_data) {
            continue;
        }

        bool l_event_matches = false;
        
        // Check if event relates to our auction based on event type and data
        switch (l_event->event_type) {
            case DAP_CHAIN_AUCTION_EVENT_TYPE_AUCTION_CREATED: {
                dap_chain_auction_event_auction_created_t *l_data = 
                    (dap_chain_auction_event_auction_created_t*)l_event->event_data;
                if (dap_hash_fast_compare(&l_data->auction_hash, a_auction_hash)) {
                    l_event_matches = true;
                }
                break;
            }
            case DAP_CHAIN_AUCTION_EVENT_TYPE_BID_PLACED: {
                dap_chain_auction_event_bid_placed_t *l_data = 
                    (dap_chain_auction_event_bid_placed_t*)l_event->event_data;
                if (dap_hash_fast_compare(&l_data->auction_hash, a_auction_hash)) {
                    l_event_matches = true;
                }
                break;
            }
            case DAP_CHAIN_AUCTION_EVENT_TYPE_AUCTION_ENDED: {
                dap_chain_auction_event_auction_ended_t *l_data = 
                    (dap_chain_auction_event_auction_ended_t*)l_event->event_data;
                if (dap_hash_fast_compare(&l_data->auction_hash, a_auction_hash)) {
                    l_event_matches = true;
                }
                break;
            }
            case DAP_CHAIN_AUCTION_EVENT_TYPE_WINNER_DETERMINED: {
                dap_chain_auction_event_winner_determined_t *l_data = 
                    (dap_chain_auction_event_winner_determined_t*)l_event->event_data;
                if (dap_hash_fast_compare(&l_data->auction_hash, a_auction_hash)) {
                    l_event_matches = true;
                }
                break;
            }
            case DAP_CHAIN_AUCTION_EVENT_TYPE_AUCTION_CANCELLED: {
                dap_chain_auction_event_auction_cancelled_t *l_data = 
                    (dap_chain_auction_event_auction_cancelled_t*)l_event->event_data;
                if (dap_hash_fast_compare(&l_data->auction_hash, a_auction_hash)) {
                    l_event_matches = true;
                }
                break;
            }
            default:
                // Unknown event type
                break;
        }

        if (l_event_matches) {
            // Create a copy of the event for the filtered list
            dap_chain_tx_event_t *l_event_copy = DAP_NEW_Z(dap_chain_tx_event_t);
            if (l_event_copy) {
                *l_event_copy = *l_event;
                l_event_copy->group_name = dap_strdup(l_event->group_name);
                if (l_event->event_data_size > 0) {
                    l_event_copy->event_data = DAP_DUP_SIZE(l_event->event_data, l_event->event_data_size);
                }
                l_filtered_events = dap_list_append(l_filtered_events, l_event_copy);
            }
        }
    }

    // Free the original list
    dap_chain_auction_events_list_free(l_all_events);

    log_it(L_DEBUG, "Filtered %zu events for auction %s", 
           dap_list_length(l_filtered_events), 
           dap_hash_fast_to_str_static(a_auction_hash));

    return l_filtered_events;
}

/**
 * @brief Read auction events by type
 */
dap_list_t* dap_chain_auction_events_read_by_type(dap_chain_net_t *a_net, uint16_t a_event_type)
{
    if (!a_net) {
        log_it(L_ERROR, "Network parameter is NULL");
        return NULL;
    }

    dap_list_t *l_all_events = dap_chain_auction_events_read_all(a_net);
    if (!l_all_events) {
        return NULL;
    }

    dap_list_t *l_filtered_events = NULL;
    
    for (dap_list_t *it = l_all_events; it; it = it->next) {
        dap_chain_tx_event_t *l_event = (dap_chain_tx_event_t*)it->data;
        if (!l_event) {
            continue;
        }

        if (l_event->event_type == a_event_type) {
            // Create a copy of the event for the filtered list
            dap_chain_tx_event_t *l_event_copy = DAP_NEW_Z(dap_chain_tx_event_t);
            if (l_event_copy) {
                *l_event_copy = *l_event;
                l_event_copy->group_name = dap_strdup(l_event->group_name);
                if (l_event->event_data_size > 0) {
                    l_event_copy->event_data = DAP_DUP_SIZE(l_event->event_data, l_event->event_data_size);
                }
                l_filtered_events = dap_list_append(l_filtered_events, l_event_copy);
            }
        }
    }

    // Free the original list
    dap_chain_auction_events_list_free(l_all_events);

    log_it(L_DEBUG, "Filtered %zu events of type %u", 
           dap_list_length(l_filtered_events), a_event_type);

    return l_filtered_events;
}

/**
 * @brief Find specific auction event by transaction hash
 */
dap_chain_tx_event_t* dap_chain_auction_event_find_by_hash(dap_chain_net_t *a_net, dap_hash_fast_t *a_tx_hash)
{
    if (!a_net || !a_tx_hash) {
        log_it(L_ERROR, "Invalid parameters for auction event find");
        return NULL;
    }

    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);
    if (!l_ledger) {
        log_it(L_ERROR, "Cannot find ledger for network %s", a_net->pub.name);
        return NULL;
    }

    // Find specific event by transaction hash
    dap_chain_tx_event_t *l_event = dap_ledger_event_find(l_ledger, a_tx_hash);
    
    // Verify it's an auction event
    if (l_event && l_event->group_name && 
        dap_strcmp(l_event->group_name, DAP_CHAIN_AUCTION_EVENT_GROUP) == 0) {
        log_it(L_DEBUG, "Found auction event by hash %s", 
               dap_hash_fast_to_str_static(a_tx_hash));
        return l_event;
    }

    return NULL;
}

/**
 * @brief Create and add auction event to ledger
 */
int dap_chain_auction_event_add(dap_chain_net_t *a_net, 
                                dap_hash_fast_t *a_tx_hash,
                                dap_hash_fast_t *a_pkey_hash,
                                uint16_t a_event_type,
                                void *a_event_data,
                                size_t a_event_data_size)
{
    if (!a_net || !a_tx_hash || !a_pkey_hash) {
        log_it(L_ERROR, "Invalid parameters for auction event add");
        return -1;
    }

    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);
    if (!l_ledger) {
        log_it(L_ERROR, "Cannot find ledger for network %s", a_net->pub.name);
        return -2;
    }

    // Create new event structure
    dap_chain_tx_event_t *l_event = DAP_NEW_Z(dap_chain_tx_event_t);
    if (!l_event) {
        log_it(L_ERROR, "Failed to allocate memory for auction event");
        return -3;
    }

    // Fill event structure
    l_event->group_name = dap_strdup(DAP_CHAIN_AUCTION_EVENT_GROUP);
    l_event->tx_hash = *a_tx_hash;
    l_event->pkey_hash = *a_pkey_hash;
    l_event->event_type = a_event_type;
    l_event->event_data_size = a_event_data_size;

    // Copy event data if provided
    if (a_event_data && a_event_data_size > 0) {
        l_event->event_data = DAP_DUP_SIZE(a_event_data, a_event_data_size);
        if (!l_event->event_data) {
            DAP_DELETE(l_event->group_name);
            DAP_DELETE(l_event);
            log_it(L_ERROR, "Failed to allocate memory for event data");
            return -4;
        }
    }

    // Add event to ledger
    int l_result = dap_ledger_event_add(l_ledger, l_event);
    
    if (l_result == 0) {
        log_it(L_INFO, "Added auction event type %u for tx %s", 
               a_event_type, dap_hash_fast_to_str_static(a_tx_hash));
    } else {
        log_it(L_ERROR, "Failed to add auction event to ledger, error code %d", l_result);
        // Clean up on failure
        DAP_DEL_Z(l_event->event_data);
        DAP_DELETE(l_event->group_name);
        DAP_DELETE(l_event);
    }

    return l_result;
}

/**
 * @brief Clean up event data structures
 */
void dap_chain_auction_events_list_free(dap_list_t *a_events)
{
    if (!a_events) {
        return;
    }

    for (dap_list_t *it = a_events; it; it = it->next) {
        dap_chain_tx_event_t *l_event = (dap_chain_tx_event_t*)it->data;
        if (l_event) {
            DAP_DEL_Z(l_event->event_data);
            DAP_DEL_Z(l_event->group_name);
            DAP_DELETE(l_event);
        }
    }
    
    dap_list_free(a_events);
}

/**
 * @brief Load auction state from ledger events
 */
int dap_chain_auction_state_load_from_events(dap_chain_net_t *a_net)
{
    if (!a_net) {
        log_it(L_ERROR, "Network parameter is NULL");
        return -1;
    }

    // Read all auction events
    dap_list_t *l_events = dap_chain_auction_events_read_all(a_net);
    if (!l_events) {
        log_it(L_INFO, "No auction events found in ledger for network %s", a_net->pub.name);
        return 0;
    }

    int l_auctions_loaded = 0;
    int l_events_processed = 0;

    // Process each event to rebuild auction state
    for (dap_list_t *it = l_events; it; it = it->next) {
        dap_chain_tx_event_t *l_event = (dap_chain_tx_event_t*)it->data;
        if (!l_event) {
            continue;
        }

        int l_result = dap_chain_auction_event_process(l_event);
        if (l_result == 0) {
            l_events_processed++;
            
            // Count new auctions created
            if (l_event->event_type == DAP_CHAIN_AUCTION_EVENT_TYPE_AUCTION_CREATED) {
                l_auctions_loaded++;
            }
        } else {
            log_it(L_WARNING, "Failed to process auction event type %u, error %d", 
                   l_event->event_type, l_result);
        }
    }

    // Clean up events list
    dap_chain_auction_events_list_free(l_events);

    log_it(L_INFO, "Loaded %d auctions from %d processed events in network %s", 
           l_auctions_loaded, l_events_processed, a_net->pub.name);

    return l_auctions_loaded;
}

/**
 * @brief Process auction event and update state
 */
int dap_chain_auction_event_process(dap_chain_tx_event_t *a_event)
{
    if (!a_event || !a_event->event_data) {
        log_it(L_ERROR, "Invalid event for processing");
        return -1;
    }

    switch (a_event->event_type) {
        case DAP_CHAIN_AUCTION_EVENT_TYPE_AUCTION_CREATED: {
            dap_chain_auction_event_auction_created_t *l_data = 
                (dap_chain_auction_event_auction_created_t*)a_event->event_data;
            
            // Create new auction info structure
            dap_chain_auction_info_t *l_auction = DAP_NEW_Z(dap_chain_auction_info_t);
            if (!l_auction) {
                log_it(L_ERROR, "Failed to allocate memory for auction info");
                return -2;
            }

            // Initialize auction from event data
            l_auction->auction_hash = l_data->auction_hash;
            l_auction->start_time = l_data->start_time;
            l_auction->end_time = l_data->end_time;
            l_auction->is_candle_auction = l_data->is_candle_auction;
            l_auction->is_active = (dap_time_now() < l_data->end_time);
            l_auction->bids = NULL;
            l_auction->winning_bid = NULL;

            // Initialize lock
            if (pthread_rwlock_init(&l_auction->lock, NULL) != 0) {
                DAP_DELETE(l_auction);
                log_it(L_ERROR, "Failed to initialize auction lock");
                return -3;
            }

            // Add to global storage
            pthread_rwlock_wrlock(&s_auction_storage.auctions_lock);
            HASH_ADD(hh, s_auction_storage.auctions, auction_hash, sizeof(dap_hash_fast_t), l_auction);
            s_auction_storage.total_auctions++;
            if (l_auction->is_active) {
                s_auction_storage.active_auctions++;
            }
            pthread_rwlock_unlock(&s_auction_storage.auctions_lock);

            log_it(L_DEBUG, "Created auction from event: %s", 
                   dap_hash_fast_to_str_static(&l_data->auction_hash));
            break;
        }

        case DAP_CHAIN_AUCTION_EVENT_TYPE_BID_PLACED: {
            dap_chain_auction_event_bid_placed_t *l_data = 
                (dap_chain_auction_event_bid_placed_t*)a_event->event_data;
            
            // Find the auction
            dap_chain_auction_info_t *l_auction = dap_chain_auction_find_by_hash(
                &l_data->auction_hash, (dap_chain_net_id_t){0}); // Network ID will be set by find function
            
            if (!l_auction) {
                log_it(L_WARNING, "Auction %s not found for bid event", 
                       dap_hash_fast_to_str_static(&l_data->auction_hash));
                return -4;
            }

            // Create bid info structure
            dap_chain_auction_bid_info_t *l_bid_info = DAP_NEW_Z(dap_chain_auction_bid_info_t);
            if (!l_bid_info) {
                log_it(L_ERROR, "Failed to allocate memory for bid info");
                return -5;
            }

            // Fill bid info from event data
            l_bid_info->bid_hash = l_data->bid_hash;
            l_bid_info->auction_hash = l_data->auction_hash;
            l_bid_info->bidder_hash = l_data->bidder_hash;
            l_bid_info->range_start = l_data->range_start;
            l_bid_info->range_end = l_data->range_end;
            l_bid_info->bid_amount = l_data->bid_amount;
            l_bid_info->lock_time = l_data->lock_time;
            l_bid_info->score = l_data->score;
            l_bid_info->timestamp = l_data->timestamp;
            l_bid_info->is_valid = true;

            // Add bid to auction
            int l_add_result = dap_chain_auction_add_bid(l_auction, l_bid_info);
            if (l_add_result != DAP_CHAIN_AUCTION_BID_OK) {
                DAP_DELETE(l_bid_info);
                log_it(L_WARNING, "Failed to add bid from event, error %d", l_add_result);
                return -6;
            }

            log_it(L_DEBUG, "Added bid from event: %s score %"PRIu64, 
                   dap_hash_fast_to_str_static(&l_data->bid_hash), l_data->score);
            break;
        }

        case DAP_CHAIN_AUCTION_EVENT_TYPE_AUCTION_ENDED: {
            dap_chain_auction_event_auction_ended_t *l_data = 
                (dap_chain_auction_event_auction_ended_t*)a_event->event_data;
            
            // Find the auction
            dap_chain_auction_info_t *l_auction = dap_chain_auction_find_by_hash(
                &l_data->auction_hash, (dap_chain_net_id_t){0});
            
            if (l_auction) {
                pthread_rwlock_wrlock(&l_auction->lock);
                l_auction->is_active = false;
                l_auction->actual_end_time = l_data->end_time;
                pthread_rwlock_unlock(&l_auction->lock);

                // Update global counter
                pthread_rwlock_wrlock(&s_auction_storage.auctions_lock);
                if (s_auction_storage.active_auctions > 0) {
                    s_auction_storage.active_auctions--;
                }
                pthread_rwlock_unlock(&s_auction_storage.auctions_lock);

                log_it(L_DEBUG, "Marked auction as ended: %s", 
                       dap_hash_fast_to_str_static(&l_data->auction_hash));
            }
            break;
        }

        case DAP_CHAIN_AUCTION_EVENT_TYPE_WINNER_DETERMINED: {
            dap_chain_auction_event_winner_determined_t *l_data = 
                (dap_chain_auction_event_winner_determined_t*)a_event->event_data;
            
            // Find the auction
            dap_chain_auction_info_t *l_auction = dap_chain_auction_find_by_hash(
                &l_data->auction_hash, (dap_chain_net_id_t){0});
            
            if (l_auction) {
                // Find the winning bid
                pthread_rwlock_rdlock(&l_auction->lock);
                for (dap_list_t *it = l_auction->bids; it; it = it->next) {
                    dap_chain_auction_bid_info_t *l_bid = (dap_chain_auction_bid_info_t*)it->data;
                    if (dap_hash_fast_compare(&l_bid->bid_hash, &l_data->winning_bid_hash)) {
                        l_auction->winning_bid = l_bid;
                        break;
                    }
                }
                pthread_rwlock_unlock(&l_auction->lock);

                log_it(L_DEBUG, "Set auction winner: %s", 
                       dap_hash_fast_to_str_static(&l_data->winning_bid_hash));
            }
            break;
        }

        case DAP_CHAIN_AUCTION_EVENT_TYPE_AUCTION_CANCELLED: {
            dap_chain_auction_event_auction_cancelled_t *l_data = 
                (dap_chain_auction_event_auction_cancelled_t*)a_event->event_data;
            
            // Find the auction
            dap_chain_auction_info_t *l_auction = dap_chain_auction_find_by_hash(
                &l_data->auction_hash, (dap_chain_net_id_t){0});
            
            if (l_auction) {
                pthread_rwlock_wrlock(&l_auction->lock);
                l_auction->is_active = false;
                pthread_rwlock_unlock(&l_auction->lock);

                // Update global counter
                pthread_rwlock_wrlock(&s_auction_storage.auctions_lock);
                if (s_auction_storage.active_auctions > 0) {
                    s_auction_storage.active_auctions--;
                }
                pthread_rwlock_unlock(&s_auction_storage.auctions_lock);

                log_it(L_DEBUG, "Marked auction as cancelled: %s", 
                       dap_hash_fast_to_str_static(&l_data->auction_hash));
            }
            break;
        }

        default:
            log_it(L_WARNING, "Unknown auction event type %u", a_event->event_type);
            return -7;
    }

    return 0;
}

/**
 * @brief Get auction information from events
 */
dap_chain_auction_info_t* dap_chain_auction_info_from_events(dap_chain_net_t *a_net, dap_hash_fast_t *a_auction_hash)
{
    if (!a_net || !a_auction_hash) {
        log_it(L_ERROR, "Invalid parameters for auction info from events");
        return NULL;
    }

    // Read events for this specific auction
    dap_list_t *l_events = dap_chain_auction_events_read_by_auction(a_net, a_auction_hash);
    if (!l_events) {
        log_it(L_DEBUG, "No events found for auction %s", 
               dap_hash_fast_to_str_static(a_auction_hash));
        return NULL;
    }

    dap_chain_auction_info_t *l_auction = NULL;

    // Process events to build auction info
    for (dap_list_t *it = l_events; it; it = it->next) {
        dap_chain_tx_event_t *l_event = (dap_chain_tx_event_t*)it->data;
        if (!l_event) {
            continue;
        }

        // Process this single event (it will update global state)
        dap_chain_auction_event_process(l_event);
    }

    // Clean up events
    dap_chain_auction_events_list_free(l_events);

    // Now retrieve the reconstructed auction
    l_auction = dap_chain_auction_find_by_hash(a_auction_hash, (dap_chain_net_id_t){0});

    if (l_auction) {
        log_it(L_INFO, "Reconstructed auction info for %s from events", 
               dap_hash_fast_to_str_static(a_auction_hash));
    }

    return l_auction;
}

/**
 * @brief Create a new auction bid transaction
 * 
 * This function creates a bid transaction for an existing auction.
 * The bid includes the auction hash, bid amount, and CellSlot range.
 * 
 * @param a_net Chain network
 * @param a_wallet Wallet for fee payment
 * @param a_auction_hash Hash of the auction to bid on
 * @param a_bid_amount Amount to bid (in datoshi)
 * @param a_range_start Start of CellSlot range (1-8)
 * @param a_range_end End of CellSlot range (1-8)
 * @param a_fee Transaction fee
 * @param a_hash_out_type Output hash format ("hex" or "base58")
 * @param a_hash_tx_out Output transaction hash string
 * @return 0 on success, negative error code on failure
 */
int dap_chain_net_auction_bid_create(dap_chain_net_t *a_net,
                                     dap_chain_wallet_t *a_wallet,
                                     dap_hash_fast_t a_auction_hash,
                                     uint256_t a_bid_amount,
                                     uint8_t a_range_start,
                                     uint8_t a_range_end,
                                     uint256_t a_fee,
                                     const char *a_hash_out_type,
                                     char **a_hash_tx_out)
{
    if (!a_net || !a_wallet || !a_hash_tx_out) {
        log_it(L_ERROR, "Invalid parameters for bid creation");
        return DAP_CHAIN_NET_AUCTIONS_ERROR_INVALID_PARAMS;
    }

    // Validate bid parameters
    int l_ret = dap_chain_auction_bid_validate_params(a_range_start, a_range_end, a_bid_amount);
    if (l_ret != DAP_CHAIN_NET_AUCTIONS_OK) {
        return l_ret;
    }

    // Calculate bid score for logging
    dap_chain_auction_bid_score_params_t l_score_params = {
        .range_start = a_range_start,
        .range_end = a_range_end,
        .bid_amount = a_bid_amount
    };
    uint256_t l_calculated_score;
    dap_chain_auction_bid_calculate_score(&l_score_params, &l_calculated_score);

    log_it(L_INFO, "Creating auction bid: auction=%s, amount=%s, range=%u-%u, score=%s",
           dap_hash_fast_to_str_static(&a_auction_hash),
           dap_uint256_decimal_to_char(a_bid_amount),
           a_range_start, a_range_end,
           dap_uint256_decimal_to_char(l_calculated_score));

    // TODO: Implement transaction creation
    // This will be implemented in the next phase
    // For now, return success with placeholder
    
    *a_hash_tx_out = dap_strdup("0x1234567890abcdef"); // Placeholder
    
    log_it(L_INFO, "Auction bid created successfully with hash: %s", *a_hash_tx_out);
    return DAP_CHAIN_NET_AUCTIONS_OK;
}

/**
 * @brief Read auction events from ledger
 * @param a_net Chain network
 * @param a_auction_hash Auction hash to read events for (or NULL for all)
 * @return List of auction events, NULL on error
 */
dap_list_t *dap_chain_auction_events_read(dap_chain_net_t *a_net, dap_hash_fast_t *a_auction_hash)
{
    if (!a_net) {
        log_it(L_ERROR, "Invalid network parameter");
        return NULL;
    }

    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);
    if (!l_ledger) {
        log_it(L_ERROR, "Cannot find ledger for network %s", a_net->pub.name);
        return NULL;
    }

    // Read events from ledger using auction event group
    dap_list_t *l_events = dap_ledger_event_get_list(l_ledger, DAP_CHAIN_AUCTIONS_EVENT_GROUP);
    
    log_it(L_INFO, "Read %d auction events from ledger", dap_list_length(l_events));
    return l_events;
}

/**
 * @brief Find auction information by hash
 * @param a_auction_hash Hash of the auction
 * @return Auction info structure or NULL if not found
 */
dap_chain_auction_info_t *dap_chain_auction_find(dap_hash_fast_t a_auction_hash)
{
    pthread_rwlock_rdlock(&s_auctions_storage.auctions_rwlock);
    
    dap_chain_auction_info_t *l_auction = NULL;
    HASH_FIND(hh, s_auctions_storage.auctions, &a_auction_hash, sizeof(dap_hash_fast_t), l_auction);
    
    pthread_rwlock_unlock(&s_auctions_storage.auctions_rwlock);
    
    return l_auction;
}

/**
 * @brief Determine auction winner by calculating highest score
 * @param a_auction_info Auction information structure
 * @return 0 on success, negative error code on failure
 */
int dap_chain_auction_determine_winner(dap_chain_auction_info_t *a_auction_info)
{
    if (!a_auction_info) {
        return DAP_CHAIN_NET_AUCTIONS_ERROR_INVALID_PARAMS;
    }

    pthread_rwlock_rdlock(&a_auction_info->bids_rwlock);
    
    dap_chain_auction_bid_t *l_current_bid = a_auction_info->bids;
    dap_chain_auction_bid_t *l_winner_bid = NULL;
    uint256_t l_highest_score = uint256_from_uint64(0);

    // Iterate through all bids to find the highest score
    while (l_current_bid) {
        if (compare_256(l_current_bid->calculated_score, l_highest_score) > 0) {
            l_highest_score = l_current_bid->calculated_score;
            l_winner_bid = l_current_bid;
        }
        l_current_bid = l_current_bid->next;
    }

    if (l_winner_bid) {
        a_auction_info->winner_bid_hash = l_winner_bid->bid_hash;
        a_auction_info->winning_score = l_highest_score;
        
        log_it(L_INFO, "Auction winner determined: bid_hash=%s, score=%s",
               dap_hash_fast_to_str_static(&l_winner_bid->bid_hash),
               dap_uint256_decimal_to_char(l_highest_score));
    }

    pthread_rwlock_unlock(&a_auction_info->bids_rwlock);
    
    return l_winner_bid ? DAP_CHAIN_NET_AUCTIONS_OK : DAP_CHAIN_NET_AUCTIONS_ERROR_AUCTION_NOT_FOUND;
}

/**
 * @brief Clean up auction bid structure
 * @param a_bid Bid structure to clean up
 */
void dap_chain_auction_bid_free(dap_chain_auction_bid_t *a_bid)
{
    if (a_bid) {
        DAP_DELETE(a_bid);
    }
}

/**
 * @brief Clean up auction info structure
 * @param a_auction_info Auction info structure to clean up
 */
void dap_chain_auction_info_free(dap_chain_auction_info_t *a_auction_info)
{
    if (!a_auction_info) {
        return;
    }

    // Clean up all bids
    dap_chain_auction_bid_t *l_bid = a_auction_info->bids;
    while (l_bid) {
        dap_chain_auction_bid_t *l_next = l_bid->next;
        dap_chain_auction_bid_free(l_bid);
        l_bid = l_next;
    }

    pthread_rwlock_destroy(&a_auction_info->bids_rwlock);
    DAP_DELETE(a_auction_info);
}

/**
 * @brief Tag check function for auction transactions
 * @param a_ledger Ledger instance
 * @param a_tx Transaction to check
 * @param a_items_grp Transaction item groups
 * @param a_action Output action type
 * @return true if transaction is auction-related
 */
static bool s_tag_check_auctions(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, 
                                 dap_chain_datum_tx_item_groups_t *a_items_grp, 
                                 dap_chain_tx_tag_action_type_t *a_action)
{
    // TODO: Implement proper auction transaction detection
    // For now, return false as we focus on bid scoring logic
    return false;
}

/**
 * @brief CLI command handler for auction operations
 * @param argc Argument count
 * @param argv Argument values
 * @param a_str_reply Reply string
 * @param a_version Version
 * @return 0 on success, negative on error
 */
static int s_cli_auctions(int argc, char **argv, void **a_str_reply, int a_version)
{
    // TODO: Implement CLI commands for auction operations
    // For now, return error
    if (a_str_reply) {
        *a_str_reply = dap_strdup("Auction CLI not yet implemented");
    }
    return -1;
} 

/**
 * @brief dap_chain_auction_bid_verificator
 * Verificator callback function for auction bid conditional transactions
 * Validates auction bid parameters according to Cellframe auction rules
 * 
 * @param a_ledger Ledger instance
 * @param a_cond Conditional output being validated
 * @param a_tx_in Input transaction
 * @param a_owner Whether this transaction is from the owner
 * @return 0 on success, negative error code on failure
 */
static int dap_chain_auction_bid_verificator(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_cond,
                                             dap_chain_datum_tx_t *a_tx_in, bool a_owner)
{
    if (!a_ledger || !a_cond || !a_tx_in) {
        log_it(L_ERROR, "Invalid arguments to auction bid verificator");
        return DAP_CHAIN_AUCTION_BID_VERIFICATOR_INVALID_ARGS;
    }

    // Verify this is an auction bid conditional transaction
    if (a_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID) {
        log_it(L_ERROR, "Wrong subtype for auction bid verificator: %d", a_cond->header.subtype);
        return DAP_CHAIN_AUCTION_BID_VERIFICATOR_WRONG_SUBTYPE;
    }

    // Verify service UID matches auction service
    if (!dap_chain_net_srv_uid_compare(a_cond->header.srv_uid, DAP_CHAIN_NET_SRV_AUCTIONS_ID)) {
        log_it(L_ERROR, "Wrong service UID for auction bid: expected 0x%x, got 0x%x", 
               DAP_CHAIN_NET_SRV_AUCTIONS_ID.uint64, a_cond->header.srv_uid.uint64);
        return DAP_CHAIN_AUCTION_BID_VERIFICATOR_WRONG_SERVICE;
    }

    // Extract auction bid data from conditional transaction
    dap_hash_fast_t *l_auction_hash = &a_cond->subtype.srv_auction_bid.auction_hash;
    uint8_t l_range_end = a_cond->subtype.srv_auction_bid.range_end;
    dap_time_t l_lock_time = a_cond->subtype.srv_auction_bid.lock_time;
    uint256_t l_bid_amount = a_cond->header.value;

    // Parse TSD section for additional auction bid data
    dap_chain_auction_bid_tsd_t *l_bid_tsd = NULL;
    if (a_cond->tsd_size >= sizeof(dap_chain_auction_bid_tsd_t)) {
        l_bid_tsd = (dap_chain_auction_bid_tsd_t*)a_cond->tsd;
        
        // Verify TSD data consistency with conditional transaction data
        if (!dap_hash_fast_compare(&l_bid_tsd->auction_hash, l_auction_hash)) {
            log_it(L_ERROR, "Auction hash mismatch between conditional data and TSD");
            return DAP_CHAIN_AUCTION_BID_VERIFICATOR_TSD_MISMATCH;
        }
        if (l_bid_tsd->range_end != l_range_end) {
            log_it(L_ERROR, "Range end mismatch between conditional data and TSD: %d vs %d", 
                   l_range_end, l_bid_tsd->range_end);
            return DAP_CHAIN_AUCTION_BID_VERIFICATOR_TSD_MISMATCH;
        }
        if (l_bid_tsd->lock_time != l_lock_time) {
            log_it(L_ERROR, "Lock time mismatch between conditional data and TSD");
            return DAP_CHAIN_AUCTION_BID_VERIFICATOR_TSD_MISMATCH;
        }
        if (!EQUAL_256(l_bid_tsd->bid_amount, l_bid_amount)) {
            log_it(L_ERROR, "Bid amount mismatch between conditional data and TSD");
            return DAP_CHAIN_AUCTION_BID_VERIFICATOR_TSD_MISMATCH;
        }
    }

    // Validate auction bid parameters according to Cellframe rules
    int l_validation_result = dap_chain_auction_bid_validate_params(l_range_end, l_bid_amount, l_lock_time);
    if (l_validation_result != 0) {
        const char *l_error_msg = "";
        switch (l_validation_result) {
            case DAP_CHAIN_AUCTION_BID_ERROR_INVALID_RANGE:
                l_error_msg = "Range end must be between 1 and 8";
                break;
            case DAP_CHAIN_AUCTION_BID_ERROR_AMOUNT_TOO_LOW:
                l_error_msg = "Bid amount too low for the specified range";
                break;
            case DAP_CHAIN_AUCTION_BID_ERROR_AMOUNT_TOO_HIGH:
                l_error_msg = "Bid amount too high (maximum 250,000 CELL for 2 years)";
                break;
            case DAP_CHAIN_AUCTION_BID_ERROR_LOCK_TIME_TOO_SHORT:
                l_error_msg = "Lock time too short (minimum 3 months)";
                break;
            case DAP_CHAIN_AUCTION_BID_ERROR_LOCK_TIME_TOO_LONG:
                l_error_msg = "Lock time too long (maximum 2 years)";
                break;
            default:
                l_error_msg = "Unknown validation error";
                break;
        }
        log_it(L_ERROR, "Auction bid validation failed: %s (error code %d)", l_error_msg, l_validation_result);
        return DAP_CHAIN_AUCTION_BID_VERIFICATOR_INVALID_PARAMS;
    }

    // Verify the auction exists and is active
    if (dap_hash_fast_is_blank(l_auction_hash)) {
        log_it(L_ERROR, "Blank auction hash in bid");
        return DAP_CHAIN_AUCTION_BID_VERIFICATOR_BLANK_AUCTION_HASH;
    }

    // TODO: Add auction existence and status verification when auction creation is implemented
    // For now, we assume the auction hash is valid if it's not blank

    // Verify bid amount matches transaction value
    if (!EQUAL_256(l_bid_amount, a_cond->header.value)) {
        log_it(L_ERROR, "Bid amount does not match transaction value");
        return DAP_CHAIN_AUCTION_BID_VERIFICATOR_VALUE_MISMATCH;
    }

    // Verify token is CELL (native token)
    const char *l_native_ticker = a_ledger->net->pub.native_ticker;
    if (!l_native_ticker || strcmp(l_native_ticker, "CELL") != 0) {
        log_it(L_ERROR, "Auction bids must use CELL token, got: %s", l_native_ticker ? l_native_ticker : "NULL");
        return DAP_CHAIN_AUCTION_BID_VERIFICATOR_WRONG_TOKEN;
    }

    // Check for duplicate bids (owner can't bid multiple times on same auction)
    // Get transaction signature to identify bidder
    dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    if (!l_tx_sig) {
        log_it(L_ERROR, "No signature found in auction bid transaction");
        return DAP_CHAIN_AUCTION_BID_VERIFICATOR_NO_SIGNATURE;
    }

    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
    if (!l_sign) {
        log_it(L_ERROR, "Cannot extract signature from transaction");
        return DAP_CHAIN_AUCTION_BID_VERIFICATOR_INVALID_SIGNATURE;
    }

    dap_hash_fast_t l_bidder_pkey_hash = {};
    if (!dap_sign_get_pkey_hash(l_sign, &l_bidder_pkey_hash)) {
        log_it(L_ERROR, "Cannot extract public key hash from signature");
        return DAP_CHAIN_AUCTION_BID_VERIFICATOR_INVALID_SIGNATURE;
    }

    // TODO: Check for duplicate bids from same bidder on same auction
    // This would require scanning the ledger for existing bids from this bidder
    // For now, we allow multiple bids from the same bidder (last one wins)

    log_it(L_INFO, "Auction bid validation successful: range_end=%d, amount=%s, lock_time=%lu", 
           l_range_end, dap_uint256_to_char(l_bid_amount, NULL), l_lock_time);

    return 0; // Validation successful
} 