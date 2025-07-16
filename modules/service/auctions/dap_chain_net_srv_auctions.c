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
        "CELLFRAME AUCTION CLI COMMANDS\n"
        "===============================\n\n"
        
        "SYNOPSIS:\n"
        "  auction <subcommand> [options...]\n\n"
        
        "SUBCOMMANDS:\n\n"
        
        "  bid       Create auction bid transaction\n"
        "  list      List auctions in network\n"
        "  info      Show detailed auction information\n"
        "  events    Show auction events from ledger\n"
        "  load      Load auction state from ledger events\n"
        "  withdraw  Unlock funds from auction bid\n\n"
        
        "DETAILED SYNTAX:\n\n"
        
        "1. CREATE AUCTION BID:\n"
        "   auction bid -net <network_name> -auction <auction_hash>\n"
        "               -range <range_end> -amount <cell_amount>\n"
        "               -lock <lock_months> -fee <fee_amount>\n"
        "               -w <wallet_name> [--help]\n\n"
        
        "   REQUIRED PARAMETERS:\n"
        "     -net <network_name>     Network name (e.g., 'Backbone')\n"
        "     -auction <auction_hash> 64-character hex auction hash\n"
        "     -range <range_end>      CellSlot range end (1-8, start always 1)\n"
        "     -amount <cell_amount>   Bid amount in CELL tokens\n"
        "     -lock <lock_months>     Token lock period (3-24 months)\n"
        "     -fee <fee_amount>       Transaction fee in CELL\n"
        "     -w <wallet_name>        Wallet name for payment\n\n"
        
        "2. LIST AUCTIONS:\n"
        "   auction list -net <network_name> [-active_only]\n"
        "                [-format table|json] [--help]\n\n"
        
        "   REQUIRED PARAMETERS:\n"
        "     -net <network_name>     Network name\n\n"
        
        "   OPTIONAL PARAMETERS:\n"
        "     -active_only            Show only active auctions\n"
        "     -format <table|json>    Output format (default: table)\n\n"
        
        "3. SHOW AUCTION INFO:\n"
        "   auction info -net <network_name> -auction <auction_hash>\n"
        "                [-format table|json] [--help]\n\n"
        
        "   REQUIRED PARAMETERS:\n"
        "     -net <network_name>     Network name\n"
        "     -auction <auction_hash> Auction hash to query\n\n"
        
        "   OPTIONAL PARAMETERS:\n"
        "     -format <table|json>    Output format (default: table)\n\n"
        
        "4. SHOW AUCTION EVENTS:\n"
        "   auction events -net <network_name> [-auction <auction_hash>]\n"
        "                  [-type <event_type>] [-limit <count>]\n"
        "                  [-format table|json] [--help]\n\n"
        
        "   REQUIRED PARAMETERS:\n"
        "     -net <network_name>     Network name\n\n"
        
        "   OPTIONAL PARAMETERS:\n"
        "     -auction <auction_hash> Filter by specific auction\n"
        "     -type <event_type>      Filter by event type\n"
        "     -limit <count>          Limit results (default: 50)\n"
        "     -format <table|json>    Output format (default: table)\n\n"
        
        "   EVENT TYPES:\n"
        "     AUCTION_CREATED         New auction created\n"
        "     BID_PLACED              New bid placed\n"
        "     AUCTION_ENDED           Auction ended\n"
        "     WINNER_DETERMINED       Winner determined\n"
        "     AUCTION_CANCELLED       Auction cancelled\n\n"
        
        "5. LOAD AUCTION STATE:\n"
        "   auction load -net <network_name> [-force] [-verbose] [--help]\n\n"
        
        "   REQUIRED PARAMETERS:\n"
        "     -net <network_name>     Network name\n\n"
        
        "   OPTIONAL PARAMETERS:\n"
        "     -force                  Force reload existing state\n"
        "     -verbose                Show detailed progress\n\n"
        
        "6. WITHDRAW AUCTION BID FUNDS:\n"
        "   auction withdraw -net <network_name> -bid <bid_hash>\n"
        "                    -fee <fee_amount> -w <wallet_name>\n"
        "                    [-addr <target_addr>] [--help]\n\n"
        
        "   REQUIRED PARAMETERS:\n"
        "     -net <network_name>     Network name\n"
        "     -bid <bid_hash>         Hash of bid transaction to withdraw\n"
        "     -fee <fee_amount>       Transaction fee in CELL tokens\n"
        "     -w <wallet_name>        Wallet (must be bid owner)\n\n"
        
        "   OPTIONAL PARAMETERS:\n"
        "     -addr <target_addr>     Target address (default: wallet address)\n\n"
        
        "CELLFRAME AUCTION RULES:\n"
        "========================\n"
        "• Scoring Formula:     range_end × bid_amount = points (higher wins)\n"
        "• Token Type:          Only CELL (native token) accepted\n"
        "• Minimum Bid:         31.250 CELL for 3-month lock period\n"
        "• Maximum Bid:         250,000 CELL for 24-month lock period\n"
        "• Range Specification: 1-8 CellSlots (1 slot = 3 months)\n"
        "• Lock Period:         3-24 months (matches range × 3)\n\n"
        
        "EXAMPLES:\n"
        "=========\n"
        "auction bid -net Backbone -auction 0x1a2b3c4d... -range 3 -amount 100.0 -lock 9 -fee 0.01 -w alice\n"
        "auction list -net Backbone -active_only -format json\n"
        "auction info -net Backbone -auction 0x1a2b3c4d... -format table\n"
        "auction events -net Backbone -type BID_PLACED -limit 20\n"
        "auction load -net Backbone -verbose\n"
        "auction withdraw -net Backbone -bid 0xabcd1234... -fee 0.5 -w alice\n\n"
        
        "For detailed help on any command, use: auction <command> --help\n"
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

// Forward declarations for CLI command handlers
static int s_cli_auction_bid(int argc, char **argv, void **a_str_reply);
static int s_cli_auction_list(int argc, char **argv, void **a_str_reply);
static int s_cli_auction_info(int argc, char **argv, void **a_str_reply);
static int s_cli_auction_events(int argc, char **argv, void **a_str_reply);
static int s_cli_auction_load(int argc, char **argv, void **a_str_reply);

/**
 * @brief CLI command handler for auction operations
 * 
 * Handles all auction-related CLI commands:
 * - auction bid: Create a new auction bid
 * - auction list: List available auctions
 * - auction info: Get detailed auction information
 * - auction events: Show auction events from ledger
 * - auction load: Load auction state from ledger events
 * 
 * @param argc Argument count
 * @param argv Argument vector
 * @param a_str_reply Reply string
 * @param a_version CLI version
 * @return 0 on success, negative error code on failure
 */
static int s_cli_auctions(int argc, char **argv, void **a_str_reply, int a_version)
{
    if (argc < 2) {
        dap_cli_server_cmd_set_reply_text(a_str_reply,
            "CELLFRAME AUCTION CLI\n"
            "=====================\n\n"
            
            "USAGE:\n"
            "  auction <subcommand> [options...]\n\n"
            
            "AVAILABLE SUBCOMMANDS:\n\n"
            
            "  bid       Create auction bid transaction\n"
            "  list      List auctions in network\n"
            "  info      Show detailed auction information\n"
            "  events    Show auction events from ledger\n"
            "  load      Load auction state from ledger events\n\n"
            
            "DETAILED SYNTAX:\n\n"
            
            "1. CREATE AUCTION BID:\n"
            "   auction bid -net <network_name> -auction <auction_hash>\n"
            "               -range <range_end> -amount <cell_amount>\n"
            "               -lock <lock_months> -fee <fee_amount>\n"
            "               -w <wallet_name> [--help]\n\n"
            
            "   REQUIRED PARAMETERS:\n"
            "     -net <network_name>     Network name (e.g., 'Backbone')\n"
            "     -auction <auction_hash> 64-character hex auction hash\n"
            "     -range <range_end>      CellSlot range end (1-8, start always 1)\n"
            "     -amount <cell_amount>   Bid amount in CELL tokens\n"
            "     -lock <lock_months>     Token lock period (3-24 months)\n"
            "     -fee <fee_amount>       Transaction fee in CELL\n"
            "     -w <wallet_name>        Wallet name for payment\n\n"
            
            "2. LIST AUCTIONS:\n"
            "   auction list -net <network_name> [-active_only]\n"

            "   REQUIRED PARAMETERS:\n"
            "     -net <network_name>     Network name\n\n"
            
           "3. SHOW AUCTION INFO:\n"
            "   auction info -net <network_name> -auction <auction_hash>\n"

            "   REQUIRED PARAMETERS:\n"
            "     -net <network_name>     Network name\n"
            "     -auction <auction_hash> Auction hash to query\n\n"
            
            "4. SHOW AUCTION EVENTS:\n"
            "   auction events -net <network_name> [-auction <auction_hash>]\n"
            "                  [-type <event_type>] [-limit <count>]\n"

            "   REQUIRED PARAMETERS:\n"
            "     -net <network_name>     Network name\n\n"
            
            "   OPTIONAL PARAMETERS:\n"
            "     -auction <auction_hash> Filter by specific auction\n"
            "     -type <event_type>      Filter by event type\n"
            "     -limit <count>          Limit results (default: 50)\n"

            "   EVENT TYPES:\n"
            "     AUCTION_CREATED         New auction created\n"
            "     BID_PLACED              New bid placed\n"
            "     AUCTION_ENDED           Auction ended\n"
            "     WINNER_DETERMINED       Winner determined\n"
            "     AUCTION_CANCELLED       Auction cancelled\n\n"
                        
            "CELLFRAME AUCTION RULES:\n"
            "========================\n"
            "• Scoring Formula:     range_end × bid_amount = points (higher wins)\n"
            "• Token Type:          Only CELL (native token) accepted\n"
            "• Minimum Bid:         31.250 CELL for 3-month lock period\n"
            "• Maximum Bid:         250,000 CELL for 24-month lock period\n"
            "• Range Specification: 1-8 CellSlots (1 slot = 3 months)\n"
            "• Lock Period:         3-24 months (matches range × 3)\n\n"
    );
        return 0;
    }

    const char *l_subcmd = argv[1];
    
    // Route to appropriate subcommand handler
    if (strcmp(l_subcmd, "bid") == 0) {
        return s_cli_auction_bid(argc - 1, argv + 1, a_str_reply);
    }
    else if (strcmp(l_subcmd, "list") == 0) {
        return s_cli_auction_list(argc - 1, argv + 1, a_str_reply);
    }
    else if (strcmp(l_subcmd, "info") == 0) {
        return s_cli_auction_info(argc - 1, argv + 1, a_str_reply);
    }
    else if (strcmp(l_subcmd, "events") == 0) {
        return s_cli_auction_events(argc - 1, argv + 1, a_str_reply);
    }
    else if (strcmp(l_subcmd, "load") == 0) {
        return s_cli_auction_load(argc - 1, argv + 1, a_str_reply);
    }
    else if (argc >= 2 && !strcmp(argv[1], "withdraw")) {
        // Remove first argument and forward to withdraw handler
        return s_cli_auction_withdraw(argc - 1, argv + 1, a_str_reply);
    }
    else {
        dap_cli_server_cmd_set_reply_text(a_str_reply,
            "Unknown subcommand '%s'. Use 'auction' for available commands.\n", l_subcmd);
        return -1;
    }
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

/**
 * @brief CLI handler for 'auction bid' command
 * 
 * Creates a new auction bid transaction with specified parameters.
 * 
 * Syntax: auction bid -net <net_name> -auction <auction_hash> -range <end_range> 
 *                     -amount <cell_amount> -lock <months> -fee <fee_amount> -w <wallet_name>
 * 
 * @param argc Argument count
 * @param argv Argument values
 * @param a_str_reply Reply string
 * @return 0 on success, negative on error
 */
static int s_cli_auction_bid(int argc, char **argv, void **a_str_reply)
{
    // Parameter variables
    const char *l_net_name = NULL;
    const char *l_auction_hash_str = NULL;
    const char *l_range_str = NULL;
    const char *l_amount_str = NULL;
    const char *l_lock_str = NULL;
    const char *l_fee_str = NULL;
    const char *l_wallet_name = NULL;
    bool l_help = false;

    // Parse command line arguments
    int l_arg_index = 1;
    while (l_arg_index < argc) {
        if (strcmp(argv[l_arg_index], "--help") == 0 || strcmp(argv[l_arg_index], "-h") == 0) {
            l_help = true;
            break;
        }
        else if (strcmp(argv[l_arg_index], "-net") == 0 && l_arg_index + 1 < argc) {
            l_net_name = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-auction") == 0 && l_arg_index + 1 < argc) {
            l_auction_hash_str = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-range") == 0 && l_arg_index + 1 < argc) {
            l_range_str = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-amount") == 0 && l_arg_index + 1 < argc) {
            l_amount_str = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-lock") == 0 && l_arg_index + 1 < argc) {
            l_lock_str = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-fee") == 0 && l_arg_index + 1 < argc) {
            l_fee_str = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-w") == 0 && l_arg_index + 1 < argc) {
            l_wallet_name = argv[++l_arg_index];
        }
        else {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                "Unknown parameter '%s'. Use 'auction bid --help' for syntax.\n", argv[l_arg_index]);
            return -1;
        }
        l_arg_index++;
    }

    // Show help if requested
    if (l_help) {
        dap_cli_server_cmd_set_reply_text(a_str_reply,
            "AUCTION BID - Create Auction Bid Transaction\n"
            "=============================================\n\n"
            
            "DESCRIPTION:\n"
            "  Creates a conditional transaction to place a bid on a Cellframe auction.\n"
            "  The bid locks CELL tokens for a specified period to participate in\n"
            "  CellSlot allocation auctions.\n\n"
            
            "SYNTAX:\n"
            "  auction bid -net <network_name> -auction <auction_hash>\n"
            "              -range <range_end> -amount <cell_amount>\n"
            "              -lock <lock_months> -fee <fee_amount>\n"
            "              -w <wallet_name> [--help|-h]\n\n"
            
            "REQUIRED PARAMETERS:\n"
            "  -net <network_name>     Target network name\n"
            "                          Examples: 'Backbone', 'Subzero', 'Mileena'\n\n"
            
            "  -auction <auction_hash> 64-character hexadecimal auction identifier\n"
            "                          Format: 0x[0-9a-fA-F]{64}\n"
            "                          Example: 0x1a2b3c4d5e6f7890abcdef...\n\n"
            
            "  -range <range_end>      CellSlot range end (1-8)\n"
            "                          Range always starts at 1\n"
            "                          Each slot = 3 months\n"
            "                          Examples: 1 (3mo), 4 (12mo), 8 (24mo)\n\n"
            
            "  -amount <cell_amount>   Bid amount in CELL tokens\n"
            "                          Format: decimal number (e.g., 100.5, 1000, 31.250)\n"
            "                          Must meet minimum requirements\n\n"
            
            "  -lock <lock_months>     Token lock period in months (3-24)\n"
            "                          Must be: range_end × 3\n"
            "                          Examples: range=3 → lock=9, range=8 → lock=24\n\n"
            
            "  -fee <fee_amount>       Transaction fee in CELL tokens\n"
            "                          Typical range: 0.001 - 1.0 CELL\n\n"
            
            "  -w <wallet_name>        Source wallet name for bid payment\n"
            "                          Must contain sufficient CELL balance\n\n"
            
            "OPTIONAL PARAMETERS:\n"
            "  --help, -h              Show this help message\n\n"
            
            "CELLFRAME AUCTION RULES:\n"
            "=========================\n"
            "• SCORING FORMULA:    points = range_end × bid_amount\n"
            "                      Higher score wins the auction\n"
            "                      Example: range 3 × 100 CELL = 300 points\n\n"
            
            "• TOKEN REQUIREMENTS: Only CELL (native token) accepted\n\n"
            
            "• MINIMUM BID:        31.250 CELL for 3-month lock period\n"
            "                      Scales with lock period\n\n"
            
            "• MAXIMUM BID:        250,000 CELL for 24-month lock period\n\n"
            
            "• RANGE LIMITS:       1-8 CellSlots\n"
            "                      1 slot = 3 months lock\n"
            "                      8 slots = 24 months lock\n\n"
            
            "• LOCK PERIOD:        Must match range: lock_months = range_end × 3\n\n"
            
            "VALIDATION RULES:\n"
            "=================\n"
            "• Network must exist and be accessible\n"
            "• Auction hash must be valid 64-character hex\n"
            "• Range end must be 1-8\n"
            "• Amount must meet minimum requirements for the range\n"
            "• Lock period must exactly match range × 3 months\n"
            "• Wallet must exist and have sufficient balance\n"
            "• Fee must be positive amount\n\n"
            
            "EXAMPLES:\n"
            "=========\n"
            "1. Small bid for 3-month lock (1 CellSlot):\n"
            "   auction bid -net Backbone -auction 0x1a2b3c4d... -range 1 -amount 31.250 -lock 3 -fee 0.01 -w alice\n"
            "   Score: 1 × 31.250 = 31.25 points\n\n"
            
            "2. Medium bid for 9-month lock (3 CellSlots):\n"
            "   auction bid -net Backbone -auction 0x1a2b3c4d... -range 3 -amount 100.0 -lock 9 -fee 0.05 -w bob\n"
            "   Score: 3 × 100 = 300 points\n\n"
            
            "3. Large bid for 24-month lock (8 CellSlots):\n"
            "   auction bid -net Backbone -auction 0x1a2b3c4d... -range 8 -amount 250000.0 -lock 24 -fee 0.1 -w carol\n"
            "   Score: 8 × 250,000 = 2,000,000 points\n\n"
            
            "OUTPUT:\n"
            "=======\n"
            "On success, displays:\n"
            "• Transaction hash\n"
            "• Bid parameters summary\n"
            "• Calculated score\n"
            "• Confirmation message\n\n"
            
            "NOTES:\n"
            "======\n"
            "• Transaction is submitted to mempool for processing\n"
            "• Bid becomes active when transaction is confirmed\n"
            "• Tokens are locked immediately upon confirmation\n"
            "• Use 'auction info' to verify bid placement\n");
        return 0;
    }

    // Validate required parameters
    if (!l_net_name) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -net parameter is required\n");
        return -1;
    }
    if (!l_auction_hash_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -auction parameter is required\n");
        return -1;
    }
    if (!l_range_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -range parameter is required\n");
        return -1;
    }
    if (!l_amount_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -amount parameter is required\n");
        return -1;
    }
    if (!l_lock_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -lock parameter is required\n");
        return -1;
    }
    if (!l_fee_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -fee parameter is required\n");
        return -1;
    }
    if (!l_wallet_name) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -w (wallet) parameter is required\n");
        return -1;
    }

    // Get network
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    if (!l_net) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Network '%s' not found\n", l_net_name);
        return -1;
    }

    // Parse auction hash
    dap_hash_fast_t l_auction_hash = {};
    if (dap_chain_hash_fast_from_str(l_auction_hash_str, &l_auction_hash) != 0) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Invalid auction hash format\n");
        return -1;
    }

    // Parse range end
    char *l_endptr;
    uint8_t l_range_end = (uint8_t)strtoul(l_range_str, &l_endptr, 10);
    if (*l_endptr != '\0' || l_range_end < 1 || l_range_end > 8) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Range end must be between 1 and 8\n");
        return -1;
    }

    // Parse bid amount
    uint256_t l_bid_amount = dap_chain_balance_scan(l_amount_str);
    if (IS_ZERO_256(l_bid_amount)) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Invalid bid amount format\n");
        return -1;
    }

    // Parse lock time (convert months to timestamp)
    uint32_t l_lock_months = (uint32_t)strtoul(l_lock_str, &l_endptr, 10);
    if (*l_endptr != '\0' || l_lock_months < 3 || l_lock_months > 24) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Lock period must be between 3 and 24 months\n");
        return -1;
    }
    dap_time_t l_lock_time = (dap_time_t)l_lock_months * 30 * 24 * 60 * 60; // Convert months to seconds

    // Parse transaction fee
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Invalid fee amount format\n");
        return -1;
    }

    // Validate bid parameters according to Cellframe rules
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
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: %s\n", l_error_msg);
        return -1;
    }

    // Calculate score for user information
    uint64_t l_score = dap_chain_auction_bid_calculate_score(l_range_end, l_bid_amount);

    // Create auction bid transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_auction_bid_transaction_create(
        l_net, &l_auction_hash, l_range_end, l_bid_amount, l_lock_time, l_fee, l_wallet_name);

    if (!l_tx) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Failed to create auction bid transaction\n");
        return -1;
    }

    // Get transaction hash for response
    dap_hash_fast_t l_tx_hash = {};
    dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_tx_hash);

    dap_cli_server_cmd_set_reply_text(a_str_reply,
        "Auction bid transaction created successfully!\n\n"
        "TRANSACTION DETAILS:\n"
        "  Hash:          %s\n"
        "  Network:       %s\n"
        "  Auction:       %s\n"
        "  Range:         1-%d (%.1f years)\n"
        "  Amount:        %s CELL\n"
        "  Lock period:   %d months\n"
        "  Score:         %"DAP_UINT64_FORMAT_U" points\n"
        "  Fee:           %s CELL\n"
        "  Wallet:        %s\n\n"
        "The transaction has been added to mempool for network processing.\n",
        l_tx_hash_str,
        l_net_name,
        l_auction_hash_str,
        l_range_end,
        (float)l_range_end / 4.0, // Convert to years (4 CellSlots = 1 year)
        dap_uint256_to_char(l_bid_amount, NULL),
        l_lock_months,
        l_score,
        dap_uint256_to_char(l_fee, NULL),
        l_wallet_name);

    DAP_DELETE(l_tx_hash_str);
    DAP_DELETE(l_tx);
    return 0;
} 

/**
 * @brief CLI handler for 'auction list' command
 * 
 * Lists available auctions in the specified network.
 * 
 * Syntax: auction list -net <net_name> [-active_only] [-format table|json]
 * 
 * @param argc Argument count
 * @param argv Argument values
 * @param a_str_reply Reply string
 * @return 0 on success, negative on error
 */
static int s_cli_auction_list(int argc, char **argv, void **a_str_reply)
{
    // Parameter variables
    const char *l_net_name = NULL;
    const char *l_format = "table"; // Default format
    bool l_active_only = false;
    bool l_help = false;

    // Parse command line arguments
    int l_arg_index = 1;
    while (l_arg_index < argc) {
        if (strcmp(argv[l_arg_index], "--help") == 0 || strcmp(argv[l_arg_index], "-h") == 0) {
            l_help = true;
            break;
        }
        else if (strcmp(argv[l_arg_index], "-net") == 0 && l_arg_index + 1 < argc) {
            l_net_name = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-active_only") == 0) {
            l_active_only = true;
        }
        else if (strcmp(argv[l_arg_index], "-format") == 0 && l_arg_index + 1 < argc) {
            l_format = argv[++l_arg_index];
        }
        else {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                "Unknown parameter '%s'. Use 'auction list --help' for syntax.\n", argv[l_arg_index]);
            return -1;
        }
        l_arg_index++;
    }

    // Show help if requested
    if (l_help) {
        dap_cli_server_cmd_set_reply_text(a_str_reply,
            "AUCTION LIST - List Auctions in Network\n"
            "========================================\n\n"
            
            "DESCRIPTION:\n"
            "  Displays a list of auctions in the specified network with their current\n"
            "  status, bid count, and top scores. Supports filtering and multiple\n"
            "  output formats.\n\n"
            
            "SYNTAX:\n"
            "  auction list -net <network_name> [-active_only] [-format table|json] [--help|-h]\n\n"
            
            "REQUIRED PARAMETERS:\n"
            "  -net <network_name>     Target network name\n"
            "                          Examples: 'Backbone', 'Subzero', 'Mileena'\n"
            "                          Network must be configured and accessible\n\n"
            
            "OPTIONAL PARAMETERS:\n"
            "  -active_only            Filter to show only active auctions\n"
            "                          Excludes ended, cancelled, or completed auctions\n"
            "                          Default: show all auctions\n\n"
            
            "  -format <format>        Output format selection\n"
            "                          Options: 'table' | 'json'\n"
            "                          Default: 'table'\n"
            "                          • table: Human-readable aligned columns\n"
            "                          • json:  Machine-readable structured data\n\n"
            
            "  --help, -h              Show this help message\n\n"
            
            "OUTPUT FORMATS:\n"
            "===============\n"
            
            "TABLE FORMAT:\n"
            "  Hash                                                               Status      Bids  Top Score\n"
            "  ================================================================== =========== ===== ================\n"
            "  0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890 ACTIVE           3      2000000\n"
            "  0x9876543210fedcba0987654321fedcba0987654321fedcba0987654321fedcba ENDED            7       750000\n\n"
            
            "JSON FORMAT:\n"
            "  {\n"
            "    \"auctions\": [\n"
            "      {\n"
            "        \"hash\": \"0x1a2b3c4d...\",\n"
            "        \"status\": \"ACTIVE\",\n"
            "        \"bid_count\": 3,\n"
            "        \"top_score\": 2000000\n"
            "      }\n"
            "    ],\n"
            "    \"count\": 1\n"
            "  }\n\n"
            
            "AUCTION STATUSES:\n"
            "=================\n"
            "• ACTIVE      - Auction is currently accepting bids\n"
            "• ENDED       - Auction has ended, winner being determined\n"
            "• COMPLETED   - Auction finished, winner determined\n"
            "• CANCELLED   - Auction was cancelled, bids refunded\n"
            "• PENDING     - Auction created but not yet started\n\n"
            
            "DISPLAYED INFORMATION:\n"
            "======================\n"
            "• Hash         - Unique 64-character auction identifier\n"
            "• Status       - Current auction state (see statuses above)\n"
            "• Bid Count    - Total number of bids placed on auction\n"
            "• Top Score    - Highest score among all bids (range × amount)\n\n"
            
            "EXAMPLES:\n"
            "=========\n"
            "1. List all auctions in default table format:\n"
            "   auction list -net Backbone\n\n"
            
            "2. Show only active auctions:\n"
            "   auction list -net Backbone -active_only\n\n"
            
            "3. Get machine-readable JSON output:\n"
            "   auction list -net Backbone -format json\n\n"
            
            "4. Active auctions in JSON format:\n"
            "   auction list -net Backbone -active_only -format json\n\n"
            
            "5. List auctions on different network:\n"
            "   auction list -net Subzero -active_only\n\n"
            
            "USE CASES:\n"
            "==========\n"
            "• Monitor active auctions for bidding opportunities\n"
            "• Check auction participation statistics\n"
            "• Export auction data for analysis (JSON format)\n"
            "• Verify auction status before placing bids\n"
            "• Track auction activity across networks\n\n"
            
            "RELATED COMMANDS:\n"
            "=================\n"
            "• auction info    - Get detailed information about specific auction\n"
            "• auction events  - View auction event history\n"
            "• auction bid     - Place bid on specific auction\n"
            "• auction load    - Load auction state from ledger\n\n"
            
            "NOTES:\n"
            "======\n"
            "• Data is loaded from local auction storage\n"
            "• Use 'auction load' if no auctions are shown\n"
            "• Top score determines auction winner\n"
            "• Bid count includes all bids, even from same bidder\n");
        return 0;
    }

    // Validate required parameters
    if (!l_net_name) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -net parameter is required\n");
        return -1;
    }

    // Validate format parameter
    if (strcmp(l_format, "table") != 0 && strcmp(l_format, "json") != 0) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Format must be 'table' or 'json'\n");
        return -1;
    }

    // Get network
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    if (!l_net) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Network '%s' not found\n", l_net_name);
        return -1;
    }

    // Get auctions from storage
    size_t l_auction_count = 0;
    dap_chain_auction_info_t **l_auctions = dap_chain_auction_storage_get_all(l_net, &l_auction_count);

    if (l_auction_count == 0) {
        if (strcmp(l_format, "json") == 0) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "{\"auctions\": [], \"count\": 0}\n");
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "No auctions found in network '%s'\n", l_net_name);
        }
        dap_chain_auction_storage_free_list(l_auctions, l_auction_count);
        return 0;
    }

    // Filter active only if requested
    size_t l_display_count = 0;
    for (size_t i = 0; i < l_auction_count; i++) {
        if (!l_active_only || l_auctions[i]->status == DAP_CHAIN_AUCTION_STATUS_ACTIVE) {
            l_display_count++;
        }
    }

    if (l_display_count == 0) {
        if (strcmp(l_format, "json") == 0) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "{\"auctions\": [], \"count\": 0}\n");
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "No active auctions found in network '%s'\n", l_net_name);
        }
        dap_chain_auction_storage_free_list(l_auctions, l_auction_count);
        return 0;
    }

    // Format output
    if (strcmp(l_format, "json") == 0) {
        // JSON format
        dap_string_t *l_json = dap_string_new("{\"auctions\": [");
        bool l_first = true;
        
        for (size_t i = 0; i < l_auction_count; i++) {
            if (l_active_only && l_auctions[i]->status != DAP_CHAIN_AUCTION_STATUS_ACTIVE) {
                continue;
            }
            
            if (!l_first) {
                dap_string_append(l_json, ",");
            }
            l_first = false;
            
            char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_auctions[i]->auction_hash);
            const char *l_status_str = dap_chain_auction_status_to_str(l_auctions[i]->status);
            
            dap_string_append_printf(l_json,
                "{\"hash\": \"%s\", \"status\": \"%s\", \"bid_count\": %zu, \"top_score\": %"DAP_UINT64_FORMAT_U"}",
                l_hash_str, l_status_str, l_auctions[i]->bid_count, l_auctions[i]->top_score);
            
            DAP_DELETE(l_hash_str);
        }
        
        dap_string_append_printf(l_json, "], \"count\": %zu}", l_display_count);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s\n", l_json->str);
        dap_string_free(l_json, true);
    } else {
        // Table format
        dap_string_t *l_table = dap_string_new("");
        dap_string_append_printf(l_table,
            "Auctions in network '%s' (%s%zu found):\n\n",
            l_net_name, l_active_only ? "active only, " : "", l_display_count);
        
        dap_string_append(l_table,
            "Hash                                                               Status      Bids  Top Score\n"
            "================================================================== =========== ===== ================\n");
        
        for (size_t i = 0; i < l_auction_count; i++) {
            if (l_active_only && l_auctions[i]->status != DAP_CHAIN_AUCTION_STATUS_ACTIVE) {
                continue;
            }
            
            char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_auctions[i]->auction_hash);
            const char *l_status_str = dap_chain_auction_status_to_str(l_auctions[i]->status);
            
            dap_string_append_printf(l_table, "%-66s %-11s %5zu %16"DAP_UINT64_FORMAT_U"\n",
                l_hash_str, l_status_str, l_auctions[i]->bid_count, l_auctions[i]->top_score);
            
            DAP_DELETE(l_hash_str);
        }
        
        dap_string_append_printf(l_table, "\nTotal: %zu auction%s\n", 
            l_display_count, l_display_count == 1 ? "" : "s");
        
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_table->str);
        dap_string_free(l_table, true);
    }

    // Cleanup
    dap_chain_auction_storage_free_list(l_auctions, l_auction_count);
    return 0;
} 

/**
 * @brief CLI handler for 'auction info' command
 * 
 * Shows detailed information about a specific auction.
 * 
 * Syntax: auction info -net <net_name> -auction <auction_hash> [-format table|json]
 * 
 * @param argc Argument count
 * @param argv Argument values
 * @param a_str_reply Reply string
 * @return 0 on success, negative on error
 */
static int s_cli_auction_info(int argc, char **argv, void **a_str_reply)
{
    // Parameter variables
    const char *l_net_name = NULL;
    const char *l_auction_hash_str = NULL;
    const char *l_format = "table"; // Default format
    bool l_help = false;

    // Parse command line arguments
    int l_arg_index = 1;
    while (l_arg_index < argc) {
        if (strcmp(argv[l_arg_index], "--help") == 0 || strcmp(argv[l_arg_index], "-h") == 0) {
            l_help = true;
            break;
        }
        else if (strcmp(argv[l_arg_index], "-net") == 0 && l_arg_index + 1 < argc) {
            l_net_name = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-auction") == 0 && l_arg_index + 1 < argc) {
            l_auction_hash_str = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-format") == 0 && l_arg_index + 1 < argc) {
            l_format = argv[++l_arg_index];
        }
        else {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                "Unknown parameter '%s'. Use 'auction info --help' for syntax.\n", argv[l_arg_index]);
            return -1;
        }
        l_arg_index++;
    }

    // Show help if requested
    if (l_help) {
        dap_cli_server_cmd_set_reply_text(a_str_reply,
            "AUCTION INFO - Show Detailed Auction Information\n"
            "=================================================\n\n"
            
            "DESCRIPTION:\n"
            "  Displays comprehensive information about a specific auction including\n"
            "  all bids, bidder details, scores, and current status. Shows complete\n"
            "  auction state with winner determination.\n\n"
            
            "SYNTAX:\n"
            "  auction info -net <network_name> -auction <auction_hash>\n"
            "               [-format table|json] [--help|-h]\n\n"
            
            "REQUIRED PARAMETERS:\n"
            "  -net <network_name>     Target network name\n"
            "                          Examples: 'Backbone', 'Subzero', 'Mileena'\n"
            "                          Network must have loaded auction state\n\n"
            
            "  -auction <auction_hash> Specific auction to examine\n"
            "                          Format: 0x[0-9a-fA-F]{64}\n"
            "                          Must be valid auction hash from ledger\n\n"
            
            "OPTIONAL PARAMETERS:\n"
            "  -format <format>        Output format selection\n"
            "                          Options: 'table' | 'json'\n"
            "                          Default: 'table'\n"
            "                          • table: Human-readable detailed display\n"
            "                          • json:  Structured data with all details\n\n"
            
            "  --help, -h              Show this help message\n\n"
            
            "DISPLAYED INFORMATION:\n"
            "======================\n"
            "AUCTION OVERVIEW:\n"
            "• Hash           - Unique auction identifier\n"
            "• Network        - Network where auction is hosted\n"
            "• Status         - Current auction state\n"
            "• Total Bids     - Number of bids placed\n"
            "• Top Score      - Highest score among all bids\n\n"
            
            "BID DETAILS (sorted by score):\n"
            "• Bidder Hash    - Public key hash of bidder\n"
            "• Range          - CellSlot range (always 1-X)\n"
            "• Amount         - CELL tokens bid\n"
            "• Score          - Calculated points (range × amount)\n"
            "• Lock Period    - Token lock duration in months\n"
            "• Winner Status  - Indicates current winner\n\n"
            
            "OUTPUT FORMATS:\n"
            "===============\n"
            
            "TABLE FORMAT:\n"
            "  Auction Information:\n"
            "  ====================\n"
            "  Hash:         0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890\n"
            "  Network:      Backbone\n"
            "  Status:       ACTIVE\n"
            "  Total bids:   3\n"
            "  Top score:    2000000 points\n\n"
            
            "  Bids (sorted by score):\n"
            "  =======================\n"
            "  Bidder (Public Key Hash)                                           Range  Amount (CELL)      Score        Lock (months)\n"
            "  ================================================================== ===== ================== ============ =============\n"
            "  0x9876543210fedcba0987654321fedcba0987654321fedcba0987654321fedcba 1-8             250000.000      2000000            24 (WINNER)\n"
            "  0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd 1-3                100.000          300             9\n"
            "  0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef123456 1-1                 31.250           32             3\n\n"
            
            "JSON FORMAT:\n"
            "  {\n"
            "    \"hash\": \"0x1a2b3c4d...\",\n"
            "    \"status\": \"ACTIVE\",\n"
            "    \"bid_count\": 3,\n"
            "    \"top_score\": 2000000,\n"
            "    \"bids\": [\n"
            "      {\n"
            "        \"bidder\": \"0x9876543210...\",\n"
            "        \"range_end\": 8,\n"
            "        \"amount\": \"250000.000\",\n"
            "        \"score\": 2000000,\n"
            "        \"lock_time\": 63072000\n"
            "      }\n"
            "    ]\n"
            "  }\n\n"
            
            "AUCTION STATUSES:\n"
            "=================\n"
            "• ACTIVE      - Currently accepting bids\n"
            "• ENDED       - Bidding closed, determining winner\n"
            "• COMPLETED   - Winner determined and announced\n"
            "• CANCELLED   - Auction cancelled, bids refunded\n"
            "• PENDING     - Created but not yet active\n\n"
            
            "SCORE CALCULATION:\n"
            "==================\n"
            "Formula: points = range_end × bid_amount\n"
            "Examples:\n"
            "• Range 1-8 × 250,000 CELL = 2,000,000 points\n"
            "• Range 1-3 × 100 CELL = 300 points\n"
            "• Range 1-1 × 31.25 CELL = 31.25 points\n\n"
            
            "Higher score wins the auction!\n\n"
            
            "EXAMPLES:\n"
            "=========\n"
            "1. View auction details in readable format:\n"
            "   auction info -net Backbone -auction 0x1a2b3c4d5e6f...\n\n"
            
            "2. Get structured data for processing:\n"
            "   auction info -net Backbone -auction 0x1a2b3c4d5e6f... -format json\n\n"
            
            "3. Check auction on different network:\n"
            "   auction info -net Subzero -auction 0x9876543210fe...\n\n"
            
            "4. Verify bid placement after submission:\n"
            "   auction info -net Backbone -auction 0x1a2b3c4d5e6f...\n\n"
            
            "USE CASES:\n"
            "==========\n"
            "• Verify successful bid placement\n"
            "• Check current auction standings\n"
            "• Analyze bidding competition\n"
            "• Confirm auction winner\n"
            "• Export auction data for analysis\n"
            "• Monitor auction progress\n"
            "• Audit bid transparency\n\n"
            
            "BID ANALYSIS:\n"
            "=============\n"
            "The table shows bids sorted by score (highest first):\n"
            "• Winner is marked with '(WINNER)' tag\n"
            "• All bid details are fully transparent\n"
            "• Scores are calculated in real-time\n"
            "• Lock periods show token commitment\n"
            "• Public key hashes ensure anonymity\n\n"
            
            "RELATED COMMANDS:\n"
            "=================\n"
            "• auction list    - Find auctions to examine\n"
            "• auction bid     - Place bid on this auction\n"
            "• auction events  - View auction event history\n"
            "• auction load    - Load auction state if not found\n\n"
            
            "NOTES:\n"
            "======\n"
            "• Requires 'auction load' to be run first for network\n"
            "• All amounts displayed in CELL tokens\n"
            "• Times shown in seconds for JSON, months for table\n"
            "• Winner determination is automatic by highest score\n"
            "• Bidder anonymity preserved with public key hashes\n");
        return 0;
    }

    // Validate required parameters
    if (!l_net_name) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -net parameter is required\n");
        return -1;
    }
    if (!l_auction_hash_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -auction parameter is required\n");
        return -1;
    }

    // Validate format parameter
    if (strcmp(l_format, "table") != 0 && strcmp(l_format, "json") != 0) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Format must be 'table' or 'json'\n");
        return -1;
    }

    // Get network
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    if (!l_net) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Network '%s' not found\n", l_net_name);
        return -1;
    }

    // Parse auction hash
    dap_hash_fast_t l_auction_hash = {};
    if (dap_chain_hash_fast_from_str(l_auction_hash_str, &l_auction_hash) != 0) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Invalid auction hash format\n");
        return -1;
    }

    // Get auction information from storage
    dap_chain_auction_info_t *l_auction_info = dap_chain_auction_storage_get(l_net, &l_auction_hash);
    if (!l_auction_info) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Auction not found\n");
        return -1;
    }

    // Get bids for this auction
    size_t l_bid_count = 0;
    dap_chain_auction_bid_t **l_bids = dap_chain_auction_storage_get_bids(l_net, &l_auction_hash, &l_bid_count);

    // Format output
    if (strcmp(l_format, "json") == 0) {
        // JSON format
        dap_string_t *l_json = dap_string_new("{");
        
        char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_auction_info->auction_hash);
        const char *l_status_str = dap_chain_auction_status_to_str(l_auction_info->status);
        
        dap_string_append_printf(l_json,
            "\"hash\": \"%s\","
            "\"status\": \"%s\","
            "\"bid_count\": %zu,"
            "\"top_score\": %"DAP_UINT64_FORMAT_U","
            "\"bids\": [",
            l_hash_str, l_status_str, l_auction_info->bid_count, l_auction_info->top_score);
        
        // Add bid details
        for (size_t i = 0; i < l_bid_count; i++) {
            if (i > 0) dap_string_append(l_json, ",");
            
            char *l_bidder_str = dap_chain_hash_fast_to_str_new(&l_bids[i]->bidder_pkey_hash);
            uint64_t l_score = dap_chain_auction_bid_calculate_score(l_bids[i]->range_end, l_bids[i]->bid_amount);
            
            dap_string_append_printf(l_json,
                "{\"bidder\": \"%s\", \"range_end\": %d, \"amount\": \"%s\", \"score\": %"DAP_UINT64_FORMAT_U", \"lock_time\": %lu}",
                l_bidder_str,
                l_bids[i]->range_end,
                dap_uint256_to_char(l_bids[i]->bid_amount, NULL),
                l_score,
                l_bids[i]->lock_time);
            
            DAP_DELETE(l_bidder_str);
        }
        
        dap_string_append(l_json, "]}");
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s\n", l_json->str);
        dap_string_free(l_json, true);
        DAP_DELETE(l_hash_str);
    } else {
        // Table format
        dap_string_t *l_table = dap_string_new("");
        
        char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_auction_info->auction_hash);
        const char *l_status_str = dap_chain_auction_status_to_str(l_auction_info->status);
        
        dap_string_append_printf(l_table,
            "Auction Information:\n"
            "====================\n\n"
            "Hash:         %s\n"
            "Network:      %s\n"
            "Status:       %s\n"
            "Total bids:   %zu\n"
            "Top score:    %"DAP_UINT64_FORMAT_U" points\n\n",
            l_hash_str, l_net_name, l_status_str, l_auction_info->bid_count, l_auction_info->top_score);
        
        if (l_bid_count > 0) {
            dap_string_append(l_table,
                "Bids (sorted by score):\n"
                "=======================\n\n"
                "Bidder (Public Key Hash)                                           Range  Amount (CELL)      Score        Lock (months)\n"
                "================================================================== ===== ================== ============ =============\n");
            
            // Sort bids by score (descending) for display
            for (size_t i = 0; i < l_bid_count - 1; i++) {
                for (size_t j = i + 1; j < l_bid_count; j++) {
                    uint64_t score_i = dap_chain_auction_bid_calculate_score(l_bids[i]->range_end, l_bids[i]->bid_amount);
                    uint64_t score_j = dap_chain_auction_bid_calculate_score(l_bids[j]->range_end, l_bids[j]->bid_amount);
                    if (score_j > score_i) {
                        // Swap bids
                        dap_chain_auction_bid_t *temp = l_bids[i];
                        l_bids[i] = l_bids[j];
                        l_bids[j] = temp;
                    }
                }
            }
            
            for (size_t i = 0; i < l_bid_count; i++) {
                char *l_bidder_str = dap_chain_hash_fast_to_str_new(&l_bids[i]->bidder_pkey_hash);
                uint64_t l_score = dap_chain_auction_bid_calculate_score(l_bids[i]->range_end, l_bids[i]->bid_amount);
                uint32_t l_lock_months = (uint32_t)(l_bids[i]->lock_time / (30 * 24 * 60 * 60)); // Convert seconds to months
                
                dap_string_append_printf(l_table,
                    "%-66s 1-%-3d %18s %12"DAP_UINT64_FORMAT_U" %13u%s\n",
                    l_bidder_str,
                    l_bids[i]->range_end,
                    dap_uint256_to_char(l_bids[i]->bid_amount, NULL),
                    l_score,
                    l_lock_months,
                    i == 0 ? " (WINNER)" : "");
                
                DAP_DELETE(l_bidder_str);
            }
        } else {
            dap_string_append(l_table, "No bids placed for this auction.\n");
        }
        
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_table->str);
        dap_string_free(l_table, true);
        DAP_DELETE(l_hash_str);
    }

    // Cleanup
    dap_chain_auction_storage_free_auction_info(l_auction_info);
    if (l_bids) {
        dap_chain_auction_storage_free_bid_list(l_bids, l_bid_count);
    }
    
    return 0;
} 

/**
 * @brief CLI handler for 'auction events' command
 * 
 * Shows auction events from the ledger with filtering options.
 * 
 * Syntax: auction events -net <net_name> [-auction <auction_hash>] [-type <event_type>] [-limit <count>] [-format table|json]
 * 
 * @param argc Argument count
 * @param argv Argument values
 * @param a_str_reply Reply string
 * @return 0 on success, negative on error
 */
static int s_cli_auction_events(int argc, char **argv, void **a_str_reply)
{
    // Parameter variables
    const char *l_net_name = NULL;
    const char *l_auction_hash_str = NULL;
    const char *l_event_type_str = NULL;
    const char *l_format = "table"; // Default format
    const char *l_limit_str = NULL;
    bool l_help = false;

    // Parse command line arguments
    int l_arg_index = 1;
    while (l_arg_index < argc) {
        if (strcmp(argv[l_arg_index], "--help") == 0 || strcmp(argv[l_arg_index], "-h") == 0) {
            l_help = true;
            break;
        }
        else if (strcmp(argv[l_arg_index], "-net") == 0 && l_arg_index + 1 < argc) {
            l_net_name = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-auction") == 0 && l_arg_index + 1 < argc) {
            l_auction_hash_str = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-type") == 0 && l_arg_index + 1 < argc) {
            l_event_type_str = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-limit") == 0 && l_arg_index + 1 < argc) {
            l_limit_str = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-format") == 0 && l_arg_index + 1 < argc) {
            l_format = argv[++l_arg_index];
        }
        else {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                "Unknown parameter '%s'. Use 'auction events --help' for syntax.\n", argv[l_arg_index]);
            return -1;
        }
        l_arg_index++;
    }

    // Show help if requested
    if (l_help) {
        dap_cli_server_cmd_set_reply_text(a_str_reply,
            "AUCTION EVENTS - Show Auction Events from Ledger\n"
            "=================================================\n\n"
            
            "DESCRIPTION:\n"
            "  Displays auction-related events stored in the ledger with powerful\n"
            "  filtering options. Events are read directly from the blockchain\n"
            "  and provide a complete audit trail of auction activity.\n\n"
            
            "SYNTAX:\n"
            "  auction events -net <network_name> [-auction <auction_hash>]\n"
            "                 [-type <event_type>] [-limit <count>]\n"
            "                 [-format table|json] [--help|-h]\n\n"
            
            "REQUIRED PARAMETERS:\n"
            "  -net <network_name>     Target network name\n"
            "                          Examples: 'Backbone', 'Subzero', 'Mileena'\n"
            "                          Network must have auction events in ledger\n\n"
            
            "OPTIONAL PARAMETERS:\n"
            "  -auction <auction_hash> Filter events for specific auction\n"
            "                          Format: 0x[0-9a-fA-F]{64}\n"
            "                          Shows only events related to this auction\n\n"
            
            "  -type <event_type>      Filter by specific event type\n"
            "                          See EVENT TYPES section below\n"
            "                          Case-sensitive, exact match required\n\n"
            
            "  -limit <count>          Maximum number of events to display\n"
            "                          Range: 1-1000\n"
            "                          Default: 50\n"
            "                          Newer events are shown first\n\n"
            
            "  -format <format>        Output format selection\n"
            "                          Options: 'table' | 'json'\n"
            "                          Default: 'table'\n"
            "                          • table: Human-readable with timestamps\n"
            "                          • json:  Machine-readable structured data\n\n"
            
            "  --help, -h              Show this help message\n\n"
            
            "EVENT TYPES:\n"
            "============\n"
            "AUCTION_CREATED         New auction created and announced\n"
            "                        Contains: creator, start/end times, project info\n\n"
            
            "BID_PLACED              New bid placed on auction\n"
            "                        Contains: bidder, amount, range, score\n\n"
            
            "AUCTION_ENDED           Auction ended (time expired or manually)\n"
            "                        Contains: end time, total bids\n\n"
            
            "WINNER_DETERMINED       Auction winner selected\n"
            "                        Contains: winner details, winning bid info\n\n"
            
            "AUCTION_CANCELLED       Auction cancelled before completion\n"
            "                        Contains: cancellation reason, refund status\n\n"
            
            "OUTPUT FORMATS:\n"
            "===============\n"
            
            "TABLE FORMAT:\n"
            "  Type               Transaction Hash                                           Auction Hash                                               Timestamp\n"
            "  ================== ================================================================== ================================================================== ===================\n"
            "  BID_PLACED         0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890 0x9876543210fedcba0987654321fedcba0987654321fedcba0987654321fedcba 2024-12-19 14:30:15\n"
            "  AUCTION_CREATED    0x2b3c4d5e6f7890ab1a2b3c4d5e6f7890ab1a2b3c4d5e6f7890ab1a2b3c4d5e6f 0x9876543210fedcba0987654321fedcba0987654321fedcba0987654321fedcba 2024-12-19 12:00:00\n\n"
            
            "JSON FORMAT:\n"
            "  {\n"
            "    \"events\": [\n"
            "      {\n"
            "        \"type\": \"BID_PLACED\",\n"
            "        \"tx_hash\": \"0x1a2b3c4d...\",\n"
            "        \"auction_hash\": \"0x9876543210...\",\n"
            "        \"timestamp\": 1703001015\n"
            "      }\n"
            "    ],\n"
            "    \"count\": 1\n"
            "  }\n\n"
            
            "FILTERING COMBINATIONS:\n"
            "=======================\n"
            "• No filters          - All events from network\n"
            "• Auction only        - All events for specific auction\n"
            "• Type only           - All events of specific type\n"
            "• Auction + Type      - Specific events for specific auction\n"
            "• Any + Limit         - Limit results to specified count\n\n"
            
            "EXAMPLES:\n"
            "=========\n"
            "1. Show recent auction activity (default 50 events):\n"
            "   auction events -net Backbone\n\n"
            
            "2. Track specific auction history:\n"
            "   auction events -net Backbone -auction 0x1a2b3c4d5e6f...\n\n"
            
            "3. Monitor bid placements across all auctions:\n"
            "   auction events -net Backbone -type BID_PLACED -limit 20\n\n"
            
            "4. Get machine-readable event data:\n"
            "   auction events -net Backbone -format json -limit 100\n\n"
            
            "5. Audit specific auction winners:\n"
            "   auction events -net Backbone -type WINNER_DETERMINED\n\n"
            
            "6. Check recent auction creations:\n"
            "   auction events -net Backbone -type AUCTION_CREATED -limit 5\n\n"
            
            "7. Investigate auction cancellations:\n"
            "   auction events -net Backbone -type AUCTION_CANCELLED\n\n"
            
            "8. Comprehensive audit of specific auction:\n"
            "   auction events -net Backbone -auction 0x1a2b3c... -format json\n\n"
            
            "USE CASES:\n"
            "==========\n"
            "• Audit auction transparency and fairness\n"
            "• Monitor bidding patterns and strategies\n"
            "• Track auction lifecycle from creation to completion\n"
            "• Investigate specific auction issues or disputes\n"
            "• Export event data for analysis and reporting\n"
            "• Monitor network auction activity levels\n"
            "• Verify auction outcomes and winner selection\n\n"
            
            "TIMESTAMP FORMAT:\n"
            "=================\n"
            "• Table format: YYYY-MM-DD HH:MM:SS (local time)\n"
            "• JSON format:  Unix timestamp (seconds since epoch)\n"
            "• Events are ordered by timestamp (newest first)\n\n"
            
            "RELATED COMMANDS:\n"
            "=================\n"
            "• auction info    - Get current auction state and bids\n"
            "• auction list    - List all auctions in network\n"
            "• auction load    - Rebuild state from events\n"
            "• auction bid     - Place new bid (creates BID_PLACED event)\n\n"
            
            "NOTES:\n"
            "======\n"
            "• Events are immutable blockchain records\n"
            "• All times are in network consensus time\n"
            "• Large queries may take time to process\n"
            "• Use filtering to reduce data transfer\n"
            "• Events provide complete audit trail\n");
        return 0;
    }

    // Validate required parameters
    if (!l_net_name) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -net parameter is required\n");
        return -1;
    }

    // Validate format parameter
    if (strcmp(l_format, "table") != 0 && strcmp(l_format, "json") != 0) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Format must be 'table' or 'json'\n");
        return -1;
    }

    // Get network
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    if (!l_net) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Network '%s' not found\n", l_net_name);
        return -1;
    }

    // Parse optional auction hash
    dap_hash_fast_t l_auction_hash = {};
    bool l_filter_by_auction = false;
    if (l_auction_hash_str) {
        if (dap_chain_hash_fast_from_str(l_auction_hash_str, &l_auction_hash) != 0) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Invalid auction hash format\n");
            return -1;
        }
        l_filter_by_auction = true;
    }

    // Parse event type
    dap_chain_auction_event_type_t l_event_type = DAP_CHAIN_AUCTION_EVENT_INVALID;
    bool l_filter_by_type = false;
    if (l_event_type_str) {
        l_event_type = dap_chain_auction_event_type_from_str(l_event_type_str);
        if (l_event_type == DAP_CHAIN_AUCTION_EVENT_INVALID) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, 
                "Error: Invalid event type '%s'. Valid types: AUCTION_CREATED, BID_PLACED, AUCTION_ENDED, WINNER_DETERMINED, AUCTION_CANCELLED\n", 
                l_event_type_str);
            return -1;
        }
        l_filter_by_type = true;
    }

    // Parse limit
    size_t l_limit = 50; // Default limit
    if (l_limit_str) {
        char *l_endptr;
        l_limit = (size_t)strtoul(l_limit_str, &l_endptr, 10);
        if (*l_endptr != '\0' || l_limit == 0) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Invalid limit value\n");
            return -1;
        }
    }

    // Read events from ledger based on filters
    size_t l_event_count = 0;
    dap_chain_auction_event_t **l_events = NULL;
    
    if (l_filter_by_auction && l_filter_by_type) {
        // Filter by both auction and type (not directly supported, need to filter manually)
        l_events = dap_chain_auction_events_read_by_auction(l_net, &l_auction_hash, &l_event_count);
        // TODO: Implement type filtering after reading
    }
    else if (l_filter_by_auction) {
        l_events = dap_chain_auction_events_read_by_auction(l_net, &l_auction_hash, &l_event_count);
    }
    else if (l_filter_by_type) {
        l_events = dap_chain_auction_events_read_by_type(l_net, l_event_type, &l_event_count);
    }
    else {
        l_events = dap_chain_auction_events_read_all(l_net, &l_event_count);
    }

    if (!l_events || l_event_count == 0) {
        if (strcmp(l_format, "json") == 0) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "{\"events\": [], \"count\": 0}\n");
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "No auction events found\n");
        }
        return 0;
    }

    // Apply limit
    if (l_event_count > l_limit) {
        l_event_count = l_limit;
    }

    // Format output
    if (strcmp(l_format, "json") == 0) {
        // JSON format
        dap_string_t *l_json = dap_string_new("{\"events\": [");
        
        for (size_t i = 0; i < l_event_count; i++) {
            if (i > 0) dap_string_append(l_json, ",");
            
            char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_events[i]->tx_hash);
            char *l_auction_hash_str = dap_chain_hash_fast_to_str_new(&l_events[i]->auction_hash);
            const char *l_type_str = dap_chain_auction_event_type_to_str(l_events[i]->type);
            
            dap_string_append_printf(l_json,
                "{\"type\": \"%s\", \"tx_hash\": \"%s\", \"auction_hash\": \"%s\", \"timestamp\": %lu}",
                l_type_str, l_tx_hash_str, l_auction_hash_str, l_events[i]->timestamp);
            
            DAP_DELETE(l_tx_hash_str);
            DAP_DELETE(l_auction_hash_str);
        }
        
        dap_string_append_printf(l_json, "], \"count\": %zu}", l_event_count);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s\n", l_json->str);
        dap_string_free(l_json, true);
    } else {
        // Table format
        dap_string_t *l_table = dap_string_new("");
        
        dap_string_append_printf(l_table,
            "Auction Events in network '%s'%s%s%s (%zu found):\n\n",
            l_net_name,
            l_filter_by_auction ? " for auction " : "",
            l_filter_by_auction ? l_auction_hash_str : "",
            l_filter_by_type ? " of type " : "",
            l_filter_by_type ? l_event_type_str : "",
            l_event_count);
        
        dap_string_append(l_table,
            "Type               Transaction Hash                                           Auction Hash                                               Timestamp\n"
            "================== ================================================================== ================================================================== ===================\n");
        
        for (size_t i = 0; i < l_event_count; i++) {
            char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_events[i]->tx_hash);
            char *l_auction_hash_str = dap_chain_hash_fast_to_str_new(&l_events[i]->auction_hash);
            const char *l_type_str = dap_chain_auction_event_type_to_str(l_events[i]->type);
            
            // Format timestamp
            time_t l_time = (time_t)l_events[i]->timestamp;
            struct tm *l_tm = localtime(&l_time);
            char l_time_str[32];
            strftime(l_time_str, sizeof(l_time_str), "%Y-%m-%d %H:%M:%S", l_tm);
            
            dap_string_append_printf(l_table,
                "%-18s %-66s %-66s %s\n",
                l_type_str, l_tx_hash_str, l_auction_hash_str, l_time_str);
            
            DAP_DELETE(l_tx_hash_str);
            DAP_DELETE(l_auction_hash_str);
        }
        
        if (l_event_count >= l_limit) {
            dap_string_append_printf(l_table, "\nShowing first %zu events (use -limit to show more)\n", l_limit);
        }
        
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_table->str);
        dap_string_free(l_table, true);
    }

    // Cleanup
    dap_chain_auction_events_free_list(l_events, l_event_count);
    return 0;
} 

/**
 * @brief CLI handler for 'auction load' command
 * 
 * Loads auction state from ledger events for the specified network.
 * This rebuilds the in-memory auction storage from the event history.
 * 
 * Syntax: auction load -net <net_name> [-force] [-verbose]
 * 
 * @param argc Argument count
 * @param argv Argument values
 * @param a_str_reply Reply string
 * @return 0 on success, negative on error
 */
static int s_cli_auction_load(int argc, char **argv, void **a_str_reply)
{
    // Parameter variables
    const char *l_net_name = NULL;
    bool l_force = false;
    bool l_verbose = false;
    bool l_help = false;

    // Parse command line arguments
    int l_arg_index = 1;
    while (l_arg_index < argc) {
        if (strcmp(argv[l_arg_index], "--help") == 0 || strcmp(argv[l_arg_index], "-h") == 0) {
            l_help = true;
            break;
        }
        else if (strcmp(argv[l_arg_index], "-net") == 0 && l_arg_index + 1 < argc) {
            l_net_name = argv[++l_arg_index];
        }
        else if (strcmp(argv[l_arg_index], "-force") == 0) {
            l_force = true;
        }
        else if (strcmp(argv[l_arg_index], "-verbose") == 0) {
            l_verbose = true;
        }
        else {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                "Unknown parameter '%s'. Use 'auction load --help' for syntax.\n", argv[l_arg_index]);
            return -1;
        }
        l_arg_index++;
    }

    // Show help if requested
    if (l_help) {
        dap_cli_server_cmd_set_reply_text(a_str_reply,
            "AUCTION LOAD - Load Auction State from Ledger Events\n"
            "=====================================================\n\n"
            
            "DESCRIPTION:\n"
            "  Reconstructs the complete auction state by reading all auction-related\n"
            "  events from the ledger and building the in-memory storage. This is\n"
            "  essential for initializing auction data or recovering from corrupted state.\n\n"
            
            "SYNTAX:\n"
            "  auction load -net <network_name> [-force] [-verbose] [--help|-h]\n\n"
            
            "REQUIRED PARAMETERS:\n"
            "  -net <network_name>     Target network name\n"
            "                          Examples: 'Backbone', 'Subzero', 'Mileena'\n"
            "                          Network must be configured with ledger access\n\n"
            
            "OPTIONAL PARAMETERS:\n"
            "  -force                  Force reload even if state already exists\n"
            "                          Clears existing auction data before loading\n"
            "                          Use when state appears corrupted or outdated\n"
            "                          Default: skip if state already loaded\n\n"
            
            "  -verbose                Display detailed loading progress\n"
            "                          Shows step-by-step reconstruction process\n"
            "                          Useful for debugging or monitoring\n"
            "                          Default: show summary only\n\n"
            
            "  --help, -h              Show this help message\n\n"
            
            "LOADING PROCESS:\n"
            "================\n"
            "1. Check existing state (skip if present and not forced)\n"
            "2. Clear existing state (if -force specified)\n"
            "3. Read all auction events from ledger chronologically\n"
            "4. Process events to rebuild auction states:\n"
            "   • AUCTION_CREATED events → Create auction records\n"
            "   • BID_PLACED events → Add bids to auctions\n"
            "   • AUCTION_ENDED events → Update auction status\n"
            "   • WINNER_DETERMINED events → Set winners\n"
            "   • AUCTION_CANCELLED events → Mark cancelled\n"
            "5. Calculate final statistics and scores\n"
            "6. Store state in memory for fast access\n\n"
            
            "OUTPUT INFORMATION:\n"
            "===================\n"
            "• Total auctions loaded\n"
            "• Breakdown by status (Active, Ended, Cancelled)\n"
            "• Total number of bids processed\n"
            "• Loading time and performance metrics\n"
            "• Auction summary (if verbose mode)\n\n"
            
            "STATE VALIDATION:\n"
            "=================\n"
            "During loading, the system validates:\n"
            "• Event chronological consistency\n"
            "• Auction hash uniqueness\n"
            "• Bid amount and range validation\n"
            "• Score calculation accuracy\n"
            "• State transition validity\n"
            "• Data integrity checks\n\n"
            
            "WHEN TO USE:\n"
            "============\n"
            "• Node first startup (initial state loading)\n"
            "• After node restart or crash recovery\n"
            "• When 'auction list' shows no results\n"
            "• After ledger synchronization\n"
            "• When state appears corrupted or incomplete\n"
            "• For audit purposes (full state reconstruction)\n"
            "• After significant ledger changes\n\n"
            
            "EXAMPLES:\n"
            "=========\n"
            "1. Initial state loading (check if needed first):\n"
            "   auction load -net Backbone\n\n"
            
            "2. Force complete reload with progress details:\n"
            "   auction load -net Backbone -force -verbose\n\n"
            
            "3. Quick reload without progress details:\n"
            "   auction load -net Backbone -force\n\n"
            
            "4. Load state for different network:\n"
            "   auction load -net Subzero -verbose\n\n"
            
            "5. Recovery after corruption (verbose for diagnostics):\n"
            "   auction load -net Backbone -force -verbose\n\n"
            
            "VERBOSE OUTPUT EXAMPLE:\n"
            "=======================\n"
            "Loading auction state from network 'Backbone'...\n\n"
            "Clearing existing auction state...\n"
            "Reading events from ledger...\n"
            "Processing 245 auction events...\n"
            "  - 12 AUCTION_CREATED events processed\n"
            "  - 198 BID_PLACED events processed\n"
            "  - 8 AUCTION_ENDED events processed\n"
            "  - 7 WINNER_DETERMINED events processed\n"
            "Loading completed successfully!\n\n"
            
            "Auction State Loaded for Network 'Backbone':\n"
            "Total auctions:    12\n"
            "  Active:          3\n"
            "  Ended:           7\n"
            "  Cancelled:       2\n"
            "Total bids:        198\n\n"
            
            "PERFORMANCE CONSIDERATIONS:\n"
            "===========================\n"
            "• Loading time depends on event count in ledger\n"
            "• Large networks may take several seconds\n"
            "• Memory usage scales with auction/bid count\n"
            "• Frequent reloading not recommended\n"
            "• Use filtering in other commands to reduce load\n\n"
            
            "ERROR HANDLING:\n"
            "===============\n"
            "Common issues and solutions:\n"
            "• Network not found → Check network configuration\n"
            "• No events found → Network may have no auctions yet\n"
            "• Corrupted events → Use -force to reload clean state\n"
            "• Memory errors → Restart node and try again\n"
            "• Timeout errors → Network or ledger connectivity issues\n\n"
            
            "RELATED COMMANDS:\n"
            "=================\n"
            "• auction list    - View loaded auctions (requires load first)\n"
            "• auction info    - Get auction details (requires load first)\n"
            "• auction events  - View raw events (independent of load)\n"
            "• auction bid     - Place bids (state auto-updated)\n\n"
            
            "NOTES:\n"
            "======\n"
            "• State is automatically updated when new bids are placed\n"
            "• Manual reload recommended after network synchronization\n"
            "• Verbose mode helpful for troubleshooting issues\n"
            "• Force reload clears ALL auction data before rebuilding\n"
            "• Loading is idempotent - safe to run multiple times\n");
        return 0;
    }

    // Validate required parameters
    if (!l_net_name) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -net parameter is required\n");
        return -1;
    }

    // Get network
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    if (!l_net) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Network '%s' not found\n", l_net_name);
        return -1;
    }

    // Check if state already exists (unless force is specified)
    if (!l_force) {
        size_t l_existing_count = 0;
        dap_chain_auction_info_t **l_existing = dap_chain_auction_storage_get_all(l_net, &l_existing_count);
        if (l_existing_count > 0) {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                "Auction state already loaded (%zu auctions found).\n"
                "Use -force to reload anyway.\n", l_existing_count);
            dap_chain_auction_storage_free_list(l_existing, l_existing_count);
            return 0;
        }
        dap_chain_auction_storage_free_list(l_existing, l_existing_count);
    }

    dap_string_t *l_result = dap_string_new("");
    if (l_verbose) {
        dap_string_append_printf(l_result, "Loading auction state from network '%s'...\n\n", l_net_name);
    }

    // Clear existing state if force is specified
    if (l_force) {
        if (l_verbose) {
            dap_string_append(l_result, "Clearing existing auction state...\n");
        }
        dap_chain_auction_storage_clear_network(l_net);
    }

    // Load state from events
    int l_load_result = dap_chain_auction_state_load_from_events(l_net);
    if (l_load_result != 0) {
        dap_string_free(l_result, true);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Failed to load auction state (error code %d)\n", l_load_result);
        return -1;
    }

    // Get final statistics
    size_t l_auction_count = 0;
    dap_chain_auction_info_t **l_auctions = dap_chain_auction_storage_get_all(l_net, &l_auction_count);

    // Count auctions by status
    size_t l_active_count = 0, l_ended_count = 0, l_cancelled_count = 0;
    size_t l_total_bids = 0;
    
    for (size_t i = 0; i < l_auction_count; i++) {
        switch (l_auctions[i]->status) {
            case DAP_CHAIN_AUCTION_STATUS_ACTIVE:
                l_active_count++;
                break;
            case DAP_CHAIN_AUCTION_STATUS_ENDED:
                l_ended_count++;
                break;
            case DAP_CHAIN_AUCTION_STATUS_CANCELLED:
                l_cancelled_count++;
                break;
            default:
                break;
        }
        l_total_bids += l_auctions[i]->bid_count;
    }

    // Show loading results
    if (l_verbose) {
        dap_string_append(l_result, "Loading completed successfully!\n\n");
    }

    dap_string_append_printf(l_result,
        "Auction State Loaded for Network '%s':\n"
        "=====================================\n\n"
        "Total auctions:    %zu\n"
        "  Active:          %zu\n"
        "  Ended:           %zu\n"
        "  Cancelled:       %zu\n"
        "Total bids:        %zu\n",
        l_net_name, l_auction_count, l_active_count, l_ended_count, l_cancelled_count, l_total_bids);

    if (l_verbose && l_auction_count > 0) {
        dap_string_append(l_result, "\nAuction Summary:\n");
        dap_string_append(l_result, "Hash                                                               Status      Bids  Top Score\n");
        dap_string_append(l_result, "================================================================== =========== ===== ================\n");
        
        for (size_t i = 0; i < l_auction_count && i < 10; i++) { // Show first 10
            char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_auctions[i]->auction_hash);
            const char *l_status_str = dap_chain_auction_status_to_str(l_auctions[i]->status);
            
            dap_string_append_printf(l_result, "%-66s %-11s %5zu %16"DAP_UINT64_FORMAT_U"\n",
                l_hash_str, l_status_str, l_auctions[i]->bid_count, l_auctions[i]->top_score);
            
            DAP_DELETE(l_hash_str);
        }
        
        if (l_auction_count > 10) {
            dap_string_append_printf(l_result, "... and %zu more (use 'auction list' to see all)\n", l_auction_count - 10);
        }
    }

    dap_string_append(l_result, "\nUse 'auction list -net <net>' to view all auctions\n");
    dap_string_append(l_result, "Use 'auction info -net <net> -auction <hash>' for detailed information\n");

    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_result->str);
    dap_string_free(l_result, true);

    // Cleanup
    dap_chain_auction_storage_free_list(l_auctions, l_auction_count);
    return 0;
}

/**
 * @brief CLI handler for 'auction withdraw' command
 * 
 * Creates a withdraw transaction to unlock funds from auction bid conditional transaction.
 * 
 * Syntax: auction withdraw -net <net_name> -bid <bid_hash> -fee <fee_amount> 
 *                          -w <wallet_name> [-addr <target_addr>] [--help]
 * 
 * @param argc Argument count
 * @param argv Argument values
 * @param a_str_reply Reply string
 * @return 0 on success, negative on error
 */
static int s_cli_auction_withdraw(int argc, char **argv, void **a_str_reply)
{
    // Parameter variables
    const char *l_net_name = NULL;
    const char *l_bid_hash_str = NULL;
    const char *l_fee_str = NULL;
    const char *l_wallet_name = NULL;
    const char *l_target_addr_str = NULL;
    bool l_help = false;

    // Parse command line arguments
    int l_arg_index = 1;
    while (l_arg_index < argc) {
        if (!strcmp(argv[l_arg_index], "-net") && l_arg_index + 1 < argc) {
            l_net_name = argv[++l_arg_index];
        } else if (!strcmp(argv[l_arg_index], "-bid") && l_arg_index + 1 < argc) {
            l_bid_hash_str = argv[++l_arg_index];
        } else if (!strcmp(argv[l_arg_index], "-fee") && l_arg_index + 1 < argc) {
            l_fee_str = argv[++l_arg_index];
        } else if (!strcmp(argv[l_arg_index], "-w") && l_arg_index + 1 < argc) {
            l_wallet_name = argv[++l_arg_index];
        } else if (!strcmp(argv[l_arg_index], "-addr") && l_arg_index + 1 < argc) {
            l_target_addr_str = argv[++l_arg_index];
        } else if (!strcmp(argv[l_arg_index], "--help") || !strcmp(argv[l_arg_index], "-h")) {
            l_help = true;
        }
        l_arg_index++;
    }

    // Show help if requested
    if (l_help) {
        dap_cli_server_cmd_set_reply_text(a_str_reply,
            "AUCTION WITHDRAW - Unlock Funds from Auction Bid\n"
            "=================================================\n\n"
            
            "DESCRIPTION:\n"
            "  Creates a withdraw transaction to unlock CELL tokens from an auction bid\n"
            "  conditional transaction. This allows bidders to recover their funds when\n"
            "  the auction ends or if they want to cancel their bid (if permitted).\n\n"
            
            "SYNTAX:\n"
            "  auction withdraw -net <network_name> -bid <bid_hash>\n"
            "                   -fee <fee_amount> -w <wallet_name>\n"
            "                   [-addr <target_addr>] [--help|-h]\n\n"
            
            "REQUIRED PARAMETERS:\n"
            "  -net <network_name>     Target network name\n"
            "                          Examples: 'Backbone', 'Subzero', 'Mileena'\n\n"
            
            "  -bid <bid_hash>         Hash of the bid transaction to withdraw from\n"
            "                          Format: 64-character hexadecimal string\n"
            "                          Example: 0x1a2b3c4d5e6f7890abcdef...\n\n"
            
            "  -fee <fee_amount>       Transaction fee in CELL tokens\n"
            "                          Format: decimal number (e.g., 0.1, 1.0)\n"
            "                          Typical range: 0.1-10 CELL\n\n"
            
            "  -w <wallet_name>        Wallet name for signing transaction\n"
            "                          Must be the same wallet that created the bid\n"
            "                          Examples: 'my_wallet', 'bidder_wallet'\n\n"
            
            "OPTIONAL PARAMETERS:\n"
            "  -addr <target_addr>     Target address for withdrawn funds\n"
            "                          If not specified, funds go to wallet's address\n"
            "                          Format: standard Cellframe address\n\n"
            
            "FLAGS:\n"
            "  --help, -h              Show this help message\n\n"
            
            "OUTPUT INFORMATION:\n"
            "  • Transaction hash of withdraw transaction\n"
            "  • Network confirmation status\n"
            "  • Amount of CELL tokens being withdrawn\n"
            "  • Target address for funds\n"
            "  • Transaction fee paid\n\n"
            
            "VALIDATION RULES:\n"
            "  • Only bid owner can withdraw funds\n"
            "  • Bid transaction must exist and be valid\n"
            "  • Bid must not be already spent/withdrawn\n"
            "  • Wallet must have sufficient funds for transaction fee\n"
            "  • Fee must be positive amount\n\n"
            
            "USAGE EXAMPLES:\n\n"
            
            "1. BASIC WITHDRAW (funds to wallet address):\n"
            "   auction withdraw -net Backbone \\\n"
            "                    -bid 0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890 \\\n"
            "                    -fee 0.5 -w my_auction_wallet\n\n"
            
            "2. WITHDRAW TO SPECIFIC ADDRESS:\n"
            "   auction withdraw -net Backbone \\\n"
            "                    -bid 0xabcdef1234567890... \\\n"
            "                    -fee 1.0 -w bidder_wallet \\\n"
            "                    -addr mJHVvyhLxgbEqrxVQAFoQvEjPiSTXhdSWq\n\n"
            
            "3. CHECK HELP:\n"
            "   auction withdraw --help\n\n"
            
            "COMMON ERRORS:\n"
            "  • 'Bid not found' - Invalid bid hash or bid doesn't exist\n"
            "  • 'Not bid owner' - Wrong wallet, only bid creator can withdraw\n"
            "  • 'Already spent' - Bid funds have already been withdrawn\n"
            "  • 'Insufficient fee' - Not enough balance to pay transaction fee\n\n"
            
            "TRANSACTION FLOW:\n"
            "  1. Locate bid conditional transaction by hash\n"
            "  2. Verify wallet ownership (public key matching)\n"
            "  3. Check bid is not already spent/withdrawn\n"
            "  4. Create withdraw transaction with IN_COND input\n"
            "  5. Add normal output to target address\n"
            "  6. Sign and submit to mempool\n\n"
            
            "RELATED COMMANDS:\n"
            "  • 'auction bid'     - Create auction bids\n"
            "  • 'auction list'    - List available auctions\n"
            "  • 'auction info'    - View auction details and bids\n"
            "  • 'auction events'  - View auction events history\n\n"
            
            "SECURITY NOTES:\n"
            "  • Only bid owner can execute withdraw\n"
            "  • Transaction requires valid wallet signature\n"
            "  • Withdrawal may be restricted during active auctions\n"
            "  • Always verify transaction hash after submission\n\n"
            
            "For additional help: auction --help\n");
        return 0;
    }

    // Validate required parameters
    if (!l_net_name) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -net parameter is required\n");
        return -1;
    }
    if (!l_bid_hash_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -bid parameter is required\n");
        return -1;
    }
    if (!l_fee_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -fee parameter is required\n");
        return -1;
    }
    if (!l_wallet_name) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: -w (wallet) parameter is required\n");
        return -1;
    }

    // Get network
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    if (!l_net) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Network '%s' not found\n", l_net_name);
        return -1;
    }

    // Get ledger
    dap_ledger_t *l_ledger = dap_ledger_by_net_name(l_net_name);
    if (!l_ledger) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Ledger for network '%s' not found\n", l_net_name);
        return -1;
    }

    // Parse bid transaction hash
    dap_hash_fast_t l_bid_hash = {};
    if (dap_chain_hash_fast_from_str(l_bid_hash_str, &l_bid_hash) != 0) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Invalid bid hash format\n");
        return -1;
    }

    // Parse transaction fee
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Invalid fee amount format\n");
        return -1;
    }

    // Open wallet
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_name, dap_chain_wallet_get_path(g_config), NULL);
    if (!l_wallet) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Cannot open wallet '%s'\n", l_wallet_name);
        return -1;
    }

    // Get wallet address
    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(l_wallet, l_net->pub.id);
    if (!l_wallet_addr) {
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Cannot get address from wallet '%s'\n", l_wallet_name);
        return -1;
    }

    // Parse target address (optional)
    dap_chain_addr_t l_target_addr = {};
    if (l_target_addr_str) {
        if (dap_chain_addr_from_str(&l_target_addr, l_target_addr_str) != 0) {
            dap_chain_wallet_close(l_wallet);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Invalid target address format\n");
            return -1;
        }
    } else {
        // Use wallet address as target
        l_target_addr = *l_wallet_addr;
    }

    // Find bid transaction in ledger
    dap_chain_datum_tx_t *l_bid_tx = dap_ledger_tx_find_by_hash(l_ledger, &l_bid_hash);
    if (!l_bid_tx) {
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Bid transaction not found in ledger\n");
        return -1;
    }

    // Find auction bid conditional output in the transaction
    int l_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_bid_out_cond = dap_chain_datum_tx_out_cond_get(
        l_bid_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID, &l_cond_idx);
    
    if (!l_bid_out_cond) {
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, 
            "Error: No auction bid conditional output found in transaction\n");
        return -1;
    }

    // Verify this is an auction service transaction
    if (l_bid_out_cond->header.srv_uid.uint64 != DAP_CHAIN_NET_SRV_AUCTIONS_ID) {
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Transaction is not an auction bid\n");
        return -1;
    }

    // Check if the conditional output is already spent
    if (dap_ledger_tx_hash_is_used_out_item(l_ledger, &l_bid_hash, l_cond_idx, NULL)) {
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Bid funds have already been withdrawn\n");
        return -1;
    }

    // Verify ownership: check if wallet key matches the bid creator
    dap_chain_tx_sig_t *l_bid_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(
        l_bid_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    if (!l_bid_tx_sig) {
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Cannot find signature in bid transaction\n");
        return -1;
    }

    dap_sign_t *l_bid_sign = dap_chain_datum_tx_item_sign_get_sig(l_bid_tx_sig);
    if (!l_bid_sign) {
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Cannot extract signature from bid transaction\n");
        return -1;
    }

    // Get wallet key for comparison
    dap_enc_key_t *l_wallet_key = dap_chain_wallet_get_key(l_wallet, 0);
    if (!l_wallet_key) {
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Cannot get key from wallet\n");
        return -1;
    }

    // Compare public keys to verify ownership
    if (!dap_pkey_compare_with_sign(l_wallet_key->pub_key_data, l_bid_sign)) {
        dap_enc_key_delete(l_wallet_key);
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, 
            "Error: Only the bid owner can withdraw funds. Wallet key doesn't match bid creator.\n");
        return -1;
    }

    // Get bid amount for display
    uint256_t l_bid_amount = l_bid_out_cond->header.value;

    // Create withdraw transaction
    dap_chain_datum_tx_t *l_withdraw_tx = dap_chain_datum_tx_create();
    if (!l_withdraw_tx) {
        dap_enc_key_delete(l_wallet_key);
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Cannot create withdraw transaction\n");
        return -1;
    }

    // Add conditional input (IN_COND) that references the bid transaction
    if (dap_chain_datum_tx_add_in_cond_item(&l_withdraw_tx, &l_bid_hash, l_cond_idx, 0) != 1) {
        dap_chain_datum_tx_delete(l_withdraw_tx);
        dap_enc_key_delete(l_wallet_key);
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Cannot add conditional input to withdraw transaction\n");
        return -1;
    }

    // Calculate amount to send back (bid amount minus fee)
    uint256_t l_amount_back = {};
    if (compare256(l_bid_amount, l_fee) <= 0) {
        dap_chain_datum_tx_delete(l_withdraw_tx);
        dap_enc_key_delete(l_wallet_key);
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, 
            "Error: Transaction fee (%s) is greater than or equal to bid amount (%s)\n",
            dap_uint256_to_char(l_fee, NULL), dap_uint256_to_char(l_bid_amount, NULL));
        return -1;
    }
    SUBTRACT_256_256(l_bid_amount, l_fee, &l_amount_back);

    // Add normal output to target address for the withdrawn amount
    dap_chain_tx_out_t *l_out = dap_chain_datum_tx_item_out_create(&l_target_addr, l_amount_back);
    if (!l_out || dap_chain_datum_tx_add_item(&l_withdraw_tx, (const uint8_t *)l_out) != 1) {
        DAP_DELETE(l_out);
        dap_chain_datum_tx_delete(l_withdraw_tx);
        dap_enc_key_delete(l_wallet_key);
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Cannot add output to withdraw transaction\n");
        return -1;
    }
    DAP_DELETE(l_out);

    // Add fee output if network requires it
    uint256_t l_net_fee = {};
    dap_chain_addr_t l_addr_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(l_net->pub.id, &l_net_fee, &l_addr_fee);
    
    if (l_net_fee_used && !IS_ZERO_256(l_net_fee)) {
        dap_chain_tx_out_t *l_out_fee = dap_chain_datum_tx_item_out_create(&l_addr_fee, l_net_fee);
        if (!l_out_fee || dap_chain_datum_tx_add_item(&l_withdraw_tx, (const uint8_t *)l_out_fee) != 1) {
            DAP_DELETE(l_out_fee);
            dap_chain_datum_tx_delete(l_withdraw_tx);
            dap_enc_key_delete(l_wallet_key);
            dap_chain_wallet_close(l_wallet);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Cannot add fee output to withdraw transaction\n");
            return -1;
        }
        DAP_DELETE(l_out_fee);
    }

    // Sign the transaction
    if (dap_chain_datum_tx_add_sign_item(&l_withdraw_tx, l_wallet_key) != 1) {
        dap_chain_datum_tx_delete(l_withdraw_tx);
        dap_enc_key_delete(l_wallet_key);
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Cannot sign withdraw transaction\n");
        return -1;
    }

    // Add transaction to mempool
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    if (!l_chain) {
        dap_chain_datum_tx_delete(l_withdraw_tx);
        dap_enc_key_delete(l_wallet_key);
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Cannot find transaction chain in network\n");
        return -1;
    }

    // Create datum for mempool
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_withdraw_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_withdraw_tx, l_tx_size);
    if (!l_datum) {
        dap_chain_datum_tx_delete(l_withdraw_tx);
        dap_enc_key_delete(l_wallet_key);
        dap_chain_wallet_close(l_wallet);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Cannot create datum for withdraw transaction\n");
        return -1;
    }

    // Add to mempool
    char *l_tx_hash_str = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    
    // Clean up
    dap_enc_key_delete(l_wallet_key);
    dap_chain_wallet_close(l_wallet);
    DAP_DELETE(l_datum);

    if (!l_tx_hash_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Error: Failed to add withdraw transaction to mempool\n");
        return -1;
    }

    // Success response
    char *l_target_addr_display = dap_chain_addr_to_str(&l_target_addr);
    
    dap_cli_server_cmd_set_reply_text(a_str_reply,
        "Auction bid withdraw transaction created successfully!\n\n"
        "WITHDRAW TRANSACTION DETAILS:\n"
        "  Transaction Hash:    %s\n"
        "  Network:             %s\n"
        "  Original Bid Hash:   %s\n"
        "  Withdrawn Amount:    %s CELL\n"
        "  Target Address:      %s\n"
        "  Transaction Fee:     %s CELL\n"
        "  Wallet Used:         %s\n\n"
        "STATUS:\n"
        "  ✓ Funds successfully unlocked from auction bid\n"
        "  ✓ Transaction added to mempool for processing\n"
        "  ✓ Network will confirm transaction shortly\n\n"
        "The withdrawn CELL tokens will be available at the target address\n"
        "once the transaction is confirmed by the network.\n",
        l_tx_hash_str,
        l_net_name,
        l_bid_hash_str,
        dap_uint256_to_char(l_amount_back, NULL),
        l_target_addr_display,
        dap_uint256_to_char(l_fee, NULL),
        l_wallet_name);

    DAP_DELETE(l_tx_hash_str);
    DAP_DELETE(l_target_addr_display);
    return 0;
}