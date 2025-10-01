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
#include "dap_chain_net_srv_auctions.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_node_cli.h"
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

#define LOG_TAG "dap_chain_net_srv_auctions"
#define set_ret_code(p,ret_code) if (p) { *p = ret_code;}

// Global auction cache (one per application instance)
static dap_auction_cache_t *s_auction_cache = NULL;

// Error codes
enum error_code {
    AUCTION_NO_ERROR = 0,
    NET_ARG_ERROR = 1,
    NET_ERROR = 2,
    AUCTION_HASH_ARG_ERROR = 3,
    AUCTION_HASH_FORMAT_ERROR = 4,
    WALLET_ARG_ERROR = 5,
    WALLET_OPEN_ERROR = 6,
    AMOUNT_ARG_ERROR = 9,
    AMOUNT_FORMAT_ERROR = 10,
    LOCK_ARG_ERROR = 11,
    LOCK_FORMAT_ERROR = 12,
    FEE_ARG_ERROR = 13,
    FEE_FORMAT_ERROR = 14,
    BID_TX_HASH_ARG_ERROR = 15,
    BID_TX_HASH_FORMAT_ERROR = 16,
    AUCTION_NOT_FOUND_ERROR = 17,
    AUCTION_NOT_ACTIVE_ERROR = 18,
    BID_CREATE_ERROR = 19,
    WITHDRAW_CREATE_ERROR = 20,
    COMMAND_NOT_RECOGNIZED = 21,
    AUCTION_NAME_ARG_ERROR = 22,
    AUCTION_DURATION_ARG_ERROR = 23,
    AUCTION_DURATION_FORMAT_ERROR = 24,
    AUCTION_END_TIME_ERROR = 25,
    PROJECT_ID_ARG_ERROR = 27,
    PROJECT_ID_FORMAT_ERROR = 28,
    AUCTION_CACHE_NOT_INITIALIZED = 29,
    PROJECT_NOT_FOUND_IN_AUCTION = 30,
    INVALID_EVENT_TYPE_ERROR = 31
};

// Callbacks
static void s_auction_bid_callback_updater(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_prev_out_item);
static int s_auction_bid_callback_verificator(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx_in, bool a_owner);
// Forward declaration for optimization function
static dap_auction_cache_item_t *s_find_auction_by_hash_fast(dap_auction_cache_t *a_cache, const dap_hash_fast_t *a_auction_hash);

int com_auction(int argc, char **argv, void **str_reply, int a_version);

/**
 * @brief Service initialization
 * @return Returns 0 on success
 */
int dap_chain_net_srv_auctions_init(void)
{
    // Initialize auction cache
    s_auction_cache = dap_auction_cache_create();
    if (!s_auction_cache) {
        log_it(L_CRITICAL, "Failed to create auction cache");
        return -1;
    }
    
    // Register verificator for auction bid conditional outputs
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID, 
                               s_auction_bid_callback_verificator, 
                               s_auction_bid_callback_updater, 
                               NULL);

    // Register event notification callback for all existing networks
    dap_chain_net_t *l_net = dap_chain_net_iter_start();
    while (l_net) {
        if (l_net->pub.ledger) {
            dap_ledger_event_notify_add(l_net->pub.ledger, dap_auction_cache_event_callback, s_auction_cache);
            log_it(L_DEBUG, "Registered auction event callback for network %s", l_net->pub.name);
        } else {
            log_it(L_WARNING, "Network %s has no ledger, skipping auction event registration", l_net->pub.name);
        }
        l_net = dap_chain_net_iter_next(l_net);
    }
    
    dap_cli_server_cmd_add ("auction", com_auction, NULL, "Auction commands",
                "bid -net <network> -auction <auction_name|tx_hash> -amount <value> -lock_period <3..24> -project <project_id> -fee <value> -w <wallet>\n"
                "\tPlace a bid on an auction for a specific project\n"
                "\t-project: project ID (uint32) for which the bid is made\n\n"
                "withdraw -net <network> -bid_tx_hash <hash> -fee <value> -w <wallet>\n"
                "\tWithdraw a bid from an auction\n\n"
                "list -net <network> [-active_only] [-projects]\n"
                "\tList all auctions or active auctions only\n"
                "\t-active_only: show only active auctions\n"
                "\t-projects: include basic project information\n\n"
                "info -net <network> -auction <auction_name|tx_hash>\n"
                "\tGet detailed information about a specific auction\n\n"
                "events -net <network> [-auction <auction_name|tx_hash>] [-type <event_type>]\n"
                "\tGet auction events history\n"
                "\t-auction: filter events for specific auction\n"
                "\t-type: filter events for specific type\n\n"
                "stats -net <network>\n"
                "\tGet auction statistics\n\n"
                "  Examples:\n"
                "  auction list -net myCellFrame -active_only -projects\n"
                "  auction bid -net myCellFrame -auction <auction_name|tx_hash> -amount 1000 -lock_period 6 -project 1 -fee 0.1 -w myWallet\n"
                "  auction info -net myCellFrame -auction <auction_name|tx_hash>\n"
                "  auction withdraw -net myCellFrame -bid_tx_hash <hash> -fee 0.1 -w myWallet\n"
                "  auction events -net myCellFrame -auction <auction_name|tx_hash> -type <event_type>\n"
                "  auction stats -net myCellFrame\n"
                "  Notes:\n"
                "  - Each bid has lock period (3-24 months) set by -lock_period option.\n"
                "    This period is used AFTER the auction ends to lock the bid amount for the winner projects only for provided time.\n"
                "    For loosed projects bid can be withdrawn immediatly after the auction ends.\n"
                "    It's no way to unlock the bid amount before the auction ends.\n\n");
    log_it(L_NOTICE, "Auction service initialized successfully with cache monitoring");
    return 0;
}

//====================================================================
// AUCTION CACHE IMPLEMENTATION
//====================================================================

/**
 * @brief Create auction cache
 * @return Returns auction cache instance or NULL on error
 */
dap_auction_cache_t *dap_auction_cache_create(void)
{
    dap_auction_cache_t *l_cache = DAP_NEW_Z(dap_auction_cache_t);
    if (!l_cache) {
        log_it(L_CRITICAL, "Memory allocation error for auction cache");
        return NULL;
    }
    
    // Initialize read-write lock
    if (pthread_rwlock_init(&l_cache->cache_rwlock, NULL) != 0) {
        log_it(L_ERROR, "Failed to initialize cache rwlock");
        DAP_DELETE(l_cache);
        return NULL;
    }
    
    l_cache->auctions = NULL;
    l_cache->auctions_by_hash = NULL;    // Initialize secondary hash table
    l_cache->total_auctions = 0;
    l_cache->active_auctions = 0;
    
    log_it(L_DEBUG, "Auction cache created successfully");
    return l_cache;
}

/**
 * @brief Delete auction cache and cleanup all data
 * @param a_cache Cache instance to delete
 */
void dap_auction_cache_delete(dap_auction_cache_t *a_cache)
{
    if (!a_cache)
        return;
    
    pthread_rwlock_wrlock(&a_cache->cache_rwlock);
    
    // Clean up all auctions and their bids and projects
    dap_auction_cache_item_t *l_auction, *l_tmp_auction;
    HASH_ITER(hh, a_cache->auctions, l_auction, l_tmp_auction) {
        
        // Clean up all projects in this auction
        dap_auction_project_cache_item_t *l_project, *l_tmp_project;
        HASH_ITER(hh, l_auction->projects, l_project, l_tmp_project) {
            HASH_DEL(l_auction->projects, l_project);
            // Clean up all bids in this project
            dap_auction_bid_cache_item_t *l_bid, *l_tmp_bid;
            HASH_ITER(hh, l_project->bids, l_bid, l_tmp_bid) {
                HASH_DEL(l_project->bids, l_bid);
                DAP_DELETE(l_bid);
            }
            DAP_DELETE(l_project);
        }
        
        // Remove auction from both hash tables
        HASH_DELETE(hh, a_cache->auctions, l_auction);           // Remove from primary table (by GUUID)
        HASH_DELETE(hh_hash, a_cache->auctions_by_hash, l_auction); // Remove from secondary table (by auction_tx_hash)
        
        // Clean up auction data
        DAP_DELETE(l_auction->guuid);
        DAP_DELETE(l_auction->description);
        DAP_DELETE(l_auction->winners_ids);  // Clean up winners array
        DAP_DELETE(l_auction);
    }
    
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    pthread_rwlock_destroy(&a_cache->cache_rwlock);
    DAP_DELETE(a_cache);
    
    log_it(L_DEBUG, "Auction cache deleted");
}

/**
 * @brief Add new auction to cache from auction started event data
 * @param a_cache Cache instance
 * @param a_auction_hash Hash of auction transaction
 * @param a_net_id Network ID
 * @param a_guuid Event group name for this auction
 * @param a_started_data Auction started event data
 * @param a_tx_timestamp Timestamp of the auction transaction
 * @return Returns 0 on success, negative error code otherwise
 */
int dap_auction_cache_add_auction(dap_auction_cache_t *a_cache, 
                                  dap_hash_fast_t *a_auction_hash,
                                  dap_chain_net_id_t a_net_id,
                                  const char *a_guuid,
                                  dap_chain_tx_event_data_auction_started_t *a_started_data,
                                  dap_time_t a_tx_timestamp)
{
    if (!a_cache || !a_auction_hash || !a_guuid)
        return -1;
    
    pthread_rwlock_wrlock(&a_cache->cache_rwlock);
    
    // Check if auction already exists by GUUID (faster than hash iteration)
    dap_auction_cache_item_t *l_existing = NULL;
    HASH_FIND_STR(a_cache->auctions, a_guuid, l_existing);
    if (l_existing) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_WARNING, "Auction %s already exists in cache", 
               dap_chain_hash_fast_to_str_static(a_auction_hash));
        return -2;
    }
    
    // Create new auction cache item
    dap_auction_cache_item_t *l_auction = DAP_NEW_Z(dap_auction_cache_item_t);
    if (!l_auction) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_CRITICAL, "Memory allocation error for auction cache item");
        return -3;
    }
    
    // Initialize basic auction data
    *l_auction = (dap_auction_cache_item_t) { .auction_tx_hash = *a_auction_hash,
                                              .net_id = a_net_id,
                                              .created_time = a_tx_timestamp,
                                              .start_time = a_tx_timestamp,
                                              .end_time = a_tx_timestamp,
                                              .guuid = dap_strdup(a_guuid),
                                              .status = DAP_AUCTION_STATUS_ACTIVE
    };

    // Calculate end time from auction started data if provided
    if (a_started_data) {
        switch (a_started_data->time_unit) {
            case DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_HOURS:
                l_auction->end_time = a_tx_timestamp + (a_started_data->duration * 3600);
                break;
            case DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_DAYS:
                l_auction->end_time = a_tx_timestamp + (a_started_data->duration * 24 * 3600);
                break;
            case DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_WEEKS:
                l_auction->end_time = a_tx_timestamp + (a_started_data->duration * 7 * 24 * 3600);
                break;
            case DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_MONTHS:
                l_auction->end_time = a_tx_timestamp + (a_started_data->duration * 30 * 24 * 3600);
                break;
            default:
                // Fallback to seconds
                l_auction->end_time = a_tx_timestamp + a_started_data->duration;
                break;
        }
        
        // Add projects from the auction started data
        if (a_started_data->projects_cnt > 0) {
           
            // Create project cache entries for each project ID
            for (uint8_t i = 0; i < a_started_data->projects_cnt; i++) {
                uint64_t l_project_id = a_started_data->project_ids[i];              
                // Create project cache item
                dap_auction_project_cache_item_t *l_project = NULL;
                HASH_FIND(hh, l_auction->projects, &l_project_id, sizeof(uint64_t), l_project);
                if (l_project) {
                    log_it(L_ERROR, "Project %" DAP_UINT64_FORMAT_U " already exists in auction cache", l_project_id);
                    continue;
                }
                l_project = DAP_NEW_Z(dap_auction_project_cache_item_t);
                if (!l_project) {
                    log_it(L_CRITICAL, "Memory allocation error for project cache item");
                    return -4;
                }
                l_project->project_id = l_project_id;

                // Add to projects hash table
                HASH_ADD(hh, l_auction->projects, project_id, sizeof(uint64_t), l_project);
            }
        }
        
        log_it(L_DEBUG, "Added auction %s with %u projects, duration: %lu %s", 
               dap_chain_hash_fast_to_str_static(a_auction_hash),
               a_started_data->projects_cnt,
               a_started_data->duration,
               a_started_data->time_unit == DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_HOURS ? "hours" :
               a_started_data->time_unit == DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_DAYS ? "days" :
               a_started_data->time_unit == DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_WEEKS ? "weeks" :
               a_started_data->time_unit == DAP_CHAIN_TX_EVENT_DATA_TIME_UNIT_MONTHS ? "months" : "seconds");
    }
    
    // Add to both hash tables for optimal performance
    HASH_ADD_STR(a_cache->auctions, guuid, l_auction);  // Primary table by GUUID
    HASH_ADD(hh_hash, a_cache->auctions_by_hash, auction_tx_hash, sizeof(dap_hash_fast_t), l_auction);  // Secondary table by tx hash
    a_cache->total_auctions++;
    a_cache->active_auctions++;
    
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    
    log_it(L_DEBUG, "Added auction %s to cache with ACTIVE status", 
           dap_chain_hash_fast_to_str_static(a_auction_hash));
    return 0;
}

/**
 * @brief Add bid to auction in cache
 * @param a_cache Cache instance
 * @param a_auction_hash Hash of auction transaction
 * @param a_bid_hash Hash of bid transaction
 * @param a_bid_amount Bid amount
 * @param a_lock_time Lock time in seconds
 * @param a_project_id ID of project this bid is for
 * @return Returns 0 on success, negative error code otherwise
 */
int dap_auction_cache_add_bid(dap_auction_cache_t *a_cache,
                              dap_hash_fast_t *a_auction_hash,
                              dap_hash_fast_t *a_bid_hash,
                              uint256_t a_bid_amount,
                              dap_time_t a_lock_time,
                              dap_time_t a_created_time,
                              uint64_t a_project_id)
{
    dap_return_val_if_fail(a_cache && a_bid_hash, -1);
    
    pthread_rwlock_wrlock(&a_cache->cache_rwlock);
    
    // Find auction using ultra-fast O(1) hash lookup
    dap_auction_cache_item_t *l_auction = s_find_auction_by_hash_fast(a_cache, a_auction_hash);
    if (!l_auction) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_WARNING, "Auction not found in cache for bid add (hash missing or not resolved by name)");
        return -2;
    }
          
    // Find project in auction cache
    dap_auction_project_cache_item_t *l_project = NULL;
    HASH_FIND(hh, l_auction->projects, &a_project_id, sizeof(uint64_t), l_project);
    if (!l_project) {
        log_it(L_ERROR, "Project not found in auction cache for bid add");
        return -4;
    }

    // Create new bid cache item
    dap_auction_bid_cache_item_t *l_bid = DAP_NEW_Z(dap_auction_bid_cache_item_t);
    if (!l_bid) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_CRITICAL, "Memory allocation error for bid cache item");
        return -5;
    }

    // Update project aggregation
    if (SUM_256_256(l_project->total_amount, a_bid_amount, &l_project->total_amount)) {
        log_it(L_ERROR, "Overflow detected when adding bid amount to project total");
    }


    // Initialize bid data
    *l_bid = (dap_auction_bid_cache_item_t) { .bid_tx_hash = *a_bid_hash,
                                             .bid_amount = a_bid_amount,
                                             .lock_time = a_lock_time,
                                             .created_time = a_created_time
                                            };
    
    // Add to auction's bids
    HASH_ADD(hh, l_project->bids, bid_tx_hash, sizeof(dap_hash_fast_t), l_bid);
    l_project->active_bids_count++;
    l_auction->bids_count++;
    l_auction->active_bids_count++;
        
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    
    log_it(L_DEBUG, "Added bid %s to auction %s in cache", 
                        dap_chain_hash_fast_to_str_static(a_bid_hash), dap_chain_hash_fast_to_str_static(a_auction_hash));
    return 0;
}

/**
 * @brief Update auction status in cache
 * @param a_cache Cache instance
 * @param a_auction_hash Hash of auction transaction
 * @param a_new_status New auction status
 * @return Returns 0 on success, negative error code otherwise
 */
int dap_auction_cache_update_auction_status(dap_auction_cache_t *a_cache,
                                           dap_hash_fast_t *a_auction_hash,
                                           dap_auction_status_t a_new_status)
{
    dap_return_val_if_fail(a_cache && a_auction_hash, -1);
    
    pthread_rwlock_wrlock(&a_cache->cache_rwlock);
    
    // Find auction using ultra-fast O(1) hash lookup
    dap_auction_cache_item_t *l_auction = s_find_auction_by_hash_fast(a_cache, a_auction_hash);
    
    if (!l_auction) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_WARNING, "Auction %s not found in cache for status update", 
               dap_chain_hash_fast_to_str_static(a_auction_hash));
        return -2;
    }
    
    dap_auction_status_t l_old_status = l_auction->status;
    l_auction->status = a_new_status;
    
    // Update active auctions counter
    if (l_old_status == DAP_AUCTION_STATUS_ACTIVE && a_new_status != DAP_AUCTION_STATUS_ACTIVE) {
        if (a_cache->active_auctions > 0)
            a_cache->active_auctions--;
    } else if (l_old_status != DAP_AUCTION_STATUS_ACTIVE && a_new_status == DAP_AUCTION_STATUS_ACTIVE) {
        a_cache->active_auctions++;
    }
    
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    
    log_it(L_DEBUG, "Updated auction %s status from %s to %s", 
           dap_chain_hash_fast_to_str_static(a_auction_hash),
           dap_auction_status_to_str(l_old_status),
           dap_auction_status_to_str(a_new_status));
    return 0;
}

/**
 * @brief Mark bid as withdrawn in cache
 * @param a_cache Cache instance
 * @param a_bid_hash Hash of bid transaction
 * @return Returns 0 on success, negative error code otherwise
 */
int dap_auction_cache_withdraw_bid(dap_auction_project_cache_item_t *a_cache, dap_hash_fast_t *a_bid_hash)
{
    dap_return_val_if_fail(a_cache && a_bid_hash, -1);
    // Find matching bid by parameters from conditional output
    dap_auction_bid_cache_item_t *l_bid = NULL;
    HASH_FIND(hh, a_cache->bids, a_bid_hash, sizeof(dap_hash_fast_t), l_bid);

    if (!l_bid) {
        log_it(L_WARNING, "Bid %s not found in auction cache during bid withdrawal",
                dap_chain_hash_fast_to_str_static(a_bid_hash));
        return -2;
    }
    l_bid->is_withdrawn = true;
    if (a_cache->active_bids_count > 0)
        a_cache->active_bids_count--;
    log_it(L_DEBUG, "Marked bid %s as withdrawn in cache", 
           dap_chain_hash_fast_to_str_static(a_bid_hash));
    return 0;
}

/**
 * @brief Set winners of auction
 * @param a_cache Cache instance
 * @param a_auction_hash Hash of auction transaction
 * @param a_winners_cnt Number of winners
 * @param a_winners_ids Array of winner project IDs
 * @return Returns 0 on success, negative error code otherwise
 */
int dap_auction_cache_set_winners(dap_auction_cache_t *a_cache,
                                 dap_hash_fast_t *a_auction_hash,
                                 uint8_t a_winners_cnt,
                                 uint32_t *a_winners_ids)
{
    dap_return_val_if_fail(a_cache && a_auction_hash && a_winners_ids && a_winners_cnt > 0, -1);
    
    pthread_rwlock_wrlock(&a_cache->cache_rwlock);
    
    // Find auction using ultra-fast O(1) hash lookup
    dap_auction_cache_item_t *l_auction = s_find_auction_by_hash_fast(a_cache, a_auction_hash);
    
    if (!l_auction) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_WARNING, "Auction %s not found in cache for setting multiple winners", 
               dap_chain_hash_fast_to_str_static(a_auction_hash));
        return -2;
    }
    
    // Clean up previous winners array if exists
    DAP_DELETE(l_auction->winners_ids);
    
    // Set multiple winners information
    l_auction->has_winner = true;
    l_auction->winners_cnt = a_winners_cnt;
    l_auction->winners_ids = DAP_NEW_Z_SIZE(uint32_t, sizeof(uint32_t) * a_winners_cnt);
    if (!l_auction->winners_ids) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_CRITICAL, "Memory allocation error for winners array");
        return -3;
    }
    
    // Copy winners IDs
    memcpy(l_auction->winners_ids, a_winners_ids, sizeof(uint32_t) * a_winners_cnt);
    
    // Log the winners for debugging
    for (uint8_t i = 0; i < a_winners_cnt; i++) {
        log_it(L_DEBUG, "Winner #%u: project ID %u", i + 1, a_winners_ids[i]);
    }
    
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    
    log_it(L_DEBUG, "Set %u winners for auction %s", 
           a_winners_cnt, dap_chain_hash_fast_to_str_static(a_auction_hash));
    
    return 0;
}

/**
 * @brief Find auction in cache
 * @param a_cache Cache instance
 * @param a_auction_hash Hash of auction transaction
 * @return Returns auction cache item or NULL if not found
 */
dap_auction_cache_item_t *dap_auction_cache_find_auction(dap_auction_cache_t *a_cache,
                                                         dap_hash_fast_t *a_auction_hash)
{
    dap_return_val_if_fail(a_cache && a_auction_hash, NULL);
    
    pthread_rwlock_rdlock(&a_cache->cache_rwlock);
    
    // Direct O(1) hash lookup using optimized secondary table
    dap_auction_cache_item_t *l_auction = s_find_auction_by_hash_fast(a_cache, a_auction_hash);
    
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    return l_auction;
}

/**
 * @brief Diagnostic function to verify integrity of dual hash tables
 * @param a_cache Cache instance  
 * @return Returns true if integrity check passes
 */
static bool s_verify_dual_hash_table_integrity(dap_auction_cache_t *a_cache)
{
    dap_return_val_if_fail(a_cache, false);
    
    uint32_t primary_count = 0, secondary_count = 0;
    dap_auction_cache_item_t *l_auction, *l_tmp;
    
    // Count items in primary table (by GUUID)
    HASH_ITER(hh, a_cache->auctions, l_auction, l_tmp) {
        primary_count++;
        
        // Verify that each item in primary table exists in secondary table
        dap_auction_cache_item_t *l_found = NULL;
        HASH_FIND(hh_hash, a_cache->auctions_by_hash, &l_auction->auction_tx_hash, sizeof(dap_hash_fast_t), l_found);
        if (!l_found) {
            log_it(L_ERROR, "Integrity violation: auction %s found in primary but not in secondary table",
                   dap_chain_hash_fast_to_str_static(&l_auction->auction_tx_hash));
            return false;
        }
        if (l_found != l_auction) {
            log_it(L_ERROR, "Integrity violation: different auction objects for same hash");
            return false;
        }
    }
    
    // Count items in secondary table (by auction_tx_hash)  
    HASH_ITER(hh_hash, a_cache->auctions_by_hash, l_auction, l_tmp) {
        secondary_count++;
        
        // Verify that each item in secondary table exists in primary table
        dap_auction_cache_item_t *l_found = NULL;
        if (l_auction->guuid) {
            HASH_FIND_STR(a_cache->auctions, l_auction->guuid, l_found);
            if (!l_found) {
                log_it(L_ERROR, "Integrity violation: auction %s found in secondary but not in primary table",
                       l_auction->guuid);
                return false;
            }
            if (l_found != l_auction) {
                log_it(L_ERROR, "Integrity violation: different auction objects for same GUUID");
                return false;
            }
        }
    }
    
    // Verify counts match
    if (primary_count != secondary_count) {
        log_it(L_ERROR, "Integrity violation: table count mismatch - primary: %u, secondary: %u", 
               primary_count, secondary_count);
        return false;
    }
    
    if (primary_count != a_cache->total_auctions) {
        log_it(L_WARNING, "Count mismatch: tables have %u items but total_auctions=%u", 
               primary_count, a_cache->total_auctions);
    }
    
    log_it(L_DEBUG, "Hash table integrity check passed: %u auctions in both tables", primary_count);
    return true;
}

/**
 * @brief Fast auction lookup by hash using secondary hash table (O(1) performance)
 * @param a_cache Cache instance
 * @param a_auction_hash Hash of auction transaction
 * @return Returns auction cache item or NULL if not found
 */
static dap_auction_cache_item_t *s_find_auction_by_hash_fast(dap_auction_cache_t *a_cache, const dap_hash_fast_t *a_auction_hash)
{
    if (!a_cache || !a_auction_hash)
        return NULL;
    
    // Direct O(1) hash lookup using secondary table
    dap_auction_cache_item_t *l_auction = NULL;
    HASH_FIND(hh_hash, a_cache->auctions_by_hash, a_auction_hash, sizeof(dap_hash_fast_t), l_auction);
    return l_auction;
}

dap_auction_cache_item_t *dap_auction_cache_find_auction_by_name(dap_auction_cache_t *a_cache,
                                                                 const char *a_guuid)
{
    if (!a_cache || !a_guuid)
        return NULL;
    pthread_rwlock_rdlock(&a_cache->cache_rwlock);
    dap_auction_cache_item_t *l_auction = NULL, *l_tmp_auction = NULL;
    HASH_FIND_STR(a_cache->auctions, a_guuid, l_auction);
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    return l_auction;
}

int dap_auction_cache_update_auction_status_by_name(dap_auction_cache_t *a_cache,
                                                   const char *a_guuid,
                                                   dap_auction_status_t a_new_status)
{
    if (!a_cache || !a_guuid)
        return -1;
    pthread_rwlock_wrlock(&a_cache->cache_rwlock);
    dap_auction_cache_item_t *l_auction = NULL, *l_tmp_auction = NULL;
    HASH_FIND_STR(a_cache->auctions, a_guuid, l_auction);
    if (!l_auction) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        return -2;
    }
    dap_auction_status_t l_old_status = l_auction->status;
    l_auction->status = a_new_status;
    if (l_old_status == DAP_AUCTION_STATUS_ACTIVE && a_new_status != DAP_AUCTION_STATUS_ACTIVE) {
        if (a_cache->active_auctions > 0)
            a_cache->active_auctions--;
    } else if (l_old_status != DAP_AUCTION_STATUS_ACTIVE && a_new_status == DAP_AUCTION_STATUS_ACTIVE) {
        a_cache->active_auctions++;
    }
    pthread_rwlock_unlock(&a_cache->cache_rwlock);
    log_it(L_DEBUG, "Updated auction '%s' status from %s to %s",
        a_guuid,
           dap_auction_status_to_str(l_old_status),
           dap_auction_status_to_str(a_new_status));
    return 0;
}

/**
 * @brief Find bid in auction
 * @param a_auction Auction cache item
 * @param a_bid_hash Hash of bid transaction
 * @return Returns bid cache item or NULL if not found
 */
dap_auction_bid_cache_item_t *dap_auction_cache_find_bid(dap_auction_cache_item_t *a_auction,
                                                         dap_hash_fast_t *a_bid_hash)
{
    if (!a_auction || !a_bid_hash)
        return NULL;
    
    for (dap_auction_project_cache_item_t *l_project = a_auction->projects; l_project; l_project = l_project->hh.next) {
        dap_auction_bid_cache_item_t *l_bid = NULL;
        HASH_FIND(hh, l_project->bids, a_bid_hash, sizeof(dap_hash_fast_t), l_bid);
        if (l_bid) {
            return l_bid;
        }
    }
    
    return NULL;
}

/**
 * @brief Find project in auction
 * @param a_auction Auction cache item
 * @param a_project_hash Hash of project
 * @return Returns project cache item or NULL if not found
 */
dap_auction_project_cache_item_t *dap_auction_cache_find_project(dap_auction_cache_item_t *a_auction,
                                                                 uint64_t a_project_id)
{
    if (!a_auction || !a_project_id)
        return NULL;
    
    dap_auction_project_cache_item_t *l_project = NULL;
    HASH_FIND(hh, a_auction->projects, &a_project_id, sizeof(uint64_t), l_project);
    
    return l_project;
}

/**
 * @brief Event fixation callback for auction monitoring
 * @param a_arg User argument (auction cache)
 * @param a_ledger Ledger instance
 * @param a_event Event data
 * @param a_tx_hash Transaction hash
 * @param a_opcode Operation code (added/deleted)
 */
void dap_auction_cache_event_callback(void *a_arg, 
                                       dap_ledger_t *a_ledger,
                                       dap_chain_tx_event_t *a_event,
                                       dap_hash_fast_t *a_tx_hash,
                                       dap_chan_ledger_notify_opcodes_t a_opcode)
{
    if (!a_event || !a_tx_hash || !s_auction_cache) {
        log_it(L_WARNING, "Invalid parameters in auction event callback");
        return;
    }
    
    // Дополнительный отладочный вывод по входящему событию
    const char *l_group_name = a_event->group_name ? a_event->group_name : "(null)";
    const char *l_opcode_str =
            a_opcode == DAP_LEDGER_NOTIFY_OPCODE_ADDED   ? "ADDED" :
            a_opcode == DAP_LEDGER_NOTIFY_OPCODE_DELETED ? "DELETED" : "UNKNOWN";
    log_it(L_DEBUG, "Auction event received: type=%u opcode=%s tx=%s GUUID=\"%s\" data_size=%zu timestamp=%" DAP_UINT64_FORMAT_U,
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
        log_it(L_DEBUG, "Auction event data preview (%zu bytes): %s", l_preview_len, l_data_hex);
    }
    
    // Handle only auction-related events
    switch (a_event->event_type) {
        case DAP_CHAIN_TX_EVENT_TYPE_AUCTION_STARTED: {
            log_it(L_DEBUG, "Processing auction started event for %s", 
                   dap_chain_hash_fast_to_str_static(&a_event->tx_hash));
            
            if (a_opcode == DAP_LEDGER_NOTIFY_OPCODE_ADDED) {
                // Parse event data for auction started info
                if (a_event->event_data && a_event->event_data_size >= sizeof(dap_chain_tx_event_data_auction_started_t)) {
                    dap_chain_tx_event_data_auction_started_t *l_started_data = 
                        (dap_chain_tx_event_data_auction_started_t *)a_event->event_data;
                    
                    // Validate buffer size for potential project_ids array access
                    size_t l_required_size = sizeof(dap_chain_tx_event_data_auction_started_t) + 
                                           (l_started_data->projects_cnt * sizeof(uint32_t));
                    if (a_event->event_data_size < l_required_size) {
                        log_it(L_ERROR, "Event data size %zu is insufficient for %u projects (required: %zu)", 
                               a_event->event_data_size, l_started_data->projects_cnt, l_required_size);
                        return;
                    }
                    
                // Check if auction already exists in cache
                dap_auction_cache_item_t *l_auction = dap_auction_cache_find_auction(s_auction_cache, &a_event->tx_hash);
                if (!l_auction) {
                    // Create new auction entry with proper auction started data
                    int l_result = dap_auction_cache_add_auction(s_auction_cache, &a_event->tx_hash, 
                                                               a_ledger->net->pub.id, a_event->group_name,
                                                               l_started_data, a_event->timestamp);
                    if (l_result != 0) {
                        log_it(L_ERROR, "Failed to add auction %s to cache: %d", 
                               dap_chain_hash_fast_to_str_static(&a_event->tx_hash), l_result);
                        return;
                    }
                } else {
                    // Auction already exists, just ignore double event
                    log_it(L_WARNING, "Auction %s already exists in cache", 
                           dap_chain_hash_fast_to_str_static(&a_event->tx_hash));
                    return;
                }
                    
                    log_it(L_INFO, "Auction %s started with %u projects, duration: %"DAP_UINT64_FORMAT_U" %s", 
                           dap_chain_hash_fast_to_str_static(&a_event->tx_hash),
                           l_started_data->projects_cnt,
                           l_started_data->duration,
                           dap_chain_tx_event_data_time_unit_to_str(l_started_data->time_unit));
                }
            } else {
                // TODO: Handle deleted auction started event
                log_it(L_DEBUG, "Processing deleted auction started event for %s", 
                       dap_chain_hash_fast_to_str_static(&a_event->tx_hash));
            }
        } break;
        
        case DAP_CHAIN_TX_EVENT_TYPE_AUCTION_ENDED: {
            log_it(L_DEBUG, "Processing auction ended event for %s", 
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
                    
                    // Find auction by name and update status + end time efficiently
                    dap_auction_cache_item_t *l_auction = dap_auction_cache_find_auction_by_name(s_auction_cache, a_event->group_name);
                    if (l_auction) {
                        // Update status and counters efficiently (avoid second cache lookup)
                        pthread_rwlock_wrlock(&s_auction_cache->cache_rwlock);
                        dap_auction_status_t l_old_status = l_auction->status;
                        l_auction->status = DAP_AUCTION_STATUS_ENDED;
                        l_auction->end_time = a_event->timestamp;
                        
                        // Update active auctions counter
                        if (l_old_status == DAP_AUCTION_STATUS_ACTIVE && s_auction_cache->active_auctions > 0) {
                            s_auction_cache->active_auctions--;
                        }
                        pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
                        
                        log_it(L_DEBUG, "Updated auction %s status from %s to %s", 
                                dap_chain_hash_fast_to_str_static(&a_event->tx_hash),
                                dap_auction_status_to_str(l_old_status),
                                dap_auction_status_to_str(DAP_AUCTION_STATUS_ENDED));
                    }
                    
                    // Set winners
                    if (l_ended_data->winners_cnt > 0) {
                        const uint32_t *l_winners_ids = (const uint32_t *)((const byte_t *)l_ended_data +
                            offsetof(dap_chain_tx_event_data_ended_t, winners_ids));
                        dap_auction_cache_set_winners_by_name(s_auction_cache, a_event->group_name,
                                                             l_ended_data->winners_cnt, (uint32_t *)l_winners_ids);
                        
                        log_it(L_INFO, "Auction %s ended with %u winner(s)", 
                                 dap_chain_hash_fast_to_str_static(&a_event->tx_hash),
                                 l_ended_data->winners_cnt);
                        
                        // Log all winners
                        for (uint8_t i = 0; i < l_ended_data->winners_cnt; i++) {
                            log_it(L_DEBUG, "Winner #%u: project ID %u", i + 1, l_winners_ids[i]);
                        }
                    } else {
                        log_it(L_INFO, "Auction %s ended with no winners", 
                                 dap_chain_hash_fast_to_str_static(&a_event->tx_hash));
                    }
                }
            } else {
                // TODO: Handle deleted auction ended event
                log_it(L_DEBUG, "Processing deleted auction ended event for %s", 
                       dap_chain_hash_fast_to_str_static(&a_event->tx_hash));
            }
        } break;
        
        case DAP_CHAIN_TX_EVENT_TYPE_AUCTION_CANCELLED: {
            log_it(L_DEBUG, "Processing auction cancelled event for %s", a_event->group_name);
            
            if (a_opcode == DAP_LEDGER_NOTIFY_OPCODE_ADDED) {
                // Find auction once and update status + end time efficiently
                dap_auction_cache_item_t *l_auction = dap_auction_cache_find_auction_by_name(s_auction_cache, a_event->group_name);
                if (l_auction) {
                    // Update status and counters efficiently (avoid second cache lookup)
                    pthread_rwlock_wrlock(&s_auction_cache->cache_rwlock);
                    dap_auction_status_t l_old_status = l_auction->status;
                    l_auction->status = DAP_AUCTION_STATUS_CANCELLED;
                    l_auction->end_time = a_event->timestamp;
                    
                    // Update active auctions counter
                    if (l_old_status == DAP_AUCTION_STATUS_ACTIVE && s_auction_cache->active_auctions > 0) {
                        s_auction_cache->active_auctions--;
                    }
                    pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
                    
                    log_it(L_DEBUG, "Updated auction %s status from %s to %s", 
                           a_event->group_name,
                           dap_auction_status_to_str(l_old_status),
                           dap_auction_status_to_str(DAP_AUCTION_STATUS_CANCELLED));
                } else {
                    log_it(L_DEBUG, "Auction %s not found in cache", 
                           a_event->group_name);
                    return;
                }
            } else {
                // TODO: Handle deleted auction cancelled event
                log_it(L_DEBUG, "Processing deleted auction cancelled event for %s", 
                       dap_chain_hash_fast_to_str_static(&a_event->tx_hash));
            }
        } break;
        
        default:
            // Not an auction event, ignore
            break;
    }
}

/**
 * @brief Convert auction status to string
 * @param a_status Auction status
 * @return Returns string representation of status
 */
const char *dap_auction_status_to_str(dap_auction_status_t a_status)
{
    switch (a_status) {
        case DAP_AUCTION_STATUS_UNKNOWN: return "unknown";
        case DAP_AUCTION_STATUS_EXPIRED: return "expired";
        case DAP_AUCTION_STATUS_ACTIVE: return "active";
        case DAP_AUCTION_STATUS_ENDED: return "ended";
        case DAP_AUCTION_STATUS_CANCELLED: return "cancelled";
        default: return "invalid";
    }
}

/**
 * @brief Convert event type to auction status
 * @param a_event_type Event type
 * @return Returns corresponding auction status
 */
dap_auction_status_t dap_auction_status_from_event_type(uint16_t a_event_type)
{
    switch (a_event_type) {
        case DAP_CHAIN_TX_EVENT_TYPE_AUCTION_STARTED: return DAP_AUCTION_STATUS_ACTIVE;
        case DAP_CHAIN_TX_EVENT_TYPE_AUCTION_CANCELLED: return DAP_AUCTION_STATUS_CANCELLED;
        default: return DAP_AUCTION_STATUS_UNKNOWN;
    }
}

/**
 * @brief Service deinitialization
 */
void dap_chain_net_srv_auctions_deinit(void)
{
    // Clean up auction cache
    if (s_auction_cache) {
        dap_auction_cache_delete(s_auction_cache);
        s_auction_cache = NULL;
    }
    
    log_it(L_NOTICE, "Auction service deinitialized");
}

static void s_auction_bid_callback_updater(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in,
                                           dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_prev_out_item)
{
    // Basic validation - don't exit early for NULL a_prev_out_item!
    if (!s_auction_cache || !a_tx_in || !a_tx_in_hash) {
        return;
    }

    if (!a_prev_out_item) {
        // **BID CREATION LOGIC** - when a_prev_out_item is NULL
        log_it(L_DEBUG, "Processing bid creation for transaction %s", 
               dap_chain_hash_fast_to_str_static(a_tx_in_hash));

        // 1. Find auction bid conditional output in the current transaction
        int l_out_num = 0;
        dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(a_tx_in, 
                                                                             DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID,
                                                                             &l_out_num);
        if (!l_out_cond) {
            log_it(L_DEBUG, "No auction bid conditional output found in transaction %s", 
                   dap_chain_hash_fast_to_str_static(a_tx_in_hash));
            return;
        }

        // 2. Extract bid parameters from conditional output
        dap_hash_fast_t l_auction_hash = l_out_cond->subtype.srv_auction_bid.auction_hash;
        dap_time_t l_lock_time = l_out_cond->subtype.srv_auction_bid.lock_time;
        uint32_t l_project_id = l_out_cond->subtype.srv_auction_bid.project_id;

        // 3. Extract bid amount from conditional output value
        uint256_t l_bid_amount = l_out_cond->header.value;


        // 4. Add bid to auction cache
        int l_add_result = dap_auction_cache_add_bid(s_auction_cache,
                                                     &l_auction_hash,
                                                     a_tx_in_hash,
                                                     l_bid_amount,
                                                     l_lock_time,
                                                     a_tx_in->header.ts_created,
                                                     l_project_id);

        if (l_add_result == 0) {
            log_it(L_INFO, "Successfully added bid %s to auction %s cache (project_id=%u, lock_time=%"DAP_UINT64_FORMAT_U", amount=%s)", 
                   dap_chain_hash_fast_to_str_static(a_tx_in_hash),
                   dap_chain_hash_fast_to_str_static(&l_auction_hash),
                   l_project_id,
                   l_lock_time,
                   dap_uint256_to_char(l_bid_amount, NULL));
        } else {
            log_it(L_WARNING, "Failed to add bid %s to auction %s cache (error: %d)", 
                   dap_chain_hash_fast_to_str_static(a_tx_in_hash),
                   dap_chain_hash_fast_to_str_static(&l_auction_hash),
                   l_add_result);
        }

    } else {
        uint8_t *l_in_cond = dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL);
        if (!l_in_cond) {
            log_it(L_ERROR, "No auction bid conditional output found in transaction %s", 
                   dap_chain_hash_fast_to_str_static(a_tx_in_hash));
            return;
        }
        dap_chain_tx_in_cond_t *l_in_cond_item = (dap_chain_tx_in_cond_t *)l_in_cond;
        dap_hash_fast_t *l_bid_hash = &l_in_cond_item->header.tx_prev_hash;
        // **BID WITHDRAWAL LOGIC** - when a_prev_out_item exists (EXISTING LOGIC)
        log_it(L_DEBUG, "Processing bid withdrawal for transaction %s", 
               dap_chain_hash_fast_to_str_static(l_bid_hash));

        // Extract auction hash from conditional output
        dap_hash_fast_t l_auction_hash = a_prev_out_item->subtype.srv_auction_bid.auction_hash;

        pthread_rwlock_wrlock(&s_auction_cache->cache_rwlock);

        // Find auction in cache using ultra-fast O(1) hash lookup
        dap_auction_cache_item_t *l_auction = s_find_auction_by_hash_fast(s_auction_cache, &l_auction_hash);
        if (!l_auction) {
            pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
            log_it(L_ERROR, "Auction %s not found in cache during bid withdrawal",
                   dap_chain_hash_fast_to_str_static(&l_auction_hash));
            return;
        }
        uint64_t l_project_id = a_prev_out_item->subtype.srv_auction_bid.project_id;
        dap_auction_project_cache_item_t *l_project = NULL;
        HASH_FIND(hh, l_auction->projects, &l_project_id, sizeof(uint64_t), l_project);
        if (!l_project) {
            log_it(L_ERROR, "Project %" DAP_UINT64_FORMAT_U " not found in auction cache during bid withdrawal", l_project_id);
            return;
        }
        int l_result = dap_auction_cache_withdraw_bid(l_project, l_bid_hash);
        if (l_result != 0) {
            log_it(L_ERROR, "Failed to withdraw bid %s from auction %s",
                    dap_chain_hash_fast_to_str_static(l_bid_hash),
                    dap_chain_hash_fast_to_str_static(&l_auction_hash));
            pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
            return;
        }

        pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
    }
}

/**
 * @brief Verify auction bid conditional output
 * @param a_ledger Ledger instance
 * @param a_cond Conditional output to verify
 * @param a_tx_in Input transaction (withdrawal transaction)
 * @param a_owner Whether the transaction is from the owner (who created the lock)
 * @return Returns 0 on success, negative error code otherwise
 */
static int s_auction_bid_callback_verificator(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_cond, 
                                                    dap_chain_datum_tx_t *a_tx_in, bool a_owner)
{
    if (!a_cond) {
        log_it(L_WARNING, "NULL conditional output specified");
        return -1;
    }

    // Check if output type is auction bid
    if (a_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID) {
        log_it(L_WARNING, "Invalid conditional output subtype (expected auction bid)");
        return -2;
    }

    // Validate project_id 
    uint32_t l_project_id = a_cond->subtype.srv_auction_bid.project_id;
    if (l_project_id == 0) {
        log_it(L_WARNING, "Invalid project_id value 0 (must be > 0)");
        return -4;
    }

    // Only the owner (who created the bid/lock) can withdraw funds
    if (!a_owner) {
        log_it(L_WARNING, "Withdrawal denied: only the owner who created the bid can withdraw funds");
        return -9;
    }

    // 1. In withdrawal transaction, find the auction transaction hash from the conditional output
    dap_hash_fast_t l_auction_hash = a_cond->subtype.srv_auction_bid.auction_hash;
    char l_auction_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_auction_hash, l_auction_hash_str, sizeof(l_auction_hash_str));
    
    log_it(L_DEBUG, "Verifying withdrawal for auction hash %s by owner", l_auction_hash_str);

    // 2. Find the auction transaction by hash
    dap_chain_datum_tx_t *l_auction_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_auction_hash);
    if (!l_auction_tx) {
        log_it(L_WARNING, "Auction transaction %s not found in ledger", l_auction_hash_str);
        return -4;
    }

    int ret_code = 0;
    dap_time_t l_auction_end_time = 0;
    

    // 3. Check auction status with thread-safe access
    pthread_rwlock_rdlock(&s_auction_cache->cache_rwlock);
    
    // Find auction using ultra-fast O(1) hash lookup
    dap_auction_cache_item_t *l_auction = s_find_auction_by_hash_fast(s_auction_cache, &l_auction_hash);
    if (!l_auction) {
        pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
        log_it(L_WARNING, "Auction %s not found in cache", l_auction_hash_str);
        return -7;
    }

    switch (l_auction->status) {

        case DAP_AUCTION_STATUS_CANCELLED: {
            log_it(L_DEBUG, "Withdrawal allowed: auction %s was cancelled", l_auction_hash_str);
            ret_code = 0;
        } break;

        case DAP_AUCTION_STATUS_ENDED: {
            // 1. Get project id from bid transaction
            uint32_t l_bid_project = a_cond->subtype.srv_auction_bid.project_id;

            // 2. Check if this project is among the winners
            bool l_is_winner = false;
            if (!l_auction->winners_ids && l_auction->winners_cnt > 0) {
                log_it(L_ERROR, "Inconsistent winner data: count > 0 but no IDs");
                ret_code = -10;
                break;
            }
            if (l_auction->winners_cnt > 0 && l_auction->winners_ids) {
                for (uint32_t i = 0; i < l_auction->winners_cnt; i++) {
                    if (l_auction->winners_ids[i] == l_bid_project) {
                        l_is_winner = true;
                        break;
                    }
                }
            }
            
            // 3. Make decision about withdrawal validity
            if (l_is_winner) { // If project is winner, check if lock period expired
                dap_time_t l_current_time = dap_ledger_get_blockchain_time(a_ledger);
                dap_time_t l_lock_end_time = l_auction->end_time + a_cond->subtype.srv_auction_bid.lock_time;
                
                if (l_current_time >= l_lock_end_time) {
                    log_it(L_DEBUG, "Withdrawal allowed: auction %s won and lock period expired", l_auction_hash_str);
                    ret_code = 0;
                } else {
                    log_it(L_WARNING, "Withdrawal denied: auction %s won but lock period not expired (current: %"DAP_UINT64_FORMAT_U", lock_end: %"DAP_UINT64_FORMAT_U")", 
                        l_auction_hash_str, l_current_time, l_lock_end_time);
                    ret_code = -7;
                }
            } else { // If project is not winner
                log_it(L_DEBUG, "Withdrawal allowed: project %u in auction %s lost", l_bid_project, l_auction_hash_str);
                ret_code = 0;
            }
        } break;

        case DAP_AUCTION_STATUS_ACTIVE: {
            // For active auctions, check if time has expired based on cache data
            dap_time_t l_current_time = dap_ledger_get_blockchain_time(a_ledger);
            if (l_auction->end_time > 0 && l_current_time >= l_auction->end_time + a_cond->subtype.srv_auction_bid.lock_time) {
                log_it(L_DEBUG, "Withdrawal allowed: auction %s ended by time", l_auction_hash_str);
                ret_code = 0;
            } else {
                log_it(L_WARNING, "Withdrawal denied: auction %s still active", l_auction_hash_str);
                ret_code = -7;
            }
        } break;

        default:
            log_it(L_WARNING, "Auction %s has unknown status %d", l_auction_hash_str, l_auction->status);
            ret_code = -6;
            break;
    }

    pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);

    return ret_code;
}

/**
 * @brief Create auctions service
 * @param a_srv Parent service
 * @return Returns service instance or NULL on error
 */
dap_chain_net_srv_auctions_t *dap_chain_net_srv_auctions_create(dap_chain_net_srv_t *a_srv)
{
    dap_chain_net_srv_auctions_t *l_auctions = DAP_NEW_Z(dap_chain_net_srv_auctions_t);
    if(!l_auctions) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_auctions->parent = a_srv;
    l_auctions->cache = s_auction_cache; // Use global cache
    return l_auctions;
}

/**
 * @brief Delete auctions service
 * @param a_auctions Service instance to delete
 */
void dap_chain_net_srv_auctions_delete(dap_chain_net_srv_auctions_t *a_auctions)
{
    if (!a_auctions)
        return;
    
    // Note: We don't delete the cache here as it's global and shared
    // The cache is managed by init/deinit functions
    DAP_DELETE(a_auctions);
}

/**
 * @brief Free auction structure returned by find function
 * @param a_auction Auction structure to free
 */
void dap_chain_net_srv_auction_delete(dap_chain_net_srv_auction_t *a_auction)
{
    dap_return_if_fail(a_auction);
    
    DAP_DEL_Z(a_auction->guuid);
    DAP_DEL_Z(a_auction->description);
    DAP_DEL_Z(a_auction->winners_ids);  // Free winners array   
    DAP_DEL_Z(a_auction->projects);     // Free projects array if present
    
    DAP_DELETE(a_auction);
}

/**
 * @brief Find auction by hash
 * @param a_net Network instance
 * @param a_hash Auction hash
 * @return Returns auction instance or NULL if not found
 */
dap_chain_net_srv_auction_t *dap_chain_net_srv_auctions_find(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_hash)
{
    if(!a_net || !a_hash || !s_auction_cache)
        return NULL;
    
    // Search in auction cache
    dap_auction_cache_item_t *l_cached_auction = dap_auction_cache_find_auction(s_auction_cache, a_hash);
    if (!l_cached_auction) {
        log_it(L_DEBUG, "Auction %s not found in cache", dap_chain_hash_fast_to_str_static(a_hash));
        return NULL;
    }
    
    // Create external API structure
    dap_chain_net_srv_auction_t *l_auction = DAP_NEW_Z(dap_chain_net_srv_auction_t);
    if (!l_auction) {
        log_it(L_CRITICAL, "Memory allocation error for auction API structure");
        return NULL;
    }
    
    // Fill auction data from cache
    l_auction->auction_hash = l_cached_auction->auction_tx_hash;
    l_auction->guuid = l_cached_auction->guuid ? dap_strdup(l_cached_auction->guuid) : NULL;
    l_auction->status = l_cached_auction->status;
    l_auction->created_time = l_cached_auction->created_time;
    l_auction->start_time = l_cached_auction->start_time;
    l_auction->end_time = l_cached_auction->end_time;
    l_auction->description = l_cached_auction->description ? dap_strdup(l_cached_auction->description) : NULL;
    l_auction->bids_count = l_cached_auction->bids_count;
    l_auction->projects_count = HASH_COUNT(l_cached_auction->projects);
    
    // Winner information with proper memory management
    l_auction->has_winner = l_cached_auction->has_winner;
    if (l_cached_auction->winners_cnt > 0 && l_cached_auction->winners_ids) {
        l_auction->winners_ids = DAP_NEW_Z_SIZE(uint32_t, sizeof(uint32_t) * l_cached_auction->winners_cnt);
        if (l_auction->winners_ids) {
            l_auction->winners_cnt = l_cached_auction->winners_cnt;
            memcpy(l_auction->winners_ids, l_cached_auction->winners_ids, 
                   sizeof(uint32_t) * l_cached_auction->winners_cnt);
        } else {
            // Memory allocation failed - reset to consistent state
            log_it(L_ERROR, "Failed to allocate memory for winners array");
            l_auction->winners_cnt = 0;
            l_auction->has_winner = false;
        }
    } else {
        l_auction->winners_cnt = 0;
        l_auction->winners_ids = NULL;
    }
    
    if (l_cached_auction->description) {
        l_auction->description = dap_strdup(l_cached_auction->description);
    }
    
    // Projects array is not filled here - use get_detailed for that
    
    log_it(L_DEBUG, "Found auction %s in cache with status %s", 
           dap_chain_hash_fast_to_str_static(a_hash),
           dap_auction_status_to_str(l_auction->status));
    
    return l_auction;
}

//====================================================================
// EXTERNAL API FUNCTIONS
//====================================================================

/**
 * @brief Get detailed auction information with all projects
 * @param a_net Network instance
 * @param a_hash Auction hash
 * @return Returns detailed auction structure or NULL if not found
 */
dap_chain_net_srv_auction_t *dap_chain_net_srv_auctions_get_detailed(dap_chain_net_t *a_net,
                                                                     dap_chain_hash_fast_t *a_hash)
{
    if (!a_net || !a_hash || !s_auction_cache)
        return NULL;
    
    pthread_rwlock_rdlock(&s_auction_cache->cache_rwlock);
    
    // Find auction in cache using ultra-fast O(1) hash lookup
    dap_auction_cache_item_t *l_cached_auction = s_find_auction_by_hash_fast(s_auction_cache, a_hash);
    if (!l_cached_auction) {
        pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
        return NULL;
    }
    
    // Create detailed auction structure
    dap_chain_net_srv_auction_t *l_auction = DAP_NEW_Z(dap_chain_net_srv_auction_t);
    if (!l_auction) {
        pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
        return NULL;
    }
    
    // Fill basic auction data
    l_auction->auction_hash = l_cached_auction->auction_tx_hash;
    l_auction->guuid = l_cached_auction->guuid ? dap_strdup(l_cached_auction->guuid) : NULL;
    l_auction->status = l_cached_auction->status;
    l_auction->created_time = l_cached_auction->created_time;
    l_auction->start_time = l_cached_auction->start_time;
    l_auction->end_time = l_cached_auction->end_time;
    l_auction->description = l_cached_auction->description ? dap_strdup(l_cached_auction->description) : NULL;
    l_auction->bids_count = l_cached_auction->bids_count;
    l_auction->projects_count = HASH_COUNT(l_cached_auction->projects);
    
    // Winner information with proper memory management
    l_auction->has_winner = l_cached_auction->has_winner;
    if (l_cached_auction->winners_cnt > 0 && l_cached_auction->winners_ids) {
        l_auction->winners_ids = DAP_NEW_Z_SIZE(uint32_t, sizeof(uint32_t) * l_cached_auction->winners_cnt);
        if (l_auction->winners_ids) {
            l_auction->winners_cnt = l_cached_auction->winners_cnt;
            memcpy(l_auction->winners_ids, l_cached_auction->winners_ids, 
                   sizeof(uint32_t) * l_cached_auction->winners_cnt);
        } else {
            // Memory allocation failed - reset to consistent state
            log_it(L_ERROR, "Failed to allocate memory for winners array in detailed view");
            l_auction->winners_cnt = 0;
            l_auction->has_winner = false;
        }
    } else {
        l_auction->winners_cnt = 0;
        l_auction->winners_ids = NULL;
    }
    
    // Fill projects array
    if (l_auction->projects_count) {
        l_auction->projects = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_net_srv_auction_project_t,
                                                            sizeof(dap_chain_net_srv_auction_project_t) * l_auction->projects_count,
                                                            NULL);
        if (l_auction->projects) {
            uint32_t l_index = 0;
            for (dap_auction_project_cache_item_t *l_project = l_cached_auction->projects; l_project; l_project = l_project->hh.next) {
                if (l_index == l_auction->projects_count) {
                    log_it(L_ERROR, "Projects count mismatch in detailed view (expected %u, got more projects)", l_auction->projects_count);
                    break;
                }
                l_auction->projects[l_index].project_id = l_project->project_id;
                l_auction->projects[l_index].total_amount = l_project->total_amount;
                l_auction->projects[l_index].bids_count = HASH_COUNT(l_project->bids);
                l_auction->projects[l_index].active_bids_count = l_project->active_bids_count; 
                
                l_index++;
            }
        }
    }
    pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
    
    log_it(L_DEBUG, "Retrieved detailed auction %s with %u projects", 
           dap_chain_hash_fast_to_str_static(a_hash), l_auction->projects_count);
    
    return l_auction;
}

/**
 * @brief Get list of auctions with optional filtering
 * @param a_net Network instance
 * @param a_status_filter Filter by status (DAP_AUCTION_STATUS_UNKNOWN = no filter)
 * @param a_include_projects Whether to include basic project information
 * @return Returns list of auctions (must be freed with dap_list_free)
 */
dap_list_t *dap_chain_net_srv_auctions_get_list(dap_chain_net_t *a_net, 
                                                dap_auction_status_t a_status_filter, 
                                                bool a_include_projects)
{
    if (!a_net || !s_auction_cache)
        return NULL;
    
    dap_list_t *l_list = NULL;
    pthread_rwlock_rdlock(&s_auction_cache->cache_rwlock);
    
    // Diagnostic: Log current cache state
    log_it(L_INFO, "Getting auctions list for network %s, status_filter=%d, include_projects=%s", 
           a_net->pub.name, a_status_filter, a_include_projects ? "true" : "false");
    log_it(L_INFO, "Cache state: total_auctions=%u, active_auctions=%u, auctions_table=%s", 
           s_auction_cache->total_auctions, s_auction_cache->active_auctions,
           s_auction_cache->auctions ? "present" : "NULL");
    
    // Verify cache integrity before iteration
    if (!s_auction_cache->auctions && s_auction_cache->total_auctions > 0) {
        log_it(L_ERROR, "Cache corruption detected: NULL auctions table but total_auctions=%u", 
               s_auction_cache->total_auctions);
        pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
        return NULL;
    }
    
    // Early exit if no auctions in cache
    if (!s_auction_cache->auctions || s_auction_cache->total_auctions == 0) {
        log_it(L_INFO, "No auctions in cache - returning empty list");
        pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
        return NULL;
    }
    
    // Perform comprehensive dual hash table integrity check
    if (!s_verify_dual_hash_table_integrity(s_auction_cache)) {
        log_it(L_ERROR, "Dual hash table integrity check failed - aborting list operation");
        pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
        return NULL;
    }
    
    uint32_t l_total_found = 0, l_network_matches = 0, l_status_matches = 0;
    
    dap_auction_cache_item_t *l_cached_auction = NULL, *l_tmp_auction = NULL;
    HASH_ITER(hh, s_auction_cache->auctions, l_cached_auction, l_tmp_auction) {
        l_total_found++;
        
        // Safety check to prevent segfault
        if (!l_cached_auction) {
            log_it(L_ERROR, "NULL auction found during iteration - cache corruption detected");
            continue;
        }
        
        // Filter by network ID
        if (l_cached_auction->net_id.uint64 != a_net->pub.id.uint64) {
            log_it(L_DEBUG, "Auction %s: network mismatch (expected %"DAP_UINT64_FORMAT_U", got %"DAP_UINT64_FORMAT_U")",
                   l_cached_auction->guuid ? l_cached_auction->guuid : "no_name",
                   a_net->pub.id.uint64, l_cached_auction->net_id.uint64);
            continue;
        }
        l_network_matches++;
        
        // Filter by status if specified
        if (a_status_filter != DAP_AUCTION_STATUS_UNKNOWN && 
            l_cached_auction->status != a_status_filter) {
            log_it(L_DEBUG, "Auction %s: status mismatch (expected %d, got %d)",
                   l_cached_auction->guuid ? l_cached_auction->guuid : "no_name",
                   a_status_filter, l_cached_auction->status);
            continue;
        }
        l_status_matches++;
        
        // Create auction structure
        dap_chain_net_srv_auction_t *l_auction = DAP_NEW_Z(dap_chain_net_srv_auction_t);
        if (!l_auction)
            continue;
        
        // Fill basic data
        l_auction->auction_hash = l_cached_auction->auction_tx_hash;
        l_auction->guuid = l_cached_auction->guuid ? dap_strdup(l_cached_auction->guuid) : NULL;
        l_auction->status = l_cached_auction->status;
        l_auction->created_time = l_cached_auction->created_time;
        l_auction->start_time = l_cached_auction->start_time;
        l_auction->end_time = l_cached_auction->end_time;
        l_auction->description = l_cached_auction->description ? dap_strdup(l_cached_auction->description) : NULL;
        l_auction->bids_count = l_cached_auction->bids_count;
        l_auction->projects_count = HASH_COUNT(l_cached_auction->projects);
        
        // Winner information with proper memory management
        l_auction->has_winner = l_cached_auction->has_winner;
        if (l_cached_auction->winners_cnt > 0 && l_cached_auction->winners_ids) {
            l_auction->winners_ids = DAP_NEW_Z_SIZE(uint32_t, sizeof(uint32_t) * l_cached_auction->winners_cnt);
            if (l_auction->winners_ids) {
                l_auction->winners_cnt = l_cached_auction->winners_cnt;
                memcpy(l_auction->winners_ids, l_cached_auction->winners_ids, 
                       sizeof(uint32_t) * l_cached_auction->winners_cnt);
            } else {
                // Memory allocation failed - reset to consistent state
                log_it(L_ERROR, "Failed to allocate memory for winners array in list view");
                l_auction->winners_cnt = 0;
                l_auction->has_winner = false;
            }
        } else {
            l_auction->winners_cnt = 0;
            l_auction->winners_ids = NULL;
        }
        
        // Fill projects array if requested and available
        if (a_include_projects && l_auction->projects_count > 0) {
            l_auction->projects = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_net_srv_auction_project_t,
                                                                sizeof(dap_chain_net_srv_auction_project_t) * l_auction->projects_count,
                                                                NULL);
            if (l_auction->projects) {
                uint32_t l_index = 0;
                dap_auction_project_cache_item_t *l_project, *l_tmp_project;
                HASH_ITER(hh, l_cached_auction->projects, l_project, l_tmp_project) {
                    // Safety check to prevent segfault in nested iteration
                    if (!l_project) {
                        log_it(L_ERROR, "NULL project found during iteration - project cache corruption detected");
                        break;
                    }
                    if (l_index >= l_auction->projects_count)
                        break;
                    
                    l_auction->projects[l_index].project_id = l_project->project_id;
                    l_auction->projects[l_index].total_amount = l_project->total_amount;
                    l_auction->projects[l_index].bids_count = HASH_COUNT(l_project->bids);
                    l_auction->projects[l_index].active_bids_count = l_project->active_bids_count;
                    
                    l_index++;
                }
            } else {
                // Memory allocation failed - log error but continue
                log_it(L_ERROR, "Failed to allocate memory for projects array in list view");
                l_auction->projects_count = 0;
            }
        }
        
        l_list = dap_list_append(l_list, l_auction);
    }
    
    pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
    
    uint32_t l_final_count = dap_list_length(l_list);
    log_it(L_INFO, "Auction filtering results: found=%u, network_matches=%u, status_matches=%u, final_list=%u", 
           l_total_found, l_network_matches, l_status_matches, l_final_count);
    log_it(L_DEBUG, "Retrieved %u auctions from cache", l_final_count);
    return l_list;
}

/**
 * @brief Get statistics about auctions
 * @param a_net Network instance
 * @return Returns statistics structure (must be freed)
 */
dap_auction_stats_t *dap_chain_net_srv_auctions_get_stats(dap_chain_net_t *a_net)
{
    if (!a_net || !s_auction_cache)
        return NULL;
    
    dap_auction_stats_t *l_stats = DAP_NEW_Z(dap_auction_stats_t);
    if (!l_stats)
        return NULL;
    
    pthread_rwlock_rdlock(&s_auction_cache->cache_rwlock);
    
    dap_auction_cache_item_t *l_auction = NULL, *l_tmp_auction = NULL;
    HASH_ITER(hh, s_auction_cache->auctions, l_auction, l_tmp_auction) {
        // Filter by network ID
        if (l_auction->net_id.uint64 != a_net->pub.id.uint64)
            continue;
        
        l_stats->total_auctions++;
        l_stats->total_bids += l_auction->bids_count;
        l_stats->total_projects += HASH_COUNT(l_auction->projects);
        
        switch (l_auction->status) {
            case DAP_AUCTION_STATUS_ACTIVE:
                l_stats->active_auctions++;
                break;
            case DAP_AUCTION_STATUS_ENDED:
                l_stats->ended_auctions++;
                break;
            case DAP_AUCTION_STATUS_CANCELLED:
                l_stats->cancelled_auctions++;
                break;
            default:
                break;
        }
    }
    
    pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
    
    log_it(L_DEBUG, "Auction stats: total=%u, active=%u, ended=%u, cancelled=%u", 
           l_stats->total_auctions, l_stats->active_auctions, 
           l_stats->ended_auctions, l_stats->cancelled_auctions);
    
    return l_stats;
} 

/**
 * @brief Create withdraw transaction
 * @param a_net Network instance
 * @param a_key_from Wallet key for signing
 * @param a_bid_tx_hash Hash of the bid transaction
 * @param a_fee Validator fee
 * @return Returns transaction hash string or NULL on error
 */
char *dap_chain_net_srv_auction_withdraw_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_to, dap_hash_fast_t *a_bid_tx_hash, uint256_t a_fee, uint256_t *a_value, int *a_ret_code)
{
    if (!a_net || !a_key_to || !a_bid_tx_hash || IS_ZERO_256(a_fee))
        return NULL;
    
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    if (!l_ledger) {
        log_it(L_ERROR, "Ledger not found");
        set_ret_code(a_ret_code, -101);
        return NULL;
    }

    // 1. Find bid transaction
    dap_chain_datum_tx_t *l_bid_tx = dap_ledger_tx_find_by_hash(l_ledger, a_bid_tx_hash);
    if (!l_bid_tx) {
        log_it(L_ERROR, "Bid transaction not found");
        set_ret_code(a_ret_code, -102);
        return NULL;
    }

    // 2. Find bid output
    int l_out_num = 0;
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_bid_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID, &l_out_num);
    if (!l_out_cond) {
        log_it(L_ERROR, "Bid output not found");
        set_ret_code(a_ret_code, -103);
        return NULL;
    }

    if (dap_ledger_tx_hash_is_used_out_item(l_ledger, a_bid_tx_hash, l_out_num, NULL)) {
        log_it(L_ERROR, "Bid transaction is already withdrawn");
        set_ret_code(a_ret_code, -104);
        return NULL;
    }

    // 3. Find auction
    dap_hash_fast_t l_auction_hash = l_out_cond->subtype.srv_auction_bid.auction_hash;
    dap_auction_cache_item_t *l_auction = dap_auction_cache_find_auction(s_auction_cache, &l_auction_hash);
    if (!l_auction) {
        log_it(L_WARNING, "Auction %s not found in cache", dap_chain_hash_fast_to_str_static(&l_auction_hash));
        set_ret_code(a_ret_code, -105);
        return NULL;
    }
    
    // 4. Verify bid withdrawal is allowed
    switch (l_auction->status){
        case DAP_AUCTION_STATUS_ENDED:
        {
            // 1. Get project id from bid transaction
            uint32_t l_bid_project = l_out_cond->subtype.srv_auction_bid.project_id;
            // 2. Get winners from auction ended event

            uint32_t l_winners_count = l_auction->winners_cnt;
            // 3. Check project won or lost
            bool l_is_winner = false;
            for (uint32_t i = 0; i < l_winners_count; i++) {
                if (l_auction->winners_ids[i] == l_bid_project) {
                    l_is_winner = true;
                    break;
                }
            }
            // 4. Make decision about withdrawal validity
            if (l_is_winner) { // If project is winner, check if lock period expired
                dap_time_t l_current_time = dap_ledger_get_blockchain_time(l_ledger);
                dap_time_t l_lock_end_time = l_auction->end_time + l_out_cond->subtype.srv_auction_bid.lock_time;
                
                if (l_current_time < l_lock_end_time) {
                    log_it(L_WARNING, "Withdrawal denied: auction %s won but lock period not expired (current: %"DAP_UINT64_FORMAT_U", lock_end: %"DAP_UINT64_FORMAT_U")", 
                        dap_chain_hash_fast_to_str_static(&l_auction_hash), l_current_time, l_lock_end_time);
                    set_ret_code(a_ret_code, -106);
                    return NULL;
                }
            } 
            break;
        }
        case DAP_AUCTION_STATUS_ACTIVE:
        {
            dap_time_t l_auction_end_timeout = l_auction->end_time + l_out_cond->subtype.srv_auction_bid.lock_time;
            dap_time_t l_current_time = dap_ledger_get_blockchain_time(l_ledger);
            if (l_current_time < l_auction_end_timeout) {
                log_it(L_DEBUG, "Withdrawal debiued: auction %s still active", dap_chain_hash_fast_to_str_static(&l_auction_hash));
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
    const char *l_ticker_str = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_auction_hash);
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
        if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_delegated_ticker_str, &l_addr, &l_list_used_out, l_value_delegated, &l_value_transfer) == -101)
            l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_delegated_ticker_str,
                                                                                 &l_addr, l_value_delegated, &l_value_transfer);
        if(!l_list_used_out) {
            log_it( L_ERROR, "Nothing to transfer (not enough delegated tokens)");
            set_ret_code(a_ret_code, -111);
            return NULL;
        }
    }

    // 6. Create withdraw transaction
    dap_chain_datum_tx_t *l_withdraw_tx = dap_chain_datum_tx_create();
    if (!l_withdraw_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        set_ret_code(a_ret_code, -112);
        return NULL;
    }

    // add 'in_cond' & 'in' items
    dap_chain_datum_tx_add_in_cond_item(&l_withdraw_tx, a_bid_tx_hash, l_out_num, 0);
    
    if (l_list_used_out) {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_withdraw_tx, l_list_used_out);
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
        if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_ticker_str, &l_addr, &l_list_used_out, l_value_shortage, &l_fee_transfer) == -101)
            l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_ticker_str, &l_addr, l_value_shortage, &l_fee_transfer);
        if(!l_list_used_out) {
            log_it( L_ERROR, "Nothing to transfer (not enough coins)");
            set_ret_code(a_ret_code, -111);
            return NULL;
        }
        SUM_256_256(l_value_pack, l_fee_transfer, &l_value_pack);
    }
    if (l_list_used_out) {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_withdraw_tx, l_list_used_out);
        assert(EQUAL_256(l_value_to_items, l_fee_transfer));
        dap_list_free_full(l_list_used_out, NULL);
    }

    uint256_t l_value_back = {};
    // add 'out_ext' items
    // Network fee
    if (l_net_fee_used && !dap_chain_datum_tx_add_out_ext_item(&l_withdraw_tx, &l_addr_fee, l_net_fee, a_net->pub.native_ticker)) {
        dap_chain_datum_tx_delete(l_withdraw_tx);
        log_it(L_ERROR, "Failed to add network fee output");
        set_ret_code(a_ret_code, -113);
        return NULL;
    }

    // Validator's fee
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_withdraw_tx, a_fee) != 1) {
        dap_chain_datum_tx_delete(l_withdraw_tx);
        log_it(L_ERROR, "Failed to add validator fee");
        set_ret_code(a_ret_code, -114);
        return NULL;
    }
    // coin back
    if (SUBTRACT_256_256(l_value_pack, l_fee_pack, &l_value_back)) {
        dap_chain_datum_tx_delete(l_withdraw_tx);
        log_it(L_ERROR, "Failed to calculate coin back");
        set_ret_code(a_ret_code, -115);
        return NULL;
    }
    if(!IS_ZERO_256(l_value_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_withdraw_tx, &l_addr, l_value_back, a_net->pub.native_ticker)!=1) {
            dap_chain_datum_tx_delete(l_withdraw_tx);
            log_it(L_ERROR, "Failed to add coin back output");
            set_ret_code(a_ret_code, -116);
            return NULL;
        }
    }
    if (!l_is_native && dap_chain_datum_tx_add_out_ext_item(&l_withdraw_tx, &l_addr, l_out_cond->header.value, l_ticker_str) != 1) {
        dap_chain_datum_tx_delete(l_withdraw_tx);
        log_it(L_ERROR, "Failed to add coin back output");
        set_ret_code(a_ret_code, -116);
        return NULL;
    }
    
    // add burning 'out_ext'
    if (!IS_ZERO_256(l_value_delegated)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_withdraw_tx, &c_dap_chain_addr_blank,
                                               l_value_delegated, l_delegated_ticker_str) != 1) {
            dap_chain_datum_tx_delete(l_withdraw_tx);
            log_it(L_ERROR, "Failed to add delegated token burn output");
            set_ret_code(a_ret_code, -117);
            return NULL;
        }
        // delegated token coin back
        SUBTRACT_256_256(l_value_transfer, l_value_delegated, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_withdraw_tx, &l_addr, l_value_back, l_delegated_ticker_str) != 1) {
                dap_chain_datum_tx_delete(l_withdraw_tx);
                log_it(L_ERROR, "Failed to add delegated token coin back output");
                set_ret_code(a_ret_code, -118);
                return NULL;
            }
        }
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_withdraw_tx, a_key_to) != 1) {
        dap_chain_datum_tx_delete(l_withdraw_tx);
        log_it(L_ERROR, "Failed to sign transaction");
        set_ret_code(a_ret_code, -119);
        return NULL;
    }

    // 13. Create datum and add to mempool
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_withdraw_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_withdraw_tx, l_tx_size);
    dap_chain_datum_tx_delete(l_withdraw_tx);
    
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
        log_it(L_ERROR, "Failed to add auction bid transaction to mempool");
        set_ret_code(a_ret_code, -121);
        return NULL;
    }

    if (a_value)
        *a_value = l_out_cond->header.value;
    log_it(L_INFO, "Successfully created and added auction bid transaction to mempool: %s", l_ret);
    set_ret_code(a_ret_code, 0);
    return l_ret;
}

/**
 * @brief Create auction bid transaction
 * @param a_net Network instance
 * @param a_key_from Encryption key for transaction signing
 * @param a_auction_hash Hash of the auction transaction
 * @param a_amount Bid amount
 * @param a_lock_time Lock time in seconds
 * @param a_project_id Project ID for which the bid is made
 * @param a_fee Transaction fee
 * @param a_ret_code Return code for error handling
 * @return Returns transaction hash string or NULL on error
 */
char *dap_chain_net_srv_auction_bid_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_from, const dap_hash_fast_t *a_auction_hash, 
                                     uint256_t a_amount, dap_time_t a_lock_time, uint32_t a_project_id, uint256_t a_fee, int *a_ret_code)
{
    if (!a_net || !a_key_from || !a_auction_hash || IS_ZERO_256(a_amount) || a_project_id == 0)
        return NULL;

    dap_ledger_t *l_ledger = a_net->pub.ledger;
    if (!l_ledger) {
        log_it(L_ERROR, "Ledger not found");
        set_ret_code(a_ret_code, -100);
        return NULL;
    }

    // Validate project_id exists in auction
    if (!s_auction_cache) {
        log_it(L_ERROR, "Auction cache not initialized");
        set_ret_code(a_ret_code, -101);
        return NULL;
    }
    
    pthread_rwlock_rdlock(&s_auction_cache->cache_rwlock);
    
    // Find auction using ultra-fast O(1) hash lookup
    dap_auction_cache_item_t *l_auction_cache = s_find_auction_by_hash_fast(s_auction_cache, a_auction_hash);
    
    if (!l_auction_cache) {
        pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
        log_it(L_ERROR, "Auction %s not found in cache", dap_chain_hash_fast_to_str_static(a_auction_hash));
        set_ret_code(a_ret_code, -102);
        return NULL;
    }
      
    uint64_t l_project_id = a_project_id;
    dap_auction_project_cache_item_t *l_project = NULL;
    HASH_FIND(hh, l_auction_cache->projects, &l_project_id, sizeof(uint64_t), l_project);    
    pthread_rwlock_unlock(&s_auction_cache->cache_rwlock);
    if (!l_project) {
        log_it(L_ERROR, "Project ID %u not found in auction", a_project_id);
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

    // 1. Verify auction exists and is valid
    dap_chain_datum_tx_t *l_auction_tx = dap_ledger_tx_find_by_hash(l_ledger, a_auction_hash);
    if (!l_auction_tx) {
        log_it(L_ERROR, "Auction transaction not found");
        set_ret_code(a_ret_code, -106);
        return NULL;
    }

    // Calculate total costs: bid amount + network fee + validator fee
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
    if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, l_native_ticker, &l_addr_from, 
                                                    &l_list_used_out, l_total_cost, &l_value_transfer) == -101) {
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                              &l_addr_from, l_total_cost, &l_value_transfer);
    }
    if (!l_list_used_out) {
        log_it(L_ERROR, "Not enough funds to place bid");
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

    // 6. Add conditional output (auction bid lock)
    dap_chain_net_srv_uid_t l_srv_uid = {.uint64 = DAP_CHAIN_NET_SRV_AUCTION_ID};
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_auction_bid(
        l_srv_uid, a_amount, a_auction_hash, a_lock_time, a_project_id, NULL, 0);
    if (!l_out_cond) {
        log_it(L_ERROR, "Failed to create auction bid conditional output");
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
        log_it(L_ERROR, "Failed to add auction bid transaction to mempool");
        set_ret_code(a_ret_code, -120);
        return NULL;
    }
    
    log_it(L_INFO, "Successfully created and added auction bid transaction to mempool: %s", l_ret);
    set_ret_code(a_ret_code, 0);
    return l_ret;
}

/**
 * @brief Main auction command handler
 * @param argc Argument count
 * @param argv Arguments array
 * @param str_reply Reply string
 * @param a_version Protocol version
 * @return Error code
 */
int com_auction(int argc, char **argv, void **str_reply, UNUSED_ARG int a_version)
{
    enum {
        CMD_NONE, CMD_BID, CMD_WITHDRAW, CMD_LIST, CMD_INFO, CMD_EVENTS, CMD_STATS
    };

    int arg_index = 1;
    int cmd_num = CMD_NONE;
    const char *str_tmp = NULL;
    json_object **l_json_arr_reply = (json_object **) str_reply;
    
    // Ensure JSON reply is an array to avoid segfaults on json_object_array_add
    if (!l_json_arr_reply) {
        return -1;
    }
    if (!*l_json_arr_reply || !json_object_is_type(*l_json_arr_reply, json_type_array)) {
        *l_json_arr_reply = json_object_new_array();
    }
    
    // Parse command
    if(arg_index >= argc) {
        dap_json_rpc_error_add(*l_json_arr_reply, COMMAND_NOT_RECOGNIZED, "Command not specified");
        return -1;
    }

    str_tmp = argv[arg_index];
    if(!strcmp(str_tmp, "bid"))
        cmd_num = CMD_BID;
    else if(!strcmp(str_tmp, "withdraw"))
        cmd_num = CMD_WITHDRAW;
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
        case CMD_BID: {
            // Parse auction identifier (GUUID or tx hash)
            const char *l_auction_id_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-auction", &l_auction_id_str);
            if(!l_auction_id_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, AUCTION_HASH_ARG_ERROR, "Auction identifier not specified");
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
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-lock_period", &str_tmp);
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

            // Parse project ID
            str_tmp = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-project", &str_tmp);
            if(!str_tmp) {
                dap_json_rpc_error_add(*l_json_arr_reply, PROJECT_ID_ARG_ERROR, "Project ID not specified");
                return -9;
            }
            uint32_t l_project_id = (uint32_t)atoi(str_tmp);
            if(l_project_id == 0) {
                dap_json_rpc_error_add(*l_json_arr_reply, PROJECT_ID_FORMAT_ERROR, "Invalid project ID format");
                return -10;
            }

            // Resolve auction: try as hash; if fails, resolve by GUUID from cache
            dap_auction_cache_item_t *l_auction = NULL;
            dap_hash_fast_t l_auction_hash = {};
            bool l_hash_parsed = (dap_chain_hash_fast_from_str(l_auction_id_str, &l_auction_hash) == 0);
            if (l_hash_parsed) {
                l_auction = dap_auction_cache_find_auction(s_auction_cache, &l_auction_hash);
            } else {
                // Try resolve by GUUID via auction cache
                l_auction = dap_auction_cache_find_auction_by_name(s_auction_cache, l_auction_id_str);
                if (l_auction)
                    l_auction_hash = l_auction->auction_tx_hash;
            }
            // Check auction is active           
            if (!l_auction) {
                dap_json_rpc_error_add(*l_json_arr_reply, AUCTION_NOT_FOUND_ERROR, "Auction '%s' not found",
                                                                                l_hash_parsed ? dap_hash_fast_to_str_static(&l_auction_hash) : l_auction_id_str);
                return -11;
            }
            if (l_auction->status != DAP_AUCTION_STATUS_ACTIVE) {
                dap_json_rpc_error_add(*l_json_arr_reply, AUCTION_NOT_ACTIVE_ERROR, "Auction is not active");
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

            // Create auction bid transaction
            int l_ret_code = 0;
            char *l_tx_hash_str = dap_chain_net_srv_auction_bid_create(l_net, l_enc_key, &l_auction_hash, 
                                                         l_amount, l_lock_time, l_project_id, l_fee, &l_ret_code);
            DAP_DELETE(l_enc_key);
            
            // Close wallet
            dap_chain_wallet_close(l_wallet);

            if (l_tx_hash_str) {
                // Success - return transaction hash
                json_object *l_json_obj = json_object_new_object();
                json_object_object_add(l_json_obj, "command", json_object_new_string("bid"));
                json_object_object_add(l_json_obj, "status", json_object_new_string("success"));
                json_object_object_add(l_json_obj, "tx_hash", json_object_new_string(l_tx_hash_str));
                json_object_object_add(l_json_obj, "auction_tx_hash", json_object_new_string(dap_chain_hash_fast_to_str_static(&l_auction_hash)));
                json_object_object_add(l_json_obj, "auction_name", json_object_new_string(l_auction->guuid));
                const char *l_amount_str = dap_uint256_to_char(l_amount, NULL);
                json_object_object_add(l_json_obj, "amount", json_object_new_string(l_amount_str));
                
                
                const char *l_fee_str = dap_uint256_to_char(l_fee, NULL);
                json_object_object_add(l_json_obj, "fee", json_object_new_string(l_fee_str));
                
                json_object_object_add(l_json_obj, "lock_months", json_object_new_int(l_lock_months));
                json_object_array_add(*l_json_arr_reply, l_json_obj);
                
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
                        l_error_msg = "Auction cache not initialized";
                        break;
                    case -102:
                        l_error_msg = "Auction not found in cache";
                        break;
                    case -103:
                        l_error_msg = "Lock time must be between 3 and 24 months";
                        break;
                    case -104:
                        l_error_msg = "Project ID not found in auction";
                        break;
                    case -105:
                        l_error_msg = "Failed to get emission rate for delegated token";
                        break;
                    case -106:
                        l_error_msg = "Auction transaction not found";
                        break;
                    case -107:
                        l_error_msg = "Overflow detected when adding network fee to total cost";
                        break;
                    case -108:
                        l_error_msg = "Overflow detected when adding validator fee to total cost";
                        break;
                    case -109:
                        l_error_msg = "Not enough funds to place bid";
                        break;
                    case -110:
                        l_error_msg = "Failed to create transaction";
                        break;
                    case -111:
                        l_error_msg = "Failed to add input items";
                        break;
                    case -112:
                        l_error_msg = "Failed to create auction bid conditional output";
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
                        l_error_msg = "Failed to add auction bid transaction to mempool";
                        break;
                    default:
                        l_error_msg = "Unknown error occurred";
                        break;
                }
                dap_json_rpc_error_add(*l_json_arr_reply, BID_CREATE_ERROR, "Error creating bid transaction: %s (code: %d)", l_error_msg, l_ret_code);
                return -14;
            }
        } break;

        case CMD_WITHDRAW: {
            // Parse bid transaction hash
            const char *l_bid_tx_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-bid_tx_hash", &l_bid_tx_hash_str);
            if(!l_bid_tx_hash_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, BID_TX_HASH_ARG_ERROR, "Bid transaction hash not specified");
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

            dap_hash_fast_t l_bid_tx_hash = {};
            if (dap_chain_hash_fast_from_str(l_bid_tx_hash_str, &l_bid_tx_hash) != 0) {
                dap_json_rpc_error_add(*l_json_arr_reply, BID_TX_HASH_FORMAT_ERROR, "Invalid bid transaction hash format");
                DAP_DELETE(l_enc_key);
                dap_chain_wallet_close(l_wallet);
                return -6;
            }
            uint256_t l_value = {};
            int l_ret_code = 0;
            char *l_tx_hash_str = dap_chain_net_srv_auction_withdraw_create(l_net, l_enc_key, &l_bid_tx_hash, l_fee, &l_value, &l_ret_code);
            DAP_DELETE(l_enc_key);

            // Close wallet
            dap_chain_wallet_close(l_wallet);

            if (l_ret_code == 0) {
                // Success - return transaction hash
                json_object *l_json_obj = json_object_new_object();
                json_object_object_add(l_json_obj, "command", json_object_new_string("withdraw"));
                json_object_object_add(l_json_obj, "status", json_object_new_string("success"));
                json_object_object_add(l_json_obj, "tx_hash", json_object_new_string(l_tx_hash_str));
                json_object_object_add(l_json_obj, "bid_tx_hash", json_object_new_string(l_bid_tx_hash_str));
                const char *l_value_str; dap_uint256_to_char(l_value, &l_value_str);
                json_object_object_add(l_json_obj, "value", json_object_new_string(l_value_str));
                const char *l_fee_str; dap_uint256_to_char(l_fee, &l_fee_str);
                json_object_object_add(l_json_obj, "fee", json_object_new_string(l_fee_str));
                
                json_object_array_add(*l_json_arr_reply, l_json_obj);
                
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
                        l_error_msg = "Bid transaction not found";
                        break;
                    case -103:
                        l_error_msg = "Bid output not found";
                        break;
                    case -104:
                        l_error_msg = "Bid transaction is already withdrawn";
                        break;
                    case -105:
                        l_error_msg = "Auction not found in cache";
                        break;
                    case -106:
                        l_error_msg = "Withdrawal denied: auction won but lock period not expired";
                        break;
                    case -107:
                        l_error_msg = "Withdrawal denied: auction still active";
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
                        l_error_msg = "Failed to add auction bid transaction to mempool";
                        break;
                    default:
                        l_error_msg = "Unknown error occurred";
                        break;
                }
                dap_json_rpc_error_add(*l_json_arr_reply, WITHDRAW_CREATE_ERROR, "Error creating withdraw transaction: %s (code: %d)", l_error_msg, l_ret_code);
                return -7;
            }
        } break;

        case CMD_LIST: {
            bool l_active_only = (dap_cli_server_cmd_check_option(argv, arg_index, argc, "-active_only") != -1);
            bool l_include_projects = (dap_cli_server_cmd_check_option(argv, arg_index, argc, "-projects") != -1);
            
            // Get list of auctions from cache
            dap_auction_status_t l_status_filter = l_active_only ? DAP_AUCTION_STATUS_ACTIVE : DAP_AUCTION_STATUS_UNKNOWN;
            dap_list_t *l_auctions_list = dap_chain_net_srv_auctions_get_list(l_net, l_status_filter, l_include_projects);
            
            // Diagnostic: Check returned list
            if (!l_auctions_list) {
                log_it(L_INFO, "CMD_LIST: get_list returned NULL");
            } else {
                uint32_t l_list_length = dap_list_length(l_auctions_list);
                log_it(L_INFO, "CMD_LIST: get_list returned list with %u items", l_list_length);
            }
            
            json_object *l_json_obj = json_object_new_object();
            json_object_object_add(l_json_obj, "command", json_object_new_string("list"));
            json_object_object_add(l_json_obj, "status", json_object_new_string("success"));
            json_object_object_add(l_json_obj, "active_only", json_object_new_boolean(l_active_only));
            json_object_object_add(l_json_obj, "include_projects", json_object_new_boolean(l_include_projects));
            
            // Create auctions array
            json_object *l_auctions_array = json_object_new_array();
            uint32_t l_count = 0;
            uint32_t l_processed = 0;
            
            log_it(L_INFO, "CMD_LIST: Starting auction processing loop");
            for (dap_list_t *l_item = l_auctions_list; l_item; l_item = dap_list_next(l_item)) {
                l_processed++;
                log_it(L_DEBUG, "CMD_LIST: Processing auction item %u", l_processed);
                
                dap_chain_net_srv_auction_t *l_auction = (dap_chain_net_srv_auction_t *)l_item->data;
                if (!l_auction) {
                    log_it(L_WARNING, "CMD_LIST: Item %u has NULL data", l_processed);
                    continue;
                }
                
                log_it(L_DEBUG, "CMD_LIST: Auction %u: guuid=%s, status=%d", 
                       l_processed, l_auction->guuid ? l_auction->guuid : "NULL", l_auction->status);
                
                json_object *l_auction_obj = json_object_new_object();
                
                // Basic auction info
                json_object_object_add(l_auction_obj, "hash", 
                    json_object_new_string(dap_chain_hash_fast_to_str_static(&l_auction->auction_hash)));
                if (l_auction->guuid)
                    json_object_object_add(l_auction_obj, "auction_name", json_object_new_string(l_auction->guuid));
                json_object_object_add(l_auction_obj, "status", 
                    json_object_new_string(dap_auction_status_to_str(l_auction->status)));
                
                // Format times as human-readable strings
                char created_time_str[DAP_TIME_STR_SIZE], start_time_str[DAP_TIME_STR_SIZE], end_time_str[DAP_TIME_STR_SIZE];
                dap_time_to_str_rfc822(created_time_str, DAP_TIME_STR_SIZE, l_auction->created_time);
                dap_time_to_str_rfc822(start_time_str, DAP_TIME_STR_SIZE, l_auction->start_time);
                dap_time_to_str_rfc822(end_time_str, DAP_TIME_STR_SIZE, l_auction->end_time);
                json_object_object_add(l_auction_obj, "created_time", json_object_new_string(created_time_str));
                json_object_object_add(l_auction_obj, "start_time", json_object_new_string(start_time_str));
                json_object_object_add(l_auction_obj, "end_time", json_object_new_string(end_time_str));
                json_object_object_add(l_auction_obj, "bids_count", 
                    json_object_new_uint64(l_auction->bids_count));
                json_object_object_add(l_auction_obj, "projects_count", 
                    json_object_new_uint64(l_auction->projects_count));
                
                // Winners information
                if (l_auction->has_winner && l_auction->winners_cnt > 0) {
                    json_object *l_winners_array = json_object_new_array();
                    for (uint8_t i = 0; i < l_auction->winners_cnt; i++) {
                    json_object *l_winner_obj = json_object_new_object();
                        json_object_object_add(l_winner_obj, "project_id", 
                            json_object_new_uint64(l_auction->winners_ids[i]));
                        json_object_array_add(l_winners_array, l_winner_obj);
                    }
                    json_object_object_add(l_auction_obj, "winners", l_winners_array);
                    json_object_object_add(l_auction_obj, "winners_count", 
                        json_object_new_uint64(l_auction->winners_cnt));
                }
                
                // Projects information (if requested and available)
                if (l_include_projects && l_auction->projects && l_auction->projects_count > 0) {
                    json_object *l_projects_array = json_object_new_array();
                    for (uint32_t i = 0; i < l_auction->projects_count; i++) {
                        json_object *l_project_obj = json_object_new_object();
                        
                        // Project ID
                        json_object_object_add(l_project_obj, "project_id", json_object_new_uint64(l_auction->projects[i].project_id));
                        
                        // Total amount
                        char *l_total_amount_str = dap_uint256_uninteger_to_char(l_auction->projects[i].total_amount);
                        if (l_total_amount_str) {
                            json_object_object_add(l_project_obj, "total_amount", json_object_new_string(l_total_amount_str));
                            DAP_DELETE(l_total_amount_str);
                        } else {
                            json_object_object_add(l_project_obj, "total_amount", json_object_new_string("0"));
                        }
                        
                        // Total amount in CELL
                        char *l_total_amount_coin_str = dap_uint256_decimal_to_char(l_auction->projects[i].total_amount);
                        if (l_total_amount_coin_str) {
                            json_object_object_add(l_project_obj, "total_amount_coin", json_object_new_string(l_total_amount_coin_str));
                            DAP_DELETE(l_total_amount_coin_str);
                        } else {
                            json_object_object_add(l_project_obj, "total_amount_coin", json_object_new_string("0.0"));
                        }
                        
                        // Bids counts
                        json_object_object_add(l_project_obj, "bids_count", json_object_new_uint64(l_auction->projects[i].bids_count));
                        json_object_object_add(l_project_obj, "active_bids_count", json_object_new_uint64(l_auction->projects[i].active_bids_count));
                        
                        json_object_array_add(l_projects_array, l_project_obj);
                    }
                    json_object_object_add(l_auction_obj, "projects", l_projects_array);
                }
                
                json_object_array_add(l_auctions_array, l_auction_obj);
                l_count++;
                log_it(L_DEBUG, "CMD_LIST: Successfully added auction %u to JSON array", l_count);
            }
            
            log_it(L_INFO, "CMD_LIST: Processed %u items, added %u auctions to JSON array", l_processed, l_count);
            json_object_object_add(l_json_obj, "auctions", l_auctions_array);
            json_object_object_add(l_json_obj, "count", json_object_new_uint64(l_count));
            json_object_array_add(*l_json_arr_reply, l_json_obj);
            
            log_it(L_INFO, "CMD_LIST: JSON response prepared with %u auctions", l_count);
            
            // Cleanup
            if (l_auctions_list) {
                for (dap_list_t *l_item = l_auctions_list; l_item; l_item = dap_list_next(l_item)) {
                    dap_chain_net_srv_auction_delete((dap_chain_net_srv_auction_t *)l_item->data);
                }
                dap_list_free(l_auctions_list);
            }
        } break;

        case CMD_INFO: {
            // Parse auction ID
            const char *l_auction_id_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-auction", &l_auction_id_str);
            if(!l_auction_id_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, AUCTION_HASH_ARG_ERROR, "Auction hash not specified");
                return -1;
            }
            dap_auction_cache_item_t *l_auction = NULL;
            dap_hash_fast_t l_auction_hash = {};
            bool l_hash_parsed = (dap_chain_hash_fast_from_str(l_auction_id_str, &l_auction_hash) == 0);
            if (l_hash_parsed) {
                l_auction = dap_auction_cache_find_auction(s_auction_cache, &l_auction_hash);
            } else {
                // Try resolve by GUUID via auction cache
                l_auction = dap_auction_cache_find_auction_by_name(s_auction_cache, l_auction_id_str);
                if (l_auction)
                    l_auction_hash = l_auction->auction_tx_hash;
            }
            if(!l_auction) {
                dap_json_rpc_error_add(*l_json_arr_reply, AUCTION_NOT_FOUND_ERROR, "Auction '%s' not found",
                                                                                l_hash_parsed ? dap_hash_fast_to_str_static(&l_auction_hash) : l_auction_id_str);
                return -2;
            }          
            bool l_verbose = (dap_cli_server_cmd_check_option(argv, arg_index, argc, "-verbose") != -1);
            json_object *l_json_obj = json_object_new_object();
            json_object_object_add(l_json_obj, "command", json_object_new_string("info"));
            json_object_object_add(l_json_obj, "status", json_object_new_string("success"));
            json_object_object_add(l_json_obj, "verbose", json_object_new_boolean(l_verbose));
            json_object_object_add(l_json_obj, "auction_tx_hash", json_object_new_string(dap_hash_fast_to_str_static(&l_auction->auction_tx_hash)));
            json_object_object_add(l_json_obj, "auction_name", json_object_new_string(l_auction->guuid));
            
            // Basic auction information
            json_object_object_add(l_json_obj, "auction_status", 
                json_object_new_string(dap_auction_status_to_str(l_auction->status)));
            
            // Format times as human-readable strings
            char info_created_time_str[DAP_TIME_STR_SIZE], info_start_time_str[DAP_TIME_STR_SIZE], info_end_time_str[DAP_TIME_STR_SIZE];
            dap_time_to_str_rfc822(info_created_time_str, DAP_TIME_STR_SIZE, l_auction->created_time);
            dap_time_to_str_rfc822(info_start_time_str, DAP_TIME_STR_SIZE, l_auction->start_time);
            dap_time_to_str_rfc822(info_end_time_str, DAP_TIME_STR_SIZE, l_auction->end_time);
            json_object_object_add(l_json_obj, "created_time", json_object_new_string(info_created_time_str));
            json_object_object_add(l_json_obj, "start_time", json_object_new_string(info_start_time_str));
            json_object_object_add(l_json_obj, "end_time", json_object_new_string(info_end_time_str));
            json_object_object_add(l_json_obj, "bids_count", json_object_new_uint64(l_auction->bids_count));
            json_object_object_add(l_json_obj, "projects_count", json_object_new_uint64(HASH_COUNT(l_auction->projects)));
            
            if (l_auction->description) {
                json_object_object_add(l_json_obj, "description", 
                    json_object_new_string(l_auction->description));
            }
            
            // Winners information
            if (l_auction->has_winner && l_auction->winners_cnt > 0) {
                json_object *l_winners_array = json_object_new_array();
                for (uint8_t i = 0; i < l_auction->winners_cnt; i++) {
                json_object *l_winner_obj = json_object_new_object();
                    json_object_object_add(l_winner_obj, "project_id", 
                        json_object_new_uint64(l_auction->winners_ids[i]));
                    json_object_array_add(l_winners_array, l_winner_obj);
                }
                json_object_object_add(l_json_obj, "winners", l_winners_array);
                json_object_object_add(l_json_obj, "winners_count", 
                    json_object_new_uint64(l_auction->winners_cnt));
            }
            
            // Projects information
            if (l_auction->projects && HASH_COUNT(l_auction->projects) > 0) {
                json_object *l_projects_array = json_object_new_array();
                
                for (dap_auction_project_cache_item_t *l_project = l_auction->projects; l_project; l_project = l_project->hh.next) {
                    json_object *l_project_obj = json_object_new_object();
                    json_object_array_add(l_projects_array, l_project_obj);
                    // Project ID
                    json_object_object_add(l_project_obj, "project_id", json_object_new_uint64(l_project->project_id));
                   
                    const char *l_total_amount_str = dap_uint256_to_char(l_project->total_amount, NULL);
                    json_object_object_add(l_project_obj, "total_amount", json_object_new_string(l_total_amount_str));
                    
                    // Total amount in CELL
                    char *l_total_amount_coin_str = dap_uint256_decimal_to_char(l_project->total_amount);
                    if (l_total_amount_coin_str) {
                        json_object_object_add(l_project_obj, "total_amount_coin", json_object_new_string(l_total_amount_coin_str));
                        DAP_DELETE(l_total_amount_coin_str);
                    } else {
                        json_object_object_add(l_project_obj, "total_amount_coin", json_object_new_string("0.0"));
                    }
                    
                    json_object_object_add(l_project_obj, "bids_count", 
                        json_object_new_uint64(HASH_COUNT(l_project->bids)));
                    json_object_object_add(l_project_obj, "active_bids_count", 
                        json_object_new_uint64(l_project->active_bids_count));
                    if (l_verbose) {
                        json_object *l_bids_array = json_object_new_array();
                        json_object_object_add(l_project_obj, "bids", l_bids_array);
                        for (dap_auction_bid_cache_item_t *l_bid = l_project->bids; l_bid; l_bid = l_bid->hh.next) {
                            json_object *l_bid_obj = json_object_new_object();
                            json_object_array_add(l_bids_array, l_bid_obj);
                            json_object_object_add(l_bid_obj, "bid_tx_hash", json_object_new_string(dap_hash_fast_to_str_static(&l_bid->bid_tx_hash)));
                            json_object_object_add(l_bid_obj, "bid_amount", json_object_new_string(dap_uint256_to_char(l_bid->bid_amount, NULL)));
                            json_object_object_add(l_bid_obj, "lock_time", json_object_new_uint64(l_bid->lock_time));
                            char l_bid_created_time_str[DAP_TIME_STR_SIZE] = {'\0'};
                            dap_time_to_str_rfc822(l_bid_created_time_str, sizeof(l_bid_created_time_str), l_bid->created_time);
                            json_object_object_add(l_bid_obj, "created_time", json_object_new_string(l_bid_created_time_str));
                            json_object_object_add(l_bid_obj, "is_withdrawn", json_object_new_boolean(l_bid->is_withdrawn));
                        }
                    }
                }
                
                json_object_object_add(l_json_obj, "projects", l_projects_array);
            }
            
            json_object_array_add(*l_json_arr_reply, l_json_obj);

        } break;

        case CMD_EVENTS: {
            // Parse auction ID
            const char *l_auction_id_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-auction", &l_auction_id_str);
            dap_auction_cache_item_t *l_auction = NULL;
            if (!l_auction_id_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, AUCTION_HASH_ARG_ERROR, "Auction hash not specified");
                return -1;
            }
            dap_hash_fast_t l_auction_hash = {};
            bool l_hash_parsed = (dap_chain_hash_fast_from_str(l_auction_id_str, &l_auction_hash) == 0);
            if (l_hash_parsed)
                l_auction = dap_auction_cache_find_auction(s_auction_cache, &l_auction_hash);
            else {
                // Try resolve by GUUID via auction cache
                l_auction = dap_auction_cache_find_auction_by_name(s_auction_cache, l_auction_id_str);
                if (l_auction)
                    l_auction_hash = l_auction->auction_tx_hash;
            }
            if(!l_auction) {
                dap_json_rpc_error_add(*l_json_arr_reply, AUCTION_NOT_FOUND_ERROR, "Auction '%s' not found", l_auction_id_str);
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

            dap_list_t *l_events = dap_ledger_event_get_list(l_net->pub.ledger, l_auction->guuid);
            
            json_object *l_json_obj = json_object_new_object();
            json_object_object_add(l_json_obj, "command", json_object_new_string("events"));
            json_object_object_add(l_json_obj, "status", json_object_new_string("success"));
            json_object_object_add(l_json_obj, "auction_name", json_object_new_string(l_auction->guuid));
            json_object *l_events_array = json_object_new_array();
            for (dap_list_t *it = l_events; it; it = it->next) {
                dap_chain_tx_event_t *l_event = (dap_chain_tx_event_t *)it->data;
                if (l_event_type_int && l_event->event_type != l_event_type_int)
                    continue;
                json_object *l_event_obj = json_object_new_object();
                json_object_array_add(l_events_array, l_event_obj);
                dap_chain_datum_tx_event_to_json(l_event_obj, l_event, "hex");
                json_object *l_auction_data = json_object_new_object();
                json_object_object_add(l_event_obj, "auction_data", l_auction_data);
                switch (l_event->event_type) {
                case DAP_CHAIN_TX_EVENT_TYPE_AUCTION_STARTED: {
                    dap_chain_tx_event_data_auction_started_t *l_started_data = (dap_chain_tx_event_data_auction_started_t *)l_event->event_data;
                    json_object_object_add(l_auction_data, "multiplier", json_object_new_uint64(l_started_data->multiplier));
                    json_object_object_add(l_auction_data, "duration", json_object_new_uint64(l_started_data->duration));
                    json_object_object_add(l_auction_data, "time_unit", json_object_new_string(dap_chain_tx_event_data_time_unit_to_str(l_started_data->time_unit)));
                    json_object_object_add(l_auction_data, "calculation_rule_id", json_object_new_uint64(l_started_data->calculation_rule_id));
                    json_object_object_add(l_auction_data, "projects_cnt", json_object_new_uint64(l_started_data->projects_cnt));
                    json_object *l_projects_array = json_object_new_array();
                    json_object_object_add(l_auction_data, "projects", l_projects_array);
                    for (uint8_t i = 0; i < l_started_data->projects_cnt; i++) {
                        json_object *l_project_obj = json_object_new_object();
                        json_object_object_add(l_project_obj, "project_id", json_object_new_uint64(l_started_data->project_ids[i]));
                        json_object_array_add(l_projects_array, l_project_obj);
                    }
                } break;
                case DAP_CHAIN_TX_EVENT_TYPE_AUCTION_ENDED: {
                    dap_chain_tx_event_data_ended_t *l_ended_data = (dap_chain_tx_event_data_ended_t *)l_event->event_data;
                    json_object_object_add(l_auction_data, "winners_cnt", json_object_new_uint64(l_ended_data->winners_cnt));
                    json_object *l_winners_array = json_object_new_array();
                    json_object_object_add(l_auction_data, "winners", l_winners_array);
                    for (uint8_t i = 0; i < l_ended_data->winners_cnt; i++) {
                        json_object *l_winner_obj = json_object_new_object();
                        json_object_object_add(l_winner_obj, "winner_id", json_object_new_uint64(l_ended_data->winners_ids[i]));
                        json_object_array_add(l_winners_array, l_winner_obj);
                    }
                } break;
                default:
                    json_object_object_add(l_auction_data, "empty", json_object_new_null());
                    break;
                }
            }
            json_object_object_add(l_json_obj, "events", l_events_array);
            json_object_array_add(*l_json_arr_reply, l_json_obj);
        } break;

        case CMD_STATS: {
            // Get auction statistics
            dap_auction_stats_t *l_stats = dap_chain_net_srv_auctions_get_stats(l_net);
            
            json_object *l_json_obj = json_object_new_object();
            json_object_object_add(l_json_obj, "command", json_object_new_string("stats"));
            
            if (l_stats) {
                json_object_object_add(l_json_obj, "status", json_object_new_string("success"));
                json_object_object_add(l_json_obj, "total_auctions", json_object_new_uint64(l_stats->total_auctions));
                json_object_object_add(l_json_obj, "active_auctions", json_object_new_uint64(l_stats->active_auctions));
                json_object_object_add(l_json_obj, "ended_auctions", json_object_new_uint64(l_stats->ended_auctions));
                json_object_object_add(l_json_obj, "cancelled_auctions", json_object_new_uint64(l_stats->cancelled_auctions));
                json_object_object_add(l_json_obj, "total_bids", json_object_new_uint64(l_stats->total_bids));
                json_object_object_add(l_json_obj, "total_projects", json_object_new_uint64(l_stats->total_projects));
                
                DAP_DELETE(l_stats);
            } else {
                json_object_object_add(l_json_obj, "status", json_object_new_string("error"));
                json_object_object_add(l_json_obj, "message", json_object_new_string("Failed to get statistics"));
            }
            
            json_object_array_add(*l_json_arr_reply, l_json_obj);
        } break;

        default:
            dap_json_rpc_error_add(*l_json_arr_reply, COMMAND_NOT_RECOGNIZED, "Unknown command");
            return -1;
    }

    return 0;
}

int dap_auction_cache_set_winners_by_name(dap_auction_cache_t *a_cache,
                                         const char *a_guuid,
                                         uint8_t a_winners_cnt,
                                         uint32_t *a_winners_ids)
{
    if (!a_cache || !a_guuid || !a_winners_ids || a_winners_cnt == 0)
        return -1;

    pthread_rwlock_wrlock(&a_cache->cache_rwlock);

    // Find auction
    dap_auction_cache_item_t *l_auction = NULL;
    HASH_FIND_STR(a_cache->auctions, a_guuid, l_auction);
    if (!l_auction) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_WARNING, "Auction '%s' not found in cache for setting winners", a_guuid);
        return -2;
    }

    // Clean up previous winners array if exists
    DAP_DELETE(l_auction->winners_ids);

    // Set multiple winners information
    l_auction->has_winner = true;
    l_auction->winners_cnt = a_winners_cnt;
    l_auction->winners_ids = DAP_NEW_Z_SIZE(uint32_t, sizeof(uint32_t) * a_winners_cnt);
    if (!l_auction->winners_ids) {
        pthread_rwlock_unlock(&a_cache->cache_rwlock);
        log_it(L_CRITICAL, "Memory allocation error for winners array (by GUUID)");
        return -3;
    }

    memcpy(l_auction->winners_ids, a_winners_ids, sizeof(uint32_t) * a_winners_cnt);

    pthread_rwlock_unlock(&a_cache->cache_rwlock);

    log_it(L_DEBUG, "Set %u winners for auction '%s' (by GUUID)", a_winners_cnt, a_guuid);
    return 0;
}

byte_t *dap_chain_srv_auction_started_tx_event_create(size_t *a_data_size, uint32_t a_multiplier, dap_time_t a_duration,
    dap_chain_tx_event_data_time_unit_t a_time_unit, uint32_t a_calculation_rule_id, uint8_t a_projects_cnt, uint32_t a_project_ids[])
{
    size_t l_data_size = sizeof(dap_chain_tx_event_data_auction_started_t) + a_projects_cnt * sizeof(uint32_t);
    dap_chain_tx_event_data_auction_started_t *l_data = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_event_data_auction_started_t, l_data_size, NULL);

    l_data->multiplier = a_multiplier;
    l_data->duration = a_duration;
    l_data->time_unit = a_time_unit;
    l_data->calculation_rule_id = a_calculation_rule_id;
    l_data->projects_cnt = a_projects_cnt;
    memcpy(l_data->project_ids, a_project_ids, a_projects_cnt * sizeof(uint32_t));

    if (a_data_size)
        *a_data_size = l_data_size;

    return (byte_t *)l_data;
}

byte_t *dap_chain_srv_auction_ended_tx_event_create(size_t *a_data_size, uint8_t a_winners_cnt, uint32_t a_winners_ids[])
{
    size_t l_data_size = sizeof(dap_chain_tx_event_data_ended_t) + a_winners_cnt * sizeof(uint32_t);
    dap_chain_tx_event_data_ended_t *l_data = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_event_data_ended_t, l_data_size, NULL);
    l_data->winners_cnt = a_winners_cnt;
    memcpy(l_data->winners_ids, a_winners_ids, a_winners_cnt * sizeof(uint32_t));

    if (a_data_size)
        *a_data_size = l_data_size;

    return (byte_t *)l_data;
}
