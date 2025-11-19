/*
 * Authors:
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network  https://github.com/demlabs-cellframe
 * Copyright  (c) 2025
 * All rights reserved.
 *
 * This file is part of DAP (Distributed Applications Platform) the open source project
 *
 * DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DAP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dap_chain_ledger_utxo.h"
#include "dap_chain_ledger_item.h"
#include "dap_common.h"
#include "dap_hash.h"
#include "uthash.h"

#define LOG_TAG "dap_ledger_utxo"

// ============================================================================
// UTXO BLOCKLIST INTERNAL API IMPLEMENTATIONS
// ============================================================================

/**
 * @brief Add entry to UTXO blocking history
 * @details Records all changes to UTXO blocking state for Zero/Main Chain sync.
 *          History is stored as chronologically sorted double-linked list.
 * @param a_utxo_item UTXO block item to add history to
 * @param a_action Action type (ADD/REMOVE/CLEAR)
 * @param a_bc_time Blockchain time when action occurred
 * @param a_becomes_effective When blocking becomes effective
 * @param a_becomes_unblocked When unblocking becomes effective
 * @param a_token_update_hash Hash of token_update that caused this change
 * @return 0 on success, -1 on error
 */
static int s_ledger_utxo_block_history_add(dap_ledger_utxo_block_item_t *a_utxo_item,
                                             dap_ledger_utxo_block_action_t a_action,
                                             dap_time_t a_bc_time,
                                             dap_time_t a_becomes_effective,
                                             dap_time_t a_becomes_unblocked,
                                             dap_hash_fast_t *a_token_update_hash)
{
    if (!a_utxo_item || !a_token_update_hash) {
        log_it(L_ERROR, "Invalid arguments for s_ledger_utxo_block_history_add");
        return -1;
    }
    
    // Allocate new history item
    dap_ledger_utxo_block_history_item_t *l_history_item = DAP_NEW_Z(dap_ledger_utxo_block_history_item_t);
    if (!l_history_item) {
        log_it(L_ERROR, "Memory allocation failed for UTXO block history item");
        return -1;
    }
    
    l_history_item->action = a_action;
    l_history_item->bc_time = a_bc_time;
    l_history_item->becomes_effective = a_becomes_effective;
    l_history_item->becomes_unblocked = a_becomes_unblocked;
    l_history_item->token_update_hash = *a_token_update_hash;
    l_history_item->next = NULL;
    l_history_item->prev = NULL;
    
    // Write lock for history modification
    pthread_rwlock_wrlock(&a_utxo_item->history_rwlock);
    
    // Add to tail (newest)
    if (!a_utxo_item->history_head) {
        // First history entry
        a_utxo_item->history_head = l_history_item;
        a_utxo_item->history_tail = l_history_item;
    } else {
        // Append to tail
        l_history_item->prev = a_utxo_item->history_tail;
        a_utxo_item->history_tail->next = l_history_item;
        a_utxo_item->history_tail = l_history_item;
    }
    
    pthread_rwlock_unlock(&a_utxo_item->history_rwlock);
    
    log_it(L_DEBUG, "Added UTXO block history entry: action=%d, bc_time=%"DAP_UINT64_FORMAT_U,
           a_action, a_bc_time);
    
    return 0;
}

bool dap_ledger_utxo_block_get_state_at_time(dap_ledger_token_item_t *a_token_item,
                                              dap_chain_hash_fast_t *a_tx_hash,
                                              uint32_t a_out_idx,
                                              dap_time_t a_blockchain_time)
{
    if (!a_token_item || !a_tx_hash) {
        return false;
    }
    
    // Check if UTXO blocking is disabled for this token
    if (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED) {
        return false;
    }
    
    // Read lock for checking
    pthread_rwlock_rdlock(&a_token_item->utxo_blocklist_rwlock);
    
    // Create lookup key
    dap_ledger_utxo_block_key_t lookup_key = {
        .tx_hash = *a_tx_hash,
        .out_idx = a_out_idx
    };
    
    // Search in hash table
    dap_ledger_utxo_block_item_t *l_found = NULL;
    HASH_FIND(hh, a_token_item->utxo_blocklist, &lookup_key, sizeof(dap_ledger_utxo_block_key_t), l_found);
    
    if (!l_found) {
        pthread_rwlock_unlock(&a_token_item->utxo_blocklist_rwlock);
        return false;  // UTXO not in blocklist
    }
    
    // Replay history if available
    pthread_rwlock_rdlock(&l_found->history_rwlock);
    
    if (!l_found->history_head) {
        // No history → fallback to current state (backward compatibility)
        pthread_rwlock_unlock(&l_found->history_rwlock);
        pthread_rwlock_unlock(&a_token_item->utxo_blocklist_rwlock);
        
        // Use current state logic
        bool l_is_blocked = (l_found->becomes_effective <= a_blockchain_time) &&
                           (l_found->becomes_unblocked == 0 || l_found->becomes_unblocked > a_blockchain_time);
        return l_is_blocked;
    }
    
    // Replay history chronologically
    bool l_current_state_blocked = false;
    dap_ledger_utxo_block_history_item_t *l_history_item = l_found->history_head;
    
    while (l_history_item) {
        // Only process events that occurred before or at query time
        if (l_history_item->bc_time <= a_blockchain_time) {
            switch (l_history_item->action) {
                case BLOCK_ACTION_ADD:
                    // Check if blocking is effective at query time
                    if (l_history_item->becomes_effective <= a_blockchain_time) {
                        l_current_state_blocked = true;
                    }
                    break;
                case BLOCK_ACTION_REMOVE:
                    // Check if unblocking is effective at query time
                    if (l_history_item->becomes_unblocked == 0 || 
                        l_history_item->becomes_unblocked <= a_blockchain_time) {
                        l_current_state_blocked = false;
                    }
                    break;
                case BLOCK_ACTION_CLEAR:
                    l_current_state_blocked = false;
                    break;
                default:
                    log_it(L_WARNING, "Unknown UTXO block history action: %d", l_history_item->action);
                    break;
            }
        } else {
            // Future events don't affect state at query time
            break;
        }
        
        l_history_item = l_history_item->next;
    }
    
    pthread_rwlock_unlock(&l_found->history_rwlock);
    pthread_rwlock_unlock(&a_token_item->utxo_blocklist_rwlock);
    
    return l_current_state_blocked;
}

bool dap_ledger_utxo_is_blocked(dap_ledger_token_item_t *a_token_item,
                                dap_chain_hash_fast_t *a_tx_hash,
                                uint32_t a_out_idx,
                                dap_ledger_t *a_ledger)
{
    if (!a_token_item || !a_tx_hash || !a_ledger) {
        return false;
    }
    
    // Use history-aware function for accurate state reconstruction
    dap_time_t l_blockchain_time = dap_ledger_get_blockchain_time(a_ledger);
    return dap_ledger_utxo_block_get_state_at_time(a_token_item, a_tx_hash, a_out_idx, l_blockchain_time);
}

int dap_ledger_utxo_block_add(dap_ledger_token_item_t *a_token_item,
                              dap_chain_hash_fast_t *a_tx_hash,
                              uint32_t a_out_idx,
                              dap_time_t a_becomes_effective,
                              dap_hash_fast_t *a_token_update_hash,
                              dap_ledger_t *a_ledger)
{
    if (!a_token_item || !a_tx_hash) {
        log_it(L_ERROR, "Invalid arguments for dap_ledger_utxo_block_add");
        return -1;
    }

    // Check if UTXO blocking is disabled
    if (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED) {
        log_it(L_WARNING, "UTXO blocking is disabled for token %s", a_token_item->ticker);
        return -1;
    }

    // Check if blocklist is static
    if (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_STATIC_BLOCKLIST) {
        log_it(L_WARNING, "UTXO blocklist is static for token %s, cannot modify", a_token_item->ticker);
        return -1;
    }

    // Write lock for modification
    pthread_rwlock_wrlock(&a_token_item->utxo_blocklist_rwlock);

    // Check if already exists
    dap_ledger_utxo_block_key_t lookup_key = {
        .tx_hash = *a_tx_hash,
        .out_idx = a_out_idx
    };

    dap_ledger_utxo_block_item_t *l_found = NULL;
    HASH_FIND(hh, a_token_item->utxo_blocklist, &lookup_key, sizeof(dap_ledger_utxo_block_key_t), l_found);

    if (l_found) {
        pthread_rwlock_unlock(&a_token_item->utxo_blocklist_rwlock);
        log_it(L_DEBUG, "UTXO already blocked");
        return 0;  // Already blocked
    }

    // Create new block item
    dap_ledger_utxo_block_item_t *l_item = DAP_NEW_Z(dap_ledger_utxo_block_item_t);
    if (!l_item) {
        pthread_rwlock_unlock(&a_token_item->utxo_blocklist_rwlock);
        log_it(L_ERROR, "Memory allocation failed for UTXO block item");
        return -1;
    }

    l_item->key.tx_hash = *a_tx_hash;
    l_item->key.out_idx = a_out_idx;
    l_item->blocked_time = dap_time_now();
    l_item->becomes_effective = a_becomes_effective;
    l_item->becomes_unblocked = 0;  // 0 = permanent block (no scheduled unblock)
    
    // Initialize history
    l_item->history_head = NULL;
    l_item->history_tail = NULL;
    if (pthread_rwlock_init(&l_item->history_rwlock, NULL) != 0) {
        pthread_rwlock_unlock(&a_token_item->utxo_blocklist_rwlock);
        DAP_DELETE(l_item);
        log_it(L_ERROR, "Failed to initialize history rwlock for UTXO block item");
        return -1;
    }

    // Add to hash table
    HASH_ADD(hh, a_token_item->utxo_blocklist, key, sizeof(dap_ledger_utxo_block_key_t), l_item);
    a_token_item->utxo_blocklist_count++;

    pthread_rwlock_unlock(&a_token_item->utxo_blocklist_rwlock);

    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_tx_hash, l_hash_str, sizeof(l_hash_str));
    log_it(L_INFO, "Added UTXO to blocklist: token=%s, tx=%s, out_idx=%u, becomes_effective=%"DAP_UINT64_FORMAT_U,
           a_token_item->ticker, l_hash_str, a_out_idx, a_becomes_effective);
    
    // Add to history if token_update_hash is provided
    if (a_token_update_hash && a_ledger) {
        dap_time_t l_bc_time = dap_ledger_get_blockchain_time(a_ledger);
        if (s_ledger_utxo_block_history_add(l_item, BLOCK_ACTION_ADD, l_bc_time, 
                                              a_becomes_effective, 0, a_token_update_hash) != 0) {
            log_it(L_WARNING, "Failed to add UTXO block history entry for token %s", a_token_item->ticker);
            // Continue anyway - history is for audit, not critical for blocking functionality
        }
    }

    return 0;
}

int dap_ledger_utxo_block_remove(dap_ledger_token_item_t *a_token_item,
                                 dap_chain_hash_fast_t *a_tx_hash,
                                 uint32_t a_out_idx,
                                 dap_time_t a_becomes_unblocked,
                                 dap_hash_fast_t *a_token_update_hash,
                                 dap_ledger_t *a_ledger)
{
    if (!a_token_item || !a_tx_hash) {
        log_it(L_ERROR, "Invalid arguments for dap_ledger_utxo_block_remove");
        return -1;
    }

    // Check if blocklist is static
    if (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_STATIC_BLOCKLIST) {
        log_it(L_WARNING, "UTXO blocklist is static for token %s, cannot modify", a_token_item->ticker);
        return -1;
    }

    // Write lock for modification
    pthread_rwlock_wrlock(&a_token_item->utxo_blocklist_rwlock);

    // Find item
    dap_ledger_utxo_block_key_t lookup_key = {
        .tx_hash = *a_tx_hash,
        .out_idx = a_out_idx
    };

    dap_ledger_utxo_block_item_t *l_found = NULL;
    HASH_FIND(hh, a_token_item->utxo_blocklist, &lookup_key, sizeof(dap_ledger_utxo_block_key_t), l_found);

    if (!l_found) {
        pthread_rwlock_unlock(&a_token_item->utxo_blocklist_rwlock);
        log_it(L_WARNING, "UTXO not found in blocklist");
        return -1;
    }

    // Update becomes_unblocked time (0 = immediate, >0 = delayed)
    // Note: We keep item in hash table for history tracking.
    // Cleanup happens during periodic history maintenance.
    l_found->becomes_unblocked = a_becomes_unblocked;

    pthread_rwlock_unlock(&a_token_item->utxo_blocklist_rwlock);

    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_tx_hash, l_hash_str, sizeof(l_hash_str));
    if (a_becomes_unblocked == 0) {
        log_it(L_INFO, "Scheduled UTXO immediate unblocking: token=%s, tx=%s, out_idx=%u",
               a_token_item->ticker, l_hash_str, a_out_idx);
    } else {
        log_it(L_INFO, "Scheduled UTXO delayed unblocking: token=%s, tx=%s, out_idx=%u, unblock_time=%"DAP_UINT64_FORMAT_U,
               a_token_item->ticker, l_hash_str, a_out_idx, (uint64_t)a_becomes_unblocked);
    }
    
    // Add to history if token_update_hash is provided
    if (a_token_update_hash && a_ledger) {
        dap_time_t l_bc_time = dap_ledger_get_blockchain_time(a_ledger);
        if (s_ledger_utxo_block_history_add(l_found, BLOCK_ACTION_REMOVE, l_bc_time, 
                                              0, a_becomes_unblocked, a_token_update_hash) != 0) {
            log_it(L_WARNING, "Failed to add UTXO unblock history entry for token %s", a_token_item->ticker);
            // Continue anyway - history is for audit, not critical for unblocking functionality
        }
    }

    return 0;
}

int dap_ledger_utxo_block_clear(dap_ledger_token_item_t *a_token_item,
                                dap_hash_fast_t *a_token_update_hash,
                                dap_ledger_t *a_ledger)
{
    if (!a_token_item) {
        log_it(L_ERROR, "Invalid arguments for dap_ledger_utxo_block_clear");
        return -1;
    }

    // Check if blocklist is static
    if (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_STATIC_BLOCKLIST) {
        log_it(L_WARNING, "UTXO blocklist is static for token %s, cannot clear", a_token_item->ticker);
        return -1;
    }

    // Get blockchain time before acquiring lock
    dap_time_t l_bc_time = a_ledger ? dap_ledger_get_blockchain_time(a_ledger) : 0;

    // Read lock is sufficient - we only add to history, not modify hash table
    pthread_rwlock_rdlock(&a_token_item->utxo_blocklist_rwlock);

    size_t l_cleared_count = 0;
    dap_ledger_utxo_block_item_t *l_item, *l_tmp;
    
    // Add CLEAR action to history for each UTXO
    // CRITICAL: DO NOT delete items from hash table!
    // Items must remain for accurate history replay during sync.
    if (a_token_update_hash && a_ledger) {
        HASH_ITER(hh, a_token_item->utxo_blocklist, l_item, l_tmp) {
            if (s_ledger_utxo_block_history_add(l_item, BLOCK_ACTION_CLEAR, l_bc_time, 
                                                  0, 0, a_token_update_hash) != 0) {
                log_it(L_WARNING, "Failed to add CLEAR history entry for UTXO in token %s", a_token_item->ticker);
            } else {
                l_cleared_count++;
            }
        }
    }

    pthread_rwlock_unlock(&a_token_item->utxo_blocklist_rwlock);

    log_it(L_INFO, "Added CLEAR action to UTXO blocklist history for token %s (%zu items marked)", 
           a_token_item->ticker, l_cleared_count);

    return 0;
}

