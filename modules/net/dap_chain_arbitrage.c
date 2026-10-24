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

#include "dap_chain_arbitrage.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_item.h"  // For dap_ledger_token_item_t definition
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_tsd.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_net.h"
#include "dap_hash.h"
#include "dap_pkey.h"
#include "dap_sign.h"
#include "dap_common.h"
#include "dap_list.h"
#include "dap_config.h"

#define LOG_TAG "dap_chain_arbitrage"

// Helper function to check debug_more flag from config
static bool s_arbitrage_debug_more(void)
{
    static bool s_checked = false;
    static bool s_value = false;
    if (!s_checked) {
        if (g_config) {
            s_value = dap_config_get_item_bool_default(g_config, "ledger", "debug_more", false);
        }
        s_checked = true;
    }
    return s_value;
}

/**
 * @brief Check if transaction is marked as arbitrage
 * @details Arbitrage TX are marked with DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE TSD section.
 *          These transactions allow token owners to claim ANY output (blocked/conditional).
 * @param a_tx Transaction to check
 * @return true if transaction has arbitrage marker, false otherwise
 */
bool dap_chain_arbitrage_tx_is_arbitrage(dap_chain_datum_tx_t *a_tx)
{
    if (!a_tx) {
        return false;
    }

    // Iterate through TX items looking for TSD with arbitrage marker
    byte_t *l_tx_item = a_tx->tx_items;
    size_t l_tx_items_pos = 0;
    size_t l_tx_items_size = a_tx->header.tx_items_size;
    bool l_found_tsd_item = false;

    while (l_tx_items_pos < l_tx_items_size) {
        uint8_t *l_item = l_tx_item + l_tx_items_pos;
        size_t l_item_size = dap_chain_datum_item_tx_get_size(l_item, l_tx_items_size - l_tx_items_pos);
        
        if (!l_item_size) {
            log_it(L_ERROR, "Zero item size in TX");
            return false;
        }

        dap_chain_tx_item_type_t l_type = *((uint8_t *)l_item);
        
        if (l_type == TX_ITEM_TYPE_TSD) {
            l_found_tsd_item = true;
            dap_chain_tx_tsd_t *l_tsd = (dap_chain_tx_tsd_t *)l_item;
            
            // Check if TSD contains arbitrage marker
            size_t l_tsd_payload_size = l_item_size > sizeof(dap_chain_tx_tsd_t)
                                        ? l_item_size - sizeof(dap_chain_tx_tsd_t) : 0;
            size_t l_tsd_total_size = l_tsd->header.size;
            if (l_tsd_total_size > l_tsd_payload_size)
                l_tsd_total_size = l_tsd_payload_size;
            size_t l_tsd_offset = 0;
            
            while (l_tsd_offset + sizeof(dap_tsd_t) <= l_tsd_total_size) {
                dap_tsd_t *l_tsd_data = (dap_tsd_t *)(l_tsd->tsd + l_tsd_offset);
                if (l_tsd_data->type == DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE) {
                    return true;  // Found arbitrage marker
                }
                size_t l_next = l_tsd_offset + sizeof(dap_tsd_t) + l_tsd_data->size;
                if (l_next <= l_tsd_offset)
                    break;
                l_tsd_offset = l_next;
            }
        }
        
        l_tx_items_pos += l_item_size;
    }

    // Log if TSD item was found but arbitrage marker was not
    if (l_found_tsd_item) {
        log_it(L_DEBUG, "TX has TSD item but no arbitrage marker found");
    }
    
    return false;  // No arbitrage marker found
}

/**
 * @brief Get arbitrage token ticker from transaction outputs
 * @details For arbitrage TX, determine which token is being arbitraged with a two-pass
 *          scan over OUT_STD/OUT_EXT outputs:
 *          pass 0 returns the first non-native ticker (multi-channel arbitrage: the
 *          target token differs from the fee token), pass 1 falls back to any ticker
 *          (single-channel arbitrage: the target token IS the native token).
 *          This is SECURITY CRITICAL - we must authorize against the real arbitrage
 *          target, not just against the fee leg of the transaction.
 * @param a_ledger Ledger containing network configuration
 * @param a_tx Transaction to analyze
 * @return Token ticker string (thread-local buffer) or NULL if not found
 * @note Returns pointer to thread-local storage - safe for concurrent validation,
 *       but callers must copy the value before the next call from the same thread
 */
const char *dap_chain_arbitrage_tx_get_token_ticker(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx)
{
    if (!a_ledger || !a_tx) {
        return NULL;
    }
    
    static _Thread_local char s_arbitrage_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    const char *l_native_ticker = a_ledger->net->pub.native_ticker;
    
    // Two-pass scan: prefer a non-native ticker (the real arbitrage target);
    // if every output is native - it's a single-channel arbitrage, return native.
    const char *l_first_ticker = NULL;
    byte_t *l_tx_item = a_tx->tx_items;
    size_t l_tx_items_size = a_tx->header.tx_items_size;
    
    for (int l_pass = 0; l_pass < 2; l_pass++) {
        size_t l_pos = 0;
        while (l_pos < l_tx_items_size) {
            uint8_t *l_item = l_tx_item + l_pos;
            size_t l_item_size = dap_chain_datum_item_tx_get_size(l_item, l_tx_items_size - l_pos);
            
            if (!l_item_size) {
                break;
            }
            
            dap_chain_tx_item_type_t l_type = *((uint8_t *)l_item);
            const char *l_token = NULL;
            
            switch (l_type) {
                case TX_ITEM_TYPE_OUT_STD:
                    l_token = ((dap_chain_tx_out_std_t *)l_item)->token;
                    break;
                case TX_ITEM_TYPE_OUT_EXT:
                    l_token = ((dap_chain_tx_out_ext_t *)l_item)->token;
                    break;
                default:
                    break;
            }
            
            if (l_token && l_token[0] != '\0') {
                if (!l_first_ticker)
                    l_first_ticker = l_token;
                bool l_is_native = l_native_ticker && !strcmp(l_token, l_native_ticker);
                // Pass 0: first non-native ticker (multi-channel arbitrage target)
                // Pass 1: any ticker (single-channel: all outputs are native)
                if (l_pass == 1 || !l_is_native) {
                    dap_strncpy(s_arbitrage_ticker, l_token, DAP_CHAIN_TICKER_SIZE_MAX - 1);
                    s_arbitrage_ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
                    return s_arbitrage_ticker;
                }
            }
            
            l_pos += l_item_size;
        }
        if (!l_first_ticker)
            break;
    }
    
    return NULL;  // No arbitrage token found in outputs
}

/**
 * @brief Check if arbitrage TX outputs are directed to fee address ONLY
 * @details Arbitrage transactions can ONLY send funds to the network fee collection address.
 *          This prevents abuse where token owners could steal funds via arbitrage.
 *          Fee address is defined in network configuration (a_ledger->net->pub.fee_addr).
 * @param a_ledger Ledger containing network configuration with fee address
 * @param a_tx Transaction to validate
 * @param a_token_item Token item (for logging)
 * @return 0 if all outputs are to fee address, -1 if any output is not to fee address
 */
int dap_chain_arbitrage_tx_check_outputs(dap_ledger_t *a_ledger,
                                         dap_chain_datum_tx_t *a_tx,
                                         dap_ledger_token_item_t *a_token_item)
{
    if (!a_ledger || !a_tx || !a_token_item) {
        log_it(L_ERROR, "Invalid arguments for arbitrage outputs check");
        return -1;
    }

    // Check if network has fee address configured
    if (dap_chain_addr_is_blank(&a_ledger->net->pub.fee_addr)) {
        log_it(L_WARNING, "Arbitrage TX for token %s rejected: network has no fee address configured", 
               a_token_item->ticker);
        return -1;
    }

    const dap_chain_addr_t *l_fee_addr = &a_ledger->net->pub.fee_addr;
    log_it(L_DEBUG, "Validating arbitrage TX outputs against fee address: %s", 
           dap_chain_addr_to_str_static(l_fee_addr));

    // Get all OUT items from transaction
    int l_out_count = 0;
    dap_list_t *l_list_out = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT_ALL, &l_out_count);
    
    if (!l_list_out || l_out_count == 0) {
        log_it(L_WARNING, "Arbitrage TX for token %s rejected: no recognizable outputs", a_token_item->ticker);
        dap_list_free(l_list_out);
        return -1;
    }

    // Check each output - ALL must go to fee address
    bool l_all_outputs_to_fee = true;
    for (dap_list_t *l_iter = l_list_out; l_iter; l_iter = l_iter->next) {
        void *l_out_item = l_iter->data;
        if (!l_out_item) {
            continue;
        }

        // Extract address from different output types
        dap_chain_addr_t *l_addr = NULL;
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_out_item;
        
        switch (l_type) {
        case TX_ITEM_TYPE_OUT_OLD:
            l_addr = &((dap_chain_tx_out_old_t *)l_out_item)->addr;
            break;
        case TX_ITEM_TYPE_OUT:
            l_addr = &((dap_chain_tx_out_t *)l_out_item)->addr;
            break;
        case TX_ITEM_TYPE_OUT_EXT:
            l_addr = &((dap_chain_tx_out_ext_t *)l_out_item)->addr;
            break;
        case TX_ITEM_TYPE_OUT_STD:
            l_addr = &((dap_chain_tx_out_std_t *)l_out_item)->addr;
            break;
        case TX_ITEM_TYPE_OUT_COND: {
            // A conditional output is redeemable on its own terms, so only the fee-kind
            // condition can be considered as "directed to the fee address".
            dap_chain_tx_out_cond_t *l_cond = (dap_chain_tx_out_cond_t *)l_out_item;
            if (l_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                log_it(L_WARNING, "Arbitrage TX for token %s rejected: non-fee conditional output (subtype 0x%02X)",
                       a_token_item->ticker, l_cond->header.subtype);
                l_all_outputs_to_fee = false;
                break;
            }
            continue;
        }
        default:
            // An output the check does not understand cannot be proven to go to the fee
            // address, so it must not pass the "fee address only" rule.
            log_it(L_WARNING, "Unknown output type 0x%02X in arbitrage TX — rejecting", l_type);
            dap_list_free(l_list_out);
            return -1;
        }

        if (!l_addr) {
            continue;
        }

        // Check if this output goes to fee address
        if (!dap_chain_addr_compare(l_fee_addr, l_addr)) {
            log_it(L_WARNING, "Arbitrage TX for token %s rejected: output to %s (NOT fee address %s)",
                   a_token_item->ticker, 
                   dap_chain_addr_to_str_static(l_addr),
                   dap_chain_addr_to_str_static(l_fee_addr));
            l_all_outputs_to_fee = false;
            break;
        }
    }

    dap_list_free(l_list_out);

    if (l_all_outputs_to_fee) {
        log_it(L_INFO, "✓ Arbitrage TX for token %s: all outputs directed to fee address", 
               a_token_item->ticker);
    }

    return l_all_outputs_to_fee ? 0 : -1;
}

/**
 * @brief Check arbitrage transaction authorization
 * @details Validates that TX is signed by required number of token owners.
 *          Token owners are determined from token datum (auth_pkeys).
 *          Also validates that all outputs go to network fee address ONLY.
 *          Wallet signature (first signature) is used ONLY for fee payment authorization,
 *          NOT for arbitrage authorization, unless fee token == arbitrage token.
 * @param a_ledger Ledger containing network configuration
 * @param a_tx Transaction to validate
 * @param a_token_item Token item with owner information
 * @return 0 if authorized, -1 if not authorized, DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS if insufficient signatures
 */
int dap_chain_arbitrage_tx_check_auth(dap_ledger_t *a_ledger,
                                      dap_chain_datum_tx_t *a_tx,
                                      dap_ledger_token_item_t *a_token_item)
{
    if (!a_ledger || !a_tx || !a_token_item) {
        log_it(L_ERROR, "Invalid arguments for arbitrage auth check");
        return -1;
    }

    // Check if arbitrage is disabled for this token
    // By default, arbitrage is ALLOWED (flag is NOT set)
    // Only if UTXO_ARBITRAGE_TX_DISABLED flag is explicitly set, arbitrage is disabled
    if (a_token_item->flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_ARBITRAGE_TX_DISABLED) {
        log_it(L_WARNING, "Arbitrage transactions disabled for token %s (UTXO_ARBITRAGE_TX_DISABLED flag is set)", a_token_item->ticker);
        return -1;
    }
    
    // Arbitrage is allowed by default (flag is not set)
    debug_if(s_arbitrage_debug_more(), L_DEBUG, "Arbitrage transactions allowed for token %s (UTXO_ARBITRAGE_TX_DISABLED flag is not set, flags=0x%08X)", 
             a_token_item->ticker, a_token_item->flags);

    // Validate the TX structure (outputs) BEFORE checking signatures: broken outputs
    // cannot be repaired by adding signatures, while a missing signature must keep the
    // TX in the mempool for the distributed-signing flow (tx_sign).
    if (dap_chain_arbitrage_tx_check_outputs(a_ledger, a_tx, a_token_item) != 0) {
        log_it(L_WARNING, "Arbitrage TX for token %s has outputs to non-fee addresses",
               a_token_item->ticker);
        return -1;
    }

    // Without configured auth keys nobody can authorize an arbitrage for this token
    if (a_token_item->auth_signs_total == 0) {
        log_it(L_WARNING, "Arbitrage TX for token %s rejected: token has no auth keys (auth_signs_total=0)",
               a_token_item->ticker);
        return -1;
    }

    // auth_signs_valid == 0 means no threshold is configured - still require one owner signature
    size_t l_min_required = a_token_item->auth_signs_valid;
    if (l_min_required == 0)
        l_min_required = 1;

    // Get TX signatures
    int l_sign_count = 0;
    dap_list_t *l_list_tx_sign = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_SIG, &l_sign_count);
    
    if (!l_list_tx_sign || l_sign_count == 0) {
        log_it(L_WARNING, "Arbitrage TX has no signatures");
        dap_list_free(l_list_tx_sign);
        return -1;
    }

    // Determine fee token (native ticker) and compare with arbitrage token
    // Wallet signature (first signature) is used ONLY for fee payment authorization,
    // NOT for arbitrage authorization, unless fee token and arbitrage token are the same
    const char *l_fee_token_ticker = a_ledger->net->pub.native_ticker;
    bool l_fee_token_same_as_arbitrage = l_fee_token_ticker && 
                                          !dap_strcmp(l_fee_token_ticker, a_token_item->ticker);
    
    debug_if(s_arbitrage_debug_more(), L_DEBUG, "Arbitrage TX for token %s: fee_token=%s, same_as_arbitrage=%d",
             a_token_item->ticker, l_fee_token_ticker ? l_fee_token_ticker : "NULL", l_fee_token_same_as_arbitrage);

    // Check that at least one signature is from token owner
    // IMPORTANT: First signature (wallet signature) is used ONLY for fee payment authorization.
    // It should NOT count towards arbitrage authorization unless fee token == arbitrage token.
    size_t l_valid_owner_signs = 0;
    size_t l_sign_index = 0;
    // Unique owner pkey hashes counted so far: one key must not be counted twice,
    // otherwise a single owner key would satisfy any threshold (heap-allocated for safety)
    dap_chain_hash_fast_t *l_counted_hashes = DAP_NEW_Z_COUNT(dap_chain_hash_fast_t, (size_t)l_sign_count);
    if (!l_counted_hashes) {
        log_it(L_ERROR, "Memory allocation failed for owner key deduplication (%d entries)", l_sign_count);
        dap_list_free(l_list_tx_sign);
        return -1;
    }
    size_t l_counted_count = 0;
    
    for (dap_list_t *l_iter = l_list_tx_sign; l_iter; l_iter = l_iter->next, l_sign_index++) {
        dap_chain_tx_sig_t *l_sig = (dap_chain_tx_sig_t *)l_iter->data;
        if (!l_sig) {
            continue;
        }

        // Get public key from signature
        dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_sig);
        if (!l_sign) {
            continue;
        }

        // Get pkey hash from signature
        dap_pkey_t *l_pkey = dap_pkey_get_from_sign(l_sign);
        if (!l_pkey) {
            continue;
        }

        dap_chain_hash_fast_t l_pkey_hash;
        if (!dap_pkey_get_hash(l_pkey, &l_pkey_hash)) {
            DAP_DELETE(l_pkey);
            continue;
        }
        DAP_DELETE(l_pkey);

        // Check if this pkey is in token's auth_pkeys
        bool l_is_owner = false;
        for (uint16_t i = 0; i < a_token_item->auth_signs_total; i++) {
            dap_chain_hash_fast_t l_owner_hash;
            if (dap_pkey_get_hash(a_token_item->auth_pkeys[i], &l_owner_hash)) {
                if (dap_hash_fast_compare(&l_pkey_hash, &l_owner_hash)) {
                    l_is_owner = true;
                    break;  // Found this owner
                }
            }
        }
        
        // CRITICAL: First signature (wallet signature) is used ONLY for fee payment authorization.
        // It should NOT count towards arbitrage authorization unless fee token == arbitrage token.
        if (l_sign_index == 0 && !l_fee_token_same_as_arbitrage) {
            // First signature is wallet signature for fee payment - skip it for arbitrage auth
            debug_if(s_arbitrage_debug_more(), L_DEBUG, "Skipping first signature (wallet) for arbitrage auth: fee_token=%s != arbitrage_token=%s",
                     l_fee_token_ticker ? l_fee_token_ticker : "NULL", a_token_item->ticker);
            continue;
        }
        
        // Count signature only if it's from token owner
        if (l_is_owner) {
            // Cryptographically verify this signature before counting it: without this,
            // anybody could craft a SIG item with a victim's pubkey and a garbage signature.
            if (dap_chain_datum_tx_verify_sign(a_tx, (int)l_sign_index) != 0) {
                log_it(L_WARNING, "Arbitrage TX: owner signature #%zu failed cryptographic verification - not counting it",
                       l_sign_index);
                continue;
            }

            // Check this owner key hasn't been counted already (a single key must not
            // satisfy a multi-signature threshold by repeating itself)
            bool l_already_counted = false;
            for (size_t k = 0; k < l_counted_count; k++) {
                if (dap_hash_fast_compare(&l_pkey_hash, &l_counted_hashes[k])) {
                    l_already_counted = true;
                    break;
                }
            }
            if (l_already_counted) {
                debug_if(s_arbitrage_debug_more(), L_DEBUG,
                         "Signature #%zu is a duplicate owner key - not counting it again", l_sign_index);
                continue;
            }
            l_counted_hashes[l_counted_count++] = l_pkey_hash;

            l_valid_owner_signs++;
            debug_if(s_arbitrage_debug_more(), L_DEBUG, "Signature #%zu is from token owner (total valid: %zu)",
                     l_sign_index, l_valid_owner_signs);
        }
    }

    dap_list_free(l_list_tx_sign);
    DAP_DEL_Z(l_counted_hashes);

    if (l_valid_owner_signs == 0) {
        log_it(L_WARNING, "Arbitrage TX for token %s not signed by token owner", 
               a_token_item->ticker);
        return -1;
    }

    // Check if we need minimum number of signatures (auth_signs_valid)
    if (l_valid_owner_signs < l_min_required) {
        log_it(L_WARNING, "Arbitrage TX for token %s requires %zu owner signatures, found %zu",
               a_token_item->ticker, l_min_required, l_valid_owner_signs);
        // Return NOT_ENOUGH_VALID_SIGNS so transaction stays in mempool for additional signatures
        // This allows distributed signing: transaction can be created on one node,
        // then signatures added from other nodes using tx_sign command.
        // See dap_chain_node_mempool_process() - transactions with DAP_CHAIN_CS_VERIFY_CODE_NOT_ENOUGH_SIGNS
        // are NOT deleted from mempool, allowing additional signatures to be added.
        return DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS;
    }

    return 0;  // Authorized
}

