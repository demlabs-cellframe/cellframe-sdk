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
            dap_tsd_t *l_tsd_data = (dap_tsd_t *)l_tsd->tsd;
            size_t l_tsd_offset = 0;
            size_t l_tsd_total_size = l_tsd->header.size;
            
            while (l_tsd_offset < l_tsd_total_size) {
                if (l_tsd_data->type == DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE) {
                    return true;  // Found arbitrage marker
                }
                l_tsd_offset += sizeof(dap_tsd_t) + l_tsd_data->size;
                l_tsd_data = (dap_tsd_t *)(l_tsd->tsd + l_tsd_offset);
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
        // No outputs - shouldn't happen for valid TX, but not arbitrage-specific error
        dap_list_free(l_list_out);
        return 0;
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
        case TX_ITEM_TYPE_OUT_COND:
            // Conditional outputs are not checked - they have their own validation
            continue;
        default:
            log_it(L_WARNING, "Unknown output type 0x%02X in arbitrage TX", l_type);
            continue;
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
            continue;
        }

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
            l_valid_owner_signs++;
            debug_if(s_arbitrage_debug_more(), L_DEBUG, "Signature #%zu is from token owner (total valid: %zu)",
                     l_sign_index, l_valid_owner_signs);
        }
    }

    dap_list_free(l_list_tx_sign);

    if (l_valid_owner_signs == 0) {
        log_it(L_WARNING, "Arbitrage TX for token %s not signed by token owner", 
               a_token_item->ticker);
        return -1;
    }

    // Check if we need minimum number of signatures (auth_signs_valid)
    if (l_valid_owner_signs < a_token_item->auth_signs_valid) {
        log_it(L_WARNING, "Arbitrage TX for token %s requires %zu owner signatures, found %zu",
               a_token_item->ticker, a_token_item->auth_signs_valid, l_valid_owner_signs);
        // Return NOT_ENOUGH_VALID_SIGNS so transaction stays in mempool for additional signatures
        // This allows distributed signing: transaction can be created on one node,
        // then signatures added from other nodes using tx_sign command.
        // See dap_chain_node_mempool_process() - transactions with DAP_CHAIN_CS_VERIFY_CODE_NOT_ENOUGH_SIGNS
        // are NOT deleted from mempool, allowing additional signatures to be added.
        return DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS;
    }

    // CRITICAL: Check that all outputs go to fee address ONLY
    if (dap_chain_arbitrage_tx_check_outputs(a_ledger, a_tx, a_token_item) != 0) {
        log_it(L_WARNING, "Arbitrage TX for token %s has outputs to non-fee addresses",
               a_token_item->ticker);
        return -1;
    }

    return 0;  // Authorized
}

