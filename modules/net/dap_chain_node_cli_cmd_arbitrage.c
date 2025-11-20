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

#include "dap_chain_node_cli_cmd_arbitrage.h"
#include "dap_chain_arbitrage.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_cache.h"
#include "dap_enc_key.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_tsd.h"
#include "dap_chain_datum.h"
#include "dap_chain_mempool.h"
#include "dap_chain_ledger.h"
#include "dap_cert.h"
#include "dap_list.h"
#include "dap_math_ops.h"
#include "dap_common.h"
#include "dap_json_rpc_errors.h"
#include "json.h"

#define LOG_TAG "dap_chain_node_cli_arbitrage"

/**
 * @brief Create arbitrage transaction with multiple signatures
 * @param a_chain Target chain
 * @param a_key_from Sender's private key (from wallet)
 * @param a_addr_from Sender's address
 * @param a_addr_to Recipient addresses (array)
 * @param a_token_ticker Token ticker
 * @param a_value Transfer values (array)
 * @param a_value_fee Fee value
 * @param a_hash_out_type Output hash type
 * @param a_tx_num Number of outputs
 * @param a_time_unlock Lock times (array, optional)
 * @param a_tsd_list List of TSD sections (must include arbitrage TSD)
 * @param a_arbitrage_certs Array of certificates for additional signatures
 * @param a_arbitrage_certs_count Number of certificates
 * @return Transaction hash string or NULL on error
 */
char *dap_chain_arbitrage_tx_create_with_signatures(
    dap_chain_t *a_chain,
    dap_enc_key_t *a_key_from,
    const dap_chain_addr_t *a_addr_from,
    const dap_chain_addr_t **a_addr_to,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t *a_value,
    uint256_t a_value_fee,
    const char *a_hash_out_type,
    size_t a_tx_num,
    dap_time_t *a_time_unlock,
    dap_list_t *a_tsd_list,
    dap_cert_t **a_arbitrage_certs,
    size_t a_arbitrage_certs_count)
{
    // Check valid params
    dap_return_val_if_pass(!a_chain || !a_key_from || !a_addr_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
            dap_chain_addr_check_sum(a_addr_from) || !a_tx_num || !a_value, NULL);
    for (size_t i = 0; i < a_tx_num; ++i) {
        dap_return_val_if_pass((a_addr_to && dap_chain_addr_check_sum(a_addr_to[i])) || IS_ZERO_256(a_value[i]), NULL);
    }

    const char *l_native_ticker = dap_chain_net_by_id(a_chain->net_id)->pub.native_ticker;
    bool l_single_channel = !dap_strcmp(a_token_ticker, l_native_ticker);
    
    // Find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_value_total = {}, l_net_fee = {}, l_total_fee = {}, l_fee_transfer = {};
    for (size_t i = 0; i < a_tx_num; ++i) {
        SUM_256_256(l_value_total, a_value[i], &l_value_total);
    }
    uint256_t l_value_need = l_value_total;
    dap_chain_addr_t l_addr_fee = {};
    dap_list_t *l_list_fee_out = NULL;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_chain->net_id, &l_net_fee, &l_addr_fee);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    dap_ledger_t *l_ledger = dap_chain_net_by_id(a_chain->net_id)->pub.ledger;
    
    if (l_single_channel)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else if (!IS_ZERO_256(l_total_fee)) {
        if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, l_native_ticker, a_addr_from, &l_list_fee_out, l_total_fee, &l_fee_transfer) == -101)
            l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                    a_addr_from, l_total_fee, &l_fee_transfer);
        if (!l_list_fee_out) {
            log_it(L_WARNING, "Not enough funds to pay fee");
            return NULL;
        }
    }
    
    dap_list_t *l_list_used_out = NULL;
    if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, a_token_ticker, a_addr_from, &l_list_used_out, l_value_need, &l_value_transfer) == -101)
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_token_ticker,
                                            a_addr_from, l_value_need, &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_WARNING, "Not enough funds to transfer");
        if (l_list_fee_out) dap_list_free_full(l_list_fee_out, NULL);
        return NULL;
    }
    
    // Create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        if (l_list_fee_out) dap_list_free_full(l_list_fee_out, NULL);
        dap_list_free_full(l_list_used_out, NULL);
        return NULL;
    }
    
    // Add 'in' items
    {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
        dap_list_free_full(l_list_used_out, NULL);
        if (l_list_fee_out) {
            uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
            assert(EQUAL_256(l_value_fee_items, l_fee_transfer));
            dap_list_free_full(l_list_fee_out, NULL);
        }
    }
    
    if (a_tx_num > 1) {
        uint32_t l_tx_num = a_tx_num;
        dap_chain_tx_tsd_t *l_out_count = dap_chain_datum_tx_item_tsd_create(&l_tx_num, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT, sizeof(uint32_t));
        if (l_out_count) {
            dap_chain_datum_tx_add_item(&l_tx, l_out_count);
            DAP_DELETE(l_out_count);
        }
    }

    // Add custom TSD sections if provided (must include arbitrage TSD)
    if (a_tsd_list) {
        for (dap_list_t *l_iter = a_tsd_list; l_iter; l_iter = l_iter->next) {
            dap_chain_tx_tsd_t *l_tsd = (dap_chain_tx_tsd_t *)l_iter->data;
            if (l_tsd) {
                if (dap_chain_datum_tx_add_item(&l_tx, l_tsd) != 1) {
                    log_it(L_WARNING, "Failed to add custom TSD item to transaction");
                    dap_chain_datum_tx_delete(l_tx);
                    return NULL;
                }
            }
        }
    }

    uint256_t l_value_pack = {}; // how much datoshi add to 'out' items
    for (size_t i = 0; i < a_tx_num; ++i) {
        if (dap_chain_datum_tx_add_out_std_item(&l_tx, a_addr_to[i], a_value[i], a_token_ticker, a_time_unlock ? a_time_unlock[i] : 0) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Failed to add output item");
            return NULL;
        } else if (l_single_channel){
            SUM_256_256(l_value_pack, a_value[i], &l_value_pack);
        }
    }

    // Network fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't add fee output");
            return NULL;
        }
        if (l_single_channel)
            SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
    }
    
    // Validator fee
    if (!IS_ZERO_256(a_value_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't add fee output");
            return NULL;
        }
        if (l_single_channel)
            SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
    }
    
    // CRITICAL: For arbitrage TX, ALL outputs (including change/back) MUST go to fee address
    // Get network fee address for change outputs
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    const dap_chain_addr_t *l_fee_addr_for_change = &l_net->pub.fee_addr;
    
    // coin back
    uint256_t l_value_back = {};
    if (l_single_channel) {
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
    } else {
        SUBTRACT_256_256(l_value_transfer, l_value_total, &l_value_back);
        if (!IS_ZERO_256(l_total_fee)) {
            uint256_t l_fee_back = {};
            SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_fee_back);
            if (!IS_ZERO_256(l_fee_back)) {
                // For arbitrage TX: send fee change to fee address (not to sender)
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_fee_addr_for_change, l_fee_back, l_native_ticker) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    log_it(L_WARNING, "Can't add fee back output");
                    return NULL;
                }
            }
        }
    }
    if (!IS_ZERO_256(l_value_back)) {
        // For arbitrage TX: send value change to fee address (not to sender)
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_fee_addr_for_change, l_value_back, a_token_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't add change output");
            return NULL;
        }
    }
    
    // Add 'sign' item from wallet (first signature)
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_WARNING, "Can't add wallet sign");
        return NULL;
    }
    
    // Add additional signatures from certificates
    for (size_t i = 0; i < a_arbitrage_certs_count; i++) {
        if (!a_arbitrage_certs[i] || !a_arbitrage_certs[i]->enc_key) {
            log_it(L_WARNING, "Invalid certificate at index %zu", i);
            continue;
        }
        if(dap_chain_datum_tx_add_sign_item(&l_tx, a_arbitrage_certs[i]->enc_key) != 1) {
            log_it(L_WARNING, "Can't add certificate sign from cert %s", a_arbitrage_certs[i]->name);
            // Continue with other certificates even if one fails
            continue;
        }
        log_it(L_DEBUG, "Added signature from certificate: %s", a_arbitrage_certs[i]->name);
    }

    // Pack transaction into the datum
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    dap_chain_datum_tx_delete(l_tx);
    if (!l_datum) {
        log_it(L_ERROR, "Failed to create datum from transaction");
        return NULL;
    }
    
    char *l_ret = dap_chain_mempool_datum_add(l_datum, a_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    return l_ret;
}

/**
 * @brief Create arbitrage transaction via CLI
 * @details Handles the logic for creating arbitrage transactions from CLI command.
 *          This function processes the -arbitrage flag and all related parameters.
 * @param a_chain Target chain
 * @param a_net Network instance
 * @param a_wallet Wallet instance (will be closed by caller)
 * @param a_priv_key Private key from wallet
 * @param a_addr_from Sender's address
 * @param a_addr_to Recipient addresses (array)
 * @param a_token_ticker Token ticker
 * @param a_value Transfer values (array)
 * @param a_value_fee Fee value
 * @param a_hash_out_type Output hash type
 * @param a_addr_el_count Number of outputs
 * @param a_time_unlock Lock times (array, optional)
 * @param a_certs_str Comma-separated list of certificate names for arbitrage authorization
 * @param a_json_arr_reply JSON array for error responses
 * @param a_jobj_result JSON object for result
 * @return Transaction hash string or NULL on error
 */
char *dap_chain_arbitrage_cli_create_tx(
    dap_chain_t *a_chain,
    dap_chain_net_t *a_net,
    dap_chain_wallet_t *a_wallet,
    dap_enc_key_t *a_priv_key,
    const dap_chain_addr_t *a_addr_from,
    dap_chain_addr_t **a_addr_to,
    const char *a_token_ticker,
    uint256_t *a_value,
    uint256_t a_value_fee,
    const char *a_hash_out_type,
    size_t a_addr_el_count,
    dap_time_t *a_time_unlock,
    const char *a_certs_str,
    json_object **a_json_arr_reply,
    json_object *a_jobj_result)
{
    // Check token requirements for arbitrage transactions
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    size_t l_auth_signs_valid = dap_ledger_token_get_auth_signs_valid(l_ledger, a_token_ticker);
    
    // Determine if fee token and arbitrage token are the same
    // Wallet signature (first signature) is used ONLY for fee payment authorization,
    // NOT for arbitrage authorization, unless fee token == arbitrage token
    const char *l_fee_token_ticker = a_net->pub.native_ticker;
    bool l_fee_token_same_as_arbitrage = l_fee_token_ticker && 
                                          !dap_strcmp(l_fee_token_ticker, a_token_ticker);
    
    log_it(L_DEBUG, "Arbitrage TX for token %s: fee_token=%s, same_as_arbitrage=%d, auth_signs_valid=%zu",
           a_token_ticker, l_fee_token_ticker ? l_fee_token_ticker : "NULL", 
           l_fee_token_same_as_arbitrage, l_auth_signs_valid);
    
    // Parse certificates for arbitrage authorization
    dap_cert_t **l_arbitrage_certs = NULL;
    size_t l_arbitrage_certs_count = 0;
    if (a_certs_str) {
        dap_cert_parse_str_list(a_certs_str, &l_arbitrage_certs, &l_arbitrage_certs_count);
            if (!l_arbitrage_certs_count) {
            log_it(L_WARNING, "Failed to parse certificates from -certs parameter");
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION, 
                                  "Arbitrage transaction requires valid certificates via -certs parameter");
            return NULL;
        }
        
        // Check if we have enough signatures for arbitrage authorization
        // IMPORTANT: Wallet signature (first signature) is used ONLY for fee payment authorization.
        // It should NOT count towards arbitrage authorization unless fee token == arbitrage token.
        size_t l_total_arbitrage_signatures = l_arbitrage_certs_count;
        if (l_fee_token_same_as_arbitrage) {
            // If fee token == arbitrage token, wallet signature can count for arbitrage
            // (only if wallet key belongs to token owner, which will be checked in ledger)
            l_total_arbitrage_signatures += 1; // +1 for wallet signature
            log_it(L_DEBUG, "Fee token == arbitrage token: wallet signature may count for arbitrage");
        } else {
            // If fee token != arbitrage token, wallet signature does NOT count for arbitrage
            log_it(L_DEBUG, "Fee token != arbitrage token: wallet signature does NOT count for arbitrage (only for fee payment)");
        }
        
        if (l_total_arbitrage_signatures < l_auth_signs_valid) {
            // Allow creating TX with insufficient signatures - it will stay in mempool
            // until additional signatures are added via tx_sign command
            log_it(L_NOTICE, "Arbitrage transaction requires %zu owner signatures, "
                   "but only %zu signatures will be provided for arbitrage authorization "
                   "(%zu certificates%s). "
                   "Transaction will be created and placed in mempool. "
                   "Add remaining %zu signatures via 'tx_sign' command.",
                   l_auth_signs_valid, l_total_arbitrage_signatures, l_arbitrage_certs_count,
                   l_fee_token_same_as_arbitrage ? " + 1 wallet" : "",
                   l_auth_signs_valid - l_total_arbitrage_signatures);
        }
    } else if (l_auth_signs_valid > 1) {
        // If token requires multiple signatures but no -certs provided
        // Check if wallet signature can count for arbitrage (only if fee token == arbitrage token)
        if (l_fee_token_same_as_arbitrage) {
            // Fee token == arbitrage token: wallet signature may count for arbitrage
            // (only if wallet key belongs to token owner, which will be checked in ledger)
            log_it(L_NOTICE, "Arbitrage transaction requires %zu owner signatures. "
                   "Fee token == arbitrage token, so wallet signature may count for arbitrage "
                   "(if wallet key belongs to token owner). "
                   "Transaction will be created with wallet signature and will remain in mempool "
                   "until additional signatures are added via tx_sign command if needed.",
                   l_auth_signs_valid);
        } else {
            // Fee token != arbitrage token: wallet signature does NOT count for arbitrage
            log_it(L_NOTICE, "Arbitrage transaction requires %zu owner signatures, but -certs parameter not provided. "
                   "Fee token != arbitrage token, so wallet signature does NOT count for arbitrage "
                   "(it's used ONLY for fee payment authorization). "
                   "Transaction will be created with wallet signature and will remain in mempool "
                   "until %zu certificate signatures are added via tx_sign command.",
                   l_auth_signs_valid, l_auth_signs_valid);
        }
        // Continue with transaction creation - it will have insufficient signatures but will remain in mempool
        // This allows distributed signing across different nodes via tx_sign command
    }
    
    // CRITICAL: For arbitrage transactions, ALL outputs MUST go to fee address ONLY
    // Ignore user-provided -to_addr and replace with network fee address
    dap_chain_addr_t l_fee_addr_copy = a_net->pub.fee_addr;
    dap_chain_addr_t *l_arbitrage_addr_to[1] = { &l_fee_addr_copy };
    
    // Calculate total value (sum of all user-requested outputs)
    uint256_t l_total_value = {};
    for (size_t i = 0; i < a_addr_el_count; ++i) {
        SUM_256_256(l_total_value, a_value[i], &l_total_value);
    }
    uint256_t l_arbitrage_value[1] = { l_total_value };
    
    log_it(L_INFO, "Arbitrage TX: replacing user-specified addresses with fee address: %s", 
           dap_chain_addr_to_str_static(&l_fee_addr_copy));
    
    // Create arbitrage TSD marker
    // Note: dap_chain_datum_tx_item_tsd_create requires non-NULL data and size > 0
    // For arbitrage TSD, we use minimal data (1 byte) as the marker itself is sufficient
    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arbitrage = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    if (!l_tsd_arbitrage) {
        log_it(L_ERROR, "Failed to create arbitrage TSD marker");
        DAP_DEL_Z(l_arbitrage_certs);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION, "Failed to create arbitrage TSD marker");
        return NULL;
    }
    
    // Create TSD list
    dap_list_t *l_tsd_list = dap_list_append(NULL, l_tsd_arbitrage);
    
    // Create arbitrage transaction with multiple signatures if needed
    char *l_tx_hash_str = NULL;
    if (l_arbitrage_certs_count > 0) {
        // Use helper function to create transaction with all signatures
        l_tx_hash_str = dap_chain_arbitrage_tx_create_with_signatures(
            a_chain, a_priv_key, a_addr_from, (const dap_chain_addr_t **)l_arbitrage_addr_to,
            a_token_ticker, l_arbitrage_value, a_value_fee, a_hash_out_type, 1, a_time_unlock,
            l_tsd_list, l_arbitrage_certs, l_arbitrage_certs_count);
        
        if (l_tx_hash_str) {
            log_it(L_INFO, "Arbitrage transaction created with %zu signatures (1 wallet + %zu certificates): %s",
                   l_arbitrage_certs_count + 1, l_arbitrage_certs_count, l_tx_hash_str);
        } else {
            log_it(L_ERROR, "Failed to create arbitrage transaction with multiple signatures");
            // Add error to JSON-RPC response (same as single signature case)
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                  "Failed to create arbitrage transaction. Possible reasons: insufficient funds, invalid parameters, or mempool error. Check logs for details.");
        }
    } else {
        // Single signature (from wallet) is sufficient - use standard extended API
        log_it(L_DEBUG, "Creating arbitrage transaction with only wallet signature (no -certs provided)");
        l_tx_hash_str = dap_chain_mempool_tx_create_extended(a_chain, a_priv_key, a_addr_from, (const dap_chain_addr_t **)l_arbitrage_addr_to,
                                                             a_token_ticker, l_arbitrage_value, a_value_fee, a_hash_out_type, 1, a_time_unlock, l_tsd_list);
        if (!l_tx_hash_str) {
            log_it(L_WARNING, "dap_chain_mempool_tx_create_extended returned NULL for arbitrage transaction (likely insufficient funds or other error)");
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                  "Failed to create arbitrage transaction. Possible reasons: insufficient funds, invalid parameters, or mempool error. Check logs for details.");
        } else {
            log_it(L_INFO, "Arbitrage transaction created with wallet signature only: %s", l_tx_hash_str);
        }
    }
    
    // Cleanup
    dap_list_free(l_tsd_list);
    DAP_DELETE(l_tsd_arbitrage);
    DAP_DEL_Z(l_arbitrage_certs);
    
    log_it(L_INFO, "Arbitrage transaction created: %s", l_tx_hash_str ? l_tx_hash_str : "FAILED");
    return l_tx_hash_str;
}

