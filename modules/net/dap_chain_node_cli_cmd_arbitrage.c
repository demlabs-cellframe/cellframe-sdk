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

char *dap_chain_arbitrage_cli_create(
    dap_chain_t *a_chain,
    dap_chain_net_t *a_net,
    const dap_chain_addr_t *a_addr_from,
    const char *a_token_ticker,
    uint256_t a_value,
    uint256_t a_value_fee,
    const char *a_hash_out_type,
    const char *a_certs_str,
    json_object **a_json_arr_reply)
{
    dap_return_val_if_fail(a_chain && a_net && a_addr_from && a_token_ticker && a_certs_str && a_json_arr_reply, NULL);

    dap_ledger_t *l_ledger = a_net->pub.ledger;

    // Parse arbitrator certificates
    dap_cert_t **l_certs = NULL;
    size_t l_certs_count = 0;
    dap_cert_parse_str_list(a_certs_str, &l_certs, &l_certs_count);
    if (!l_certs_count || !l_certs) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                              "Failed to parse arbitrator certificates from -certs '%s'", a_certs_str);
        return NULL;
    }

    // Validate fee address
    if (dap_chain_addr_is_blank(&a_net->pub.fee_addr)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                              "Network '%s' has no fee address configured", a_net->pub.name);
        DAP_DEL_Z(l_certs);
        return NULL;
    }
    const dap_chain_addr_t *l_fee_addr = &a_net->pub.fee_addr;

    // Check if arbitrage is disabled for this token
    uint32_t l_token_flags = dap_ledger_token_get_flags(l_ledger, a_token_ticker);
    if (l_token_flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_ARBITRAGE_TX_DISABLED) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                              "Arbitrage transactions disabled for token '%s' (UTXO_ARBITRAGE_TX_DISABLED flag is set)",
                              a_token_ticker);
        DAP_DEL_Z(l_certs);
        return NULL;
    }

    const char *l_native_ticker = a_net->pub.native_ticker;
    bool l_single_channel = !dap_strcmp(a_token_ticker, l_native_ticker);

    // Calculate how much UTXO we need from the target address
    uint256_t l_value_need = a_value;
    uint256_t l_net_fee = {}, l_total_fee = {};
    dap_chain_addr_t l_net_fee_addr = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_chain->net_id, &l_net_fee, &l_net_fee_addr);
    if (SUM_256_256(l_net_fee, a_value_fee, &l_total_fee)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                              "Fee value overflow (net_fee + validator_fee)");
        DAP_DEL_Z(l_certs);
        return NULL;
    }

    if (l_single_channel) {
        if (SUM_256_256(l_value_need, l_total_fee, &l_value_need)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                  "Total value overflow (value + fees)");
            DAP_DEL_Z(l_certs);
            return NULL;
        }
    }

    // Find UTXO at the TARGET address (victim), bypassing blocklist
    uint256_t l_value_transfer = {};
    dap_list_t *l_list_used_out = NULL;
    int l_cache_result = dap_chain_wallet_cache_tx_find_outs_with_val_skip_blocklist(
        l_ledger->net, a_token_ticker, a_addr_from, &l_list_used_out, l_value_need, &l_value_transfer);
    if (l_cache_result == -101 || (l_cache_result == 0 && !l_list_used_out)) {
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val_skip_blocklist(
            l_ledger, a_token_ticker, a_addr_from, l_value_need, &l_value_transfer);
    }
    if (!l_list_used_out) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                              "No UTXO found for token '%s' at address %s (or insufficient funds)",
                              a_token_ticker, dap_chain_addr_to_str_static(a_addr_from));
        DAP_DEL_Z(l_certs);
        return NULL;
    }

    // For multi-channel: try to find fee UTXO in native token at target address
    dap_list_t *l_list_fee_out = NULL;
    uint256_t l_fee_transfer = {};
    bool l_has_fee_utxo = false;
    if (!l_single_channel && !IS_ZERO_256(l_total_fee)) {
        int l_fee_cache = dap_chain_wallet_cache_tx_find_outs_with_val(
            l_ledger->net, l_native_ticker, a_addr_from, &l_list_fee_out, l_total_fee, &l_fee_transfer);
        if (l_fee_cache == -101 || (l_fee_cache == 0 && !l_list_fee_out)) {
            l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(
                l_ledger, l_native_ticker, a_addr_from, l_total_fee, &l_fee_transfer);
        }
        l_has_fee_utxo = (l_list_fee_out != NULL);
        if (!l_has_fee_utxo) {
            log_it(L_WARNING, "Target address has no native token '%s' for fee; "
                   "TX will be created without network/validator fee outputs and may be rejected by consensus",
                   l_native_ticker);
        }
    }

    // Build the transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        dap_list_free_full(l_list_used_out, NULL);
        if (l_list_fee_out) dap_list_free_full(l_list_fee_out, NULL);
        DAP_DEL_Z(l_certs);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                              "Failed to allocate transaction structure");
        return NULL;
    }

    // Add inputs from target address UTXO
    {
        uint256_t l_val = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        dap_list_free_full(l_list_used_out, NULL);
        if (!EQUAL_256(l_val, l_value_transfer)) {
            log_it(L_ERROR, "Input value mismatch: not all UTXOs were added to transaction");
            dap_chain_datum_tx_delete(l_tx);
            if (l_list_fee_out) dap_list_free_full(l_list_fee_out, NULL);
            DAP_DEL_Z(l_certs);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                  "Failed to add all input items to transaction");
            return NULL;
        }
        if (l_list_fee_out) {
            uint256_t l_fval = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
            dap_list_free_full(l_list_fee_out, NULL);
            if (!EQUAL_256(l_fval, l_fee_transfer)) {
                log_it(L_ERROR, "Fee input value mismatch: not all fee UTXOs were added");
                dap_chain_datum_tx_delete(l_tx);
                DAP_DEL_Z(l_certs);
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                      "Failed to add all fee input items to transaction");
                return NULL;
            }
        }
    }

    // Add arbitrage TSD marker
    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(
        &l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    if (!l_tsd_arb || dap_chain_datum_tx_add_item(&l_tx, l_tsd_arb) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_tsd_arb);
        DAP_DEL_Z(l_certs);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                              "Failed to add arbitrage TSD marker to transaction");
        return NULL;
    }
    DAP_DELETE(l_tsd_arb);

    // Output: all arbitrated value → fee address
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_fee_addr, a_value, a_token_ticker) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_certs);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                              "Failed to add main arbitrage output to transaction");
        return NULL;
    }

    uint256_t l_value_pack = {};
    if (l_single_channel && SUM_256_256(l_value_pack, a_value, &l_value_pack)) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_certs);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                              "Output packing overflow (value)");
        return NULL;
    }

    // Network fee output (only if we have fee UTXO in native token, or single-channel)
    if (l_net_fee_used && (l_single_channel || l_has_fee_utxo)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_fee_addr, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DEL_Z(l_certs);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                  "Failed to add network fee output to transaction");
            return NULL;
        }
        if (l_single_channel && SUM_256_256(l_value_pack, l_net_fee, &l_value_pack)) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DEL_Z(l_certs);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                  "Output packing overflow (value + net_fee)");
            return NULL;
        }
    }

    // Validator fee output (only for single-channel or when we have fee UTXO)
    if (!IS_ZERO_256(a_value_fee) && (l_single_channel || l_has_fee_utxo)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DEL_Z(l_certs);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                  "Failed to add validator fee output to transaction");
            return NULL;
        }
        if (l_single_channel && SUM_256_256(l_value_pack, a_value_fee, &l_value_pack)) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DEL_Z(l_certs);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                  "Output packing overflow (value + fees)");
            return NULL;
        }
    }

    // Change goes to fee address (arbitrage: ALL outputs → fee addr)
    uint256_t l_value_back = {};
    if (l_single_channel) {
        if (SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back)) {
            log_it(L_ERROR, "Change calculation underflow (value_transfer < packed outputs)");
            dap_chain_datum_tx_delete(l_tx);
            DAP_DEL_Z(l_certs);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                  "Internal error: value accounting underflow");
            return NULL;
        }
    } else {
        if (SUBTRACT_256_256(l_value_transfer, a_value, &l_value_back)) {
            log_it(L_ERROR, "Change calculation underflow (value_transfer < arbitrage value)");
            dap_chain_datum_tx_delete(l_tx);
            DAP_DEL_Z(l_certs);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                  "Internal error: value accounting underflow");
            return NULL;
        }
        if (l_has_fee_utxo && !IS_ZERO_256(l_total_fee) && !IS_ZERO_256(l_fee_transfer)) {
            uint256_t l_fee_back = {};
            if (SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_fee_back)) {
                log_it(L_ERROR, "Fee change calculation underflow (fee_transfer < total_fee)");
                dap_chain_datum_tx_delete(l_tx);
                DAP_DEL_Z(l_certs);
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                      "Internal error: fee accounting underflow");
                return NULL;
            }
            if (!IS_ZERO_256(l_fee_back)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_fee_addr, l_fee_back, l_native_ticker) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    DAP_DEL_Z(l_certs);
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                          "Failed to add fee change output to transaction");
                    return NULL;
                }
            }
        }
    }
    if (!IS_ZERO_256(l_value_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_fee_addr, l_value_back, a_token_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DEL_Z(l_certs);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                                  "Failed to add value change output to transaction");
            return NULL;
        }
    }

    // Sign with arbitrator certificates ONLY (no wallet signature)
    size_t l_signatures_added = 0;
    for (size_t i = 0; i < l_certs_count; i++) {
        if (!l_certs[i] || !l_certs[i]->enc_key) {
            log_it(L_WARNING, "Certificate #%zu has no encryption key — skipping", i);
            continue;
        }
        if (dap_chain_datum_tx_add_sign_item(&l_tx, l_certs[i]->enc_key) != 1) {
            log_it(L_WARNING, "Failed to add signature from cert '%s'", l_certs[i]->name);
            continue;
        }
        l_signatures_added++;
        log_it(L_DEBUG, "Added arbitrator signature from cert: %s", l_certs[i]->name);
    }
    if (!l_signatures_added) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_certs);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                              "No valid arbitrator signatures were added to transaction");
        return NULL;
    }

    // Pack into datum and add to mempool
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    dap_chain_datum_tx_delete(l_tx);
    DAP_DEL_Z(l_certs);

    if (!l_datum) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                              "Failed to create datum");
        return NULL;
    }

    char *l_ret = dap_chain_mempool_datum_add(l_datum, a_chain, a_hash_out_type);
    DAP_DELETE(l_datum);

    if (!l_ret) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION,
                              "Failed to add arbitrage datum to mempool");
    } else {
        log_it(L_INFO, "Arbitrage TX created (cert-only, no wallet): %s", l_ret);
    }

    return l_ret;
}
