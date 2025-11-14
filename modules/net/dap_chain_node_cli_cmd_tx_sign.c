/*
 * Authors:
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network  https://github.com/demlabs-cellframe
 * Copyright  (c) 2024
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

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "dap_cli_server.h"
#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_hash.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_tsd.h"
#include "dap_chain_ledger.h"
#include "dap_chain_mempool.h"
#include "dap_chain_net.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_node_cli_cmd_tx_sign.h"
#include "dap_global_db.h"
#include "dap_json_rpc_errors.h"
#include "dap_cert.h"
#include "dap_tsd.h"
#include "dap_pkey.h"

#define LOG_TAG "chain_node_cli_cmd_tx_sign"

/**
 * @brief Check if transaction has arbitrage TSD marker
 * @param a_tx Transaction to check
 * @return true if transaction has arbitrage marker, false otherwise
 */
static bool s_tx_has_arbitrage_marker(dap_chain_datum_tx_t *a_tx)
{
    if (!a_tx) {
        return false;
    }

    // Iterate through TX items looking for TSD with arbitrage marker
    byte_t *l_tx_item = a_tx->tx_items;
    size_t l_tx_items_pos = 0;
    size_t l_tx_items_size = a_tx->header.tx_items_size;

    while (l_tx_items_pos < l_tx_items_size) {
        uint8_t *l_item = l_tx_item + l_tx_items_pos;
        size_t l_item_size = dap_chain_datum_item_tx_get_size(l_item, l_tx_items_size - l_tx_items_pos);
        
        if (!l_item_size) {
            log_it(L_ERROR, "Zero item size in TX");
            return false;
        }

        dap_chain_tx_item_type_t l_type = *((uint8_t *)l_item);
        
        if (l_type == TX_ITEM_TYPE_TSD) {
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

    return false;  // No arbitrage marker found
}

/**
 * @brief Get token ticker from transaction outputs
 * @param a_tx Transaction
 * @return Token ticker or NULL if not found
 */
static const char *s_tx_get_token_ticker(dap_chain_datum_tx_t *a_tx)
{
    if (!a_tx) {
        return NULL;
    }

    // Iterate through TX items looking for output items
    byte_t *l_tx_item = a_tx->tx_items;
    size_t l_tx_items_pos = 0;
    size_t l_tx_items_size = a_tx->header.tx_items_size;

    while (l_tx_items_pos < l_tx_items_size) {
        uint8_t *l_item = l_tx_item + l_tx_items_pos;
        size_t l_item_size = dap_chain_datum_item_tx_get_size(l_item, l_tx_items_size - l_tx_items_pos);
        
        if (!l_item_size) {
            break;
        }

        dap_chain_tx_item_type_t l_type = *((uint8_t *)l_item);
        
        if (l_type == TX_ITEM_TYPE_OUT_STD) {
            dap_chain_tx_out_std_t *l_out = (dap_chain_tx_out_std_t *)l_item;
            if (l_out->token[0] != '\0') {
                return l_out->token;  // Return first token ticker found
            }
        } else if (l_type == TX_ITEM_TYPE_OUT_EXT) {
            dap_chain_tx_out_ext_t *l_out = (dap_chain_tx_out_ext_t *)l_item;
            if (l_out->token[0] != '\0') {
                return l_out->token;  // Return first token ticker found
            }
        }
        
        l_tx_items_pos += l_item_size;
    }

    return NULL;
}

/**
 * @brief Check if certificate belongs to token owners
 * @param a_ledger Ledger instance
 * @param a_token_ticker Token ticker
 * @param a_cert Certificate to check
 * @return true if certificate belongs to token owner, false otherwise
 */
static bool s_cert_is_token_owner(dap_ledger_t *a_ledger, const char *a_token_ticker, dap_cert_t *a_cert)
{
    if (!a_ledger || !a_token_ticker || !a_cert || !a_cert->enc_key) {
        return false;
    }

    // Get certificate's public key hash
    dap_chain_hash_fast_t l_cert_pkey_hash;
    if (dap_cert_get_pkey_hash(a_cert, &l_cert_pkey_hash) != 0) {
        return false;
    }

    // Get list of token owner pkey hashes
    dap_list_t *l_auth_pkey_hashes = dap_ledger_token_get_auth_pkeys_hashes(a_ledger, a_token_ticker);
    if (!l_auth_pkey_hashes) {
        return false;
    }

    // Check if certificate's pkey hash matches any token owner's pkey hash
    bool l_is_owner = false;
    for (dap_list_t *l_iter = l_auth_pkey_hashes; l_iter; l_iter = l_iter->next) {
        dap_chain_hash_fast_t *l_owner_hash = (dap_chain_hash_fast_t *)l_iter->data;
        if (l_owner_hash && !dap_hash_fast_compare(&l_cert_pkey_hash, l_owner_hash)) {
            l_is_owner = true;
            break;
        }
    }

    dap_list_free(l_auth_pkey_hashes);
    return l_is_owner;
}

/**
 * @brief Add signature to existing transaction in mempool
 * com_tx_sign command
 * @param argc
 * @param argv
 * @param str_reply
 * @param version
 * @return int
 */
int com_tx_sign(int a_argc, char **a_argv, void **a_str_reply, UNUSED_ARG int a_version)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    int arg_index = 1;

    const char *l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    if (dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_H_PARAM_ERR,
                               "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    const char *l_tx_hash_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-tx", &l_tx_hash_str);
    if (!l_tx_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_REQUIRE_TX_PARAM,
                               "tx_sign requires parameter '-tx'");
        return -2;
    }

    const char *l_certs_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);
    if (!l_certs_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_REQUIRE_CERTS_PARAM,
                               "tx_sign requires parameter '-certs'");
        return -3;
    }

    dap_chain_t *l_chain = NULL;
    dap_chain_net_t *l_net = NULL;
    dap_chain_node_cli_cmd_values_parse_net_chain_for_json(*a_json_arr_reply, &arg_index, a_argc, a_argv,
                                                           &l_chain, &l_net, CHAIN_TYPE_TX);
    if (!l_net) {
        return -4;
    }

    if (!l_chain) {
        l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    }
    if (!l_chain) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_CHAIN_NOT_FOUND,
                               "Chain not found");
        return -5;
    }

    // Parse certificates
    dap_cert_t **l_certs = NULL;
    size_t l_certs_count = 0;
    dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);
    if (!l_certs_count) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_INVALID_CERTS,
                               "tx_sign requires at least one valid certificate");
        DAP_DEL_Z(l_certs);
        return -6;
    }

    // Convert hash format if needed
    char *l_tx_hash_hex_str = NULL;
    char *l_tx_hash_base58_str = NULL;
    if (!dap_strncmp(l_tx_hash_str, "0x", 2) || !dap_strncmp(l_tx_hash_str, "0X", 2)) {
        l_tx_hash_hex_str = dap_strdup(l_tx_hash_str);
        l_tx_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_tx_hash_str);
    } else {
        l_tx_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_tx_hash_str);
        l_tx_hash_base58_str = dap_strdup(l_tx_hash_str);
    }

    const char *l_tx_hash_out_str = dap_strcmp(l_hash_out_type, "hex") ? l_tx_hash_base58_str : l_tx_hash_hex_str;

    // Get transaction from mempool
    char *l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(l_chain);
    if (!l_gdb_group_mempool) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_MEMPOOL_GROUP_ERR,
                               "Failed to get mempool group");
        DAP_DEL_MULTY(l_tx_hash_hex_str, l_tx_hash_base58_str, l_certs);
        return -7;
    }

    dap_chain_datum_t *l_datum = NULL;
    size_t l_datum_size = 0;
    log_it(L_DEBUG, "Searching for transaction %s in mempool group %s", l_tx_hash_out_str, l_gdb_group_mempool);
    l_datum = (dap_chain_datum_t *)dap_global_db_get_sync(l_gdb_group_mempool,
                                                           l_tx_hash_hex_str, &l_datum_size, NULL, NULL);
    if (!l_datum) {
        // Try listing all datums in mempool to see what's there
        size_t l_objs_size = 0;
        dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group_mempool, &l_objs_size);
        log_it(L_DEBUG, "Transaction not found by hash, mempool contains %zu datums", l_objs_size);
        if (l_objs_size > 0) {
            for (size_t i = 0; i < l_objs_size; i++) {
                if (l_objs[i].value_len >= sizeof(dap_chain_datum_t)) {
                    dap_chain_datum_t *l_datum_check = (dap_chain_datum_t *)l_objs[i].value;
                    if (l_datum_check->header.type_id == DAP_CHAIN_DATUM_TX) {
                        dap_chain_hash_fast_t l_tx_hash_check = {0};
                        dap_chain_datum_calc_hash(l_datum_check, &l_tx_hash_check);
                        char l_tx_hash_str_check[DAP_CHAIN_HASH_FAST_STR_SIZE];
                        dap_chain_hash_fast_to_str(&l_tx_hash_check, l_tx_hash_str_check, sizeof(l_tx_hash_str_check));
                        log_it(L_DEBUG, "Found TX in mempool: %s (key: %s)", l_tx_hash_str_check, l_objs[i].key);
                        // Compare hashes byte by byte with input hash
                        dap_chain_hash_fast_t l_tx_hash_input = {0};
                        if (dap_chain_hash_fast_from_hex_str(l_tx_hash_hex_str, &l_tx_hash_input) == 0) {
                            bool l_hash_match = true;
                            for (size_t j = 0; j < sizeof(dap_chain_hash_fast_t); j++) {
                                if (((uint8_t *)&l_tx_hash_check)[j] != ((uint8_t *)&l_tx_hash_input)[j]) {
                                    l_hash_match = false;
                                    break;
                                }
                            }
                            if (l_hash_match) {
                                l_datum = l_datum_check;
                                l_datum_size = l_objs[i].value_len;
                                log_it(L_INFO, "Found transaction via mempool listing");
                                break;
                            }
                        }
                    }
                }
            }
        }
        dap_global_db_objs_delete(l_objs, l_objs_size);
        
        if (!l_datum) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_TX_NOT_FOUND,
                                   "Transaction %s not found in mempool", l_tx_hash_out_str);
            DAP_DELETE(l_gdb_group_mempool);
            DAP_DEL_MULTY(l_tx_hash_hex_str, l_tx_hash_base58_str, l_certs);
            return -8;
        }
    }

    // Check if it's a transaction datum
    if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_WRONG_DATUM_TYPE,
                               "Datum %s is not a transaction", l_tx_hash_out_str);
        DAP_DELETE(l_datum);
        DAP_DELETE(l_gdb_group_mempool);
        DAP_DEL_MULTY(l_tx_hash_hex_str, l_tx_hash_base58_str, l_certs);
        return -9;
    }

    // Parse transaction
    dap_chain_datum_tx_t *l_tx = DAP_DUP_SIZE((dap_chain_datum_tx_t *)l_datum->data, l_datum->header.data_size);
    DAP_DELETE(l_datum);

    // Check if transaction has arbitrage marker
    if (!s_tx_has_arbitrage_marker(l_tx)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_NOT_ARBITRAGE,
                               "Transaction %s is not an arbitrage transaction. "
                               "tx_sign can only add signatures to arbitrage transactions.",
                               l_tx_hash_out_str);
        DAP_DELETE(l_tx);
        DAP_DELETE(l_gdb_group_mempool);
        DAP_DEL_MULTY(l_tx_hash_hex_str, l_tx_hash_base58_str, l_certs);
        return -10;
    }

    // Get token ticker from transaction
    const char *l_token_ticker = s_tx_get_token_ticker(l_tx);
    if (!l_token_ticker) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_NO_TOKEN,
                               "Cannot determine token ticker from transaction %s", l_tx_hash_out_str);
        DAP_DELETE(l_tx);
        DAP_DELETE(l_gdb_group_mempool);
        DAP_DEL_MULTY(l_tx_hash_hex_str, l_tx_hash_base58_str, l_certs);
        return -11;
    }

    // Get ledger and check token requirements
    dap_ledger_t *l_ledger = l_net->pub.ledger;
    size_t l_auth_signs_valid = dap_ledger_token_get_auth_signs_valid(l_ledger, l_token_ticker);
    if (l_auth_signs_valid == 0) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_TOKEN_NOT_FOUND,
                               "Token %s not found in ledger", l_token_ticker);
        DAP_DELETE(l_tx);
        DAP_DELETE(l_gdb_group_mempool);
        DAP_DEL_MULTY(l_tx_hash_hex_str, l_tx_hash_base58_str, l_certs);
        return -12;
    }

    // Count existing signatures
    int l_existing_sign_count = 0;
    dap_list_t *l_list_tx_sign = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_SIG, &l_existing_sign_count);
    dap_list_free(l_list_tx_sign);

    log_it(L_INFO, "Transaction %s has %d existing signatures, requires %zu total signatures",
           l_tx_hash_out_str, l_existing_sign_count, l_auth_signs_valid);

    // Verify that all certificates belong to token owners
    size_t l_valid_certs_count = 0;
    for (size_t i = 0; i < l_certs_count; i++) {
        if (!l_certs[i] || !l_certs[i]->enc_key) {
            log_it(L_WARNING, "Invalid certificate at index %zu", i);
            continue;
        }

        if (s_cert_is_token_owner(l_ledger, l_token_ticker, l_certs[i])) {
            l_valid_certs_count++;
            log_it(L_DEBUG, "Certificate %s belongs to token owner", l_certs[i]->name);
        } else {
            log_it(L_WARNING, "Certificate %s does not belong to token owner", l_certs[i]->name);
        }
    }

    if (l_valid_certs_count == 0) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_CERTS_NOT_OWNERS,
                               "None of the provided certificates belong to token %s owners", l_token_ticker);
        DAP_DELETE(l_tx);
        DAP_DELETE(l_gdb_group_mempool);
        DAP_DEL_MULTY(l_tx_hash_hex_str, l_tx_hash_base58_str, l_certs);
        return -13;
    }

    // Check if we need more signatures
    size_t l_total_signatures_after = l_existing_sign_count + l_valid_certs_count;
    if (l_total_signatures_after > l_auth_signs_valid) {
        log_it(L_WARNING, "Transaction will have %zu signatures, but only %zu are required",
               l_total_signatures_after, l_auth_signs_valid);
    }

    // Add signatures from certificates
    size_t l_signs_added = 0;
    for (size_t i = 0; i < l_certs_count; i++) {
        if (!l_certs[i] || !l_certs[i]->enc_key) {
            continue;
        }

        // Only add signature if certificate belongs to token owner
        if (!s_cert_is_token_owner(l_ledger, l_token_ticker, l_certs[i])) {
            continue;
        }

        if (dap_chain_datum_tx_add_sign_item(&l_tx, l_certs[i]->enc_key) == 1) {
            l_signs_added++;
            log_it(L_DEBUG, "Added signature from certificate: %s", l_certs[i]->name);
        } else {
            log_it(L_WARNING, "Failed to add signature from certificate: %s", l_certs[i]->name);
        }
    }

    if (l_signs_added == 0) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_NO_SIGNS_ADDED,
                               "Failed to add any signatures to transaction");
        DAP_DELETE(l_tx);
        DAP_DELETE(l_gdb_group_mempool);
        DAP_DEL_MULTY(l_tx_hash_hex_str, l_tx_hash_base58_str, l_certs);
        return -14;
    }

    // Verify arbitrage marker is still present after adding signatures
    if (!s_tx_has_arbitrage_marker(l_tx)) {
        log_it(L_ERROR, "CRITICAL: Arbitrage marker lost after adding signatures to transaction %s", l_tx_hash_out_str);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_ARBITRAGE_MARKER_LOST,
                               "Arbitrage marker lost after adding signatures");
        DAP_DELETE(l_tx);
        DAP_DELETE(l_gdb_group_mempool);
        DAP_DEL_MULTY(l_tx_hash_hex_str, l_tx_hash_base58_str, l_certs);
        return -15;
    }
    
    // Create new datum with updated transaction
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_new_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    
    // Verify arbitrage marker is preserved in new datum
    if (l_new_datum && l_new_datum->header.type_id == DAP_CHAIN_DATUM_TX) {
        dap_chain_datum_tx_t *l_new_tx = (dap_chain_datum_tx_t *)l_new_datum->data;
        if (!s_tx_has_arbitrage_marker(l_new_tx)) {
            log_it(L_ERROR, "CRITICAL: Arbitrage marker lost in new datum for transaction %s", l_tx_hash_out_str);
            DAP_DELETE(l_new_datum);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_ARBITRAGE_MARKER_LOST,
                                   "Arbitrage marker lost in new datum");
            DAP_DELETE(l_tx);
            DAP_DELETE(l_gdb_group_mempool);
            DAP_DEL_MULTY(l_tx_hash_hex_str, l_tx_hash_base58_str, l_certs);
            return -15;
        }
        log_it(L_DEBUG, "✓ Arbitrage marker preserved in new datum for transaction %s", l_tx_hash_out_str);
    }
    
    DAP_DELETE(l_tx);
    if (!l_new_datum) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_CREATE_DATUM_ERR,
                               "Failed to create datum from updated transaction");
        DAP_DELETE(l_gdb_group_mempool);
        DAP_DEL_MULTY(l_tx_hash_hex_str, l_tx_hash_base58_str, l_certs);
        return -15;
    }

    // Calculate new hash
    size_t l_new_datum_size = dap_chain_datum_size(l_new_datum);
    dap_chain_hash_fast_t l_new_hash;
    dap_hash_fast(l_new_datum->data, l_new_datum_size, &l_new_hash);
    char *l_new_hash_str = dap_chain_hash_fast_to_str_new(&l_new_hash);
    const char *l_new_hash_base58 = dap_enc_base58_encode_hash_to_str_static(&l_new_hash);
    const char *l_new_hash_out_str = dap_strcmp(l_hash_out_type, "hex") ? l_new_hash_base58 : l_new_hash_str;

    // Add new transaction to mempool
    int l_rc = 0;
    if (dap_global_db_set_sync(l_gdb_group_mempool, l_new_hash_str, l_new_datum,
                                l_new_datum_size, false) == 0) {
        // Remove old transaction from mempool
        if (dap_global_db_del_sync(l_gdb_group_mempool, l_tx_hash_hex_str) == 0) {
            json_object *l_jobj_result = json_object_new_object();
            json_object_object_add(l_jobj_result, "status", json_object_new_string("ok"));
            json_object_object_add(l_jobj_result, "old_hash", json_object_new_string(l_tx_hash_out_str));
            json_object_object_add(l_jobj_result, "new_hash", json_object_new_string(l_new_hash_out_str));
            json_object_object_add(l_jobj_result, "signatures_added", json_object_new_int64(l_signs_added));
            json_object_object_add(l_jobj_result, "total_signatures", json_object_new_int64(l_existing_sign_count + l_signs_added));
            json_object_array_add(*a_json_arr_reply, l_jobj_result);
            log_it(L_INFO, "Transaction updated in mempool: %s -> %s (%zu signatures added)",
                   l_tx_hash_out_str, l_new_hash_out_str, l_signs_added);
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_CANT_REMOVE_OLD,
                                   "Warning! Can't remove old transaction %s (new transaction %s added successfully)",
                                   l_tx_hash_out_str, l_new_hash_out_str);
            l_rc = -DAP_CHAIN_NODE_CLI_COM_TX_SIGN_CANT_REMOVE_OLD;
        }
    } else {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_SIGN_CANT_ADD_NEW,
                               "Failed to add updated transaction to mempool");
        l_rc = -DAP_CHAIN_NODE_CLI_COM_TX_SIGN_CANT_ADD_NEW;
    }

    DAP_DELETE(l_new_datum);
    DAP_DELETE(l_gdb_group_mempool);
    DAP_DELETE(l_new_hash_str);
    DAP_DEL_MULTY(l_tx_hash_hex_str, l_tx_hash_base58_str, l_certs);
    return l_rc;
}

