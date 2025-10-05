/**
 * @file dap_chain_net_srv_xchange_compose.c
 * @brief Xchange service transaction compose functions
 * 
 * These functions were moved from modules/compose/ to eliminate circular dependencies.
 * Xchange service now provides its own compose logic and registers it with compose module.
 */

#include "dap_common.h"
#include "dap_chain_net_srv_xchange.h"
#include "dap_chain_net_srv_xchange_compose.h"
#include "dap_chain_tx_compose.h"
#include "dap_chain_tx_compose_callbacks.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_ledger.h"
#include "dap_json_rpc_errors.h"
#include "dap_rand.h"

#define LOG_TAG "xchange_compose"

/**
 * @brief Create price structure from order conditional transaction
 */
dap_chain_net_srv_xchange_price_t *dap_chain_net_srv_xchange_price_from_order_compose(dap_chain_tx_out_cond_t *a_cond_tx, 
                                                                                    dap_time_t a_ts_created, dap_hash_fast_t *a_order_hash, dap_hash_fast_t *a_hash_out, const char *a_token_ticker,
                                                                                    uint256_t *a_fee, bool a_ret_is_invalid, dap_chain_tx_compose_config_t *a_config)
{
    if (!a_cond_tx || !a_order_hash || !a_config)
        return NULL;
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    if (!l_price)
        return NULL;
    l_price->creation_date = a_ts_created;
    dap_strncpy(l_price->token_buy, a_cond_tx->subtype.srv_xchange.buy_token, sizeof(l_price->token_buy) - 1);

    l_price->order_hash = *a_order_hash;
    dap_strncpy(l_price->token_sell, a_token_ticker, sizeof(l_price->token_sell) - 1);
    l_price->token_sell[sizeof(l_price->token_sell) - 1] = '\0';

    if (a_fee)
        l_price->fee = *a_fee;

    l_price->datoshi_sell = a_cond_tx->header.value;
    l_price->creator_addr = a_cond_tx->subtype.srv_xchange.seller_addr;
    l_price->rate = a_cond_tx->subtype.srv_xchange.rate;
    if ( !dap_hash_fast_is_blank(a_hash_out) ) {
        l_price->tx_hash = *a_hash_out;
    } else {
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "This order have no active conditional transaction");
        if (a_ret_is_invalid) {
            dap_hash_fast_t l_tx_hash_zero = {0};
            l_price->tx_hash = l_tx_hash_zero;
        }else{
            DAP_DELETE(l_price);
            l_price = NULL;
        }
    }
    

    return l_price;
}
dap_chain_datum_tx_t* dap_xchange_tx_invalidate_compose( dap_chain_net_srv_xchange_price_t *a_price, dap_chain_tx_out_cond_t *a_cond_tx, dap_chain_addr_t *a_wallet_addr, dap_chain_addr_t *a_seller_addr, const char *a_tx_ticker, uint32_t a_prev_cond_idx, dap_chain_tx_compose_config_t *a_config)
{
    if (!a_config) {
        return NULL;
    }

    if (!a_price) {
        dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS, "An a_price NULL argument was passed to the s_xchange_tx_invalidate() function.");
        return NULL;
    }
    if (!a_wallet_addr) {
        dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS, "An a_wallet_addr NULL argument was passed to the s_xchange_tx_invalidate() function.");
        return NULL;
    }
    const char *l_native_ticker = dap_chain_tx_compose_get_native_ticker(a_config->net_name);

#ifndef DAP_CHAIN_TX_COMPOSE_TEST

    bool l_single_channel = !dap_strcmp(a_tx_ticker, l_native_ticker);

    if (!dap_chain_addr_compare(a_seller_addr, a_wallet_addr)) {
        dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NOT_OWNER, "Only owner can invalidate exchange transaction");
        return NULL;
    }

#else
    dap_chain_tx_out_cond_t l_cond_tx_obj = { };
    a_cond_tx = &l_cond_tx_obj;
    a_cond_tx->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE;
    a_cond_tx->header.value = a_price->datoshi_sell;
    a_cond_tx->header.srv_uid.uint64 = rand() % 100;
    a_cond_tx->header.ts_expires = 0;
    strcpy(a_cond_tx->subtype.srv_xchange.buy_token, a_price->token_buy);
    a_cond_tx->subtype.srv_xchange.buy_net_id.uint64 = rand() % 100;
    a_cond_tx->subtype.srv_xchange.sell_net_id.uint64 = rand() % 100;
    a_cond_tx->subtype.srv_xchange.rate = a_price->rate;
    a_cond_tx->subtype.srv_xchange.seller_addr = *a_wallet_addr;
    a_cond_tx->tsd_size = 0;
    
    const char *l_tx_ticker = a_price->token_sell;
    bool l_single_channel = true;
    int l_prev_cond_idx = rand() % 100;
#endif
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_price->tx_hash, a_prev_cond_idx, 0);
    uint256_t l_net_fee = {};
    dap_chain_addr_t* l_addr_fee = NULL;
    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);
    uint256_t l_total_fee = a_price->fee;
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);

    if (!l_single_channel) {
        dap_json_t *l_outs_native = dap_chain_tx_compose_get_remote_tx_outs(l_native_ticker, a_seller_addr, a_config);
        if (!l_outs_native) {
            return NULL;
        }
        int l_out_native_count = dap_json_array_length(l_outs_native);
        uint256_t l_transfer_fee = {}, l_fee_back = {};
        // list of transaction with 'out' items to get net fee
        dap_list_t *l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                               l_total_fee, 
                                                               &l_transfer_fee);
        if (!l_list_fee_out) {
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INSUFFICIENT_FUNDS, "Not enough funds to pay fee");
            dap_json_object_free(l_outs_native);
            return NULL;
        }


        // add 'in' items to net fee
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
        if (!EQUAL_256(l_value_to_items, l_transfer_fee)) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_COMPOSE_FAILED, "Can't compose the transaction input");
            return NULL;
        }
        // return coins to owner
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, a_cond_tx->header.value, a_tx_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_COIN_RETURN_FAILED, "Cant add returning coins output");
            return NULL;
        }
        // Network fee
        if (l_net_fee_used &&
                dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NET_FEE_FAILED, "Cant add network fee output");
            return NULL;
        }
        // put fee coinback
        SUBTRACT_256_256(l_transfer_fee, l_total_fee, &l_fee_back);
        if (!IS_ZERO_256(l_fee_back) &&
                dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, l_fee_back, l_native_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_COINBACK_FAILED, "Cant add fee cachback output");
            return NULL;
        }

            // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            uint256_t l_fee_value = a_price->fee;
            if (dap_chain_datum_tx_add_fee_item(&l_tx, l_fee_value) == -1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_VALIDATOR_FEE_FAILED, "Cant add validator's fee output");
                return NULL;
            }
        }


    } else {
        uint256_t l_coin_back = {};
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        if (compare256(l_total_fee, a_cond_tx->header.value) >= 0) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_TOO_HIGH, "Total fee is greater or equal than order liquidity");
            return NULL;
        }
#endif
        SUBTRACT_256_256(a_cond_tx->header.value, l_total_fee, &l_coin_back);
        // return coins to owner
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, l_coin_back, l_native_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_COIN_RETURN_FAILED, "Cant add returning coins output");
            return NULL;
        }
        // Network fee
        if (l_net_fee_used &&
            dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NET_FEE_FAILED, "Cant add network fee output");
            return NULL;
        }

        // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            uint256_t l_fee_value = a_price->fee;
            if (dap_chain_datum_tx_add_fee_item(&l_tx, l_fee_value) == -1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_VALIDATOR_FEE_FAILED, "Cant add validator's fee output");
                return NULL;
            }
        }

    }

    return l_tx;
}

/**
 * @brief Find last transaction in xchange order chain
 * @details Follows the chain of transactions from initial order to the last one
 * @note Moved from compose module (was dap_find_last_xchange_tx) to break circular dependency
 */
dap_chain_tx_out_cond_t* dap_chain_net_srv_xchange_find_last_tx(dap_hash_fast_t *a_order_hash,  dap_chain_addr_t *a_seller_addr,  dap_chain_tx_compose_config_t * a_config, 
                                                  const char **a_ts_created_str, const char **a_token_ticker, uint32_t *a_prev_cond_idx, dap_hash_fast_t *a_hash_out) {
    dap_chain_tx_out_cond_t *l_cond_tx = NULL;
    dap_hash_fast_t l_current_hash = *a_order_hash;
    dap_json_t *response = NULL;
    dap_json_t *l_final_response = NULL;
    dap_json_t *l_response_array = NULL;
    bool l_found_last = false;
    bool l_first_tx = true; // Flag to identify the first transaction

    while (!l_found_last) {
        response = dap_request_command_to_rpc_with_params(a_config, "ledger", "info;-hash;%s;-net;%s",
                                                        dap_chain_hash_fast_to_str_static(&l_current_hash), a_config->net_name);
        if (!response) {
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_REMOTE_NODE_UNREACHABLE, 
                                     "Failed to get response from remote node");
            return NULL;
        }

        dap_json_t *l_first_item = dap_json_array_get_idx(response, 0);
        if (!l_first_item) {
            dap_json_object_free(response);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_RESPONSE_FORMAT,
                                     "Invalid response format");
            return NULL;
        }

        // Get ts_created and token_ticker for the first transaction
        if (!*a_ts_created_str) {
            dap_json_t *ts_created_obj = NULL, *token_ticker_obj = NULL;
            if (dap_json_object_get_ex(l_first_item, "ts_created", &ts_created_obj) &&
                dap_json_object_get_ex(l_first_item, "token_ticker", &token_ticker_obj)) {
                const char *l_temp_ts = dap_json_get_string(ts_created_obj);
                const char *l_temp_ticker = dap_json_get_string(token_ticker_obj);
                if (l_temp_ts && l_temp_ticker) {
                    *a_ts_created_str = l_temp_ts;
                    *a_token_ticker = l_temp_ticker;
                }
            }
        }

        // Extract seller address from the first transaction only
        if (l_first_tx) {
            dap_json_t *l_first_items = NULL;
            if (dap_json_object_get_ex(l_first_item, "items", &l_first_items)) {
                int l_first_items_count = dap_json_array_length(l_first_items);
                for (int i = 0; i < l_first_items_count; i++) {
                    dap_json_t *item = dap_json_array_get_idx(l_first_items, i);
                    dap_json_t *l_type_obj = NULL;
                    dap_json_object_get_ex(item, "type", &l_type_obj);
                    const char *item_type = l_type_obj ? dap_json_get_string(l_type_obj) : NULL;
                    if (item_type && dap_strcmp(item_type, "SIG") == 0) {
                        dap_json_t *sender_addr_obj = NULL;
                        if (dap_json_object_get_ex(item, "sender_addr", &sender_addr_obj)) {
                            const char *sender_addr_str = dap_json_get_string(sender_addr_obj);
                            if (sender_addr_str) {
                                dap_chain_addr_t *l_temp_addr = dap_chain_addr_from_str(sender_addr_str);
                                if (l_temp_addr) {
                                    *a_seller_addr = *l_temp_addr;
                                    DAP_DELETE(l_temp_addr);
                                    break; // Found seller address, exit the loop
                                } else {
                                    // Invalid sender address format
                                    dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS, "Invalid sender address format in first transaction");
                                    dap_json_object_free(response);
                                    return NULL;
                                }
                            }
                        }
                    }
                }
            }
            l_first_tx = false; // No longer the first transaction
        }

        // First, find the conditional output index in this transaction
        dap_json_t *l_current_items = NULL;
        int l_cond_out_idx = -1;
        if (dap_json_object_get_ex(l_first_item, "items", &l_current_items)) {
            int l_current_items_count = dap_json_array_length(l_current_items);
            int l_out_counter = 0;
            for (int i = 0; i < l_current_items_count; i++) {
                dap_json_t *item = dap_json_array_get_idx(l_current_items, i);
                dap_json_t *l_type_obj = NULL;
                dap_json_object_get_ex(item, "type", &l_type_obj);
                const char *item_type = l_type_obj ? dap_json_get_string(l_type_obj) : NULL;
                if (item_type && (dap_strcmp(item_type, "out_cond") == 0 || dap_strcmp(item_type, "out") == 0 || dap_strcmp(item_type, "out_ext") == 0 || dap_strcmp(item_type, "old_out") == 0)) {
                    if (dap_strcmp(item_type, "out_cond") == 0) {
                        dap_json_t *l_subtype_obj = NULL;
                        dap_json_object_get_ex(item, "subtype", &l_subtype_obj);
                        const char *subtype = l_subtype_obj ? dap_json_get_string(l_subtype_obj) : NULL;
                        if (subtype && !dap_strcmp(subtype, "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE")) {
                            l_cond_out_idx = l_out_counter;
                            break;
                        }
                    }
                    l_out_counter++;
                }
            }
        }

        dap_json_t *l_spent_outs = NULL;
        if (!dap_json_object_get_ex(l_first_item, "spent_outs", &l_spent_outs) ||
            !l_spent_outs || dap_json_array_length(l_spent_outs) == 0 || l_cond_out_idx == -1) {
            l_found_last = true;
            // Store the final response for processing
            l_final_response = response;
            break;
            
        }

        // Look for the conditional output index in spent_outs
        bool l_found_next = false;
        for (size_t i = 0; i < dap_json_array_length(l_spent_outs); i++) {
            dap_json_t *l_spent_out = dap_json_array_get_idx(l_spent_outs, i);
            dap_json_t *out_obj = NULL, *spent_by_tx_obj = NULL;
            if (dap_json_object_get_ex(l_spent_out, "out", &out_obj) &&
                dap_json_object_get_ex(l_spent_out, "is_spent_by_tx", &spent_by_tx_obj)) {
                int out_value = dap_json_object_get_int(out_obj, NULL);
                if (out_value == l_cond_out_idx) {
                    const char *l_next_hash = dap_json_get_string(spent_by_tx_obj);
                    if (l_next_hash && dap_chain_hash_fast_from_str(l_next_hash, &l_current_hash) == 0) {
                        l_found_next = true;
                        break;
                    }
                }
            }
        }

        if (!l_found_next) {
            l_found_last = true;
            // Store the final response for processing
            l_final_response = response;
        } else {
            // Free the current response as we'll get a new one
            dap_json_object_free(response);
        }
    }
    
    if (!l_final_response) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_RESPONSE_FORMAT, "No final response available");
        return NULL;
    }
    
    l_response_array = dap_json_array_get_idx(l_final_response, 0);
    if (!l_response_array) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_RESPONSE_FORMAT, "Can't get the first element from the response array");
        dap_json_object_free(l_final_response);
        return NULL;
    }

    dap_json_t *items = NULL;
    if (!dap_json_object_get_ex(l_response_array, "items", &items)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_ITEMS_FOUND, "No items found in response");
        dap_json_object_free(l_final_response);
        return NULL;
    }

    uint32_t l_counter_idx = 0;
    int items_count = dap_json_array_length(items);

    for (int i = 0; i < items_count; i++) {
        dap_json_t *item = dap_json_array_get_idx(items, i);
        dap_json_t *l_type_obj = NULL;
    dap_json_object_get_ex(item, "type", &l_type_obj);
    const char *item_type = l_type_obj ? dap_json_get_string(l_type_obj) : NULL;
        if (!item_type) {
            continue;
        }

        if (dap_strcmp(item_type, "out_cond") == 0) {
            dap_json_t *l_subtype_obj = NULL;
       dap_json_object_get_ex(item, "subtype", &l_subtype_obj);
       const char *subtype = l_subtype_obj ? dap_json_get_string(l_subtype_obj) : NULL;
            if (subtype && !dap_strcmp(subtype, "DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE")) {
                l_cond_tx = DAP_NEW_Z(dap_chain_tx_out_cond_t);
                if (!l_cond_tx) {
                    dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_COND_TX, "Memory allocation failed");
                    dap_json_object_free(l_final_response);
                    return NULL;
                }

                l_cond_tx->header.item_type = TX_ITEM_TYPE_OUT_COND;

                dap_json_t *value_obj = NULL, *uid_obj = NULL, *ts_expires_obj = NULL;
                dap_json_t *buy_token_obj = NULL, *rate_obj = NULL, *tsd_size_obj = NULL;

                if (dap_json_object_get_ex(item, "value", &value_obj)) {
                    const char *value_str = dap_json_get_string(value_obj);
                    l_cond_tx->header.value = dap_chain_balance_scan(value_str);
                }

                l_cond_tx->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE;

                if (dap_json_object_get_ex(item, "uid", &uid_obj)) {
                    const char *uid_str = dap_json_get_string(uid_obj);
                    l_cond_tx->header.srv_uid.uint64 = strtoull(uid_str, NULL, 16);
                }

                if (dap_json_object_get_ex(item, "ts_expires", &ts_expires_obj)) {
                    const char *ts_expires_str = dap_json_get_string(ts_expires_obj);
                    l_cond_tx->header.ts_expires = dap_time_from_str_rfc822(ts_expires_str);
                }

                if (dap_json_object_get_ex(item, "buy_token", &buy_token_obj)) {
                    const char *buy_token_str = dap_json_get_string(buy_token_obj);
                    if (buy_token_str) {
                        strncpy(l_cond_tx->subtype.srv_xchange.buy_token, buy_token_str, sizeof(l_cond_tx->subtype.srv_xchange.buy_token) - 1);
                        l_cond_tx->subtype.srv_xchange.buy_token[sizeof(l_cond_tx->subtype.srv_xchange.buy_token) - 1] = '\0';
                    }
                }

                if (dap_json_object_get_ex(item, "rate", &rate_obj)) {
                    const char *rate_str = dap_json_get_string(rate_obj);
                    l_cond_tx->subtype.srv_xchange.rate = dap_chain_balance_scan(rate_str);
                }

                if (dap_json_object_get_ex(item, "tsd_size", &tsd_size_obj)) {
                    l_cond_tx->tsd_size = dap_json_object_get_int(tsd_size_obj, NULL);
                }
                // Set seller address from the first transaction
                l_cond_tx->subtype.srv_xchange.seller_addr = *a_seller_addr;
                *a_prev_cond_idx = l_counter_idx;
            }
            l_counter_idx++;
        } else if (dap_strcmp(item_type, "out") == 0 || dap_strcmp(item_type, "out_ext") == 0 || dap_strcmp(item_type, "old_out") == 0) {
            l_counter_idx++;
        } else {
            l_counter_idx++;
        }
    }

    // Use the final response for extracting final data
    l_response_array = l_final_response;

    if (!l_cond_tx) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_COND_TX, "No transaction output condition found");
        dap_json_object_free(l_final_response);
        return NULL;
    }

    dap_json_t *final_token_ticker_obj = NULL;
    if (!dap_json_object_get_ex(l_response_array, "token_ticker", &final_token_ticker_obj)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TOKEN_TICKER, "Token_ticker not found in response");
        dap_json_object_free(l_final_response);
        return NULL;
    }
    const char *l_final_token_ticker = dap_json_get_string(final_token_ticker_obj);
    if (!l_final_token_ticker) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TOKEN_TICKER, "Token_ticker not found in response");
        DAP_DELETE(l_cond_tx);
        dap_json_object_free(l_final_response);
        return NULL;
    }
    *a_token_ticker = dap_strdup(l_final_token_ticker);
    if (!*a_token_ticker) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TOKEN_TICKER, "Failed to allocate token_ticker");
        DAP_DELETE(l_cond_tx);
        dap_json_object_free(l_final_response);
        return NULL;
    }

    dap_json_t *final_ts_created_obj = NULL;
    if (!dap_json_object_get_ex(l_response_array, "ts_created", &final_ts_created_obj)) {
        DAP_DELETE(l_cond_tx);
        dap_json_object_free(l_final_response);
        return NULL;
    }
    const char *l_final_ts_created = dap_json_get_string(final_ts_created_obj);
    if (!l_final_ts_created) {
        DAP_DELETE(l_cond_tx);
        DAP_DELETE(*a_token_ticker);
        *a_token_ticker = NULL;
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TIMESTAMP, "TS_Created not found in response");
        dap_json_object_free(l_final_response);
        return NULL;
    }
    *a_ts_created_str = dap_strdup(l_final_ts_created);
    if (!*a_ts_created_str) {
        DAP_DELETE(l_cond_tx);
        DAP_DELETE(*a_token_ticker);
        *a_token_ticker = NULL;
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TIMESTAMP, "Failed to allocate ts_created");
        dap_json_object_free(l_final_response);
        return NULL;
    }

    dap_json_object_free(l_final_response);
    *a_hash_out = l_current_hash;
    return l_cond_tx;
}
