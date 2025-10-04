/**
 * @file dap_chain_net_srv_xchange_compose.c
 * @brief Xchange service transaction compose functions
 * 
 * These functions were moved from modules/compose/ to eliminate circular dependencies.
 * Xchange service now provides its own compose logic and registers it with compose module.
 */

#include "dap_common.h"
#include "dap_chain_net_srv_xchange.h"
#include "dap_chain_tx_compose.h"
#include "dap_chain_tx_compose_callbacks.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net_tx.h"

#define LOG_TAG "xchange_compose"

/**
 * @brief Create price structure from order conditional transaction
 */
dap_chain_net_srv_xchange_price_t *dap_chain_net_srv_xchange_price_from_order_compose(dap_chain_tx_out_cond_t *a_cond_tx, 
                                                                                    dap_time_t a_ts_created, dap_hash_fast_t *a_order_hash, dap_hash_fast_t *a_hash_out, const char *a_token_ticker,
                                                                                    uint256_t *a_fee, bool a_ret_is_invalid, compose_config_t *a_config)
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
        }
    }

    return l_price;
}
dap_chain_datum_tx_t* dap_xchange_tx_invalidate_compose( dap_chain_net_srv_xchange_price_t *a_price, dap_chain_tx_out_cond_t *a_cond_tx, dap_chain_addr_t *a_wallet_addr, dap_chain_addr_t *a_seller_addr, const char *a_tx_ticker, uint32_t a_prev_cond_idx, compose_config_t *a_config)
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
    const char *l_native_ticker = dap_compose_get_native_ticker(a_config->net_name);

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
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);
    uint256_t l_total_fee = a_price->fee;
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);

    if (!l_single_channel) {
        dap_json_t *l_outs_native = dap_get_remote_tx_outs(l_native_ticker, a_seller_addr, a_config);
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
 * @brief Create xchange request transaction
 */
dap_chain_datum_tx_t *dap_xchange_tx_create_request_compose(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_addr_t *a_seller_addr,
                                                                 const char *a_native_ticker, compose_config_t *a_config)
{
    if (!a_config) {
        return NULL;
    }
    if (!a_price || !*a_price->token_sell || !*a_price->token_buy || !a_seller_addr) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_ARGUMENT, "Invalid parameter");
        return NULL;
    }
    const char *l_native_ticker = dap_compose_get_native_ticker(a_config->net_name);
    bool l_single_channel = !dap_strcmp(a_price->token_sell, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer; // how many coins to transfer
    uint256_t l_value_need = a_price->datoshi_sell,
              l_net_fee,
              l_total_fee = a_price->fee,
              l_fee_transfer;
    dap_chain_addr_t * l_addr_net_fee = NULL;
    dap_list_t *l_list_fee_out = NULL;

    bool l_net_fee_used = dap_get_remote_net_fee_and_address(&l_net_fee, &l_addr_net_fee, a_config);
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST    
    dap_json_t *l_outs_native = dap_get_remote_tx_outs(a_native_ticker, a_seller_addr, a_config);
    if (!l_outs_native) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Can't get tx outs");
        return NULL;
    }

    dap_json_t *l_outs = NULL;
    if (!dap_strcmp(a_price->token_sell, a_native_ticker)) {
        l_outs = l_outs_native;
    } else {
        l_outs = dap_get_remote_tx_outs(a_price->token_sell, a_seller_addr, a_config);
    }
    int l_out_native_count = dap_json_array_length(l_outs_native);
    int l_out_count = dap_json_array_length(l_outs);
#else
    dap_json_t *l_outs = NULL;
    dap_json_t *l_outs_native = NULL;
    int l_out_count = 0;
    int l_out_native_count = 0;
#endif

    if (l_single_channel)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else if (!IS_ZERO_256(l_total_fee)) {
        l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                               l_total_fee, 
                                                               &l_fee_transfer);
        if (!l_list_fee_out) {
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS_TO_PAY_FEE, "Not enough funds to pay fee");
            dap_json_object_free(l_outs_native);
            if (dap_strcmp(a_price->token_sell, a_native_ticker))
                dap_json_object_free(l_outs);
            DAP_DELETE(l_addr_net_fee);
            return NULL;
        }
    }
    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_out_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    
    if (dap_strcmp(a_price->token_sell, a_native_ticker))
        dap_json_object_free(l_outs);
    dap_json_object_free(l_outs_native);
    if (!l_list_used_out) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS_TO_TRANSFER, "Not enough funds to transfer");
        if (l_list_fee_out)
            dap_list_free_full(l_list_fee_out, NULL);
        DAP_DELETE(l_addr_net_fee);
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    if (!EQUAL_256(l_value_to_items, l_value_transfer) != 0) {
// dap_chain_net_srv_xchange_purchase_compose
dap_chain_datum_tx_t* dap_chain_net_srv_xchange_purchase_compose(dap_hash_fast_t *a_order_hash, uint256_t a_value,
                                       uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, char **a_hash_out, compose_config_t *a_config){
    if (!a_config || !a_order_hash || !a_wallet_addr || !a_hash_out) {
        return NULL;
    }

    const char *l_ts_created_str = NULL;
    const char *l_token_ticker = NULL;
    uint32_t l_prev_cond_idx = 0;
    dap_chain_addr_t l_seller_addr = {0};
    dap_hash_fast_t l_hash_out = {0};
    dap_chain_tx_out_cond_t *l_cond_tx = dap_find_last_xchange_tx(a_order_hash, &l_seller_addr, a_config, &l_ts_created_str, &l_token_ticker, &l_prev_cond_idx, &l_hash_out);
    if (!l_cond_tx) {
        // Clean up any allocated strings in case of failure
        if (l_ts_created_str) {
            DAP_DELETE(l_ts_created_str);
        }
        if (l_token_ticker) {
            DAP_DELETE(l_token_ticker);
        }
        return NULL;
    }

    dap_time_t l_ts_created = dap_time_from_str_rfc822(l_ts_created_str);

    dap_chain_net_srv_xchange_price_t *l_price = dap_chain_net_srv_xchange_price_from_order_compose(l_cond_tx, l_ts_created, a_order_hash, &l_hash_out, l_token_ticker, &a_fee, false, a_config);
    if(!l_price){
        DAP_DELETE(l_cond_tx);
        // Clean up allocated strings
        if (l_ts_created_str) {
            DAP_DELETE(l_ts_created_str);
        }
        if (l_token_ticker) {
            DAP_DELETE(l_token_ticker);
        }
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_PRICE_CREATE, "Failed to create price from order");
        return NULL;
    }

    // Create conditional transaction
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_create_exchange_compose(l_price, a_wallet_addr, a_value, a_fee, l_cond_tx, l_prev_cond_idx, a_config);
    DAP_DELETE(l_cond_tx);
    DAP_DELETE(l_price);
    // Clean up allocated strings
    if (l_ts_created_str) {
        DAP_DELETE(l_ts_created_str);
    }
    if (l_token_ticker) {
        DAP_DELETE(l_token_ticker);
    }
    if (!l_tx) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE, "Failed to create exchange transaction");
        return NULL;
    }
    return l_tx;
}


// dap_xchange_tx_create_exchange_compose
dap_chain_datum_tx_t *dap_xchange_tx_create_exchange_compose(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_addr_t *a_buyer_addr, uint256_t a_datoshi_buy,
                                                          uint256_t a_datoshi_fee, dap_chain_tx_out_cond_t* a_cond_tx, uint32_t a_prev_cond_idx, compose_config_t *a_config)
{
    if (!a_price || !*a_price->token_sell || !*a_price->token_buy || !a_buyer_addr || !a_cond_tx || !a_config) return NULL;

    const char *l_native_ticker = dap_compose_get_native_ticker(a_config->net_name);
    const char *l_service_ticker = NULL;
    // find the transactions from which to take away coins
    uint256_t l_value_transfer, // how many coins to transfer
              l_value_need = a_datoshi_buy,
              l_net_fee = {},
              l_service_fee,
              l_total_fee = a_datoshi_fee,
              l_fee_transfer;
    dap_chain_addr_t *l_net_fee_addr = NULL, *l_service_fee_addr = NULL;
    dap_list_t *l_list_fee_out = NULL;
    bool l_net_fee_used = dap_get_remote_net_fee_and_address(&l_net_fee, &l_net_fee_addr, a_config);
    if (l_net_fee_used)
        SUM_256_256(l_net_fee, a_price->fee, &l_total_fee);
    uint16_t l_service_fee_type  = 0;

    // Doesn't implement service fee for now
    // bool l_service_fee_used = dap_chain_net_srv_xchange_get_fee(a_price->net->pub.id, &l_service_fee, &l_service_fee_addr, &l_service_fee_type);
    // if (l_service_fee_used) {
    //     switch (l_service_fee_type) {
    //     case SERIVCE_FEE_NATIVE_PERCENT:
    //         MULT_256_COIN(l_service_fee, a_datoshi_buy, &l_service_fee);
    //     case SERVICE_FEE_NATIVE_FIXED:
    //         SUM_256_256(l_total_fee, l_service_fee, &l_total_fee);
    //         l_service_ticker = l_native_ticker;
    //         break;
    //     case SERVICE_FEE_OWN_PERCENT:
    //         MULT_256_COIN(l_service_fee, a_datoshi_buy, &l_service_fee);
    //     case SERVICE_FEE_OWN_FIXED:
    //         SUM_256_256(l_value_need, l_service_fee, &l_value_need);
    //         l_service_ticker = a_price->token_buy;
    //     default:
    //         break;
    //     }
    // }

    dap_json_t *l_outs = NULL;
    int l_outputs_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!dap_get_remote_wallet_outs_and_count(a_buyer_addr, a_price->token_buy, &l_outs, &l_outputs_count, a_config)) {
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Not enough funds to transfer");
        return NULL;
    }
#endif

    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_value_need,
                                                            &l_value_transfer);
    if (!l_list_used_out) {
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Not enough funds to transfer");
        dap_json_object_free(l_outs);
        return NULL;
    }

    bool l_pay_with_native = !dap_strcmp(a_price->token_sell, l_native_ticker);
    bool l_buy_with_native = !dap_strcmp(a_price->token_buy, l_native_ticker);
    if (!l_pay_with_native) {
        if (l_buy_with_native) {
            SUM_256_256(l_value_need, l_total_fee, &l_value_need);
        } else {
            l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                                l_total_fee, 
                                                                &l_fee_transfer);
            if (!l_list_fee_out) {
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Not enough funds to pay fee");
                dap_json_object_free(l_outs);
                dap_list_free_full(l_list_used_out, NULL);
                return NULL;
            }
        }
    }
    dap_json_object_free(l_outs);

    // Create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        dap_list_free_full(l_list_used_out, NULL);
        dap_list_free_full(l_list_fee_out, NULL);
        // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_TX_CREATE_ERROR, "Can't create transaction");
        return NULL;
    }

    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
        dap_list_free_full(l_list_fee_out, NULL);
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Can't compose the transaction input");
        return NULL;
    }
#endif

    if (!l_pay_with_native && !l_buy_with_native) {
        // add 'in' items to fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't compose the transaction input");
            return NULL;
        }
#endif
    }

    const dap_chain_addr_t *l_seller_addr = &a_cond_tx->subtype.srv_xchange.seller_addr;
    if (1 != dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_price->tx_hash, a_prev_cond_idx, 0)) {
        dap_chain_datum_tx_delete(l_tx);
        // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_COND_ERROR, "Can't add conditional input");
        return NULL;
    }

    // add 'out' items
    // transfer selling coins
    uint256_t l_datoshi_sell,
              l_datoshi_buy,
              l_value_back;
    if (!IS_ZERO_256(a_price->rate)) {
        DIV_256_COIN(a_datoshi_buy, a_price->rate, &l_datoshi_sell);
        if (compare256(a_cond_tx->header.value, l_datoshi_sell) < 0) {
            l_datoshi_sell = a_cond_tx->header.value;
            MULT_256_COIN(l_datoshi_sell, a_price->rate, &l_datoshi_buy);
            uint256_t l_exceed = {}; // Correct requested transfer value
            SUBTRACT_256_256(a_datoshi_buy, l_datoshi_buy, &l_exceed);
            SUBTRACT_256_256(l_value_need, l_exceed, &l_value_need);
        } else
            l_datoshi_buy = a_datoshi_buy;
        
        uint256_t l_value_sell = l_datoshi_sell;
        if (l_pay_with_native) {
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
            if (compare256(l_datoshi_sell, l_total_fee) <= 0) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FUNDS_ERROR, "Fee is greater or equal than transfer value");
                return NULL;
            }
#endif
            SUBTRACT_256_256(l_datoshi_sell, l_total_fee, &l_value_sell);
        }
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_buyer_addr, l_value_sell, a_price->token_sell) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add selling coins output");
            return NULL;
        }
    } else {
        // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_RATE_ERROR, "Can't add selling coins output because price rate is 0");
        return NULL;
    }
    
    if (compare256(a_cond_tx->header.value, l_datoshi_sell) == 1) {
        SUBTRACT_256_256(a_cond_tx->header.value, l_datoshi_sell, &l_value_back);
        
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(
                    c_dap_chain_net_srv_xchange_uid, dap_get_net_id(a_config->net_name), l_value_back,
                    dap_get_net_id(a_config->net_name), a_price->token_buy, a_price->rate,
                    l_seller_addr, NULL, 0);
        if (!l_tx_out) {
            dap_chain_datum_tx_delete(l_tx);
            // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_COND_ERROR, "Can't add selling coins back conditioned output (cond cashback)");
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
    } 

    // transfer buying coins
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_seller_addr, l_datoshi_buy, a_price->token_buy) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add buying coins output");
        return NULL;
    }
    
    // transfer validator's fee
    if (!IS_ZERO_256(a_datoshi_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_datoshi_fee) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't add validator fee output");
            return NULL;
        }
    }

    // Add network fee
    if (l_net_fee_used && !IS_ZERO_256(l_net_fee)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_FEE_ERROR, "Can't add net fee output");
            return NULL;
        }
    }

    // coin back
    SUBTRACT_256_256(l_value_transfer, l_value_need, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_buyer_addr, l_value_back, a_price->token_buy) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add buying coins back output");
            return NULL;
        }
    }
    // fee back
    if (!l_pay_with_native && !l_buy_with_native) {
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_buyer_addr, l_value_back, l_native_ticker) == -1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_OUT_ERROR, "Can't add buying coins back output");
                return NULL;
            }
        }
    }

    return l_tx;
}


}
}

// dap_find_last_xchange_tx
dap_chain_tx_out_cond_t* dap_find_last_xchange_tx(dap_hash_fast_t *a_order_hash,  dap_chain_addr_t *a_seller_addr,  compose_config_t * a_config, 
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
    } // End of while (!l_found_last) loop

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

// dap_tx_create_xchange_purchase_compose
dap_json_t *dap_tx_create_xchange_purchase_compose (const char *a_net_name, const char *a_order_hash, const char* a_value,
                                                     const char* a_fee, dap_chain_addr_t *a_wallet_addr, const char *a_url_str, uint16_t a_port, const char *a_cert_path) {
    // Input validation
    if (!a_net_name || !a_order_hash || !a_value || !a_fee || !a_wallet_addr || !a_url_str) {
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS, "Invalid input parameters");
        return l_json_obj_ret;
    }

    compose_config_t *l_config = s_compose_config_init(a_net_name, a_url_str, a_port, a_cert_path);
    if (!l_config) {
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_CONFIG_CREATE, "Can't create compose config");
        return l_json_obj_ret;
    }

    uint256_t l_datoshi_buy = dap_chain_balance_scan(a_value);
    if (IS_ZERO_256(l_datoshi_buy)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS, "Value must be greater than 0");
        return s_compose_config_return_response_handler(l_config);
    }

    uint256_t l_datoshi_fee = dap_chain_balance_scan(a_fee);
    if (IS_ZERO_256(l_datoshi_fee)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_FEE, "Fee must be greater than 0");
        return s_compose_config_return_response_handler(l_config);
    }

    dap_hash_fast_t l_tx_hash = {};
    if (dap_chain_hash_fast_from_str(a_order_hash, &l_tx_hash) != 0 || dap_hash_fast_is_blank(&l_tx_hash)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_HASH, "Invalid order hash");
        return s_compose_config_return_response_handler(l_config);
    }

    char *l_str_ret_hash = NULL;
    dap_chain_datum_tx_t *l_tx = dap_chain_net_srv_xchange_purchase_compose(&l_tx_hash, l_datoshi_buy, l_datoshi_fee,
                                                        a_wallet_addr, &l_str_ret_hash, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        DAP_DELETE(l_str_ret_hash); // Free allocated hash string
        dap_chain_datum_tx_delete(l_tx);
    }

    return s_compose_config_return_response_handler(l_config);
}


typedef enum dap_chain_net_srv_xchange_purchase_compose_error {
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NONE = 0,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_REMOTE_NODE_UNREACHABLE,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_RESPONSE_FORMAT,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_ITEMS_FOUND,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_COND_TX,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TOKEN_TICKER,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TIMESTAMP,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_PRICE_CREATE,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE

// dap_cli_xchange_order_remove_compose
dap_json_t * dap_cli_xchange_order_remove_compose(const char *l_net_str, const char *l_order_hash_str, const char *l_fee_str, dap_chain_addr_t *a_wallet_addr, const char *l_url_str, uint16_t l_port, const char *l_cert_path) {

    compose_config_t *l_config = s_compose_config_init(l_net_str, l_url_str, l_port, l_cert_path);
    if (!l_config) {
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS, "Invalid arguments");
        return l_json_obj_ret;
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_compose_error_add(l_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_FEE, "Format -fee <256 bit integer>");
        return s_compose_config_return_response_handler(l_config);
    }
    dap_hash_fast_t l_tx_hash = {};
    dap_chain_hash_fast_from_str(l_order_hash_str, &l_tx_hash);
    if (dap_hash_fast_is_blank(&l_tx_hash)) {
        dap_json_compose_error_add(l_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_ORDER_HASH, "Invalid order hash");
        return s_compose_config_return_response_handler(l_config);
    }
    char *l_tx_hash_ret = NULL;
    dap_chain_datum_tx_t *l_tx = dap_chain_net_srv_order_remove_compose(&l_tx_hash, l_fee, a_wallet_addr, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }
    
    return s_compose_config_return_response_handler(l_config);
}

static bool s_process_ledger_response(dap_chain_tx_out_cond_subtype_t a_cond_type, 
                                                dap_chain_hash_fast_t *a_tx_hash, dap_chain_hash_fast_t *a_out_hash, compose_config_t *a_config) {
    *a_out_hash = *a_tx_hash;
    int l_prev_tx_count = 0;
    dap_chain_hash_fast_t l_hash = {};
    
    dap_json_t *response = dap_request_command_to_rpc_with_params(a_config, "ledger", "info;-hash;%s;-net;%s", 
                                                                  dap_chain_hash_fast_to_str_static(a_tx_hash), a_config->net_name);
    if (!response) {
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "Error: Failed to get response from remote node");
        return false;
    }
    
    dap_json_t *l_response_array = dap_json_array_get_idx(response, 0);
    if (!l_response_array) {
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "Error: Can't get the first element from the response array");
        dap_json_object_free(response);
        return false;
    }

    dap_json_t *items = NULL;
    if (!dap_json_object_get_ex(l_response_array, "items", &items)) {
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "Error: No items found in response");
        return false;
    }
    bool l_found = false;
    int items_count = dap_json_array_length(items);
    for (int i = 0; i < items_count; i++) {
        dap_json_t *item = dap_json_array_get_idx(items, i);
        dap_json_t *l_type_obj = NULL;
    dap_json_object_get_ex(item, "type", &l_type_obj);
    const char *item_type = l_type_obj ? dap_json_get_string(l_type_obj) : NULL;
        if (dap_strcmp(item_type, "out_cond") == 0) {
            dap_json_t *l_subtype_obj = NULL;
       dap_json_object_get_ex(item, "subtype", &l_subtype_obj);
       const char *subtype = l_subtype_obj ? dap_json_get_string(l_subtype_obj) : NULL;
            if (!dap_strcmp(subtype, dap_chain_tx_out_cond_subtype_to_str(a_cond_type))) {
                dap_json_t *l_hash_obj = NULL;
                dap_json_object_get_ex(item, "hash", &l_hash_obj);
                if (l_hash_obj) {
                    const char *hash_str = dap_json_get_string(l_hash_obj);
                    if (hash_str) {
                        dap_chain_hash_fast_from_str(hash_str, &l_hash);
                    }
                }
                l_prev_tx_count++;
                l_found = true;
                break;
            }
        } else if (dap_strcmp(item_type, "out") == 0 || dap_strcmp(item_type, "out_cond") == 0 || dap_strcmp(item_type, "out_old") == 0) {
            l_prev_tx_count++;
        }
    }
    if (!l_found) {
        return false;
    }
    bool l_another_tx = false;
    dap_json_t *spent_outs = NULL;
    dap_json_object_get_ex(l_response_array, "spent_OUTs", &spent_outs);
    if (spent_outs) {
        int spent_outs_count = dap_json_array_length(spent_outs);
        for (int i = 0; i < spent_outs_count; i++) {
            dap_json_t *spent_out = dap_json_array_get_idx(spent_outs, i);
            dap_json_t *l_out_obj = NULL;
            dap_json_object_get_ex(spent_out, "OUT - ", &l_out_obj);
            int out_index = l_out_obj ? dap_json_object_get_int(l_out_obj, NULL) : 0;
            if (out_index == l_prev_tx_count) {
                dap_json_t *spent_by_tx_obj = NULL;
                if (dap_json_object_get_ex(spent_out, "is_spent_by_tx", &spent_by_tx_obj)) {
                    const char *spent_by_tx_str = dap_json_get_string(spent_by_tx_obj);
                    if (spent_by_tx_str) {
                        dap_chain_hash_fast_from_str(spent_by_tx_str, &l_hash);
                        l_another_tx = true;
                        break;
                    }
                }
            }
        }
    }
    if (l_another_tx) {
        *a_out_hash = l_hash;
        return true;
    }
    return false;
}

dap_chain_hash_fast_t dap_ledger_get_final_chain_tx_hash_compose(dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash, bool a_unspent_only, compose_config_t *a_config)
{
    dap_chain_hash_fast_t l_hash = { };
    if(!a_tx_hash || dap_hash_fast_is_blank(a_tx_hash))
        return l_hash;
    l_hash = *a_tx_hash;

    while(s_process_ledger_response( a_cond_type, a_tx_hash, &l_hash, a_config));

    return l_hash;
}

// dap_chain_net_srv_xchange_create_compose
dap_chain_datum_tx_t* dap_chain_net_srv_xchange_create_compose(const char *a_token_buy,
                                     const char *a_token_sell, uint256_t a_datoshi_sell,
                                     uint256_t a_rate, uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, compose_config_t *a_config){
    if (!a_config) {
        return NULL;
    }
    if ( !a_token_buy || !a_token_sell || !a_wallet_addr) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_ARGUMENT, "Invalid parameter");
        return NULL;
    }
    if (IS_ZERO_256(a_rate)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_RATE_IS_ZERO, "Invalid parameter rate");
        return NULL;
    }
    if (IS_ZERO_256(a_fee)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_FEE_IS_ZERO, "Invalid parameter fee");
        return NULL;
    }
    if (IS_ZERO_256(a_datoshi_sell)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_VALUE_SELL_IS_ZERO, "Invalid parameter value sell");
        return NULL;
    }

    dap_json_t *l_json_coins = dap_request_command_to_rpc_with_params(a_config, "ledger", "list;coins;-net;%s", a_config->net_name);
    if (!l_json_coins) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Can't get tx outs");
        return NULL;
    }
    if (!check_token_in_ledger(l_json_coins, a_token_sell) || !check_token_in_ledger(l_json_coins, a_token_buy)) {
        dap_json_object_free(l_json_coins);
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_TOKEN_TICKER_SELL_OR_BUY_IS_NOT_FOUND_LEDGER, "Token ticker sell or buy is not found in ledger");
        return NULL;
    }
    dap_json_object_free(l_json_coins);
    dap_json_t *l_json_outs = dap_request_command_to_rpc_with_params(a_config, "wallet", "info;-addr;%s;-net;%s", 
                                                                      dap_chain_addr_to_str(a_wallet_addr), a_config->net_name);
    uint256_t l_value = get_balance_from_json(l_json_outs, a_token_sell);
    uint256_t l_value_sell = a_datoshi_sell;
    if (!dap_strcmp(dap_compose_get_native_ticker(a_config->net_name), a_token_sell)) {
        if (SUM_256_256(l_value_sell, a_fee, &l_value_sell)) {
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INTEGER_OVERFLOW_WITH_SUM_OF_VALUE_AND_FEE, "Integer overflow with sum of value and fee");
            return NULL;
        }
    } else { // sell non-native ticker
        uint256_t l_fee_value = get_balance_from_json(l_json_outs, dap_compose_get_native_ticker(a_config->net_name));
        if (compare256(l_fee_value, a_fee) == -1) {
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_CASH_FOR_FEE_IN_SPECIFIED_WALLET, "Not enough cash for fee in specified wallet");
            return NULL;
        }
    }
    if (compare256(l_value, l_value_sell) == -1) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_CASH_IN_SPECIFIED_WALLET, "Not enough cash in specified wallet");
        return NULL;
    }
    // Create the price
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    if (!l_price) {
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_MEMORY_ALLOCATED, "Memory allocated");
        return NULL;
    }
    dap_stpcpy(l_price->token_sell, a_token_sell);
    dap_stpcpy(l_price->token_buy, a_token_buy);
    l_price->datoshi_sell = a_datoshi_sell;
    l_price->rate = a_rate;
    l_price->fee = a_fee;
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_create_request_compose(l_price, a_wallet_addr, dap_compose_get_native_ticker(a_config->net_name), a_config);
    DAP_DEL_Z(l_price);
    return l_tx;
}



// dap_tx_create_xchange_compose
dap_json_t* dap_tx_create_xchange_compose(const char *l_net_name, const char *l_token_buy, const char *l_token_sell, dap_chain_addr_t *l_wallet_addr, const char *l_value_str, const char *l_rate_str, const char *l_fee_str, const char *l_url_str, uint16_t l_port, const char *l_cert_path){
    compose_config_t *l_config = s_compose_config_init(l_net_name, l_url_str, l_port, l_cert_path);
    if (!l_config) {
        dap_json_t* l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Can't create compose config");
        return l_json_obj_ret;
    }

    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Invalid parameter value, rate or fee is 0, use required format 1.0e+18 ot in datoshi");
        return s_compose_config_return_response_handler(l_config);
    }
    uint256_t l_rate = dap_chain_balance_scan(l_rate_str);
    if (IS_ZERO_256(l_rate)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Invalid parameter rate");
        return s_compose_config_return_response_handler(l_config);
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Invalid parameter fee");
        return s_compose_config_return_response_handler(l_config);
    }

    dap_chain_datum_tx_t *l_tx = dap_chain_net_srv_xchange_create_compose(l_token_buy,
                                     l_token_sell, l_value, l_rate, l_fee, l_wallet_addr, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
        return s_compose_config_return_response_handler(l_config);
    }

    return s_compose_config_return_response_handler(l_config);
}

