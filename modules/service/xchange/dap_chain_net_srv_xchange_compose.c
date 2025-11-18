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
#include "dap_chain_net_srv_stake_compose.h"
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
    dap_return_val_if_pass(!a_cond_tx || !a_order_hash || !a_config, NULL);
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_net_srv_xchange_price_t, NULL);
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
        return l_price;
    } else {
        // dap_json_compose_error_add(a_config->response_handler, DAP_PROCESS_LEDGER_RESPONSE_RPC_RESPONSE, "This order have no active conditional transaction");
        if (a_ret_is_invalid) {
            log_it(L_ERROR, "This order have no active conditional transaction");
            dap_hash_fast_t l_tx_hash_zero = {0};
            l_price->tx_hash = l_tx_hash_zero;
            return l_price;
        }
    }
    return NULL;
}

dap_chain_datum_tx_t *dap_chain_net_srv_xchange_compose_tx_invalidate( dap_chain_net_srv_xchange_price_t *a_price, dap_chain_tx_out_cond_t *a_cond_tx, dap_chain_addr_t *a_wallet_addr, dap_chain_addr_t *a_seller_addr, const char *a_tx_ticker, uint32_t a_prev_cond_idx, dap_chain_tx_compose_config_t *a_config)
{
    dap_return_val_if_pass(!a_config || !a_price || !a_wallet_addr, NULL);

    if (!a_wallet_addr) {
        log_it(L_ERROR, "a_wallet_addr is NULL");
        dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS, "An a_wallet_addr NULL argument was passed to the s_xchange_tx_invalidate() function.");
        return NULL;
    }
    const char *l_native_ticker = a_config->native_ticker;

#ifndef DAP_CHAIN_TX_COMPOSE_TEST

    bool l_single_channel = !dap_strcmp(a_tx_ticker, l_native_ticker);

    if (!dap_chain_addr_compare(a_seller_addr, a_wallet_addr)) {
        log_it(L_ERROR, "not owner");
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
    dap_chain_addr_t *l_addr_fee = NULL;
    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);
    uint256_t l_total_fee = a_price->fee;
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);

    if (!l_single_channel) {
        dap_json_t *l_outs_native = dap_chain_tx_compose_get_remote_tx_outs(l_native_ticker, a_seller_addr, a_config);
        if (!l_outs_native) {
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        int l_out_native_count = dap_json_array_length(l_outs_native);
        uint256_t l_transfer_fee = {}, l_fee_back = {};
        // list of transaction with 'out' items to get net fee
        dap_list_t *l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                               l_total_fee, 
                                                               &l_transfer_fee, false);
        if (!l_list_fee_out) {
            log_it(L_ERROR, "not enough funds to pay fee");
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INSUFFICIENT_FUNDS, "Not enough funds to pay fee");
            dap_json_object_free(l_outs_native);
            DAP_DELETE(l_addr_fee);
            return NULL;
        }


        // add 'in' items to net fee
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
        if (!EQUAL_256(l_value_to_items, l_transfer_fee)) {
            log_it(L_ERROR, "Can't compose the transaction input");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_COMPOSE_FAILED, "Can't compose the transaction input");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        // return coins to owner
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, a_cond_tx->header.value, a_tx_ticker) == -1) {
            log_it(L_ERROR, "Can't add returning coins output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_COIN_RETURN_FAILED, "Cant add returning coins output");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        // Network fee
        if (l_net_fee_used &&
                dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
            log_it(L_ERROR, "Can't add network fee output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NET_FEE_FAILED, "Cant add network fee output");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        // put fee coinback
        SUBTRACT_256_256(l_transfer_fee, l_total_fee, &l_fee_back);
        if (!IS_ZERO_256(l_fee_back) &&
                dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, l_fee_back, l_native_ticker) == -1) {
            log_it(L_ERROR, "Can't add fee cachback output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_COINBACK_FAILED, "Cant add fee cachback output");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }

            // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            uint256_t l_fee_value = a_price->fee;
            if (dap_chain_datum_tx_add_fee_item(&l_tx, l_fee_value) == -1) {
                log_it(L_ERROR, "Can't add validator's fee output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_VALIDATOR_FEE_FAILED, "Cant add validator's fee output");
                DAP_DELETE(l_addr_fee);
                return NULL;
            }
        }


    } else {
        uint256_t l_coin_back = {};
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        if (compare256(l_total_fee, a_cond_tx->header.value) >= 0) {
            log_it(L_ERROR, "Total fee is greater or equal than order liquidity");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_TOO_HIGH, "Total fee is greater or equal than order liquidity");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
#endif
        SUBTRACT_256_256(a_cond_tx->header.value, l_total_fee, &l_coin_back);
        // return coins to owner
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, l_coin_back, l_native_ticker) == -1) {
            log_it(L_ERROR, "Can't add returning coins output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_COIN_RETURN_FAILED, "Cant add returning coins output");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        // Network fee
        if (l_net_fee_used &&
            dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
            log_it(L_ERROR, "Can't add network fee output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NET_FEE_FAILED, "Cant add network fee output");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        DAP_DEL_Z(l_addr_fee);

        // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            uint256_t l_fee_value = a_price->fee;
            if (dap_chain_datum_tx_add_fee_item(&l_tx, l_fee_value) == -1) {
                log_it(L_ERROR, "Can't add validator's fee output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_VALIDATOR_FEE_FAILED, "Cant add validator's fee output");
                return NULL;
            }
        }

    }
    return l_tx;
}

typedef enum dap_tx_create_xchange_purchase_compose_error {
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_NONE = 0,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_CONFIG_CREATE,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_FEE,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_HASH,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_WALLET_NOT_FOUND,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE_FAILED,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_NETWORK_ERROR,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INSUFFICIENT_FUNDS,
    DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_ORDER_NOT_FOUND
} dap_tx_create_xchange_purchase_compose_error_t;


/**
 * @brief Find last transaction in xchange order chain
 * @details Follows the chain of transactions from initial order to the last one
 * @note Moved from compose module (was dap_chain_net_srv_xchange_compose_find_last_tx) to break circular dependency
 */
dap_chain_tx_out_cond_t *dap_chain_net_srv_xchange_compose_find_last_tx(dap_hash_fast_t *a_order_hash,  dap_chain_addr_t *a_seller_addr,  dap_chain_tx_compose_config_t * a_config, 
                                                  dap_time_t *a_ts_created, char **a_token_ticker, int32_t *a_prev_cond_idx, dap_hash_fast_t *a_hash_out)
{
    dap_chain_tx_out_cond_t *l_cond_tx = NULL;
    dap_chain_tx_out_cond_t *l_ret = NULL;
    dap_hash_fast_t l_current_hash = {};
    dap_chain_datum_tx_t *l_tx = NULL;

    char *l_spent_by_hash = dap_chain_hash_fast_to_str_new(a_order_hash);
    while (l_spent_by_hash) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_cond_tx);
        if (dap_chain_hash_fast_from_str(l_spent_by_hash, &l_current_hash)) {
            log_it(L_ERROR, "failed to get hash from string");
            dap_json_compose_error_add(a_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_HASH, 
                                     "Failed to get hash from string");
            return NULL;
        }
        l_tx = dap_chain_tx_compose_get_datum_from_rpc(l_spent_by_hash, a_config, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_cond_tx, &l_spent_by_hash, a_token_ticker, a_prev_cond_idx, true);

        if (!l_tx) {
            log_it(L_ERROR, "failed to get datum info from remote node");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_REMOTE_NODE_UNREACHABLE, 
                                     "Failed to get datum info from remote node");
            return NULL;
        }
    }
    
    if (!l_cond_tx) {
        log_it(L_ERROR, "no transaction output condition found");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_COND_TX, "No transaction output condition found");
        return NULL;
    }
    l_ret = l_cond_tx;
    *a_seller_addr = l_cond_tx->subtype.srv_xchange.seller_addr;

    if (a_ts_created) {
        *a_ts_created = l_tx->header.ts_created;
    }
    *a_hash_out = l_current_hash;
    dap_chain_datum_tx_delete(l_tx);
    return l_ret;
}

/**
 * @brief Remove xchange order by invalidating it
 * @details Creates a transaction that invalidates the specified order
 */
dap_chain_datum_tx_t* dap_chain_tx_compose_datum_xchange_order_remove(dap_hash_fast_t *a_hash_tx, uint256_t a_fee,
                                     dap_chain_addr_t *a_wallet_addr, dap_chain_tx_compose_config_t *a_config)
{
    dap_return_val_if_pass(!a_hash_tx || !a_wallet_addr || !a_config, NULL);
    if(IS_ZERO_256(a_fee)){
        log_it(L_ERROR, "fee must be greater than 0");
        dap_json_compose_error_add(a_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_FEE, "Fee must be greater than 0");
        return NULL;
    }

    dap_time_t ts_created = 0;

    dap_chain_addr_t l_seller_addr = {};
    char *token_ticker = NULL;
    int32_t l_prev_cond_idx = 0;
    dap_hash_fast_t l_hash_out = {};
    dap_chain_tx_out_cond_t *l_cond_tx_last = dap_chain_net_srv_xchange_compose_find_last_tx(a_hash_tx, &l_seller_addr, a_config, NULL, &token_ticker, &l_prev_cond_idx, &l_hash_out);

    dap_chain_net_srv_xchange_price_t *l_price = dap_chain_net_srv_xchange_price_from_order_compose(l_cond_tx_last, ts_created, a_hash_tx, &l_hash_out, token_ticker, &a_fee, false, a_config);
    if (!l_price) {
        log_it(L_ERROR, "Failed to get price");
        return NULL;
    }
    dap_chain_datum_tx_t *l_tx = dap_chain_net_srv_xchange_compose_tx_invalidate(l_price, l_cond_tx_last, a_wallet_addr, &l_seller_addr, token_ticker, l_prev_cond_idx, a_config);

    DAP_DELETE(l_price);
    return l_tx;
}

/**
 * @brief CLI wrapper for xchange order removal
 */
dap_json_t *dap_chain_tx_compose_xchange_order_remove(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                  uint16_t a_port, const char *a_enc_cert_path, const char *a_order_hash_str, const char *a_fee_str, dap_chain_addr_t *a_wallet_addr)
{

    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Failed to create compose config");
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS, "Invalid arguments");
        return l_json_obj_ret;
    }
    uint256_t l_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_fee)) {
        log_it(L_ERROR, "unrecognized number in '-fee' param");
        dap_json_compose_error_add(l_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_FEE, "Format -fee <256 bit integer>");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    dap_hash_fast_t l_tx_hash = {};
    dap_chain_hash_fast_from_str(a_order_hash_str, &l_tx_hash);
    if (dap_hash_fast_is_blank(&l_tx_hash)) {
        log_it(L_ERROR, "invalid order hash");
        dap_json_compose_error_add(l_config->response_handler, SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_ORDER_HASH, "Invalid order hash");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    char *l_tx_hash_ret = NULL;
    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_xchange_order_remove(&l_tx_hash, l_fee, a_wallet_addr, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }
    
    return dap_chain_tx_compose_config_return_response_handler(l_config);
}

dap_json_t *dap_chain_tx_compose_xchange_purchase (dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                     uint16_t a_port, const char *a_enc_cert_path, const char *a_order_hash, const char *a_value,
                                                     const char *a_fee, dap_chain_addr_t *a_wallet_addr)
{
    // Input validation
    if (!a_order_hash || !a_value || !a_fee || !a_wallet_addr) {
        log_it(L_ERROR, "invalid input parameters");
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS, "Invalid input parameters");
        return l_json_obj_ret;
    }

    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Can't create compose config");
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_CONFIG_CREATE, "Can't create compose config");
        return l_json_obj_ret;
    }

    uint256_t l_datoshi_buy = dap_chain_balance_scan(a_value);
    if (IS_ZERO_256(l_datoshi_buy)) {
        log_it(L_ERROR, "value must be greater than 0");
        dap_json_compose_error_add(l_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS, "Value must be greater than 0");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    uint256_t l_datoshi_fee = dap_chain_balance_scan(a_fee);
    if (IS_ZERO_256(l_datoshi_fee)) {
        log_it(L_ERROR, "fee must be greater than 0");
        dap_json_compose_error_add(l_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_FEE, "Fee must be greater than 0");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_hash_fast_t l_tx_hash = {};
    if (dap_chain_hash_fast_from_str(a_order_hash, &l_tx_hash) != 0 || dap_hash_fast_is_blank(&l_tx_hash)) {
        log_it(L_ERROR, "invalid order hash");
        dap_json_compose_error_add(l_config->response_handler, DAP_TX_CREATE_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_HASH, "Invalid order hash");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    char *l_str_ret_hash = NULL;
    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_xchange_purchase(&l_tx_hash, l_datoshi_buy, l_datoshi_fee,
                                                        a_wallet_addr, &l_str_ret_hash, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        DAP_DELETE(l_str_ret_hash); // Free allocated hash string
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }

    return dap_chain_tx_compose_config_return_response_handler(l_config);
}


dap_chain_datum_tx_t* dap_chain_tx_compose_datum_xchange_purchase(dap_hash_fast_t *a_order_hash, uint256_t a_value,
                                       uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, char **a_hash_out, dap_chain_tx_compose_config_t *a_config)
    {
    dap_return_val_if_pass(!a_config || !a_order_hash || !a_wallet_addr || !a_hash_out, NULL);

    char *l_token_ticker = NULL;
    int32_t l_prev_cond_idx = 0;
    dap_chain_addr_t l_seller_addr = {0};
    dap_hash_fast_t l_hash_out = {0};
    dap_time_t l_ts_created = 0;
    dap_chain_tx_out_cond_t *l_cond_tx = dap_chain_net_srv_xchange_compose_find_last_tx(a_order_hash, &l_seller_addr, a_config, &l_ts_created, &l_token_ticker, &l_prev_cond_idx, &l_hash_out);
    if (!l_cond_tx) {
        log_it(L_ERROR, "Failed to find last xchange transaction");
        return NULL;
    }

    dap_chain_net_srv_xchange_price_t *l_price = dap_chain_net_srv_xchange_price_from_order_compose(l_cond_tx, l_ts_created, a_order_hash, &l_hash_out, l_token_ticker, &a_fee, false, a_config);
    if(!l_price){
        log_it(L_ERROR, "Failed to create price from order");
        DAP_DELETE(l_cond_tx);
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_PRICE_CREATE, "Failed to create price from order");
        return NULL;
    }

    // Create conditional transaction
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_create_exchange_compose(l_price, a_wallet_addr, a_value, a_fee, l_cond_tx, l_prev_cond_idx, a_config);
    DAP_DEL_MULTY(l_cond_tx, l_price);
    if (!l_tx) {
        log_it(L_ERROR, "failed to create exchange transaction");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE, "Failed to create exchange transaction");
        return NULL;
    }
    return l_tx;
}

dap_chain_datum_tx_t *dap_xchange_tx_create_exchange_compose(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_addr_t *a_buyer_addr, uint256_t a_datoshi_buy,
                                                          uint256_t a_datoshi_fee, dap_chain_tx_out_cond_t* a_cond_tx, uint32_t a_prev_cond_idx, dap_chain_tx_compose_config_t *a_config)
{
    dap_return_val_if_pass(!a_price || !*a_price->token_sell || !*a_price->token_buy || !a_buyer_addr || !a_cond_tx || !a_config, NULL);

    const char *l_native_ticker = a_config->native_ticker;
    const char *l_service_ticker = NULL;
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}, // how many coins to transfer
              l_value_need = a_datoshi_buy,
              l_net_fee = {},
              l_service_fee,
              l_total_fee = a_datoshi_fee,
              l_fee_transfer = {};
    dap_chain_addr_t *l_net_fee_addr = NULL, *l_service_fee_addr = NULL;
    dap_list_t *l_list_fee_out = NULL;
    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_net_fee_addr, a_config);
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
    if (!dap_chain_tx_compose_get_remote_wallet_outs_and_count(a_buyer_addr, a_price->token_buy, &l_outs, &l_outputs_count, a_config)) {
        log_it(L_ERROR, "not enough funds to transfer");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_FUNDS, "Not enough funds to transfer");
        DAP_DEL_Z(l_net_fee_addr);
        return NULL;
    }
#endif

    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_value_need,
                                                            &l_value_transfer, false);
    if (!l_list_used_out) {
        log_it(L_ERROR, "not enough funds to transfer");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_FUNDS, "Not enough funds to transfer");
        dap_json_object_free(l_outs);
        DAP_DEL_Z(l_net_fee_addr);
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
                                                                &l_fee_transfer, false);
            if (!l_list_fee_out) {
                log_it(L_ERROR, "not enough funds to pay fee");
                dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_FEE, "Not enough funds to pay fee");
                dap_json_object_free(l_outs);
                dap_list_free_full(l_list_used_out, NULL);
                DAP_DEL_Z(l_net_fee_addr);
                return NULL;
            }
        }
    }

    dap_json_object_free(l_outs);

    // Create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Can't create transaction");
        dap_list_free_full(l_list_used_out, NULL);
        dap_list_free_full(l_list_fee_out, NULL);
        // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_TX_CREATE_ERROR, "Can't create transaction");
        DAP_DEL_Z(l_net_fee_addr);
        return NULL;
    }

    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
        log_it(L_ERROR, "Can't compose the transaction input");
        dap_list_free_full(l_list_fee_out, NULL);
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_FUNDS, "Can't compose the transaction input");
        DAP_DELETE(l_net_fee_addr);
        return NULL;
    }
#endif

    if (!l_pay_with_native && !l_buy_with_native) {
        // add 'in' items to fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
            log_it(L_ERROR, "Can't compose the transaction input");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_FEE, "Can't compose the transaction input");
            DAP_DELETE(l_net_fee_addr);
            return NULL;
        }
#endif
    }

    const dap_chain_addr_t *l_seller_addr = &a_cond_tx->subtype.srv_xchange.seller_addr;
    if (1 != dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_price->tx_hash, a_prev_cond_idx, 0)) {
        log_it(L_ERROR, "Can't add conditional input");
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_COND_TX, "Can't add conditional input");
        DAP_DELETE(l_net_fee_addr);
        return NULL;
    }

    // add 'out' items
    // transfer selling coins
    uint256_t l_datoshi_sell,
              l_datoshi_buy,
              l_value_back = {};
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
                log_it(L_ERROR, "Fee is greater or equal than transfer value");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_FUNDS, "Fee is greater or equal than transfer value");
                DAP_DELETE(l_net_fee_addr);
                return NULL;
            }
#endif
            SUBTRACT_256_256(l_datoshi_sell, l_total_fee, &l_value_sell);
        }
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_buyer_addr, l_value_sell, a_price->token_sell) == -1) {
            log_it(L_ERROR, "Can't add selling coins output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE, "Can't add selling coins output");
            DAP_DELETE(l_net_fee_addr);
            return NULL;
        }
    } else {
        log_it(L_ERROR, "price rate is 0");
        // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_RATE_ERROR, "Can't add selling coins output because price rate is 0");
        DAP_DELETE(l_net_fee_addr);
        return NULL;
    }
    
    if (compare256(a_cond_tx->header.value, l_datoshi_sell) == 1) {
        SUBTRACT_256_256(a_cond_tx->header.value, l_datoshi_sell, &l_value_back);
        
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(
                    c_dap_chain_net_srv_xchange_uid, a_config->net_id, l_value_back,
                    a_config->net_id, a_price->token_buy, a_price->rate,
                    l_seller_addr, NULL, 0);
        if (!l_tx_out) {
            log_it(L_ERROR, "Can't add selling coins back conditioned output (cond cashback)");
            dap_chain_datum_tx_delete(l_tx);
            // dap_json_compose_error_add(a_config->response_handler, TX_CREATE_COMPOSE_COND_ERROR, "Can't add selling coins back conditioned output (cond cashback)");
            DAP_DELETE(l_net_fee_addr);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
    } 

    // transfer buying coins
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_seller_addr, l_datoshi_buy, a_price->token_buy) == -1) {
        log_it(L_ERROR, "Can't add buying coins output");
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE, "Can't add buying coins output");
        DAP_DELETE(l_net_fee_addr);
        return NULL;
    }
    
    // transfer validator's fee
    if (!IS_ZERO_256(a_datoshi_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_datoshi_fee) == -1) {
            log_it(L_ERROR, "Can't add validator fee output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_FEE, "Can't add validator fee output");
            DAP_DELETE(l_net_fee_addr);
            return NULL;
        }
    }

    // Add network fee
    if (l_net_fee_used && !IS_ZERO_256(l_net_fee)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker) == -1) {
            log_it(L_ERROR, "Can't add net fee output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_FEE, "Can't add net fee output");
            DAP_DELETE(l_net_fee_addr);
            return NULL;
        }
    }
    DAP_DEL_Z(l_net_fee_addr);

    // coin back
    SUBTRACT_256_256(l_value_transfer, l_value_need, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_buyer_addr, l_value_back, a_price->token_buy) == -1) {
            log_it(L_ERROR, "Can't add buying coins back output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE, "Can't add buying coins back output");
            return NULL;
        }
    }
    // fee back
    if (!l_pay_with_native && !l_buy_with_native) {
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_buyer_addr, l_value_back, l_native_ticker) == -1) {
                log_it(L_ERROR, "Can't add buying coins back output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE, "Can't add buying coins back output");
                return NULL;
            }
        }
    }

    return l_tx;
}


typedef enum dap_xchange_compose_error {
    DAP_XCHANGE_COMPOSE_ERROR_NONE = 0,
    DAP_XCHANGE_COMPOSE_ERROR_INVALID_ARGUMENT,
    DAP_XCHANGE_COMPOSE_ERROR_RATE_IS_ZERO,
    DAP_XCHANGE_COMPOSE_ERROR_FEE_IS_ZERO,
    DAP_XCHANGE_COMPOSE_ERROR_VALUE_SELL_IS_ZERO,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS,
    DAP_XCHANGE_COMPOSE_ERROR_TOKEN_TICKER_SELL_OR_BUY_IS_NOT_FOUND_LEDGER,
    DAP_XCHANGE_COMPOSE_ERROR_INTEGER_OVERFLOW_WITH_SUM_OF_VALUE_AND_FEE,
    DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_CASH_FOR_FEE_IN_SPECIFIED_WALLET,
    DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_CASH_IN_SPECIFIED_WALLET,
    DAP_XCHANGE_COMPOSE_ERROR_MEMORY_ALLOCATED,
    DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS_TO_PAY_FEE,
    DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS_TO_TRANSFER,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_COMPOSE_THE_TRANSACTION_INPUT,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_COMPOSE_THE_TRANSACTION_CONDITIONAL_OUTPUT,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_NETWORK_FEE_OUTPUT,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_VALIDATOR_FEE_OUTPUT,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_COIN_BACK_OUTPUT,
    DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_FEE_BACK_OUTPUT,
    DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE
} dap_xchange_compose_error_t;

dap_json_t *dap_chain_tx_compose_xchange_create(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                    uint16_t a_port, const char *a_enc_cert_path, const char *a_token_buy, const char *a_token_sell, dap_chain_addr_t *a_wallet_addr, const char *a_value_str, const char *a_rate_str, const char *a_fee_str){
    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "failed to create compose config");
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Can't create compose config");
        return l_json_obj_ret;
    }

    uint256_t l_value = dap_chain_balance_scan(a_value_str);
    if (IS_ZERO_256(l_value)) {
        log_it(L_ERROR, "invalid parameter value, rate or fee is 0, use required format 1.0e+18 ot in datoshi");
        dap_json_compose_error_add(l_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Invalid parameter value, rate or fee is 0, use required format 1.0e+18 ot in datoshi");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    uint256_t l_rate = dap_chain_balance_scan(a_rate_str);
    if (IS_ZERO_256(l_rate)) {
        log_it(L_ERROR, "invalid parameter rate, use required format 1.0e+18 ot in datoshi");
        dap_json_compose_error_add(l_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Invalid parameter rate");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    uint256_t l_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_fee)) {
        log_it(L_ERROR, "invalid parameter fee, use required format 1.0e+18 ot in datoshi");
        dap_json_compose_error_add(l_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_FEE, "Invalid parameter fee");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_xchange_create(a_token_buy,
                                     a_token_sell, l_value, l_rate, l_fee, a_wallet_addr, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    return dap_chain_tx_compose_config_return_response_handler(l_config);
}


dap_chain_datum_tx_t* dap_chain_tx_compose_datum_xchange_create(const char *a_token_buy,
                                     const char *a_token_sell, uint256_t a_datoshi_sell,
                                     uint256_t a_rate, uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, dap_chain_tx_compose_config_t *a_config)
{
    dap_return_val_if_pass(!a_config, NULL);
    if ( !a_token_buy || !a_token_sell || !a_wallet_addr) {
        log_it(L_ERROR, "invalid parameter");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_ARGUMENT, "Invalid parameter");
        return NULL;
    }
    if (IS_ZERO_256(a_rate)) {
        log_it(L_ERROR, "invalid parameter rate");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_RATE_IS_ZERO, "Invalid parameter rate");
        return NULL;
    }
    if (IS_ZERO_256(a_fee)) {
        log_it(L_ERROR, "invalid parameter fee");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_FEE_IS_ZERO, "Invalid parameter fee");
        return NULL;
    }
    if (IS_ZERO_256(a_datoshi_sell)) {
        log_it(L_ERROR, "invalid parameter value sell");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_VALUE_SELL_IS_ZERO, "Invalid parameter value sell");
        return NULL;
    }
    uint256_t l_net_fee = {};
    dap_chain_addr_t* l_addr_fee = NULL;
    dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);

    dap_json_t *l_json_coins = dap_request_command_to_rpc_with_params(a_config, "ledger", "list;coins;-net;%s", a_config->net_name);
    if (!l_json_coins) {
        log_it(L_ERROR, "can't get tx outs");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Can't get tx outs");
        return NULL;
    }
    if (!dap_chain_tx_compose_check_token_in_ledger(l_json_coins, a_token_sell) || !dap_chain_tx_compose_check_token_in_ledger(l_json_coins, a_token_buy)) {
        log_it(L_ERROR, "Token ticker sell or buy is not found in ledger");
        dap_json_object_free(l_json_coins);
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_TOKEN_TICKER_SELL_OR_BUY_IS_NOT_FOUND_LEDGER, "Token ticker sell or buy is not found in ledger");
        return NULL;
    }
    dap_json_object_free(l_json_coins);
    dap_json_t *l_json_outs = dap_request_command_to_rpc_with_params(a_config, "wallet", "info;-addr;%s;-net;%s", 
                                                                      dap_chain_addr_to_str(a_wallet_addr), a_config->net_name);
    uint256_t l_value = dap_chain_tx_compose_get_balance_from_json(l_json_outs, a_token_sell);
    uint256_t l_value_sell = a_datoshi_sell;
    if (!dap_strcmp(a_config->native_ticker, a_token_sell)) {
        if (SUM_256_256(l_value_sell, a_fee, &l_value_sell)) {
            log_it(L_ERROR, "integer overflow with sum of value and fee");
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INTEGER_OVERFLOW_WITH_SUM_OF_VALUE_AND_FEE, "Integer overflow with sum of value and fee");
            return NULL;
        }
    } else { // sell non-native ticker
        uint256_t l_fee_value = dap_chain_tx_compose_get_balance_from_json(l_json_outs, a_config->native_ticker);
        if (compare256(l_fee_value, a_fee) == -1) {
            log_it(L_ERROR, "not enough cash for fee in specified wallet");
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_CASH_FOR_FEE_IN_SPECIFIED_WALLET, "Not enough cash for fee in specified wallet");
            return NULL;
        }
    }
    if (compare256(l_value, l_value_sell) == -1) {
        log_it(L_ERROR, "not enough cash in specified wallet");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_NOT_ENOUGH_CASH_IN_SPECIFIED_WALLET, "Not enough cash in specified wallet");
        return NULL;
    }
    // Create the price
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    if (!l_price) {
        log_it(L_ERROR, "%s", c_error_memory_alloc);
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_MEMORY_ALLOCATED, "Memory allocated");
        return NULL;
    }
    dap_stpcpy(l_price->token_sell, a_token_sell);
    dap_stpcpy(l_price->token_buy, a_token_buy);
    l_price->datoshi_sell = a_datoshi_sell;
    l_price->rate = a_rate;
    l_price->fee = a_fee;
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_create_request_compose(l_price, a_wallet_addr, a_config->native_ticker, a_config);
    DAP_DELETE(l_price);
    return l_tx;
}


dap_chain_datum_tx_t *dap_xchange_tx_create_request_compose(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_addr_t *a_seller_addr,
                                                                 const char *a_native_ticker, dap_chain_tx_compose_config_t *a_config)
{
    dap_return_val_if_pass(!a_config, NULL);
    if (!a_price || !*a_price->token_sell || !*a_price->token_buy || !a_seller_addr) {
        log_it(L_ERROR, "invalid parameter");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_INVALID_ARGUMENT, "Invalid parameter");
        return NULL;
    }
    const char *l_native_ticker = a_config->native_ticker;
    bool l_single_channel = !dap_strcmp(a_price->token_sell, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_value_need = a_price->datoshi_sell,
              l_net_fee = {},
              l_total_fee = a_price->fee,
              l_fee_transfer;
    dap_chain_addr_t *l_addr_net_fee = NULL;
    dap_list_t *l_list_fee_out = NULL;

    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_addr_net_fee, a_config);
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST    
    dap_json_t *l_outs_native = dap_chain_tx_compose_get_remote_tx_outs(a_native_ticker, a_seller_addr, a_config);
    if (!l_outs_native) {
        log_it(L_ERROR, "can't get tx outs");
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Can't get tx outs");
        return NULL;
    }

    dap_json_t *l_outs = NULL;
    if (!dap_strcmp(a_price->token_sell, a_native_ticker)) {
        l_outs = l_outs_native;
    } else {
        l_outs = dap_chain_tx_compose_get_remote_tx_outs(a_price->token_sell, a_seller_addr, a_config);
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
                                                               &l_fee_transfer, false);
        if (!l_list_fee_out) {
            log_it(L_ERROR, "not enough funds to pay fee");
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
                                                            &l_value_transfer, false);
    
    if (dap_strcmp(a_price->token_sell, a_native_ticker))
        dap_json_object_free(l_outs);
    dap_json_object_free(l_outs_native);
    if (!l_list_used_out) {
        log_it(L_ERROR, "not enough funds to transfer");
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
        log_it(L_ERROR, "Can't compose the transaction input");
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_COMPOSE_THE_TRANSACTION_INPUT, "Can't compose the transaction input");
        return NULL;
    }
#endif
    if (!l_single_channel) {
        // add 'in' items to fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer) != 0) {
            log_it(L_ERROR, "Can't compose the transaction input");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_COMPOSE_THE_TRANSACTION_INPUT, "Can't compose the transaction input");
            DAP_DEL_Z(l_addr_net_fee);
            return NULL;
        }
    }

    // add 'out_cond' & 'out' items

    {
        dap_chain_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(l_uid, a_config->net_id, a_price->datoshi_sell,
                                                                                                a_config->net_id, a_price->token_buy, a_price->rate,
                                                                                                a_seller_addr, NULL, 0);
        if (!l_tx_out) {
            log_it(L_ERROR, "Can't compose the transaction conditional output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_COMPOSE_THE_TRANSACTION_CONDITIONAL_OUTPUT, "Can't compose the transaction conditional output");
            DAP_DELETE(l_addr_net_fee);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_net_fee, l_net_fee, l_native_ticker) != 1) {
                log_it(L_ERROR, "Can't add network fee output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_NETWORK_FEE_OUTPUT, "Can't add network fee output");
                DAP_DELETE(l_addr_net_fee);
                return NULL;
            }
        }
        DAP_DELETE(l_addr_net_fee);
        // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_price->fee) != 1) {
                log_it(L_ERROR, "Can't add validator's fee output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_VALIDATOR_FEE_OUTPUT, "Can't add validator's fee output");
                return NULL;
            }
        }
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_transfer, l_value_need, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, l_value_back, a_price->token_sell) != 1) {
                log_it(L_ERROR, "Can't add coin back output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_COIN_BACK_OUTPUT, "Can't add coin back output");
                return NULL;
            }
        }
        // Fee coinback
        if (!l_single_channel) {
            uint256_t l_fee_coinback = {};
            SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_fee_coinback);
            if (!IS_ZERO_256(l_fee_coinback)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_seller_addr, l_fee_coinback, l_native_ticker) != 1) {
                    log_it(L_ERROR, "Can't add fee back output");
                    dap_chain_datum_tx_delete(l_tx);
                    dap_json_compose_error_add(a_config->response_handler, DAP_XCHANGE_COMPOSE_ERROR_CAN_NOT_ADD_FEE_BACK_OUTPUT, "Can't add fee back output");
                    return NULL;
                }
            }
        }
    }
    return l_tx;
}
