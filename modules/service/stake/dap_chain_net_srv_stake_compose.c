/**
 * @file dap_chain_net_srv_stake_compose.c
 * @brief Stake service transaction compose functions
 * 
 * These functions were moved from modules/compose/ to eliminate circular dependencies.
 * Stake service now provides its own compose logic.
 */

#include "dap_common.h"
#include "dap_chain_net_srv_stake.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_net_srv_order.h"
#include "dap_enc_base64.h"
#include "dap_chain_net_srv_stake_compose.h"
#include "dap_chain_tx_compose.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_ledger.h"
#include "dap_json_rpc_errors.h"
#include "dap_json_rpc.h"
#include "dap_rand.h"

#define LOG_TAG "stake_compose"

// Stake compose functions will be added here

typedef enum {
    STAKE_LOCK_DATUM_CREATE_ERROR_NOT_ENOUGH_FUNDS_TO_PAY_FEE = -1,
    STAKE_LOCK_DATUM_CREATE_ERROR_NOT_ENOUGH_FUNDS_TO_TRANSFER = -2,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_CONDITIONAL_OUTPUT = -3,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_NETWORK_FEE_OUTPUT = -4,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_VALIDATOR_FEE_OUTPUT = -5,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_COIN_BACK_OUTPUT_FOR_MAIN_TICKER = -6,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_COIN_BACK_OUTPUT_FOR_NATIVE_TICKER = -7,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_DELEGATED_TOKEN_EMISSION_OUTPUT = -8,
    STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_SIGN_OUTPUT = -9
} stake_lock_datum_create_error_t;

dap_chain_datum_tx_t *dap_chain_tx_compose_datum_stake_lock_hold(dap_chain_addr_t *a_wallet_addr,
                                                    const char *a_main_ticker,
                                                    uint256_t a_value, uint256_t a_value_fee,
                                                    dap_time_t a_time_unlock, uint256_t a_reinvest_percent,
                                                    const char *a_delegated_ticker_str, uint256_t a_delegated_value,
                                                    dap_chain_id_t a_chain_id, dap_chain_tx_compose_config_t *a_config)
{
    dap_chain_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID };
    // check valid param
    dap_return_val_if_pass(!a_config->net_name || !a_wallet_addr || IS_ZERO_256(a_value), NULL);
    log_it_fl(L_DEBUG, "parameters validation passed");
    
    const char *l_native_ticker = a_config->native_ticker;
    bool l_main_native = !dap_strcmp(a_main_ticker, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_value_need = a_value, l_net_fee = {}, l_total_fee = {}, l_fee_transfer = {};
    dap_chain_addr_t *l_addr_fee = NULL;
    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address( &l_net_fee, &l_addr_fee, a_config);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    dap_list_t *l_list_fee_out = NULL;
    dap_json_t *l_outs_native = NULL;
    dap_json_t *l_outs_main = NULL;
    int l_out_main_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    l_outs_native = dap_chain_tx_compose_get_remote_tx_outs(l_native_ticker, a_wallet_addr, a_config);
    if (!l_outs_native) {
        log_it(L_ERROR, "Can't get remote tx outs");
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }
    if (!dap_strcmp(a_main_ticker, l_native_ticker)) {
        l_outs_main = l_outs_native;
    } else {
        l_outs_main = dap_chain_tx_compose_get_remote_tx_outs(a_main_ticker, a_wallet_addr, a_config);
    }
    int l_out_native_count = dap_json_array_length(l_outs_native);
    l_out_main_count = dap_json_array_length(l_outs_main);

    if (l_main_native)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else if (!IS_ZERO_256(l_total_fee)) {
        l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                               l_total_fee, 
                                                               &l_fee_transfer, false);
        if (!l_list_fee_out) {
            log_it(L_ERROR, "not enough funds to pay fee");
            dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_NOT_ENOUGH_FUNDS_TO_PAY_FEE, "Not enough funds to pay fee");
            dap_json_object_free(l_outs_native);
            dap_json_object_free(l_outs_main);
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
    }
#endif
    // list of transaction with 'out' items
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs_main, l_out_main_count,
                                                            l_value_need,
                                                            &l_value_transfer, false);
    if (!l_list_used_out) {
        log_it(L_ERROR, "not enough funds to transfer");
        dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_NOT_ENOUGH_FUNDS_TO_TRANSFER, "Not enough funds to transfer");
        dap_json_object_free(l_outs_native);
        dap_json_object_free(l_outs_main);
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in' items
    {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
#endif
        dap_list_free_full(l_list_used_out, NULL);
        if (l_list_fee_out) {
            uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
            assert(EQUAL_256(l_value_fee_items, l_fee_transfer));
            dap_list_free_full(l_list_fee_out, NULL);
        }
    }

    // add 'in_ems' item
    {
        dap_hash_fast_t l_blank_hash = {};
        dap_chain_tx_in_ems_t *l_in_ems = dap_chain_datum_tx_item_in_ems_create(a_chain_id, &l_blank_hash, a_delegated_ticker_str);
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in_ems);
        DAP_DEL_Z(l_in_ems);
    }

    // add 'out_cond' and 'out_ext' items
    {
        uint256_t l_value_pack = {}, l_native_pack = {}; // how much coin add to 'out_ext' items
        dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_stake_lock(
                                                        l_uid, a_value, a_time_unlock, a_reinvest_percent);
        if (l_tx_out_cond) {
            SUM_256_256(l_value_pack, a_value, &l_value_pack);
            dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out_cond);
            DAP_DEL_Z(l_tx_out_cond);
        } else {
            log_it(L_ERROR, "Can't add conditional output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_CONDITIONAL_OUTPUT, "Cant add conditional output\n");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }

        uint256_t l_value_back = {};
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) != 1) {
                log_it(L_ERROR, "Can't add network fee output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_NETWORK_FEE_OUTPUT, "Cant add network fee output\n");
                DAP_DELETE(l_addr_fee);
                return NULL;
            }
            if (l_main_native)
                SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
            else
                SUM_256_256(l_native_pack, l_net_fee, &l_native_pack);
        }
        DAP_DEL_Z(l_addr_fee);
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
                log_it(L_ERROR, "Can't add validator's fee output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_VALIDATOR_FEE_OUTPUT, "Cant add validator's fee output\n");
                return NULL;
            }
            if (l_main_native)
                SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
            else
                SUM_256_256(l_native_pack, a_value_fee, &l_native_pack);
        }
        // coin back
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, a_main_ticker) != 1) {
                log_it(L_ERROR, "Can't add coin back output for main ticker");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_COIN_BACK_OUTPUT_FOR_MAIN_TICKER, "Cant add coin back output for main ticker\n");
                return NULL;
            }
        }
        // fee coin back
        if (!IS_ZERO_256(l_fee_transfer)) {
            SUBTRACT_256_256(l_fee_transfer, l_native_pack, &l_value_back);
            if (!IS_ZERO_256(l_value_back)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, l_native_ticker) != 1) {
                    log_it(L_ERROR, "Can't add coin back output for native ticker");
                    dap_chain_datum_tx_delete(l_tx);
                    dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_COIN_BACK_OUTPUT_FOR_NATIVE_TICKER, "Cant add coin back output for native ticker\n");
                    return NULL;
                }
            }
        }
    }

    // add delegated token emission 'out_ext'
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, a_delegated_value, a_delegated_ticker_str) != 1) {
        log_it(L_ERROR, "Can't add delegated token emission output");
        dap_chain_datum_tx_delete(l_tx);
        dap_json_compose_error_add(a_config->response_handler, STAKE_LOCK_DATUM_CREATE_ERROR_CANT_ADD_DELEGATED_TOKEN_EMISSION_OUTPUT, "Cant add delegated token emission output\n");
        DAP_DELETE(l_addr_fee);
        return NULL;
    }

    DAP_DELETE(l_addr_fee);
    return l_tx;
}


typedef enum {
    CLI_TAKE_COMPOSE_OK = 0,
    CLI_TAKE_COMPOSE_ERROR_UNABLE_TO_INIT_CONFIG = -1,
    CLI_TAKE_COMPOSE_ERROR_INVALID_TRANSACTION_HASH = -2,
    CLI_TAKE_COMPOSE_ERROR_FAILED_TO_GET_RESPONSE = -3,
    CLI_TAKE_COMPOSE_ERROR_NO_ITEMS_FOUND = -4,
    CLI_TAKE_COMPOSE_ERROR_NO_TX_OUT_CONDITION = -5,
    CLI_TAKE_COMPOSE_ERROR_TX_OUT_ALREADY_USED = -6,
    CLI_TAKE_COMPOSE_ERROR_FAILED_GET_ITEMS_ARRAY = -7,
    CLI_TAKE_COMPOSE_ERROR_TOKEN_TICKER_NOT_FOUND = -8,
    CLI_TAKE_COMPOSE_ERROR_INVALID_COINS_FORMAT = -9,
    CLI_TAKE_COMPOSE_ERROR_INVALID_FEE_FORMAT = -10,
    CLI_TAKE_COMPOSE_ERROR_UNABLE_TO_OPEN_WALLET = -11,
    CLI_TAKE_COMPOSE_ERROR_OWNER_KEY_NOT_FOUND = -12,
    CLI_TAKE_COMPOSE_ERROR_NOT_ENOUGH_TIME_PASSED = -13,
    CLI_TAKE_COMPOSE_ERROR_FAILED_TO_CREATE_TX = -14,
    CLI_TAKE_COMPOSE_ERROR_NO_INFO_TX_OUT_USED = -15,
    CLI_TAKE_COMPOSE_ERROR_TX_OUT_NOT_USED = -16,
} cli_take_compose_error_t;

dap_json_t *dap_chain_tx_compose_stake_lock_take(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                    uint16_t a_port, const char *a_enc_cert_path, dap_chain_addr_t *a_wallet_addr, const char *a_tx_str,
                                    const char *a_value_fee_str){

    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Unable to init config");
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, CLI_TAKE_COMPOSE_ERROR_UNABLE_TO_INIT_CONFIG, "Unable to init config\n");
        return l_json_obj_ret;
    }

    char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
    int									l_prev_cond_idx		=	0;
    uint256_t							l_value_delegated	= 	{};
    uint256_t                           l_value_fee     	=	{};
    dap_hash_fast_t						l_tx_hash;
    dap_chain_datum_tx_t                *l_tx = NULL;
    dap_chain_tx_out_cond_t				*l_cond_tx = NULL;
    dap_enc_key_t						*l_owner_key;
    char *l_ticker_str = NULL;
    if (dap_chain_hash_fast_from_str(a_tx_str, &l_tx_hash)) {
        log_it(L_ERROR, "invalid transaction hash");
        dap_json_compose_error_add(l_config->response_handler, CLI_TAKE_COMPOSE_ERROR_INVALID_TRANSACTION_HASH, "Invalid transaction hash\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    l_tx = dap_chain_tx_compose_get_datum_from_rpc(a_tx_str, l_config, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, &l_cond_tx, NULL, &l_ticker_str, NULL, true);
    if (!l_cond_tx) {
        log_it(L_ERROR, "Failed to get datum info from rpc");
        DAP_DELETE(l_ticker_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_ticker_str);
    uint256_t l_emission_rate = dap_chain_balance_coins_scan("0.001");

    if (IS_ZERO_256(l_emission_rate) ||
        MULT_256_COIN(l_cond_tx->header.value, l_emission_rate, &l_value_delegated) ||
        IS_ZERO_256(l_value_delegated)) {
        log_it(L_ERROR, "invalid coins format");
        dap_json_compose_error_add(l_config->response_handler, CLI_TAKE_COMPOSE_ERROR_INVALID_COINS_FORMAT, "Invalid coins format\n");
        DAP_DEL_MULTY(l_ticker_str, l_cond_tx);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    if (IS_ZERO_256((l_value_fee = dap_chain_balance_scan(a_value_fee_str)))) {
        log_it(L_ERROR, "invalid fee format");
        dap_json_compose_error_add(l_config->response_handler, CLI_TAKE_COMPOSE_ERROR_INVALID_FEE_FORMAT, "Invalid fee format\n");
        DAP_DEL_MULTY(l_ticker_str, l_cond_tx);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    if (l_cond_tx->subtype.srv_stake_lock.time_unlock > dap_time_now()) {
        log_it(L_ERROR, "not enough time has passed for unlocking");
        dap_json_compose_error_add(l_config->response_handler, CLI_TAKE_COMPOSE_ERROR_NOT_ENOUGH_TIME_PASSED, "Not enough time has passed for unlocking\n");
        DAP_DEL_MULTY(l_ticker_str, l_cond_tx);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    dap_chain_datum_tx_delete(l_tx);
    l_tx = dap_chain_tx_compose_datum_stake_lock_take(a_wallet_addr, &l_tx_hash, l_prev_cond_idx,
                                          l_ticker_str, l_cond_tx->header.value, l_value_fee,
                                          l_delegated_ticker_str, l_value_delegated, l_config);

    DAP_DEL_MULTY(l_ticker_str, l_cond_tx);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }

    return dap_chain_tx_compose_config_return_response_handler(l_config);
}


typedef enum {
    TX_STAKE_LOCK_TAKE_COMPOSE_OK = 0,
    TX_STAKE_LOCK_TAKE_COMPOSE_INVALID_PARAMS = -1,
    TX_STAKE_LOCK_TAKE_COMPOSE_NOT_ENOUGH_FUNDS = -2,
    TX_STAKE_LOCK_TAKE_COMPOSE_TOTAL_FEE_MORE_THAN_STAKE = -3,
    TX_STAKE_LOCK_TAKE_COMPOSE_CANT_ADD_NETWORK_FEE_OUTPUT = -4,
    TX_STAKE_LOCK_TAKE_COMPOSE_CANT_ADD_VALIDATOR_FEE_OUTPUT = -5,
    TX_STAKE_LOCK_TAKE_COMPOSE_CANT_SUBTRACT_VALUE_PACK = -6,
    TX_STAKE_LOCK_TAKE_COMPOSE_CANT_ADD_COIN_BACK_MAIN = -7,
    TX_STAKE_LOCK_TAKE_COMPOSE_CANT_ADD_COIN_BACK_NATIVE = -8,
    TX_STAKE_LOCK_TAKE_COMPOSE_CANT_ADD_BURNING_OUTPUT = -9,
    TX_STAKE_LOCK_TAKE_COMPOSE_CANT_ADD_COIN_BACK_DELEGATED = -10
} tx_stake_lock_take_compose_error_t;

dap_chain_datum_tx_t *dap_chain_tx_compose_datum_stake_lock_take(dap_chain_addr_t *a_wallet_addr,
                                               dap_hash_fast_t *a_stake_tx_hash, uint32_t a_prev_cond_idx,
                                               const char *a_main_ticker, uint256_t a_value,
                                               uint256_t a_value_fee,
                                               const char *a_delegated_ticker_str, uint256_t a_delegated_value,
                                               dap_chain_tx_compose_config_t *a_config)
{
    // check valid param
    if (!a_config || !a_wallet_addr || dap_hash_fast_is_blank(a_stake_tx_hash)) {
        log_it(L_ERROR, "invalid parameters");
        dap_json_compose_error_add(a_config->response_handler, TX_STAKE_LOCK_TAKE_COMPOSE_INVALID_PARAMS, "Invalid parameters\n");
        return NULL;
    }

    const char *l_native_ticker = a_config->native_ticker;
    bool l_main_native = !dap_strcmp(a_main_ticker, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_net_fee = {}, l_total_fee = {}, l_fee_transfer = {};
    dap_chain_addr_t *l_addr_fee = NULL;

    dap_list_t *l_list_fee_out = NULL, *l_list_used_out = NULL;

    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);

#ifndef DAP_CHAIN_TX_COMPOSE_TEST    
    dap_json_t *l_outs_native = dap_chain_tx_compose_get_remote_tx_outs(l_native_ticker, a_wallet_addr, a_config);
    if (!l_outs_native) {
        log_it(L_ERROR, "Can't get remote tx outs");
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }

    dap_json_t *l_outs_delegated = dap_chain_tx_compose_get_remote_tx_outs(a_delegated_ticker_str, a_wallet_addr, a_config);
    if (!l_outs_delegated) {
        log_it(L_ERROR, "Can't get remote tx outs");
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }
    int l_out_native_count = dap_json_array_length(l_outs_native);
    int l_out_delegated_count = dap_json_array_length(l_outs_delegated);
#else
    dap_json_t *l_outs_native = NULL;
    dap_json_t *l_outs_delegated = NULL;
    int l_out_native_count = 0;
    int l_out_delegated_count = 0;
#endif

    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    if (!IS_ZERO_256(l_total_fee)) {
        if (!l_main_native) {
            l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                                l_total_fee, 
                                                                &l_fee_transfer, false);
            if (!l_list_fee_out) {
                log_it(L_ERROR, "not enough funds to pay fee");
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_LOCK_TAKE_COMPOSE_NOT_ENOUGH_FUNDS, "Not enough funds to pay fee");
                dap_json_object_free(l_outs_native);
                dap_json_object_free(l_outs_delegated);
                DAP_DELETE(l_addr_fee);
                return NULL;
            }
        }
#ifndef DAP_CHAIN_TX_COMPOSE_TEST  
        else if (compare256(a_value, l_total_fee) == -1) {
            log_it(L_ERROR, "total fee more than stake");
            dap_json_compose_error_add(a_config->response_handler, TX_STAKE_LOCK_TAKE_COMPOSE_TOTAL_FEE_MORE_THAN_STAKE, "Total fee more than stake\n");
            dap_json_object_free(l_outs_native);
            dap_json_object_free(l_outs_delegated);
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
#endif
    }
    if (!IS_ZERO_256(a_delegated_value)) {
        l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs_delegated, l_out_delegated_count,
                                                               a_delegated_value, 
                                                               &l_value_transfer, false);
        if (!l_list_used_out) {
            log_it(L_ERROR, "not enough funds to pay fee");
            dap_json_compose_error_add(a_config->response_handler, TX_STAKE_LOCK_TAKE_COMPOSE_NOT_ENOUGH_FUNDS, "Not enough funds to pay fee");
            dap_json_object_free(l_outs_native);
            dap_json_object_free(l_outs_delegated);
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in_cond' & 'in' items
    {
        dap_chain_datum_tx_add_in_cond_item(&l_tx, a_stake_tx_hash, a_prev_cond_idx, 0);
        if (l_list_used_out) {
            uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST  
            assert(EQUAL_256(l_value_to_items, l_value_transfer));
#endif
            dap_list_free_full(l_list_used_out, NULL);
        }
        if (l_list_fee_out) {
            uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
            assert(EQUAL_256(l_value_fee_items, l_fee_transfer));
            dap_list_free_full(l_list_fee_out, NULL);
        }
    }

    // add 'out_ext' items
    uint256_t l_value_back;
    {
        uint256_t l_value_pack = {}; // how much datoshi add to 'out' items
        // Network fee
        if(l_net_fee_used){
            if (!dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker)){
                log_it(L_ERROR, "Can't add network fee output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_LOCK_TAKE_COMPOSE_CANT_ADD_NETWORK_FEE_OUTPUT, "Can't add network fee output\n");
                DAP_DELETE(l_addr_fee);
                return NULL;
            }
            SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
        }
        DAP_DEL_Z(l_addr_fee);
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) == 1)
            {
                SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
            } else {
                log_it(L_ERROR, "Can't add validator's fee output");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_LOCK_TAKE_COMPOSE_CANT_ADD_VALIDATOR_FEE_OUTPUT, "Can't add validator's fee output\n");
                return NULL;
            }
        }
        // coin back
        //SUBTRACT_256_256(l_fee_transfer, l_value_pack, &l_value_back);
        if(l_main_native){
             if (SUBTRACT_256_256(a_value, l_value_pack, &l_value_back)) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_LOCK_TAKE_COMPOSE_CANT_SUBTRACT_VALUE_PACK, "Can't subtract value pack from value\n");
                return NULL;
            }
            if(!IS_ZERO_256(l_value_back)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, a_main_ticker)!=1) {
                    log_it(L_ERROR, "Can't add coin back output for main ticker");
                    dap_chain_datum_tx_delete(l_tx);
                    dap_json_compose_error_add(a_config->response_handler, TX_STAKE_LOCK_TAKE_COMPOSE_CANT_ADD_COIN_BACK_MAIN, "Can't add coin back output for main ticker\n");
                    return NULL;
                }
            }
        } else {
            SUBTRACT_256_256(l_fee_transfer, l_value_pack, &l_value_back);
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, a_value, a_main_ticker)!=1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_LOCK_TAKE_COMPOSE_CANT_ADD_COIN_BACK_MAIN, "Can't add coin back output for main ticker\n");
                return NULL;
            } else {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, l_native_ticker)!=1) {
                    log_it(L_ERROR, "Can't add coin back output for native ticker");
                    dap_chain_datum_tx_delete(l_tx);
                    dap_json_compose_error_add(a_config->response_handler, TX_STAKE_LOCK_TAKE_COMPOSE_CANT_ADD_COIN_BACK_NATIVE, "Can't add coin back output for native ticker\n");
                    return NULL;
                }
            }
        }
    }

    // add burning 'out_ext'
    if (!IS_ZERO_256(a_delegated_value)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &c_dap_chain_addr_blank,
                                               a_delegated_value, a_delegated_ticker_str) != 1) {
            log_it(L_ERROR, "Can't add burning output for delegated value");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, TX_STAKE_LOCK_TAKE_COMPOSE_CANT_ADD_BURNING_OUTPUT, "Can't add burning output for delegated value\n");
            return NULL;
        }
        // delegated token coin back
        SUBTRACT_256_256(l_value_transfer, a_delegated_value, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, a_delegated_ticker_str) != 1) {
                log_it(L_ERROR, "Can't add coin back output for delegated ticker");
                dap_chain_datum_tx_delete(l_tx);
                dap_json_compose_error_add(a_config->response_handler, TX_STAKE_LOCK_TAKE_COMPOSE_CANT_ADD_COIN_BACK_DELEGATED, "Can't add coin back output for delegated ticker\n");
                return NULL;
            }
        }
    }
    DAP_DELETE(l_addr_fee);
    return l_tx;
}

typedef enum {
    GET_KEY_DELEGATING_MIN_VALUE_OK = 0,
    GET_KEY_DELEGATING_MIN_VALUE_FAILED_TO_GET_RESPONSE = -1,
    GET_KEY_DELEGATING_MIN_VALUE_INVALID_RESPONSE_FORMAT = -2,
    GET_KEY_DELEGATING_MIN_VALUE_SUMMARY_NOT_FOUND = -3,
    GET_KEY_DELEGATING_MIN_VALUE_MIN_VALUE_NOT_FOUND = -4,
    GET_KEY_DELEGATING_MIN_VALUE_INVALID_VALUE_FORMAT = -5,
    GET_KEY_DELEGATING_MIN_VALUE_UNRECOGNIZED_NUMBER = -6
} get_key_delegating_min_value_error_t;

uint256_t s_get_key_delegating_min_value(dap_chain_tx_compose_config_t *a_config){

    log_it_fl(L_DEBUG, "getting key delegating min value for net %s", a_config->net_name);
    
    uint256_t l_key_delegating_min_value = uint256_0;
    dap_json_t *response = dap_request_command_to_rpc_with_params(a_config, "srv_stake", "list;keys;-net;%s", a_config->net_name);
    if (!response) {
        log_it(L_ERROR, "failed to get response from remote node");
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_FAILED_TO_GET_RESPONSE, "Failed to get response from remote node\n");
        return l_key_delegating_min_value;
    }

    dap_json_t *response_array = dap_json_array_get_idx(response, 0);
    if (!response_array) {
        log_it(L_ERROR, "invalid response format");
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_INVALID_RESPONSE_FORMAT, "Invalid response format\n");
        return l_key_delegating_min_value;
    }

    dap_json_t *summary_obj = dap_json_array_get_idx(response_array, dap_json_array_length(response_array) - 1);
    if (!summary_obj) {
        log_it(L_ERROR, "summary object not found in response");
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_SUMMARY_NOT_FOUND, "Summary object not found in response\n");
        return l_key_delegating_min_value;
    }

    const char *key_delegating_min_value_str = dap_json_object_get_string(summary_obj, "key_delegating_min_value");
    if (!key_delegating_min_value_str) {
        log_it(L_ERROR, "invalid key_delegating_min_value format");
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_INVALID_VALUE_FORMAT, "Invalid key_delegating_min_value format\n");
        return l_key_delegating_min_value;
    }

    l_key_delegating_min_value = dap_chain_balance_scan(key_delegating_min_value_str);
    if (IS_ZERO_256(l_key_delegating_min_value)) {
        log_it(L_ERROR, "unrecognized number in key_delegating_min_value");
        dap_json_compose_error_add(a_config->response_handler, GET_KEY_DELEGATING_MIN_VALUE_UNRECOGNIZED_NUMBER, "Unrecognized number in key_delegating_min_value\n");
        return l_key_delegating_min_value;
    }
    return l_key_delegating_min_value;
}

typedef enum {
    DAP_STAKE_TX_INVALIDATE_OK = 0,
    DAP_STAKE_TX_INVALIDATE_CERT_NOT_FOUND = -1,
    DAP_STAKE_TX_INVALIDATE_PRIVATE_KEY_MISSING = -2,
    DAP_STAKE_TX_INVALIDATE_WRONG_CERT = -3,
    DAP_STAKE_TX_INVALIDATE_LEDGER_ERROR = -4,
    DAP_STAKE_TX_INVALIDATE_INVALID_TX_HASH = -5,
    DAP_STAKE_TX_INVALIDATE_NOT_DELEGATED = -6,
    DAP_STAKE_TX_INVALIDATE_NO_DELEGATE_OUT = -7,
    DAP_STAKE_TX_INVALIDATE_PREV_TX_NOT_FOUND = -8,
    DAP_STAKE_TX_INVALIDATE_KEY_DELEGATED = -9,
    DAP_STAKE_TX_INVALIDATE_WALLET_NOT_FOUND = -10,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_ERROR = -11,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_LEDGER_ERROR = -12,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_ITEMS_NOT_FOUND = -13,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_OUTPUTS_SPENT = -14,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_HASH_NOT_FOUND = -15,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_COND_TX_ERROR = -16,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_COND_TX_NOT_FOUND = -17,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_SIG_NOT_FOUND = -18,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_SIG_DECODE_ERROR = -19,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_WRONG_OWNER = -20,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_TOKEN_NOT_FOUND = -21,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_OUTS_NOT_FOUND = -22,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_NOT_ENOUGH_FUNDS = -23,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_IN_ERROR = -24,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_OUT_ERROR = -25,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_NET_FEE_ERROR = -26,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_FEE_ERROR = -27,
    DAP_STAKE_TX_INVALIDATE_COMPOSE_FEE_BACK_ERROR = -28,
    DAP_STAKE_TX_INVALIDATE_FEE_ERROR = -29
} dap_cli_stake_invalidate_error_t;


dap_json_t *dap_chain_tx_compose_srv_stake_invalidate(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                  uint16_t a_port, const char *a_enc_cert_path, const char *a_tx_hash_str, dap_chain_addr_t *a_wallet_addr, 
                                                  const char *a_cert_str, const char *a_fee_str)
{
    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    dap_hash_fast_t l_tx_hash = {};

    uint256_t l_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_fee)) {
        log_it(L_ERROR, "unrecognized number in '-fee' param");
        dap_json_compose_error_add(l_config->response_handler, DAP_STAKE_TX_INVALIDATE_FEE_ERROR, "Unrecognized number in '-fee' param");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    if (a_tx_hash_str) {
        dap_chain_hash_fast_from_str(a_tx_hash_str, &l_tx_hash);
    } else {
        dap_chain_addr_t l_signing_addr;
        if (a_cert_str) {
            dap_cert_t *l_cert = dap_cert_find_by_name(a_cert_str);
            if (!l_cert) {
                log_it(L_ERROR, "specified certificate not found");
                dap_json_compose_error_add(l_config->response_handler, DAP_STAKE_TX_INVALIDATE_CERT_NOT_FOUND, "Specified certificate not found");
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
            if (!l_cert->enc_key->priv_key_data || l_cert->enc_key->priv_key_data_size == 0) {
                log_it(L_ERROR, "private key missing in certificate");
                dap_json_compose_error_add(l_config->response_handler, DAP_STAKE_TX_INVALIDATE_PRIVATE_KEY_MISSING, "Private key missing in certificate");
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
            if (dap_chain_addr_fill_from_key(&l_signing_addr, l_cert->enc_key, l_config->net_id)) {
                log_it(L_ERROR, "wrong certificate");
                dap_json_compose_error_add(l_config->response_handler, DAP_STAKE_TX_INVALIDATE_WRONG_CERT, "Wrong certificate");
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
        }
        const char *l_addr_str = dap_chain_addr_to_str_static(&l_signing_addr);

        dap_json_t *l_json_coins = dap_request_command_to_rpc_with_params(l_config, "srv_stake", "list;keys;-net;%s", l_config->net_name);
        if (!l_json_coins) {
            log_it(L_ERROR, "Failed to get coins list");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        
        int items_count = dap_json_array_length(l_json_coins);
        bool found = false;
        for (int i = 0; i < items_count; i++) {
            dap_json_t *item = dap_json_array_get_idx(l_json_coins, i);
            const char *node_addr_str = dap_json_object_get_string(item, "node_addr");
            if (node_addr_str && !dap_strcmp(l_addr_str, node_addr_str)) {
                const char *tx_hash_str = dap_json_object_get_string(item, "tx_hash");
                if (dap_chain_hash_fast_from_str(tx_hash_str, &l_tx_hash)) {
                    log_it(L_ERROR, "Invalid transaction hash format");
                    dap_json_object_free(l_json_coins);
                    dap_json_compose_error_add(l_config->response_handler, DAP_STAKE_TX_INVALIDATE_INVALID_TX_HASH, "Invalid transaction hash format");
                    return dap_chain_tx_compose_config_return_response_handler(l_config);
                }
                found = true;
                break;
            }
        }
        dap_json_object_free(l_json_coins);
        if (!found) {
            log_it(L_ERROR, "specified certificate/pkey hash is not delegated");
            dap_json_compose_error_add(l_config->response_handler, DAP_STAKE_TX_INVALIDATE_NOT_DELEGATED, "Specified certificate/pkey hash is not delegated");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
    }

    if (a_tx_hash_str) {
        const char *l_tx_hash_str_tmp = a_tx_hash_str ? a_tx_hash_str : dap_hash_fast_to_str_static(&l_tx_hash);
        dap_json_t *l_json_answer = dap_request_command_to_rpc_with_params(l_config, "srv_stake", "list;keys;-net;%s", l_config->net_name);
        if (!l_json_answer) {
            log_it(L_ERROR, "Failed to get rpc answer");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        dap_json_t *l_json_coins = dap_json_array_get_idx(l_json_answer, 0);
        if (!l_json_coins) {
            log_it(L_ERROR, "Failed to get keys list");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }

        bool tx_exists = false;
        int tx_count = dap_json_array_length(l_json_coins);
        for (int i = 0; i < tx_count; i++) {
            dap_json_t *tx_item = dap_json_array_get_idx(l_json_coins, i);
            const char *tx_hash = dap_json_object_get_string(tx_item, "tx_hash");
            if (tx_hash && strcmp(tx_hash, l_tx_hash_str_tmp) == 0) {
                const char *l_pkey_hash_str = dap_json_object_get_string(tx_item, "pkey_hash");
                log_it(L_ERROR, "Transaction %s has active delegated key %s, need to revoke it first", tx_hash, l_pkey_hash_str);
                dap_json_object_free(l_json_answer);
                dap_json_compose_error_add(l_config->response_handler, DAP_STAKE_TX_INVALIDATE_KEY_DELEGATED, "Transaction %s has active delegated key %s, need to revoke it first", tx_hash, l_pkey_hash_str);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
        }
        dap_json_object_free(l_json_answer);
    }


    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_srv_stake_invalidate(&l_tx_hash, l_fee, a_wallet_addr, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }

    return dap_chain_tx_compose_config_return_response_handler(l_config);
}

dap_chain_datum_tx_t *dap_chain_tx_compose_datum_srv_stake_invalidate(dap_hash_fast_t *a_tx_hash, uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, dap_chain_tx_compose_config_t *a_config)
{
#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    if(!a_config || !a_config->net_name || !*a_config->net_name || !a_tx_hash || !a_wallet_addr || !a_config->url_str || !*a_config->url_str || a_config->port == 0)
        return NULL;

    dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
    char *l_spent_by_hash = NULL;
    char *l_token_ticker = NULL;
    int l_tx_out_cond_idx = -1;
    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_get_datum_from_rpc(dap_hash_fast_to_str_static(a_tx_hash), a_config, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_tx_out_cond, &l_spent_by_hash, &l_token_ticker, &l_tx_out_cond_idx, true);
    if (!l_tx_out_cond || l_tx_out_cond_idx == -1) {
        log_it(L_ERROR, "Can't find tx out cond item");
        DAP_DEL_MULTY(l_token_ticker, l_spent_by_hash);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_ITEMS_NOT_FOUND, "Transaction outputs not found");
        return NULL;
    }
    dap_chain_addr_t l_owner_addr = {};
    dap_chain_addr_fill_from_sign(&l_owner_addr, dap_chain_datum_tx_get_sign(l_tx, 0), l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr.net_id);
    DAP_DEL_Z(l_tx_out_cond);
    if (l_spent_by_hash) {
        log_it(L_ERROR, "Transaction output already spent");
        DAP_DEL_MULTY(l_token_ticker, l_spent_by_hash, l_tx_out_cond);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_OUTPUTS_SPENT, "Transaction outputs not found");
        return NULL;
    }
    
    const char *l_native_ticker = a_config->native_ticker;

    dap_json_t *l_outs_native = dap_chain_tx_compose_get_remote_tx_outs(l_native_ticker, &l_owner_addr, a_config);
    if (!l_outs_native) {
        log_it(L_ERROR, "Transaction outputs not found");
        DAP_DEL_MULTY(l_token_ticker, l_tx_out_cond);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_OUTS_NOT_FOUND, "Transaction outputs not found");
        return NULL;
    }

    int l_out_native_count = dap_json_array_length(l_outs_native);
#else
    const char *l_native_ticker = a_config->native_ticker;
    char *l_token_ticker = dap_strdup("mBUZ");
    dap_json_t *l_outs_native = NULL;
    dap_json_t *response = NULL;
    int l_out_native_count = 0;
    int l_tx_out_cond_idx = rand();
    dap_chain_datum_tx_t *l_tx = NULL;
    dap_chain_addr_t l_owner_addr;
    randombytes(&l_owner_addr, sizeof(l_owner_addr));
    dap_chain_tx_out_cond_t *l_tx_out_cond = DAP_NEW_Z(dap_chain_tx_out_cond_t);
    l_tx_out_cond->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE;
    l_tx_out_cond->header.value._lo.b = rand() % 500 + 1;
    l_tx_out_cond->header.value._hi.b = rand() % 100;
#endif
    uint256_t l_fee_transfer = {}; // how many coins to transfer
    // list of transaction with 'out' items to sell
    uint256_t l_net_fee = {}, l_fee_total = a_fee;
    dap_chain_addr_t*l_net_fee_addr = NULL;
    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_net_fee_addr, a_config);
    if (l_net_fee_used)
        SUM_256_256(l_fee_total, l_net_fee, &l_fee_total);
    dap_list_t *l_list_fee_out = NULL; 
    l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                                l_fee_total, 
                                                                &l_fee_transfer, false);
    if (!l_list_fee_out) {
        log_it(L_ERROR, "Not enough funds to pay fees");
        dap_json_object_free(l_outs_native);
        DAP_DEL_MULTY(l_token_ticker, l_tx_out_cond, l_net_fee_addr);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_NOT_ENOUGH_FUNDS, "Not enough funds to pay fees");
        return NULL;
    }

    // erase and create empty transaction
    dap_chain_datum_tx_delete(l_tx);
    l_tx = dap_chain_datum_tx_create();

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_add_in_cond_item(&l_tx, a_tx_hash, l_tx_out_cond_idx, 0);

    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST 
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
        log_it(L_ERROR, "Error adding input items");
        dap_chain_datum_tx_delete(l_tx);
        dap_json_object_free(l_outs_native);
        DAP_DEL_MULTY(l_token_ticker, l_tx_out_cond, l_net_fee_addr);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_IN_ERROR, "Error adding input items");
        return NULL;
    }
#endif
    // add 'out_ext' item
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_tx_out_cond->header.value, l_token_ticker) == -1) {
        log_it(L_ERROR, "Error adding output items");
        dap_json_object_free(l_outs_native);
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_MULTY(l_token_ticker, l_tx_out_cond, l_net_fee_addr);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_TX_OUT_ERROR, "Error adding output items");
        return NULL;
    }
    DAP_DEL_Z(l_tx_out_cond);
    // add fee items
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker) != 1) {
            log_it(L_ERROR, "Error adding network fee");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_object_free(l_outs_native);
            DAP_DEL_MULTY(l_token_ticker, l_net_fee_addr);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_NET_FEE_ERROR, "Error adding network fee");
            return NULL;
        }
    }
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            log_it(L_ERROR, "Error adding fee");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_object_free(l_outs_native);
            DAP_DEL_MULTY(l_token_ticker, l_net_fee_addr);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_FEE_ERROR, "Error adding fee");
            return NULL;
        }
    }
    // fee coin back
    uint256_t l_fee_back = {};
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if(!IS_ZERO_256(l_fee_back)) {
        if(dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_fee_back, l_native_ticker) != 1) {
            log_it(L_ERROR, "Error adding fee back");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_object_free(l_outs_native);
            DAP_DEL_MULTY(l_token_ticker, l_net_fee_addr);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_INVALIDATE_COMPOSE_FEE_BACK_ERROR, "Error adding fee back");
            return NULL;
        }
    }
    dap_json_object_free(l_outs_native);
    DAP_DEL_MULTY(l_token_ticker, l_net_fee_addr);
    return l_tx;
}

dap_chain_net_srv_order_direction_t dap_chain_net_srv_order_direction_from_str(const char* str) {
    dap_chain_net_srv_order_direction_t direction = SERV_DIR_UNDEFINED;
    if (strcmp(str, "BUY") == 0) {
        direction = SERV_DIR_BUY;
    } else if (strcmp(str, "SELL") == 0) {
        direction = SERV_DIR_SELL;
    }
    return direction;
}

dap_chain_net_srv_order_t* dap_check_remote_srv_order(const char* l_net_str, const char* l_order_hash_str, uint256_t* a_tax,
                                                    uint256_t* a_value_max, dap_chain_addr_t* a_sovereign_addr, uint256_t* a_sovereign_tax, dap_json_t *response){
    dap_chain_net_srv_order_t* l_order = NULL;
    dap_json_t *orders_array = dap_json_array_get_idx(response, 0);
    size_t orders_count = dap_json_array_length(orders_array);
    for (size_t i = 0; i < orders_count; i++) {
        dap_json_t *order_obj = dap_json_array_get_idx(orders_array, i);
        dap_json_t *l_order_obj = NULL;
        dap_json_object_get_ex(order_obj, "order", &l_order_obj);
        const char *order_hash_str = l_order_obj ? dap_json_get_string(l_order_obj) : NULL;

        if (strcmp(order_hash_str, l_order_hash_str) == 0) {
            l_order = DAP_NEW_Z_SIZE(dap_chain_net_srv_order_t, sizeof(dap_chain_net_srv_order_t));
            dap_json_t *l_version_obj = NULL;
            dap_json_object_get_ex(order_obj, "version", &l_version_obj);
            l_order->version = l_version_obj ? dap_json_object_get_int(l_version_obj, NULL) : 0;
            dap_json_t *l_direction_obj = NULL;
            dap_json_object_get_ex(order_obj, "direction", &l_direction_obj);
            l_order->direction = dap_chain_net_srv_order_direction_from_str(l_direction_obj ? dap_json_get_string(l_direction_obj) : NULL);
            dap_json_t *l_created_obj = NULL;
            dap_json_object_get_ex(order_obj, "created", &l_created_obj);
            l_order->ts_created = dap_time_from_str_rfc822(l_created_obj ? dap_json_get_string(l_created_obj) : NULL);
            dap_json_t *l_srv_uid_obj = NULL;
            dap_json_object_get_ex(order_obj, "srv_uid", &l_srv_uid_obj);
            l_order->srv_uid.uint64 = dap_chain_srv_uid_from_str(l_srv_uid_obj ? dap_json_get_string(l_srv_uid_obj) : NULL).uint64;
            dap_json_t *l_price_datoshi_obj = NULL;
            dap_json_object_get_ex(order_obj, "price_datoshi", &l_price_datoshi_obj);
            l_order->price = dap_uint256_scan_uninteger(l_price_datoshi_obj ? dap_json_get_string(l_price_datoshi_obj) : NULL);

            dap_json_t *l_price_token_obj = NULL;
            dap_json_object_get_ex(order_obj, "price_token", &l_price_token_obj);
            const char *price_token_str = l_price_token_obj ? dap_json_get_string(l_price_token_obj) : NULL;
            if (price_token_str) {
                strncpy(l_order->price_ticker, price_token_str, DAP_CHAIN_TICKER_SIZE_MAX - 1);
                l_order->price_ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
            }

            dap_json_t *l_units_obj = NULL;
            dap_json_object_get_ex(order_obj, "units", &l_units_obj);
            l_order->units = l_units_obj ? dap_json_object_get_int(l_units_obj, NULL) : 0;

            dap_json_t *l_price_unit_obj = NULL;
            dap_json_object_get_ex(order_obj, "price_unit", &l_price_unit_obj);
            l_order->price_unit = dap_chain_net_srv_price_unit_uid_from_str(l_price_unit_obj ? dap_json_get_string(l_price_unit_obj) : NULL);
            dap_json_t *l_node_addr_obj = NULL;
            dap_json_object_get_ex(order_obj, "node_addr", &l_node_addr_obj);
            dap_chain_node_addr_from_str(&l_order->node_addr, l_node_addr_obj ? dap_json_get_string(l_node_addr_obj) : NULL);

            dap_json_t *l_tx_cond_hash_obj = NULL;
            dap_json_object_get_ex(order_obj, "tx_cond_hash", &l_tx_cond_hash_obj);
            const char *tx_cond_hash_str = l_tx_cond_hash_obj ? dap_json_get_string(l_tx_cond_hash_obj) : NULL;
            if (tx_cond_hash_str) {
                dap_chain_hash_fast_from_str(tx_cond_hash_str, &l_order->tx_cond_hash);
            }
            l_order->ext_size = dap_json_object_get_int(order_obj, "ext_size");

            if (l_order->ext_size > 0) {
                dap_json_t *external_params = NULL;
                if (dap_json_object_get_ex(order_obj, "external_params", &external_params)) {
                    dap_json_t *tax_obj = NULL, *value_max_obj = NULL;
                    if (dap_json_object_get_ex(external_params, "tax", &tax_obj) &&
                        dap_json_object_get_ex(external_params, "maximum_value", &value_max_obj)) {
                        const char *tax_str = dap_json_get_string(tax_obj);
                        const char *value_max_str = dap_json_get_string(value_max_obj);
                        *a_tax = dap_uint256_scan_decimal(tax_str);
                        *a_value_max = dap_uint256_scan_decimal(value_max_str);
                    }
                }
            }

            dap_json_t *conditional_tx_params = NULL;
            dap_json_object_get_ex(order_obj, "conditional_tx_params", &conditional_tx_params);
            if (conditional_tx_params && dap_json_is_object(conditional_tx_params)) {
                dap_json_t *sovereign_tax_obj = NULL;
                dap_json_object_get_ex(conditional_tx_params, "sovereign_tax", &sovereign_tax_obj);
                const char *sovereign_tax_str = sovereign_tax_obj ? dap_json_get_string(sovereign_tax_obj) : NULL;

                dap_json_t *sovereign_addr_obj = NULL;
                dap_json_object_get_ex(conditional_tx_params, "sovereign_addr", &sovereign_addr_obj);
                const char *sovereign_addr_str = sovereign_addr_obj ? dap_json_get_string(sovereign_addr_obj) : NULL;
                *a_sovereign_tax = dap_uint256_scan_decimal(sovereign_tax_str);
                if (sovereign_addr_str) {
                    a_sovereign_addr = dap_chain_addr_from_str(sovereign_addr_str);
                    if (!a_sovereign_addr) {
                        // Invalid sovereign address format
                        DAP_DELETE(l_order);
                        return NULL;
                    }
                }
            }
            break;
        }
    }
    return l_order;
}

typedef enum {
    GET_REMOTE_SRV_ORDER_RPC_RESPONSE = -1,
    GET_REMOTE_SRV_ORDER_NO_ITEMS_FOUND = -2,
    GET_REMOTE_SRV_ORDER_BAD_DATA_TYPE = -3,
    GET_REMOTE_SRV_ORDER_BAD_DATA_SIZE = -4,
    GET_REMOTE_SRV_ORDER_BAD_DATA = -5,
    GET_REMOTE_SRV_ORDER_INVALID_ORDER_HASH = -6
} s_get_remote_srv_order_error_t;

static dap_chain_net_srv_order_t *s_get_remote_srv_order(const char* l_order_hash_str, dap_chain_tx_compose_config_t *a_config){

    dap_json_t *l_raw_response = dap_request_command_to_rpc_with_params(a_config, "net_srv", "order;dump;-hash;%s;-tx_to_json;-net;%s", 
                                                                  l_order_hash_str, a_config->net_name);
    if (!l_raw_response) {
        log_it(L_ERROR, "failed to get response from remote node");
        dap_json_compose_error_add(a_config->response_handler, GET_REMOTE_SRV_ORDER_RPC_RESPONSE, "Error: Failed to get response from remote node");
        return NULL;
    }
    dap_json_t *l_responce = dap_json_array_get_idx(l_raw_response, 0);
    if (!l_responce) {
        log_it(L_ERROR, "no items found in response");
        dap_json_compose_error_add(a_config->response_handler, GET_REMOTE_SRV_ORDER_NO_ITEMS_FOUND, "No items found in response\n");
        dap_json_object_free(l_raw_response);
        return NULL;
    }

    const char *l_data_type = dap_json_object_get_string(l_responce, "data_type");
    if (!l_data_type || strcmp("order", l_data_type)) {
        log_it(L_ERROR, "current type is '%s', not 'order'", l_data_type);
        dap_json_compose_error_add(a_config->response_handler, GET_REMOTE_SRV_ORDER_BAD_DATA_TYPE, "Current type is '%s', not 'order'", l_data_type);
        dap_json_object_free(l_raw_response);
        return NULL;
    }
    uint64_t l_order_data_size = 0;
    if(!dap_json_object_get_uint64_ext(l_responce, "data_size", &l_order_data_size) || !l_order_data_size) {
        log_it(L_ERROR, "Json order: bad data_size");
        dap_json_compose_error_add(a_config->response_handler, GET_REMOTE_SRV_ORDER_BAD_DATA_SIZE, "Json order: bad data_size");
        dap_json_object_free(l_raw_response);
        return NULL;
    }
    const char *l_order_data_str = dap_json_object_get_string(l_responce, "data");
    if (!l_order_data_str) {
        log_it(L_ERROR, "Json order: bad data");
        dap_json_compose_error_add(a_config->response_handler, GET_REMOTE_SRV_ORDER_BAD_DATA, "Json order: bad data");
        dap_json_object_free(l_raw_response);
        return NULL;
    }

    dap_chain_net_srv_order_t *l_order = DAP_NEW_Z_SIZE(uint8_t, l_order_data_size+1);
    size_t l_order_data_size_decoded = dap_enc_base58_decode(l_order_data_str, l_order);
    if (l_order_data_size_decoded != l_order_data_size) {
        log_it(L_ERROR, "Json order: data size - %zu, expected - %"DAP_UINT64_FORMAT_U, l_order_data_size_decoded, l_order_data_size);
        dap_json_compose_error_add(a_config->response_handler, GET_REMOTE_SRV_ORDER_BAD_DATA_SIZE, "Json order: data size - %zu, expected - %"DAP_UINT64_FORMAT_U, l_order_data_size_decoded, l_order_data_size);
        dap_json_object_free(l_raw_response);
        DAP_DELETE(l_order);
        return NULL;
    }

    const char *l_hash_str = dap_json_object_get_string(l_responce, "data_hash");
    if (l_hash_str) {
        char *l_hash_str_current = dap_hash_fast_str_new(l_order, dap_chain_net_srv_order_get_size(l_order));
        if (l_hash_str_current && strcmp(l_hash_str, l_hash_str_current)) {
            log_it(L_ERROR, "Order has invalid hash '%s', expected hash '%s'", l_hash_str_current, l_hash_str);
            dap_json_compose_error_add(a_config->response_handler, GET_REMOTE_SRV_ORDER_INVALID_ORDER_HASH, "Order has invalid hash '%s', expected hash '%s'", l_hash_str_current, l_hash_str);
            DAP_DEL_MULTY(l_order, l_hash_str_current);
            dap_json_object_free(l_raw_response);
            return NULL;
        }
        DAP_DEL_Z(l_hash_str_current);
    }
    dap_json_object_free(l_raw_response);
    return l_order;
}

typedef enum {
    DAP_GET_REMOTE_SRV_ORDER_SIGN_RPC_RESPONSE = -1,
    DAP_GET_REMOTE_SRV_ORDER_SIGN_CANT_GET_FIRST_ELEMENT = -2,
    DAP_GET_REMOTE_SRV_ORDER_SIGN_CANT_GET_SIGN = -3
} s_get_remote_srv_order_sign_error_t;

typedef enum {
    STAKE_DELEGATE_COMPOSE_OK = 0,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_VALUE = -1,
    STAKE_DELEGATE_COMPOSE_ERR_WALLET_NOT_FOUND = -2,
    STAKE_DELEGATE_COMPOSE_ERR_CERT_NOT_FOUND = -3,
    STAKE_DELEGATE_COMPOSE_ERR_CERT_WRONG = -4,
    STAKE_DELEGATE_COMPOSE_ERR_WRONG_SIGN_TYPE = -5,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_PKEY = -6,
    STAKE_DELEGATE_COMPOSE_ERR_PKEY_UNDEFINED = -7,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_NODE_ADDR = -8,
    STAKE_DELEGATE_COMPOSE_ERR_ORDER_NOT_FOUND = -9,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_ORDER_SIZE = -10,
    STAKE_DELEGATE_COMPOSE_ERR_CERT_REQUIRED = -11,
    STAKE_DELEGATE_COMPOSE_ERR_VALUE_REQUIRED = -12,
    STAKE_DELEGATE_COMPOSE_ERR_WRONG_TICKER = -13,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_FORMAT = -14,
    STAKE_DELEGATE_COMPOSE_ERR_RPC_RESPONSE = -15,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_VALUE = -16,
    STAKE_DELEGATE_COMPOSE_ERR_NO_ITEMS = -17,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_ADDR = -18,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_SIGNER_ADDR = -19,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_SOVEREIGN_ADDR = -20,
    STAKE_DELEGATE_COMPOSE_ERR_NO_TOKEN_TICKER = -21,
    STAKE_DELEGATE_COMPOSE_ERR_VALUE_TOO_LOW = -22,
    STAKE_DELEGATE_COMPOSE_ERR_VALUE_TOO_HIGH = -23,
    STAKE_DELEGATE_COMPOSE_ERR_UNSIGNED_ORDER = -24,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_ORDER = -25,
    STAKE_DELEGATE_COMPOSE_ERR_INVALID_TAX = -26,
    STAKE_DELEGATE_COMPOSE_ERR_VALUE_BELOW_MIN = -27,
    DAP_STAKE_TX_CREATE_COMPOSE_INVALID_PARAMS = -28,
    DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_FEE = -29,
    DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_VALUE = -30,
    DAP_STAKE_TX_CREATE_COMPOSE_TX_IN_ERROR = -31,
    DAP_STAKE_TX_CREATE_COMPOSE_TX_COND_OUT_ERROR = -32,
    DAP_STAKE_TX_CREATE_COMPOSE_TX_OUT_ERROR = -33,
    DAP_STAKE_TX_CREATE_COMPOSE_NET_FEE_ERROR = -34,
    DAP_STAKE_TX_CREATE_COMPOSE_VALIDATOR_FEE_ERROR = -35,
    DAP_STAKE_TX_CREATE_COMPOSE_FEE_BACK_ERROR = -36
} stake_delegate_error_t;

dap_json_t *dap_chain_tx_compose_srv_stake_delegate(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                        uint16_t a_port, const char *a_enc_cert_path, dap_chain_addr_t *a_wallet_addr, const char *a_cert_str, 
                                        const char *a_pkey_full_str, const char *a_value_str, const char *a_node_addr_str, 
                                        const char *a_order_hash_str, const char *a_sovereign_addr_str, const char *a_fee_str) {
    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Can't create compose config");
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, STAKE_DELEGATE_COMPOSE_ERR_RPC_RESPONSE, "Can't create compose config");
        return l_json_obj_ret;
    }
    dap_chain_addr_t l_signing_addr = {}, l_sovereign_addr = {};
    uint256_t l_sovereign_tax = uint256_0;
    uint256_t l_value = uint256_0;
    if (a_value_str) {
        l_value = dap_chain_balance_scan(a_value_str);
        if (IS_ZERO_256(l_value)) {
            log_it(L_ERROR, "unrecognized number in '-value' param");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_VALUE, "Unrecognized number in '-value' param");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
    }
    dap_pkey_t *l_pkey = NULL;
    dap_chain_datum_tx_t *l_prev_tx = NULL;
    if (a_cert_str) {
        dap_cert_t *l_signing_cert = dap_cert_find_by_name(a_cert_str);
        if (!l_signing_cert) {
            log_it(L_ERROR, "specified certificate not found");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_CERT_NOT_FOUND, "Specified certificate not found");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        if (dap_chain_addr_fill_from_key(&l_signing_addr, l_signing_cert->enc_key, l_config->net_id)) {
            log_it(L_ERROR, "specified certificate is wrong");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_CERT_WRONG, "Specified certificate is wrong");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        l_pkey = dap_pkey_from_enc_key(l_signing_cert->enc_key);
    }  else if (a_pkey_full_str) {
        l_pkey = dap_pkey_get_from_str(a_pkey_full_str);
        if (!l_pkey) {
            log_it(L_ERROR, "invalid pkey string format");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_PKEY, "Invalid pkey string format, can't get pkey_full");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        dap_chain_hash_fast_t l_hash_public_key = {0};
        if (!dap_pkey_get_hash(l_pkey, &l_hash_public_key)) {
            log_it(L_ERROR, "invalid pkey hash format");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_PKEY, "Invalid pkey hash format");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        dap_chain_addr_fill(&l_signing_addr, dap_pkey_type_to_sign_type((l_pkey->header).type), &l_hash_public_key, l_config->net_id);
    }

    dap_chain_node_addr_t l_node_addr = g_node_addr;
    if (a_node_addr_str) {
        if (dap_chain_node_addr_from_str(&l_node_addr, a_node_addr_str)) {
            log_it(L_ERROR, "unrecognized node addr %s", a_node_addr_str);
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_NODE_ADDR, "Unrecognized node addr %s", a_node_addr_str);
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
    }
    if (a_order_hash_str) {
        int l_prev_tx_count = 0;
        dap_chain_net_srv_order_t *l_order = s_get_remote_srv_order(a_order_hash_str, l_config);
        if (!l_order) {
            log_it(L_ERROR, "failed to get order from remote node");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_ORDER_NOT_FOUND, "Error: Failed to get order from remote node");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }

        if (l_order->direction == SERV_DIR_BUY) { // Staker order
            char *l_token_ticker = NULL;
            if (!a_cert_str) {
                log_it(L_ERROR, "command 'delegate' requires parameter -cert with this order type");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_CERT_REQUIRED, "Command 'delegate' requires parameter -cert with this order type");
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
            if (l_order->ext_size != 0) {
                log_it(L_ERROR, "specified order has invalid size");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_ORDER_SIZE, "Specified order has invalid size");
                DAP_DELETE(l_order);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }

            dap_chain_tx_out_cond_t *l_cond_tx = NULL;
            dap_chain_datum_tx_t *l_datum = dap_chain_tx_compose_get_datum_from_rpc(dap_chain_hash_fast_to_str_static(&l_order->tx_cond_hash), l_config, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_cond_tx, NULL, &l_token_ticker, NULL, true);
            dap_chain_datum_tx_delete(l_datum);
            if (!l_cond_tx) {
                log_it(L_ERROR, "Failed to get cond tx info from RPC");
                DAP_DELETE(l_cond_tx);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }

            char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, l_config->native_ticker);

            if (dap_strcmp(l_token_ticker, l_delegated_ticker)) {
                log_it(L_ERROR, "requested conditional transaction have another ticker (not %s)", l_delegated_ticker);
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_WRONG_TICKER, "Requested conditional transaction have another ticker (not %s)", l_delegated_ticker);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
            if (l_cond_tx->tsd_size != dap_chain_datum_tx_item_out_cond_create_srv_stake_get_tsd_size(true, 0)) {
                log_it(L_ERROR, "the order's conditional transaction has invalid format");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_FORMAT, "The order's conditional transaction has invalid format");
                DAP_DEL_MULTY(l_cond_tx, l_order);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
            if (compare256(l_cond_tx->header.value, l_order->price)) {
                log_it(L_ERROR, "the order's conditional transaction has different value");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_VALUE, "The order's conditional transaction has different value");
                DAP_DEL_MULTY(l_cond_tx, l_order);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
            if (!dap_chain_addr_is_blank(&l_cond_tx->subtype.srv_stake_pos_delegate.signing_addr) ||
                    l_cond_tx->subtype.srv_stake_pos_delegate.signer_node_addr.uint64) {
                log_it(L_ERROR, "the order's conditional transaction gas not blank address or key");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_COND_TX_ADDR, "The order's conditional transaction gas not blank address or key");
                DAP_DEL_MULTY(l_cond_tx, l_order);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
            l_value = l_order->price;
            dap_tsd_t *l_tsd = dap_tsd_find(l_cond_tx->tsd, l_cond_tx->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_ADDR);
            l_sovereign_addr = dap_tsd_get_scalar(l_tsd, dap_chain_addr_t);
            l_tsd = dap_tsd_find(l_cond_tx->tsd, l_cond_tx->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_VALUE);
            l_sovereign_tax = dap_tsd_get_scalar(l_tsd, uint256_t);
            DAP_DELETE(l_cond_tx);
        } else {
            uint256_t l_value_max;
            if (!a_value_str) {
                log_it(L_ERROR, "command 'delegate' requires parameter -value with this order type");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_VALUE_REQUIRED, "Command 'delegate' requires parameter -value with this order type");
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }

            if (dap_chain_net_srv_stake_get_validator_ext(l_order, &l_sovereign_tax, &l_value_max)) {
                log_it(L_ERROR, "failed to get validator ext");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_ORDER, "Failed to get validator ext");
                DAP_DELETE(l_order);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }

            if (a_sovereign_addr_str) {
                dap_chain_addr_t *l_spec_addr = dap_chain_addr_from_str(a_sovereign_addr_str);
                if (!l_spec_addr) {
                    log_it(L_ERROR, "specified address is invalid");
                    dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_SOVEREIGN_ADDR, "Specified address is invalid");
                    return dap_chain_tx_compose_config_return_response_handler(l_config);
                }
                l_sovereign_addr = *l_spec_addr;
                DAP_DELETE(l_spec_addr);
            } else
                l_sovereign_addr = *a_wallet_addr;

            if (a_order_hash_str && compare256(l_value, l_order->price) == -1) {
                const char *l_coin_min_str, *l_value_min_str =
                    dap_uint256_to_char(l_order->price, &l_coin_min_str);
                log_it(L_ERROR, "Number in '-value' param %s is lower than order minimum allowed value %s(%s)",
                                                  a_value_str, l_coin_min_str, l_value_min_str);
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_VALUE_TOO_LOW, "Number in '-value' param %s is lower than order minimum allowed value %s(%s)",
                                                  a_value_str, l_coin_min_str, l_value_min_str);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
            if (a_order_hash_str && compare256(l_value, l_value_max) == 1) {
                const char *l_coin_max_str, *l_value_max_str =
                    dap_uint256_to_char(l_value_max, &l_coin_max_str);
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_VALUE_TOO_HIGH, "Number in '-value' param %s is higher than order minimum allowed value %s(%s)",
                                                  a_value_str, l_coin_max_str, l_value_max_str);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
            dap_sign_t *l_sign = dap_chain_net_srv_order_get_sign(l_order);
            if (!l_sign) {
                log_it(L_ERROR, "specified order is unsigned");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_UNSIGNED_ORDER, "Specified order is unsigned");
                DAP_DELETE(l_order);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
            dap_chain_addr_fill_from_sign(&l_signing_addr, l_sign, l_config->net_id);
            l_pkey = dap_pkey_get_from_sign(l_sign);
            DAP_DELETE(l_sign);
            char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_config->native_ticker);
            if (dap_strcmp(l_order->price_ticker, l_delegated_ticker_str)) {
                log_it(L_ERROR, "specified order is invalid");
                dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_ORDER, "Specified order is invalid");
                DAP_DELETE(l_order);
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
            l_node_addr = l_order->node_addr;
        }
        DAP_DELETE(l_order);
        if (compare256(l_sovereign_tax, dap_chain_balance_coins_scan("100.0")) == 1 ||
                compare256(l_sovereign_tax, GET_256_FROM_64(100)) == -1) {
            log_it(L_ERROR, "tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%");
            dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_TAX, "Tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        DIV_256(l_sovereign_tax, GET_256_FROM_64(100), &l_sovereign_tax);
    }
    if (!l_pkey) {
        log_it(L_ERROR, "pkey not defined");
        dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_PKEY_UNDEFINED, "pkey not defined");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    if (!l_node_addr.uint64) {
        dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_NODE_ADDR, "Invalid node addr, is sero");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    // int l_check_result = dap_chain_net_srv_stake_verify_key_and_node(&l_signing_addr, &l_node_addr);
    // if (l_check_result) {
    //     dap_json_compose_error_add(l_config->response_handler, l_check_result, "Key and node verification error");
    //     return dap_chain_tx_compose_config_return_response_handler(l_config);
    // }
 

    uint256_t l_allowed_min = s_get_key_delegating_min_value(l_config);
    if (compare256(l_value, l_allowed_min) == -1) {
        const char *l_coin_min_str, *l_value_min_str = dap_uint256_to_char(l_allowed_min, &l_coin_min_str);
        log_it(L_ERROR, "Number in '-value' param %s is lower than minimum allowed value %s(%s)",
                                                  a_value_str, l_coin_min_str, l_value_min_str);
        dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_VALUE_BELOW_MIN, "Number in '-value' param %s is lower than minimum allowed value %s(%s)",
                                          a_value_str, l_coin_min_str, l_value_min_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    uint256_t l_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_fee)) {
        log_it(L_ERROR, "unrecognized number in '-fee' param");
        dap_json_compose_error_add(l_config->response_handler, STAKE_DELEGATE_COMPOSE_ERR_INVALID_VALUE, "Unrecognized number in '-fee' param");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_srv_stake_delegate(a_wallet_addr, l_value, l_fee, &l_signing_addr, &l_node_addr,
                                                   a_order_hash_str ? &l_sovereign_addr : NULL, l_sovereign_tax, l_prev_tx, l_pkey, l_config);
    
    DAP_DELETE(l_pkey);

    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }

    return dap_chain_tx_compose_config_return_response_handler(l_config);
}

dap_chain_datum_tx_t *dap_chain_tx_compose_datum_srv_stake_delegate(dap_chain_addr_t *a_wallet_addr,
                                               uint256_t a_value, uint256_t a_fee,
                                               dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_node_addr,
                                               dap_chain_addr_t *a_sovereign_addr, uint256_t a_sovereign_tax,
                                               dap_chain_datum_tx_t *a_prev_tx, dap_pkey_t *a_pkey, dap_chain_tx_compose_config_t *a_config)
{
    if  (!a_wallet_addr || IS_ZERO_256(a_value) || !a_signing_addr || !a_node_addr) {
        log_it(L_ERROR, "invalid parameters for transaction creation");
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_INVALID_PARAMS, "Invalid parameters for transaction creation");
        return NULL;
    }
    const char *l_native_ticker = a_config->native_ticker;
    char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, l_native_ticker);
    uint256_t l_value_transfer = {}, l_fee_transfer = {}; 

    uint256_t l_net_fee = {}, l_fee_total = a_fee;
    dap_chain_addr_t *l_net_fee_addr = NULL;
    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_net_fee_addr, a_config);
    if (l_net_fee_used)
        SUM_256_256(l_fee_total, l_net_fee, &l_fee_total);

    dap_list_t *l_list_fee_out = NULL;

#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    dap_json_t *l_outs_native = dap_chain_tx_compose_get_remote_tx_outs(l_native_ticker, a_wallet_addr, a_config);
    if (!l_outs_native) {
        log_it(L_ERROR, "failed to get remote tx outs");
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_FEE, "Not enough funds to pay fee");
        DAP_DEL_Z(l_net_fee_addr);
        return NULL;
    }

    dap_json_t *l_outs_delegated = dap_chain_tx_compose_get_remote_tx_outs(l_delegated_ticker, a_wallet_addr, a_config);
    if (!l_outs_delegated) {
        log_it(L_ERROR, "failed to get remote tx outs");
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_VALUE, "Not enough funds for value");
        DAP_DEL_Z(l_net_fee_addr);
        return NULL;
    }

    int l_out_native_count = dap_json_array_length(l_outs_native);
    int l_out_delegated_count = dap_json_array_length(l_outs_delegated); 
#else
    dap_json_t *l_outs_native = NULL;
    dap_json_t *l_outs_delegated = NULL;
    int l_out_native_count = 0;
    int l_out_delegated_count = 0;
#endif

    l_list_fee_out = dap_ledger_get_list_tx_outs_from_json(l_outs_native, l_out_native_count,
                                                    l_fee_total, 
                                                    &l_fee_transfer, false);
    if (!l_list_fee_out) {
        log_it(L_ERROR, "Failed to get list tx outs from json");
        dap_json_object_free(l_outs_native);
        dap_json_object_free(l_outs_delegated);
        DAP_DELETE(l_net_fee_addr);
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_FEE, "Not enough funds to pay fee");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    if (!a_prev_tx) {
        dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs_delegated, l_out_delegated_count,
                                                               a_value, 
                                                               &l_value_transfer, false);
        if (!l_list_used_out) {
            log_it(L_ERROR, "Failed to get list tx outs from json");
            dap_json_object_free(l_outs_native);
            dap_json_object_free(l_outs_delegated);
            DAP_DELETE(l_net_fee_addr);
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NOT_ENOUGH_FUNDS_VALUE, "Not enough funds for value");
            return NULL;
        }
        // add 'in' items to pay for delegate
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        dap_list_free_full(l_list_used_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST 
        if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
            log_it(L_ERROR, "failed to add in item");
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_TX_IN_ERROR, "Error creating transaction input");
            goto tx_fail;
        }
#endif
    } else {
        dap_hash_fast_t l_prev_tx_hash;
        dap_hash_fast(a_prev_tx, dap_chain_datum_tx_get_size(a_prev_tx), &l_prev_tx_hash);
        int l_out_num = 0;
        dap_chain_datum_tx_out_cond_get(a_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_out_num);
        // add 'in' item to buy from conditional transaction
        if (1 != dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_prev_tx_hash, l_out_num, -1)) {
            log_it(L_ERROR, "failed to add in cond item");
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_TX_IN_ERROR, "Error creating transaction input");
            goto tx_fail;
        }
    }
    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST 
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
        log_it(L_ERROR, "failed to add in item");
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_TX_IN_ERROR, "Error creating transaction input");
        goto tx_fail;
    }
#endif
    // add 'out_cond' & 'out_ext' items
    dap_chain_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
    dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_stake(l_uid, a_value, a_signing_addr, a_node_addr,
                                                                                          a_sovereign_addr, a_sovereign_tax, a_pkey);

    if (!l_tx_out) {
        log_it(L_ERROR, "failed to create cond tx out");
        dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_TX_COND_OUT_ERROR, "Error creating conditional transaction output");
        goto tx_fail;
    }
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
    DAP_DELETE(l_tx_out);
    if (!a_prev_tx) {
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_transfer, a_value, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, l_delegated_ticker) != 1) {
                log_it(L_ERROR, "failed to add out ext item");
                dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_TX_OUT_ERROR, "Error creating transaction output");
                goto tx_fail;
            }
        }
    }

    // add fee items
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_net_fee_addr, l_net_fee, l_native_ticker) != 1) {
            log_it(L_ERROR, "Error with network fee, failed to add item");
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_NET_FEE_ERROR, "Error with network fee, failed to add item");
            goto tx_fail;
        }
    }
    DAP_DEL_Z(l_net_fee_addr);
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            log_it(L_ERROR, "Error with validator fee, failed to add item");
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_VALIDATOR_FEE_ERROR, "Error with validator fee, failed to add item");
            goto tx_fail;
        }
    }
    uint256_t l_fee_back = {};
    // fee coin back
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if (!IS_ZERO_256(l_fee_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_fee_back, l_native_ticker) != 1) {
            log_it(L_ERROR, "Error with fee back, failed to add item");
            dap_json_compose_error_add(a_config->response_handler, DAP_STAKE_TX_CREATE_COMPOSE_FEE_BACK_ERROR, "Error with fee back, failed to add item");
            goto tx_fail;
        }
    }

    return l_tx;

tx_fail:
    dap_chain_datum_tx_delete(l_tx);
    DAP_DEL_Z(l_net_fee_addr);
    return NULL;
}

static dap_chain_datum_tx_t *dap_order_tx_create_compose(dap_chain_addr_t *a_wallet_addr,
                                               uint256_t a_value, uint256_t a_fee,
                                                uint256_t a_sovereign_tax, dap_chain_addr_t *a_sovereign_addr,
                                                dap_chain_tx_compose_config_t *a_config)
{
    dap_chain_node_addr_t l_node_addr = {};
    return dap_chain_tx_compose_datum_srv_stake_delegate(a_wallet_addr, a_value, a_fee,
                             (dap_chain_addr_t *)&c_dap_chain_addr_blank, &l_node_addr,
                             a_sovereign_addr, a_sovereign_tax, NULL, NULL, a_config);
}

typedef enum {
    STAKE_ORDER_CREATE_STAKER_OK = 0,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_PARAMS = -1,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_VALUE = -2,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_FEE = -3,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_TAX = -4,
    STAKE_ORDER_CREATE_STAKER_ERR_WALLET_NOT_FOUND = -5,
    STAKE_ORDER_CREATE_STAKER_ERR_KEY_NOT_FOUND = -6,
    STAKE_ORDER_CREATE_STAKER_ERR_INVALID_ADDR = -7,
    STAKE_ORDER_CREATE_STAKER_ERR_TX_CREATE_FAILED = -8,
    STAKE_ORDER_CREATE_STAKER_ERR_JSON_FAILED = -9
} dap_cli_srv_stake_order_create_staker_error_t;

dap_json_t *dap_chain_tx_compose_stake_order_create_staker(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                          uint16_t a_port, const char *a_enc_cert_path, const char *a_value_str, const char *a_fee_str, 
                                                          const char *a_tax_str, const char *a_addr_str, dap_chain_addr_t *a_wallet_addr) 
{
    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Failed to create compose config");
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_PARAMS, "Invalid arguments");
        return l_json_obj_ret;
    }
    uint256_t l_value = dap_chain_balance_scan(a_value_str);
    if (IS_ZERO_256(l_value)) {
        log_it(L_ERROR, "unrecognized number in '-value' param");
        dap_json_compose_error_add(l_config->response_handler, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_VALUE, "Format -value <256 bit integer>");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    uint256_t l_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_fee)) {
        log_it(L_ERROR, "unrecognized number in '-fee' param");
        dap_json_compose_error_add(l_config->response_handler, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_FEE, "Format -fee <256 bit integer>");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    uint256_t l_tax = dap_chain_balance_coins_scan(a_tax_str);
    if (compare256(l_tax, dap_chain_balance_coins_scan("100.0")) == 1 ||
            compare256(l_tax, GET_256_FROM_64(100)) == -1) {
        log_it(L_ERROR, "tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%");
        dap_json_compose_error_add(l_config->response_handler, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_TAX, "Tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_chain_addr_t l_addr = {};
    if (a_addr_str) {
        dap_chain_addr_t *l_spec_addr = dap_chain_addr_from_str(a_addr_str);
        if (!l_spec_addr) {
            log_it(L_ERROR, "specified address is invalid");
            dap_json_compose_error_add(l_config->response_handler, STAKE_ORDER_CREATE_STAKER_ERR_INVALID_ADDR, "Specified address is invalid");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        l_addr = *l_spec_addr;
        DAP_DELETE(l_spec_addr);
    } else
        l_addr = *a_wallet_addr;
    DIV_256(l_tax, GET_256_FROM_64(100), &l_tax);
    dap_chain_node_addr_t l_node_addr_z = {};
    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_srv_stake_delegate(a_wallet_addr, l_value, l_fee,
        (dap_chain_addr_t *)&c_dap_chain_addr_blank, &l_node_addr_z, &l_addr, l_tax, NULL, NULL, l_config);

    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Address not defined");  
    }

    return dap_chain_tx_compose_config_return_response_handler(l_config);
}

enum cli_hold_compose_error {
    CLI_HOLD_COMPOSE_ERROR_INVALID_CONFIG = -1,
    CLI_HOLD_COMPOSE_ERROR_INVALID_TOKEN = -2,
    CLI_HOLD_COMPOSE_ERROR_INVALID_COINS = -3,
    CLI_HOLD_COMPOSE_ERROR_NO_DELEGATED_TOKEN = -4,
    CLI_HOLD_COMPOSE_ERROR_INVALID_EMISSION_RATE = -5,
    CLI_HOLD_COMPOSE_ERROR_INVALID_COINS_FORMAT = -6,
    CLI_HOLD_COMPOSE_ERROR_INVALID_FEE = -7,
    CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING = -8,
    CLI_HOLD_COMPOSE_ERROR_INVALID_REINVEST_PERCENTAGE = -9,
    CLI_HOLD_COMPOSE_ERROR_UNABLE_TO_OPEN_WALLET = -10,
    CLI_HOLD_COMPOSE_ERROR_UNABLE_TO_GET_WALLET_ADDRESS = -11,
    CLI_HOLD_COMPOSE_ERROR_INSUFFICIENT_FUNDS = -12
};


dap_json_t *dap_chain_tx_compose_stake_lock_hold(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                    uint16_t a_port, const char *a_enc_cert_path, dap_chain_id_t a_chain_id, const char *a_ticker_str, dap_chain_addr_t *a_wallet_addr, const char *a_coins_str, const char *a_time_staking_str,
                                    const char *a_cert_str, const char *a_value_fee_str, const char *a_reinvest_percent_str) {
    
    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Can't create compose config");
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, CLI_HOLD_COMPOSE_ERROR_INVALID_CONFIG, "Can't create compose config");
        return l_json_obj_ret;
    }
    
    log_it_fl(L_DEBUG, "compose config initialized successfully");
    
    char 	l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
    dap_enc_key_t						*l_key_from;
    dap_chain_addr_t					*l_addr_holder;
    dap_time_t              			l_time_staking		=	0;
    uint256_t						    l_reinvest_percent	=	{};
    uint256_t							l_value_delegated	=	{};
    uint256_t                           l_value_fee     	=	{};
    uint256_t 							l_value             =   {};

    dap_json_t *l_json_coins = dap_request_command_to_rpc_with_params(l_config, "ledger", "list;coins;-net;%s", l_config->net_name);
    if (!l_json_coins) {
        log_it(L_ERROR, "Can't get coins");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    if (!dap_chain_tx_compose_check_token_in_ledger(l_json_coins, a_ticker_str)) {
        log_it(L_ERROR, "Invalid token '%s'", a_ticker_str);
        dap_json_object_free(l_json_coins);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TOKEN, "Invalid token '%s'\n", a_ticker_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }


    if (IS_ZERO_256((l_value = dap_chain_balance_scan(a_coins_str)))) {
        log_it(L_ERROR, "Invalid coins format '%s'", a_coins_str);
        dap_json_object_free(l_json_coins);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_COINS, "Invalid coins format\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, a_ticker_str);

    if (!dap_chain_tx_compose_check_token_in_ledger(l_json_coins, l_delegated_ticker_str)) {
        log_it(L_ERROR, "No delegated token found '%s'", l_delegated_ticker_str);
        dap_json_object_free(l_json_coins);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_NO_DELEGATED_TOKEN, "No delegated token found\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    dap_json_object_free(l_json_coins);

    uint256_t l_emission_rate = dap_chain_balance_coins_scan("0.001");  // TODO 16126
    // uint256_t l_emission_rate = dap_ledger_token_get_emission_rate(l_ledger, l_delegated_ticker_str);
    // if (IS_ZERO_256(l_emission_rate)) {
    //     printf("Error: Invalid token emission rate\n");
    //     return -8;
    // }

    if (MULT_256_COIN(l_value, l_emission_rate, &l_value_delegated) || IS_ZERO_256(l_value_delegated)) {
        log_it(L_ERROR, "invalid emission rate");
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_EMISSION_RATE, "Invalid coins format\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }


    if (IS_ZERO_256((l_value_fee = dap_chain_balance_scan(a_value_fee_str)))) {
        log_it(L_ERROR, "invalid fee format '%s'", a_value_fee_str);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_FEE, "Invalid fee format\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    if (dap_strlen(a_time_staking_str) != 6) {
        log_it(L_ERROR, "invalid time staking format '%s'", a_time_staking_str);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Invalid time staking format\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    char l_time_staking_month_str[3] = {a_time_staking_str[2], a_time_staking_str[3], 0};
    int l_time_staking_month = atoi(l_time_staking_month_str);
    if (l_time_staking_month < 1 || l_time_staking_month > 12) {
        log_it(L_ERROR, "invalid time staking month '%s'", a_time_staking_str);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Invalid time staking month\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    char l_time_staking_day_str[3] = {a_time_staking_str[4], a_time_staking_str[5], 0};
    int l_time_staking_day = atoi(l_time_staking_day_str);
    if (l_time_staking_day < 1 || l_time_staking_day > 31) {
        log_it(L_ERROR, "invalid time staking day '%s'", a_time_staking_str);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Invalid time staking day\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    l_time_staking = dap_time_from_str_simplified(a_time_staking_str);
    if (!l_time_staking) {
        log_it(L_ERROR, "invalid time staking '%s'", a_time_staking_str);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Invalid time staking\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    if (l_time_staking < dap_time_now()) {
        log_it(L_ERROR, "time staking is in the past '%s'", a_time_staking_str);
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_TIME_STAKING, "Time staking is in the past\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    if ( NULL != a_reinvest_percent_str) {
        l_reinvest_percent = dap_chain_balance_coins_scan(a_reinvest_percent_str);
        if (compare256(l_reinvest_percent, dap_chain_balance_coins_scan("100.0")) == 1) {
            log_it(L_ERROR, "invalid reinvest percentage '%s'", a_reinvest_percent_str);
            dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_REINVEST_PERCENTAGE, "Invalid reinvest percentage\n");
            return dap_chain_tx_compose_config_return_response_handler(l_config);
        }
        if (IS_ZERO_256(l_reinvest_percent)) {
            int l_reinvest_percent_int = atoi(a_reinvest_percent_str);
            if (l_reinvest_percent_int < 0 || l_reinvest_percent_int > 100) {
                log_it(L_ERROR, "invalid reinvest percentage '%s'", a_reinvest_percent_str);
                dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INVALID_REINVEST_PERCENTAGE, "Invalid reinvest percentage\n");
                return dap_chain_tx_compose_config_return_response_handler(l_config);
            }
            l_reinvest_percent = dap_chain_uint256_from(l_reinvest_percent_int);
            MULT_256_256(l_reinvest_percent, GET_256_FROM_64(1000000000000000000ULL), &l_reinvest_percent);
        }
    }
    
    dap_json_t *l_json_outs = dap_request_command_to_rpc_with_params(l_config, "wallet", "info;-addr;%s;-net;%s", 
                                                                       dap_chain_addr_to_str(a_wallet_addr), l_config->net_name);

    uint256_t l_value_balance = dap_chain_tx_compose_get_balance_from_json(l_json_outs, a_ticker_str);
    dap_json_object_free(l_json_outs);
    if (compare256(l_value_balance, l_value) == -1) {
        log_it(L_ERROR, "insufficient funds in wallet");
        dap_json_compose_error_add(l_config->response_handler, CLI_HOLD_COMPOSE_ERROR_INSUFFICIENT_FUNDS, "Insufficient funds in wallet\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    // Make transfer transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_stake_lock_hold(a_wallet_addr,
                                                           a_ticker_str, l_value, l_value_fee,
                                                           l_time_staking, l_reinvest_percent,
                                                           l_delegated_ticker_str, l_value_delegated, a_chain_id, l_config);

    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }

    return dap_chain_tx_compose_config_return_response_handler(l_config);
}
