/**
 * @file dap_chain_net_srv_voting_compose.c
 * @brief Voting service transaction compose functions
 * 
 * These functions were moved from modules/compose/ to eliminate circular dependencies.
 * Voting service now provides its own compose logic and registers it with compose module.
 */

#include "dap_common.h"
#include "dap_chain_net_srv_voting.h"
#include "dap_chain_net_srv_voting_compose.h"
#include "dap_chain_tx_compose.h"
#include "dap_chain_tx_compose_callbacks.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_voting.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_ledger.h"
#include "dap_json_rpc_errors.h"
#include "dap_cert.h"
#include "dap_list.h"
#include "dap_time.h"
#include "dap_strfuncs.h"
#include "dap_rand.h"

#define LOG_TAG "voting_compose"

dap_json_t *dap_chain_tx_compose_poll_create(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                    uint16_t a_port, const char *a_enc_cert_path, const char *a_question_str, const char *a_options_list_str, 
                                    const char *a_voting_expire_str, const char *a_max_votes_count_str, const char *a_fee_str, 
                                    bool a_is_delegated_key, bool a_is_vote_changing_allowed, dap_chain_addr_t *a_wallet_addr, const char *a_token_str) {
    
    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Unable to init config");
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, -1, "Unable to init config\n");
        return l_json_obj_ret;
    }
    
    log_it_fl(L_DEBUG, "Compose config initialized successfully");
    
    if (strlen(a_question_str) > DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH){
        log_it(L_ERROR, "question too long");
        dap_json_compose_error_add(l_config->response_handler, DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH, "The question must contain no more than %d characters\n", DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_list_t *l_options_list = NULL;
    // Parse options list
    l_options_list = dap_get_options_list_from_str(a_options_list_str);
    if(!l_options_list || dap_list_length(l_options_list) < 2){
        log_it(L_ERROR, "number of options must be 2 or greater");
        dap_json_compose_error_add(l_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_NUMBER_OPTIONS_ERROR, "Number of options must be 2 or greater.\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    if(dap_list_length(l_options_list)>DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT){
        log_it(L_ERROR, "number of options must be less than %d", DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT);
        dap_json_compose_error_add(l_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_CONTAIN_MAX_OPTIONS, "The voting can contain no more than %d options\n", DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT);            
        return dap_chain_tx_compose_config_return_response_handler(l_config);

    }
    uint256_t l_value_fee = dap_chain_balance_scan(a_fee_str);


    dap_time_t l_time_expire = 0;
    if (a_voting_expire_str)
        l_time_expire = dap_time_from_str_rfc822(a_voting_expire_str);
    if (a_voting_expire_str && !l_time_expire){
        log_it(L_ERROR, "wrong time format");
        dap_json_compose_error_add(l_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_WRONG_TIME_FORMAT, "Wrong time format. -expire parameter must be in format \"Day Month Year HH:MM:SS Timezone\" e.g. \"19 August 2024 22:00:00 +00\"\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    uint64_t l_max_count = 0;
    if (a_max_votes_count_str)
        l_max_count = strtoul(a_max_votes_count_str, NULL, 10);
        
    dap_json_t *l_json_coins = dap_request_command_to_rpc_with_params(l_config, "ledger", "list;coins;-net;%s", l_config->net_name);
    if (!l_json_coins) {
        log_it(L_ERROR, "can't get ledger coins list");
        dap_json_compose_error_add(l_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_ERROR_CAN_NOT_GET_TX_OUTS, "Can't get ledger coins list\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    if (!!dap_chain_tx_compose_check_token_in_ledger(l_json_coins, a_token_str)) {
        log_it(L_ERROR, "Token does not exist");
        dap_json_object_free(l_json_coins);
        dap_json_compose_error_add(l_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_WRONG_TOKEN, "Token %s does not exist\n", a_token_str);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    dap_json_object_free(l_json_coins);

    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_poll_create(a_question_str, l_options_list, l_time_expire, l_max_count,
                                                                l_value_fee, a_is_delegated_key, a_is_vote_changing_allowed, 
                                                                a_wallet_addr, a_token_str, l_config);
    dap_list_free(l_options_list);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }
    return dap_chain_tx_compose_config_return_response_handler(l_config);
}

typedef enum {
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_OK = 0,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_INVALID_CONFIG,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_QUESTION_TOO_LONG,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_TOO_MANY_OPTIONS,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_ZERO_FEE,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_WALLET_NOT_FOUND,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_OPTION_TOO_LONG,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_OPTION_CREATE_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_INVALID_EXPIRE_TIME,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_EXPIRE_CREATE_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_MAX_VOTES_CREATE_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_DELEGATED_KEY_CREATE_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_VOTE_CHANGING_CREATE_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_TOKEN_CREATE_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_FEE_OUTPUT_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_COINBACK_FAILED,
    DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_NOT_ENOUGH_FUNDS
} dap_chain_net_vote_create_compose_error_t;

dap_chain_datum_tx_t* dap_chain_tx_compose_datum_poll_create(const char *a_question, dap_list_t *a_options, dap_time_t a_expire_vote,
                              uint64_t a_max_vote, uint256_t a_fee, bool a_delegated_key_required,
                              bool a_vote_changing_allowed, dap_chain_addr_t *a_wallet_addr,
                              const char *a_token_ticker, dap_chain_tx_compose_config_t *a_config) {
    dap_return_val_if_pass(!a_config || !a_wallet_addr, NULL);

    if (strlen(a_question) > DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH){
        log_it(L_ERROR, "question too long");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_QUESTION_TOO_LONG, "The question must contain no more than %d characters\n", DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH);
        return NULL;
    }

    // Parse options list

    if(dap_list_length(a_options) > DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT) {
        log_it(L_ERROR, "too many options");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_TOO_MANY_OPTIONS, "The voting can contain no more than %d options\n", DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT);
        return NULL;
    }

    if (IS_ZERO_256(a_fee)) {
        log_it(L_ERROR, "fee must be greater than 0");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_ZERO_FEE, "Fee must be greater than 0\n");
        return NULL;
    }

    const char *l_native_ticker = a_config->native_ticker;
    uint256_t l_net_fee = {}, l_total_fee = {}, l_value_transfer;
    dap_chain_addr_t *l_addr_fee = NULL;
    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);
    SUM_256_256(l_net_fee, a_fee, &l_total_fee);


    dap_chain_addr_t *l_addr_from = NULL;
    dap_json_t *l_outs = NULL;
    int l_outputs_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    l_addr_from = a_wallet_addr;

    if (!dap_chain_tx_compose_get_remote_wallet_outs_and_count(l_addr_from, l_native_ticker, &l_outs, &l_outputs_count, a_config)) {
        log_it(L_ERROR, "can't get remote wallet outputs");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_NOT_ENOUGH_FUNDS, "can't get remote wallet outputs\n");
        DAP_DEL_Z(l_addr_fee);
        return NULL;
    }
#else
    l_addr_from = a_wallet_addr;
#endif


    dap_list_t *l_list_used_out = NULL;
    l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_total_fee,
                                                            &l_value_transfer, false);

    dap_json_object_free(l_outs);
    if (!l_list_used_out) {
        log_it(L_ERROR, "not enough funds to transfer");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_NOT_ENOUGH_FUNDS, "Not enough funds to transfer");
        DAP_DELETE(l_addr_fee);
        return NULL;
    }


    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // Add Voting item
    dap_chain_tx_voting_t *l_voting_item = dap_chain_datum_tx_item_voting_create();

    dap_chain_datum_tx_add_item(&l_tx, l_voting_item);
    DAP_DELETE(l_voting_item);

    // Add question to tsd data
    dap_chain_tx_tsd_t *l_question_tsd = dap_chain_datum_voting_question_tsd_create(a_question, strlen(a_question));
    dap_chain_datum_tx_add_item(&l_tx, l_question_tsd);
    DAP_DEL_Z(l_question_tsd);

    // Add options to tsd
    dap_list_t *l_temp = a_options;
    while(l_temp){
        if(strlen((char*)l_temp->data) > DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_LENGTH){
            log_it(L_ERROR, "Option too long");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_OPTION_TOO_LONG, "The option must contain no more than %d characters\n", DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_LENGTH);
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        dap_chain_tx_tsd_t *l_option = dap_chain_datum_voting_answer_tsd_create((char*)l_temp->data, strlen((char*)l_temp->data));
        if(!l_option){
            log_it(L_ERROR, "Failed to create option");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_OPTION_CREATE_FAILED, "Failed to create option\n");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_option);
        DAP_DELETE(l_option);
        l_temp = l_temp->next;
    }

    // add voting expire time if needed
    if(a_expire_vote != 0){
        dap_time_t l_expired_vote = a_expire_vote;
        if (l_expired_vote < dap_time_now()){
            log_it(L_ERROR, "Expire time must be in the future");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_INVALID_EXPIRE_TIME, "Expire time must be in the future\n");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }

        dap_chain_tx_tsd_t *l_expired_item = dap_chain_datum_voting_expire_tsd_create(l_expired_vote);
        if(!l_expired_item){
            log_it(L_ERROR, "Failed to create expire time item");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_EXPIRE_CREATE_FAILED, "Failed to create expire time item\n");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_expired_item);
        DAP_DELETE(l_expired_item);
    }

    // Add vote max count if needed
    if (a_max_vote != 0) {
        dap_chain_tx_tsd_t *l_max_votes_item = dap_chain_datum_voting_max_votes_count_tsd_create(a_max_vote);
        if(!l_max_votes_item){
            log_it(L_ERROR, "Failed to create max votes item");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_MAX_VOTES_CREATE_FAILED, "Failed to create max votes item\n");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_max_votes_item);
        DAP_DELETE(l_max_votes_item);
    }

    if (a_delegated_key_required) {
        dap_chain_tx_tsd_t *l_delegated_key_req_item = dap_chain_datum_voting_delegated_key_required_tsd_create(true);
        if(!l_delegated_key_req_item){
            log_it(L_ERROR, "Failed to create delegated key requirement item");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_DELEGATED_KEY_CREATE_FAILED, "Failed to create delegated key requirement item\n");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_delegated_key_req_item);
        DAP_DELETE(l_delegated_key_req_item);
    }

    if(a_vote_changing_allowed){
        dap_chain_tx_tsd_t *l_vote_changing_item = dap_chain_datum_voting_vote_changing_allowed_tsd_create(true);
        if(!l_vote_changing_item){
            log_it(L_ERROR, "Failed to create vote changing item");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_VOTE_CHANGING_CREATE_FAILED, "Failed to create vote changing item\n");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_vote_changing_item);
        DAP_DELETE(l_vote_changing_item);
    }
    if (a_token_ticker) {
        dap_chain_tx_tsd_t *l_voting_token_item = dap_chain_datum_voting_token_tsd_create(a_token_ticker);
        if (!l_voting_token_item) {
            log_it(L_ERROR, "Failed to create token item");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_TOKEN_CREATE_FAILED, "Failed to create token item\n");
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_voting_token_item);
        DAP_DELETE(l_voting_token_item);
    }

    // add 'in' items
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST 
    assert(EQUAL_256(l_value_to_items, l_value_transfer));
#endif
    dap_list_free_full(l_list_used_out, NULL);
    uint256_t l_value_pack = {};
    // Network fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) == 1)
            SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
        else {
            log_it(L_ERROR, "Can't add network fee output");
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_addr_fee);
            return NULL;
        }
    }
    DAP_DEL_Z(l_addr_fee);
    // Validator's fee
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) == 1)
            SUM_256_256(l_value_pack, a_fee, &l_value_pack);
        else {
            log_it(L_ERROR, "Can't add fee output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_FEE_OUTPUT_FAILED, "Can't add fee output in tx");
            return NULL;
        }
    }
    // coin back
    uint256_t l_value_back;
    SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
    if(!IS_ZERO_256(l_value_back)) {
        if(dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_from, l_value_back, l_native_ticker) != 1) {
            log_it(L_ERROR, "Can't add coin back output");
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CREATE_COMPOSE_ERR_COINBACK_FAILED, "Can't add coin back in tx");
            return NULL;
        }
    }
    return l_tx;
}

typedef enum {
    DAP_CLI_VOTE_COMPOSE_OK = 0,
    DAP_CLI_VOTE_COMPOSE_INVALID_CONFIG = -1,
    DAP_CLI_VOTE_COMPOSE_INVALID_HASH = -2,
    DAP_CLI_VOTE_COMPOSE_CERT_NOT_FOUND = -3,
    DAP_CLI_VOTE_COMPOSE_INVALID_FEE = -4,
    DAP_CLI_VOTE_COMPOSE_WALLET_NOT_FOUND = -5
} dap_cli_vote_compose_error_t;

dap_json_t *dap_chain_tx_compose_poll_vote(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                    uint16_t a_port, const char *a_enc_cert_path, const char *a_hash_str, const char *a_cert_name, const char *a_fee_str, dap_chain_addr_t *a_wallet_addr, 
                                    const char *a_option_idx_str) {
    
    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        log_it(L_ERROR, "Can't create compose config");
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, DAP_CLI_VOTE_COMPOSE_INVALID_CONFIG, "Can't create compose config");
        return l_json_obj_ret;
    }

    dap_hash_fast_t l_voting_hash = {};
    if (dap_chain_hash_fast_from_str(a_hash_str, &l_voting_hash)) {
        log_it(L_ERROR, "hash string is not recognozed as hex of base58 hash");
        dap_json_compose_error_add(l_config->response_handler, DAP_CLI_VOTE_COMPOSE_INVALID_HASH, "Hash string is not recognozed as hex of base58 hash\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_cert_t *l_cert = dap_cert_find_by_name(a_cert_name);
    if (a_cert_name && !l_cert) {
        log_it(L_ERROR, "can't find certificate");
        dap_json_compose_error_add(l_config->response_handler, DAP_CLI_VOTE_COMPOSE_CERT_NOT_FOUND, "Can't find \"%s\" certificate\n", a_cert_name);
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }
    uint256_t l_value_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_value_fee)) {
        log_it(L_ERROR, "invalid fee");
        dap_json_compose_error_add(l_config->response_handler, DAP_CLI_VOTE_COMPOSE_INVALID_FEE, "command requires parameter '-fee' to be valid uint256\n");            
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    uint64_t l_option_idx_count = strtoul(a_option_idx_str, NULL, 10);

    dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_datum_poll_vote(l_cert, l_value_fee, a_wallet_addr, l_voting_hash, l_option_idx_count, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    } else {
        log_it(L_ERROR, "Failed to create transaction");
    }
    return dap_chain_tx_compose_config_return_response_handler(l_config);
}


static bool s_datum_tx_voting_coin_check_spent_compose(dap_json_t *a_votes_list, dap_hash_fast_t a_tx_hash, int a_out_idx, dap_hash_fast_t *a_pkey_hash) {
    dap_return_val_if_pass(!a_votes_list, false);

        size_t l_votes_count = dap_json_array_length(a_votes_list);

    log_it_fl(L_DEBUG, "Сhecking %zu votes", l_votes_count);

    for (size_t i = 0; i < l_votes_count; i++) {
        dap_json_t *l_vote = dap_json_array_get_idx(a_votes_list, i);
        const char
            *l_vote_hash = dap_json_object_get_string(l_vote, "vote_hash"),
            *l_pkey_hash = dap_json_object_get_string(l_vote, "pkey_hash");
        if (!dap_strcmp(l_vote_hash, dap_chain_hash_fast_to_str_static(&a_tx_hash)) && a_out_idx == dap_json_object_get_int(l_vote, "answer_idx")) {
            log_it_fl(L_DEBUG, "Found matching vote at index %zu", i);
            return a_pkey_hash ? !dap_strcmp(l_pkey_hash, dap_chain_hash_fast_to_str_static(a_pkey_hash)) : true;
        }
    }
    log_it_fl(L_DEBUG, "No matching vote found");
    return false;
}

typedef enum {
    DAP_CHAIN_NET_VOTE_COMPOSE_OK = 0,
    DAP_CHAIN_NET_VOTE_COMPOSE_CAN_NOT_FIND_CERT = -1,
    DAP_CHAIN_NET_VOTE_COMPOSE_FEE_PARAM_BAD_TYPE = -2,
    DAP_CHAIN_NET_VOTE_COMPOSE_WALLET_DOES_NOT_EXIST = -3,
    DAP_CHAIN_NET_VOTE_COMPOSE_SOURCE_ADDRESS_INVALID = -4,
    DAP_CHAIN_NET_VOTE_COMPOSE_CERT_REQUIRED = -5,
    DAP_CHAIN_NET_VOTE_COMPOSE_NO_KEY_FOUND_IN_CERT = -6,
    DAP_CHAIN_NET_VOTE_COMPOSE_FAILED_TO_RETRIEVE_COINS_FROM_LEDGER = -7,
    DAP_CHAIN_NET_VOTE_COMPOSE_KEY_IS_NOT_DELEGATED = -8,
    DAP_CHAIN_NET_VOTE_COMPOSE_NOT_ENOUGH_FUNDS_TO_TRANSFER = -9,
    DAP_CHAIN_NET_VOTE_COMPOSE_INTEGER_OVERFLOW = -10,
    DAP_CHAIN_NET_VOTE_COMPOSE_UNSPENT_UTX0_FOR_PARTICIPATION_THIS_VOTING = -11,
    DAP_CHAIN_NET_VOTE_COMPOSE_INVALID_OPTION_INDEX = -12,
    DAP_CHAIN_NET_VOTE_COMPOSE_CAN_NOT_CREATE_VOTE_ITEM = -13,
    DAP_CHAIN_NET_VOTE_COMPOSE_CAN_NOT_GET_STAKE_LIST = -14,
    DAP_CHAIN_NET_VOTE_COMPOSE_CAN_NOT_CREATE_TSD_TX_COND_ITEM = -15,
    DAP_CHAIN_NET_VOTE_COMPOSE_CAN_NOT_ADD_NET_FEE_OUT = -16,
    DAP_CHAIN_NET_VOTE_COMPOSE_CAN_NOT_ADD_OUT_WITH_VALUE_BACK = -17,
    DAP_CHAIN_NET_VOTE_COMPOSE_THIS_VOTING_HAVE_MAX_VALUE_VOTES = -18,
    DAP_CHAIN_NET_VOTE_COMPOSE_ALREADY_EXPIRED = -19,
    DAP_CHAIN_NET_VOTE_COMPOSE_DOES_NOT_ALLOW_CHANGE_YOUR_VOTE = -20,
    DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS = -21,
    DAP_CHAIN_NET_VOTE_COMPOSE_ERR_NOT_ENOUGH_FUNDS = -22,
    DAP_CHAIN_NET_VOTE_COMPOSE_FAILED_TO_GET_REMOTE_WALLET_OUTS = -23,
    DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_FEE = -24
} dap_chain_net_vote_compose_error_t;

dap_chain_datum_tx_t* dap_chain_tx_compose_datum_poll_vote(dap_cert_t *a_cert, uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, dap_hash_fast_t a_hash,
                              uint64_t a_option_idx, dap_chain_tx_compose_config_t *a_config) {
    dap_return_val_if_pass(!a_config, NULL);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    const char * l_hash_str = dap_chain_hash_fast_to_str_static(&a_hash);

    dap_json_t *l_json_voting = dap_request_command_to_rpc_with_params(a_config, "poll", "dump;-need_vote_list;-net;%s;-hash;%s", 
                                                                      a_config->net_name, l_hash_str);
    if (!l_json_voting) {
        log_it(L_ERROR, "can't get voting info");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Error: Can't get voting info\n");
        return NULL;
    }

    
    dap_json_t *l_voting_info = dap_json_array_get_idx(l_json_voting, 0);
    if (!l_voting_info) {
        log_it(L_ERROR, "can't get voting info from JSON");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Error: Can't get voting info from JSON\n");
        return NULL;
    }

    const char *l_voting_tx = dap_json_object_get_string(l_voting_info, "voting_tx");
    const char *l_expiration_str = dap_json_object_get_string(l_voting_info, "expiration");
    const char *l_status = dap_json_object_get_string(l_voting_info, "status");
    int l_votes_max = dap_json_object_get_int(l_voting_info, "votes_max");
    int l_votes_available = dap_json_object_get_int(l_voting_info, "votes_available");
    bool l_vote_changed = dap_json_object_get_bool(l_voting_info, "can_change_status");
    bool l_delegated_key_required = dap_json_object_get_bool(l_voting_info, "delegated_key_required");
    char l_token_ticker[10] = {0};
    dap_stpcpy(l_token_ticker, dap_json_object_get_string(l_voting_info, "token"));

    dap_json_t *l_options = dap_json_object_get_object(l_voting_info, "results");
    if (!l_options) {
        log_it(L_ERROR, "can't get options from JSON");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Error: Can't get options from JSON\n");
        return NULL;
    }

    uint64_t l_options_count = dap_json_array_length(l_options);
    if (a_option_idx >= l_options_count) {
        log_it(L_ERROR, "invalid option index");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_INVALID_OPTION_INDEX, "Invalid option index\n");
        return NULL;
    }

    dap_json_t *l_results = dap_json_object_get_object(l_voting_info, "results");
    if (!l_results) {
        log_it(L_ERROR, "can't get results from JSON");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Error: Can't get results from JSON\n");
        return NULL;
    }

    int l_results_count = dap_json_array_length(l_results);


    if (l_votes_max && l_votes_max <= l_results_count) {
        log_it(L_ERROR, "this voting have max value votes");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_THIS_VOTING_HAVE_MAX_VALUE_VOTES, "This voting have max value votes\n");
        return NULL;
    }

    if (l_expiration_str) {
        dap_time_t l_expiration_time = dap_time_from_str_rfc822(l_expiration_str);
        if (l_expiration_time && dap_time_now() > l_expiration_time) {
            log_it(L_ERROR, "this voting already expired");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_ALREADY_EXPIRED, "This voting already expired\n");
            return NULL;
        }
    }
    dap_hash_fast_t l_pkey_hash = {0};
#else
    dap_hash_fast_t l_pkey_hash = a_wallet_addr->data.hash_fast;
    char l_token_ticker[10] = "vBUZ"; // todo: remove this
    bool l_delegated_key_required = false;
#endif
    if (l_delegated_key_required) {
        if (!a_cert) {
            log_it(L_ERROR, "certificate is required for delegated key voting");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_CERT_REQUIRED, "Certificate is required for delegated key voting\n");
            return NULL;
        }
        if (dap_cert_get_pkey_hash(a_cert, &l_pkey_hash)) {
            log_it(L_ERROR, "no key found in certificate");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_NO_KEY_FOUND_IN_CERT, "No key found in certificate\n");
            return NULL;
        }

        dap_json_t *l_json_coins = dap_request_command_to_rpc_with_params(a_config, "srv_stake", "list;keys;-net;%s", a_config->net_name);
        if (!l_json_coins) {
            log_it(L_ERROR, "failed to retrieve coins from ledger");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_FAILED_TO_RETRIEVE_COINS_FROM_LEDGER, "Failed to retrieve coins from ledger\n");
            return NULL;
        }

        char l_hash_fast_str[DAP_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(&l_pkey_hash, l_hash_fast_str, sizeof(l_hash_fast_str));
        if (strlen(l_hash_fast_str) == 0) {
            log_it(L_ERROR, "can't covert l_pkey_hash to str");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_FAILED_TO_RETRIEVE_COINS_FROM_LEDGER, "Can't covert l_pkey_hash to str");
            return NULL;
        }
        int items_count = dap_json_array_length(l_json_coins);
        bool found = false;
        for (int i = 0; i < items_count; i++) {
            dap_json_t *item = dap_json_array_get_idx(l_json_coins, i);
            const char *pkey_hash_str = dap_json_object_get_string(item, "pkey_hash");
            if (!dap_strcmp(l_hash_fast_str, pkey_hash_str)) {
                const char *tx_hash_str = dap_json_object_get_string(item, "tx_hash");
                if (dap_chain_hash_fast_from_str(tx_hash_str, &l_pkey_hash)) {
                    log_it(L_ERROR, "invalid transaction hash format");
                    dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_KEY_IS_NOT_DELEGATED, "Invalid transaction hash format\n");
                    return NULL;
                }
                found = true;
                break;
            }
        }
        if (!found) {
            log_it(L_ERROR, "specified certificate/pkey hash is not delegated nor this delegating is approved");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_KEY_IS_NOT_DELEGATED, 
                                            "Specified certificate/pkey hash is not delegated nor this delegating is approved. Try to invalidate with tx hash instead\n");
            return NULL;
        }


    } else
        l_pkey_hash = a_wallet_addr->data.hash_fast;



    uint256_t l_net_fee = {}, l_total_fee = a_fee, l_value_transfer, l_fee_transfer;
    dap_chain_addr_t *l_addr_fee = NULL;
    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);
    if (l_net_fee_used)
        SUM_256_256(l_net_fee, a_fee, &l_total_fee);

    bool l_native_tx = !dap_strcmp(l_token_ticker, a_config->native_ticker);

    dap_json_t *l_outs = NULL;
    int l_outputs_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    if (!dap_chain_tx_compose_get_remote_wallet_outs_and_count(a_wallet_addr, l_token_ticker, &l_outs, &l_outputs_count, a_config)) {
        log_it(L_ERROR, "failed to get remote wallet outs");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_FAILED_TO_GET_REMOTE_WALLET_OUTS, "Failed to get remote wallet outs\n");
        DAP_DELETE(l_addr_fee);
        return NULL;
    }
#endif

    // todo replace with func witch will return all outpurs not only enough outputs
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                            l_total_fee,
                                                            &l_value_transfer, true);
    dap_json_object_free(l_outs);
    if (!l_list_used_out) {
        log_it(L_ERROR, "not enough funds to transfer");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_NOT_ENOUGH_FUNDS_TO_TRANSFER, "Not enough funds to transfer");
        DAP_DELETE(l_addr_fee);
        return NULL;
    }

    uint256_t l_value_transfer_new = {};
    int l_votes_count = 0;
#ifndef DAP_CHAIN_TX_COMPOSE_TEST   
    dap_json_t *l_votes_list = dap_json_object_get_object(l_voting_info, "votes_list");
    if (!l_votes_list) { 
        log_it(L_ERROR, "can't get voting list");
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_CAN_NOT_GET_TX_OUTS, "Error: Can't get voting list\n");
        DAP_DELETE(l_addr_fee);
        return NULL;
    }

    if (dap_json_is_array(l_votes_list)) {
        l_votes_count = dap_json_array_length(l_votes_list);
    } else {
        l_votes_count = 0;
    }

    for (int i = 0; i < l_votes_count; i++) {
        dap_json_t *l_vote = dap_json_array_get_idx(l_votes_list, i);
        const char *l_vote_pkey_hash = dap_json_object_get_string(l_vote, "pkey_hash");
        char l_pkey_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(&l_pkey_hash, l_pkey_hash_str, sizeof(l_pkey_hash_str));
        if (!dap_strcmp(l_vote_pkey_hash, l_pkey_hash_str)) {
            if (!l_vote_changed) {
                log_it(L_ERROR, "the poll doesn't allow change your vote");
                dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_DOES_NOT_ALLOW_CHANGE_YOUR_VOTE, "The poll doesn't allow change your vote.");
                dap_json_object_free(l_json_voting);
                DAP_DELETE(l_addr_fee);
                return NULL;
            }
        }
    }
    // No need to call get() in dap_json
    dap_json_object_free(l_json_voting);

    if (l_votes_count > 0) {
        dap_list_t *it, *tmp;
        DL_FOREACH_SAFE(l_list_used_out, it, tmp) {
            dap_chain_tx_used_out_item_t *l_out = (dap_chain_tx_used_out_item_t *)it->data;
            if (s_datum_tx_voting_coin_check_spent_compose(l_votes_list, l_out->tx_hash_fast, l_out->num_idx_out,
                                                l_vote_changed ? &l_pkey_hash : NULL)) {
                l_list_used_out = dap_list_delete_link(l_list_used_out, it);
                continue;
            }
            if (SUM_256_256(l_value_transfer_new, l_out->value, &l_value_transfer_new)) {
                log_it(L_ERROR, "failed to sum value");
                DAP_DELETE(l_addr_fee);
                return NULL;
            }
        }
        if (IS_ZERO_256(l_value_transfer_new) || (l_native_tx && compare256(l_value_transfer_new, l_total_fee) <= 0)) {
            DAP_DEL_Z(l_addr_fee);
            return NULL;
        }
        l_value_transfer = l_value_transfer_new;
    }
#else
    randombytes(&l_value_transfer_new, sizeof(l_value_transfer_new));
#endif


    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    uint256_t l_value_back = l_value_transfer, l_fee_back = {};
    if (!l_native_tx) {
        dap_list_t *l_list_fee_outs = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                               l_total_fee, 
                                                               &l_fee_transfer, false);
        if (!l_list_fee_outs) {
            log_it(L_ERROR, "not enough funds to pay fee");
            dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_COMPOSE_ERROR_FEE, "Not enough funds to pay fee");
            dap_json_object_free(l_outs);
            DAP_DELETE(l_addr_fee);
            return NULL;
        }

        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_outs);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST  
        assert(EQUAL_256(l_value_fee_items, l_fee_transfer));
#endif
        dap_list_free_full(l_list_fee_outs, NULL);
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_fee_back);
    } else
        SUBTRACT_256_256(l_value_transfer, l_total_fee, &l_value_back);

    // add 'in' items
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST  
    assert(EQUAL_256(l_value_to_items, l_value_transfer));
#endif
    dap_list_free_full(l_list_used_out, NULL);

    dap_chain_tx_vote_t *l_vote_item = dap_chain_datum_tx_item_vote_create(&a_hash, &a_option_idx);
    if(!l_vote_item){
        log_it(L_ERROR, "Failed to create vote item");
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_addr_fee);
        return NULL;
    }
    dap_chain_datum_tx_add_item(&l_tx, l_vote_item);
    DAP_DEL_Z(l_vote_item);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST  
    dap_json_t *l_cond_tx_outputs_raw = dap_request_command_to_rpc_with_params(a_config, "wallet", "outputs;-addr;%s;-net;%s;-token;%s;-cond;-mempool_check",
                                                                            dap_chain_addr_to_str(a_wallet_addr), a_config->net_name, l_token_ticker);
    if (!l_cond_tx_outputs_raw) {
        log_it(L_ERROR, "Failed to get cond tx outputs");
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_addr_fee);
        return NULL;
    }

    if (!dap_json_is_array(l_cond_tx_outputs_raw)) {
        log_it(L_ERROR, "Invalid cond tx outputs");
        dap_chain_datum_tx_delete(l_tx);
        dap_json_object_free(l_cond_tx_outputs_raw);
        DAP_DELETE(l_addr_fee);
        return NULL;
    }

    dap_json_t *l_first_array = dap_json_array_get_idx(l_cond_tx_outputs_raw, 0);
    if (!l_first_array || !dap_json_is_array(l_first_array)) {
        log_it(L_ERROR, "Invalid cond tx outputs");
        dap_chain_datum_tx_delete(l_tx);
        dap_json_object_free(l_cond_tx_outputs_raw);
        DAP_DELETE(l_addr_fee);
        return NULL;
    }

    dap_json_t *l_first_item = dap_json_array_get_idx(l_first_array, 0);
    if (!l_first_item) {
        log_it(L_ERROR, "Invalid cond tx outputs");
        dap_chain_datum_tx_delete(l_tx);
        dap_json_object_free(l_cond_tx_outputs_raw);
        DAP_DELETE(l_addr_fee);
        return NULL;
    }

    dap_json_t *l_cond_tx_outputs = NULL;
    dap_json_object_get_ex(l_first_item, "outs", &l_cond_tx_outputs);
    if (!l_cond_tx_outputs) {
        log_it(L_ERROR, "Invalid cond tx outputs");
        dap_chain_datum_tx_delete(l_tx);
        dap_json_object_free(l_cond_tx_outputs_raw);
        DAP_DELETE(l_addr_fee);
        return NULL;
    }

    size_t l_cond_outputs_count = dap_json_array_length(l_cond_tx_outputs);

    dap_list_t *l_cond_outs = dap_ledger_get_list_tx_outs_from_json(l_cond_tx_outputs, l_cond_outputs_count,
                                                            l_total_fee,    
                                                            &l_value_transfer, true);
    for (dap_list_t *it = l_cond_outs; it; it = it->next) {
        dap_chain_tx_used_out_item_t *l_out_item = (dap_chain_tx_used_out_item_t *)it->data;
        if (l_votes_count > 0) { 
            if (s_datum_tx_voting_coin_check_spent_compose(l_votes_list, l_out_item->tx_hash_fast, l_out_item->num_idx_out,
                                                    l_vote_changed ? &l_pkey_hash : NULL) != 0)
                continue;
        }
        dap_chain_tx_tsd_t *l_item = dap_chain_datum_voting_vote_tx_cond_tsd_create(l_out_item->tx_hash_fast, l_out_item->num_idx_out);
        if(!l_item){
            log_it(L_ERROR, "Failed to create cond tx tsd");
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_addr_fee);
            dap_list_free_full(l_cond_outs, NULL);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_item);
        DAP_DELETE(l_item);
    }
    dap_list_free_full(l_cond_outs, NULL);
#endif
    // Network fee
    if (l_net_fee_used && dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, a_config->native_ticker) != 1) {
        log_it(L_ERROR, "failed to add network fee output");
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_addr_fee);
        return NULL;
    }
    DAP_DEL_Z(l_addr_fee);
    // Validator's fee
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
        log_it(L_ERROR, "Failed to add fee output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    // coin back
    if (!IS_ZERO_256(l_value_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, l_token_ticker) != 1) {
        log_it(L_ERROR, "Failed to add coin back output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    if (!IS_ZERO_256(l_fee_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_fee_back, a_config->native_ticker) != 1) {
        log_it(L_ERROR, "failed to add coin back output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    return l_tx;
}

/**
 * @brief CLI vote cancel compose
 * @details Creates a cancel vote transaction through compose interface
 */
typedef enum {
    DAP_CLI_VOTE_CANCEL_COMPOSE_OK = 0,
    DAP_CLI_VOTE_CANCEL_COMPOSE_INVALID_CONFIG = -1,
    DAP_CLI_VOTE_CANCEL_COMPOSE_INVALID_HASH = -2,
    DAP_CLI_VOTE_CANCEL_COMPOSE_INVALID_FEE = -3,
    DAP_CLI_VOTE_CANCEL_COMPOSE_WALLET_NOT_FOUND = -4,
    DAP_CLI_VOTE_CANCEL_COMPOSE_NOT_OWNER = -5,
    DAP_CLI_VOTE_CANCEL_COMPOSE_VOTING_NOT_FOUND = -6
} dap_cli_vote_cancel_compose_error_t;

dap_json_t *dap_cli_vote_cancel_compose(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                    uint16_t a_port, const char *a_enc_cert_path, const char *a_hash_str, const char *a_cert_name, const char *a_fee_str, dap_chain_addr_t *a_wallet_addr) {
    dap_chain_tx_compose_config_t *l_config = dap_chain_tx_compose_config_init(a_net_id, a_net_name, a_native_ticker, a_url_str, a_port, a_enc_cert_path);
    if (!l_config) {
        dap_json_t *l_json_obj_ret = dap_json_object_new();
        dap_json_compose_error_add(l_json_obj_ret, DAP_CLI_VOTE_CANCEL_COMPOSE_INVALID_CONFIG, "Can't create compose config");
        return l_json_obj_ret;
    }

    dap_hash_fast_t l_voting_hash = {};
    if (dap_chain_hash_fast_from_str(a_hash_str, &l_voting_hash)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_CLI_VOTE_CANCEL_COMPOSE_INVALID_HASH, 
                                   "Hash string is not recognized as hex or base58 hash\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    uint256_t l_value_fee = dap_chain_balance_scan(a_fee_str);
    if (IS_ZERO_256(l_value_fee)) {
        dap_json_compose_error_add(l_config->response_handler, DAP_CLI_VOTE_CANCEL_COMPOSE_INVALID_FEE, 
                                   "Command requires parameter '-fee' to be valid uint256\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    if (!a_wallet_addr) {
        dap_json_compose_error_add(l_config->response_handler, DAP_CLI_VOTE_CANCEL_COMPOSE_WALLET_NOT_FOUND, 
                                   "Wallet address is required\n");
        return dap_chain_tx_compose_config_return_response_handler(l_config);
    }

    dap_chain_datum_tx_t *l_tx = dap_chain_net_vote_cancel_compose(l_value_fee, a_wallet_addr, l_voting_hash, l_config);
    if (l_tx) {
        dap_chain_net_tx_to_json(l_tx, l_config->response_handler);
        dap_chain_datum_tx_delete(l_tx);
    }
    return dap_chain_tx_compose_config_return_response_handler(l_config);
}

/**
 * @brief Create vote cancel transaction
 * @details Composes transaction to cancel a voting
 */
typedef enum {
    DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_OK = 0,
    DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_INVALID_CONFIG = -1,
    DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_VOTING_NOT_FOUND = -2,
    DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_NOT_OWNER = -3,
    DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_EXPIRED = -4,
    DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_NO_FUNDS = -5,
    DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_FAILED_TO_CREATE_VOTE_ITEM = -6,
    DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_FAILED_TO_CREATE_CANCEL_TSD = -7
} dap_chain_net_vote_cancel_compose_error_t;

dap_chain_datum_tx_t* dap_chain_net_vote_cancel_compose(uint256_t a_fee, dap_chain_addr_t *a_wallet_addr,
                                                         dap_hash_fast_t a_voting_hash,
                                                         dap_chain_tx_compose_config_t *a_config) {
    if (!a_config) {
        return NULL;
    }

#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    // Get voting info from remote node
    const char *l_hash_str = dap_chain_hash_fast_to_str_static(&a_voting_hash);
    dap_json_t *l_json_voting = dap_request_command_to_rpc_with_params(a_config, "poll", 
                                                                        "dump;-net;%s;-hash;%s", 
                                                                        a_config->net_name, l_hash_str);
    if (!l_json_voting) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_VOTING_NOT_FOUND,
                                   "Can't find voting with hash %s\n", l_hash_str);
        return NULL;
    }

    dap_json_t *l_voting_info = dap_json_array_get_idx(l_json_voting, 0);
    if (!l_voting_info) {
        dap_json_object_free(l_json_voting);
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_VOTING_NOT_FOUND,
                                   "Can't get voting info from JSON\n");
        return NULL;
    }

    // Check status
    dap_json_t *l_status_obj = NULL;
    dap_json_object_get_ex(l_voting_info, "status", &l_status_obj);
    const char *l_status = l_status_obj ? dap_json_get_string(l_status_obj) : NULL;
    
    if (l_status && (!dap_strcmp(l_status, "expired") || !dap_strcmp(l_status, "cancelled"))) {
        dap_json_object_free(l_json_voting);
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_EXPIRED,
                                   "Voting is already %s\n", l_status);
        return NULL;
    }

    // Check owner - get creator address
    dap_json_t *l_creator_addr_obj = NULL;
    dap_json_object_get_ex(l_voting_info, "creator_addr", &l_creator_addr_obj);
    const char *l_creator_addr_str = l_creator_addr_obj ? dap_json_get_string(l_creator_addr_obj) : NULL;
    
    if (!l_creator_addr_str) {
        dap_json_object_free(l_json_voting);
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_VOTING_NOT_FOUND,
                                   "Can't get creator address from voting info\n");
        return NULL;
    }

    dap_chain_addr_t *l_creator_addr = dap_chain_addr_from_str(l_creator_addr_str);
    if (!l_creator_addr) {
        dap_json_object_free(l_json_voting);
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_VOTING_NOT_FOUND,
                                   "Invalid creator address format\n");
        return NULL;
    }
    
    // Check if wallet address matches creator address
    if (!dap_chain_addr_compare(a_wallet_addr, l_creator_addr)) {
        DAP_DELETE(l_creator_addr);
        dap_json_object_free(l_json_voting);
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_NOT_OWNER,
                                   "You don't have rights to cancel this voting. Owner: %s, Your address: %s\n",
                                   l_creator_addr_str, dap_chain_addr_to_str(a_wallet_addr));
        return NULL;
    }
    DAP_DELETE(l_creator_addr);

    dap_json_object_free(l_json_voting);
#endif

    // Get native ticker and calculate fees
    const char *l_native_ticker = a_config->native_ticker;
    uint256_t l_net_fee = {}, l_total_fee = {};
    dap_chain_addr_t *l_addr_fee = NULL;
    bool l_net_fee_used = dap_chain_tx_compose_get_remote_net_fee_and_address(&l_net_fee, &l_addr_fee, a_config);
    SUM_256_256(l_net_fee, a_fee, &l_total_fee);

    // Get wallet outputs
    dap_json_t *l_outs = NULL;
    int l_outputs_count = 0;
    uint256_t l_value_transfer = {};
    
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    if (!dap_chain_tx_compose_get_remote_wallet_outs_and_count(a_wallet_addr, l_native_ticker, 
                                                                &l_outs, &l_outputs_count, a_config)) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_NO_FUNDS,
                                   "Failed to get wallet outputs\n");
        return NULL;
    }

    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_from_json(l_outs, l_outputs_count,
                                                                         l_total_fee, &l_value_transfer, false);
    dap_json_object_free(l_outs);
    
    if (!l_list_used_out) {
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_NO_FUNDS,
                                   "Not enough funds to pay fees\n");
        return NULL;
    }
#else
    dap_list_t *l_list_used_out = NULL;
#endif

    // Create transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // Create vote item with index 0 (for cancel)
    uint64_t l_answer_idx = 0;
    dap_chain_tx_vote_t *l_vote_item = dap_chain_datum_tx_item_vote_create(&a_voting_hash, &l_answer_idx);
    if (!l_vote_item) {
        dap_chain_datum_tx_delete(l_tx);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        dap_list_free_full(l_list_used_out, NULL);
#endif
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_FAILED_TO_CREATE_VOTE_ITEM,
                                   "Failed to create vote item\n");
        return NULL;
    }
    dap_chain_datum_tx_add_item(&l_tx, l_vote_item);
    DAP_DEL_Z(l_vote_item);

    // Add TSD with voting hash to cancel
    dap_chain_tx_tsd_t *l_cancel_tsd = dap_chain_datum_voting_cancel_tsd_create(a_voting_hash);
    if (!l_cancel_tsd) {
        dap_chain_datum_tx_delete(l_tx);
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        dap_list_free_full(l_list_used_out, NULL);
#endif
        dap_json_compose_error_add(a_config->response_handler, DAP_CHAIN_NET_VOTE_CANCEL_COMPOSE_FAILED_TO_CREATE_CANCEL_TSD,
                                   "Failed to create cancel TSD\n");
        return NULL;
    }
    dap_chain_datum_tx_add_item(&l_tx, l_cancel_tsd);
    DAP_DEL_Z(l_cancel_tsd);

#ifndef DAP_CHAIN_TX_COMPOSE_TEST
    // Add 'in' items
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    assert(EQUAL_256(l_value_to_items, l_value_transfer));
    dap_list_free_full(l_list_used_out, NULL);
#endif

    uint256_t l_value_pack = {};
    
    // Network fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_fee, l_net_fee, l_native_ticker) == 1)
            SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
        else {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, -1, "Failed to add network fee output\n");
            return NULL;
        }
    }

    // Validator's fee
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) == 1)
            SUM_256_256(l_value_pack, a_fee, &l_value_pack);
        else {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, -1, "Failed to add validator fee\n");
            return NULL;
        }
    }

    // Coin back
    uint256_t l_value_back;
    SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_back, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            dap_json_compose_error_add(a_config->response_handler, -1, "Failed to add coin back output\n");
            return NULL;
        }
    }

    return l_tx;
}
