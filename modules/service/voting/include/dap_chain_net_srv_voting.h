/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2022
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "dap_chain_ledger.h"
#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_chain_wallet.h"

#define DAP_CHAIN_NET_SRV_VOTING_ID 0x06

typedef struct dap_chain_net_voting_info_option {
    uint64_t option_idx;
    uint64_t votes_count;
    uint256_t weight;
    uint64_t description_size;
    char *description;
    dap_list_t *hashes_tx_votes;
} dap_chain_net_voting_option_info_t;

typedef struct dap_chain_net_voting_info {
    dap_hash_fast_t hash;
    dap_chain_net_id_t net_id;
    bool is_expired;
    bool is_cancelled;
    dap_time_t expired;
    bool is_max_count_votes;
    uint64_t max_count_votes;
    bool is_changing_allowed;
    bool is_delegate_key_required;
    struct {
        size_t question_size;
        char *question_str;
    } question;
    struct {
        uint64_t count_option;
        dap_chain_net_voting_option_info_t **options;
    } options;
} dap_chain_net_voting_info_t;

enum DAP_CHAIN_NET_SRV_VOTING_CLI_ERRORS {
    DAP_CHAIN_NET_VOTE_CREATE_OK,
    DAP_CHAIN_NET_VOTE_CREATE_LENGTH_QUESTION_OVERSIZE_MAX,
    DAP_CHAIN_NET_VOTE_CREATE_COUNT_OPTION_OVERSIZE_MAX,
    DAP_CHAIN_NET_VOTE_CREATE_FEE_IS_ZERO,
    DAP_CHAIN_NET_VOTE_CREATE_SOURCE_ADDRESS_IS_INVALID,
    DAP_CHAIN_NET_VOTE_CREATE_NOT_ENOUGH_FUNDS_TO_TRANSFER,
    DAP_CHAIN_NET_VOTE_CREATE_MAX_COUNT_OPTION_EXCEEDED,
    DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_OPTION_TSD_ITEM,
    DAP_CHAIN_NET_VOTE_CREATE_INPUT_TIME_MORE_CURRENT_TIME,
    DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_EXPIRE_TIME,
    DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_DELEGATE_KEY,
    DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_ADD_NET_FEE_OUT,
    DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_ADD_OUT_WITH_VALUE_BACK,
    DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_SIGNED_TX,
    DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_POOL_DATUM_IN_MEMPOOL,
    DAP_CHAIN_NET_VOTE_CREATE_QUESTION_PARAM_MISSING,
    DAP_CHAIN_NET_VOTE_CREATE_OPTION_PARAM_MISSING,
    DAP_CHAIN_NET_VOTE_CREATE_NUMBER_OPTIONS_ERROR,
    DAP_CHAIN_NET_VOTE_CREATE_CONTAIN_MAX_OPTIONS,
    DAP_CHAIN_NET_VOTE_CREATE_FEE_PARAM_NOT_VALID,
    DAP_CHAIN_NET_VOTE_CREATE_WALLET_PARAM_NOT_VALID,
    DAP_CHAIN_NET_VOTE_CREATE_WALLET_DOES_NOT_EXIST,
    DAP_CHAIN_NET_VOTE_CREATE_WRONG_TIME_FORMAT,
    DAP_CHAIN_NET_VOTE_CREATE_WRONG_TOKEN,
    DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_TOKEN,
    DAP_CHAIN_NET_VOTE_CREATE_UNKNOWN_ERR,
    DAP_CHAIN_NET_VOTE_CREATE_ERROR_CAN_NOT_GET_TX_OUTS,

    DAP_CHAIN_NET_VOTE_VOTING_OK,
    DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_FIND_SERVICE,
    DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_FIND_VOTE,
    DAP_CHAIN_NET_VOTE_VOTING_THIS_VOTING_HAVE_MAX_VALUE_VOTES,
    DAP_CHAIN_NET_VOTE_VOTING_ALREADY_EXPIRED,
    DAP_CHAIN_NET_VOTE_VOTING_CANCELLED,
    DAP_CHAIN_NET_VOTE_VOTING_NO_KEY_FOUND_IN_CERT,
    DAP_CHAIN_NET_VOTE_VOTING_CERT_REQUIRED,
    DAP_CHAIN_NET_VOTE_VOTING_KEY_IS_NOT_DELEGATED,
    DAP_CHAIN_NET_VOTE_VOTING_DOES_NOT_ALLOW_CHANGE_YOUR_VOTE,
    DAP_CHAIN_NET_VOTE_VOTING_SOURCE_ADDRESS_INVALID,
    DAP_CHAIN_NET_VOTE_VOTING_NOT_ENOUGH_FUNDS_TO_TRANSFER,
    DAP_CHAIN_NET_VOTE_VOTING_UNSPENT_UTX0_FOR_PARTICIPATION_THIS_VOTING,
    DAP_CHAIN_NET_VOTE_VOTING_INVALID_OPTION_INDEX,
    DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_VOTE_ITEM,
    DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_TSD_TX_COND_ITEM,
    DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_NET_FEE_OUT,
    DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_OUT_WITH_VALUE_BACK,
    DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_SIGN_TX,
    DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_POOL_IN_MEMPOOL,
    DAP_CHAIN_NET_VOTE_VOTING_NET_PARAM_MISSING,
    DAP_CHAIN_NET_VOTE_VOTING_NET_PARAM_NOT_VALID,
    DAP_CHAIN_NET_VOTE_VOTING_HASH_NOT_FOUND,
    DAP_CHAIN_NET_VOTE_VOTING_HASH_INVALID,
    DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_FIND_CERT,
    DAP_CHAIN_NET_VOTE_VOTING_FEE_PARAM_NOT_VALID,
    DAP_CHAIN_NET_VOTE_VOTING_FEE_PARAM_BAD_TYPE,
    DAP_CHAIN_NET_VOTE_VOTING_WALLET_PARAM_NOT_VALID,
    DAP_CHAIN_NET_VOTE_VOTING_OPTION_IDX_PARAM_NOT_VALID,
    DAP_CHAIN_NET_VOTE_VOTING_WALLET_DOES_NOT_EXIST,
    DAP_CHAIN_NET_VOTE_VOTING_INTEGER_OVERFLOW,

    DAP_CHAIN_NET_VOTE_DUMP_HASH_PARAM_NOT_FOUND,
    DAP_CHAIN_NET_VOTE_DUMP_HASH_PARAM_INVALID,
    DAP_CHAIN_NET_VOTE_DUMP_CAN_NOT_FIND_VOTE,
    DAP_CHAIN_NET_VOTE_DUMP_NO_OPTIONS,
    DAP_CHAIN_NET_VOTE_DUMP_MEMORY_ERR,

    DAP_CHAIN_NET_VOTE_CANCEL_OK,
    DAP_CHAIN_NET_VOTE_CANCEL_HASH_NOT_FOUND,
    DAP_CHAIN_NET_VOTE_CANCEL_SERVICE_NOT_FOUND,
    DAP_CHAIN_NET_VOTE_CANCEL_HASH_INVALID,
    DAP_CHAIN_NET_VOTE_CANCEL_FEE_PARAM_NOT_VALID,
    DAP_CHAIN_NET_VOTE_CANCEL_FEE_PARAM_BAD_TYPE,
    DAP_CHAIN_NET_VOTE_CANCEL_WALLET_PARAM_NOT_VALID,
    DAP_CHAIN_NET_VOTE_CANCEL_WALLET_DOES_NOT_EXIST,
    DAP_CHAIN_NET_VOTE_CANCEL_VOTING_NOT_ACTIVE,
    DAP_CHAIN_NET_VOTE_CANCEL_VOTING_EXPIRED,
    DAP_CHAIN_NET_VOTE_CANCEL_VOTING_TX_NOT_FOUND,
    DAP_CHAIN_NET_VOTE_CANCEL_NO_RIGHTS,
    DAP_CHAIN_NET_VOTE_CANCEL_SOURCE_ADDRESS_INVALID,
    DAP_CHAIN_NET_VOTE_CANCEL_NOT_ENOUGH_FUNDS,
    DAP_CHAIN_NET_VOTE_CANCEL_CAN_NOT_CREATE_VOTE_ITEM,
    DAP_CHAIN_NET_VOTE_CANCEL_CAN_NOT_SIGN_TX,
    DAP_CHAIN_NET_VOTE_CANCEL_CAN_NOT_POOL_IN_MEMPOOL,
    DAP_CHAIN_NET_VOTE_CANCEL_UNKNOWN_ERR,

    DAP_CHAIN_NET_SRV_VOTING_UNKNOWN_ERR
};

#if defined(__cplusplus)
extern "C" {
#endif

int dap_chain_net_srv_voting_init();
void dap_chain_net_srv_voting_deinit();

uint64_t *dap_chain_net_srv_voting_get_result(dap_ledger_t* a_ledger, dap_chain_hash_fast_t* a_voting_hash);
dap_time_t dap_chain_net_srv_voting_get_expiration_time(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_voting_hash);

int dap_chain_net_srv_voting_create(const char *a_question, dap_list_t *a_options, dap_time_t a_expire_vote,
                                    uint64_t a_max_vote, uint256_t a_fee, bool a_delegated_key_required,
                                    bool a_vote_changing_allowed, dap_chain_wallet_t *a_wallet,
                                    dap_chain_net_t *a_net, const char *a_token_ticker,
                                    const char *a_hash_out_type, char **a_hash_output);


int dap_chain_net_srv_vote_create(dap_cert_t *a_cert, uint256_t a_fee, dap_chain_wallet_t *a_wallet, dap_hash_fast_t *a_voting_hash,
                              uint64_t a_option_idx, dap_chain_net_t *a_net, const char *a_hash_out_type,
                              char **a_hash_tx_out);

dap_list_t *dap_chain_net_voting_list(dap_chain_net_t *a_net);
dap_chain_net_voting_info_t *dap_chain_net_voting_extract_info(dap_chain_net_t *a_net, dap_hash_fast_t *a_voting_hash);
void dap_chain_net_voting_info_free(dap_chain_net_voting_info_t *a_info);
dap_list_t* dap_get_options_list_from_str(const char* a_str);
int dap_chain_net_vote_cancel(dap_json_t *a_json_reply, uint256_t a_fee, dap_chain_wallet_t *a_wallet, dap_hash_fast_t *a_voting_hash, dap_chain_net_t *a_net, const char *a_hash_out_type, char **a_hash_tx_out);

#if defined(__cplusplus)
}
#endif
