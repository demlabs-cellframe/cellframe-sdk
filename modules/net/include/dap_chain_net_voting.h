/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2022
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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
#include "dap_chain_datum_tx_voting.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_chain_wallet.h"


typedef struct dap_chain_net_voting_result {
    uint64_t answer_idx;
    uint64_t votes_count;
} dap_chain_net_voting_result_t;

typedef struct dap_chain_net_voting_params_offsets{
    dap_chain_datum_tx_t* voting_tx;
    size_t voting_question_offset;
    size_t voting_question_length;
    dap_list_t* option_offsets_list;
    size_t voting_expire_offset;
    size_t votes_max_count_offset;
    size_t delegate_key_required_offset;
    size_t vote_changing_allowed_offset;
} dap_chain_net_voting_params_offsets_t;

typedef struct dap_chain_net_voting{
    dap_hash_fast_t hash_vote;
    dap_chain_net_id_t net_id;
}dap_chain_net_voting_t;

int dap_chain_net_voting_init();


uint64_t* dap_chain_net_voting_get_result(dap_ledger_t* a_ledger, dap_chain_hash_fast_t* a_voting_hash);

enum DAP_CHAIN_NET_VOTE_CREATE_ERROR {
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
    DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_POOL_DATUM_IN_MEMPOOL
};
int dap_chain_net_vote_create(char *a_question, dap_list_t *a_options, dap_time_t *a_expire_vote,
                             uint64_t *a_max_vote, uint256_t a_fee, bool a_delegated_key_required,
                             bool a_vote_changing_allowed, dap_chain_wallet_t *a_wallet,
                             dap_chain_net_t *a_net, char *a_hash_out_type, char **a_hash_output);

dap_list_t *dap_chain_net_vote_list(dap_chain_net_t *a_net);

/**
dap_chain_net_voting_create_vote(...);
dap_chain_net_voting_vote(dap_hash_fast_t a_vote_hash)
dap_chain_net_voting_get_vote(dap_hash_fast_t a_vote_hash)
 */

dap_list_t *dap_chain_net_voting_get_list(dap_chain_net_t *a_net);
