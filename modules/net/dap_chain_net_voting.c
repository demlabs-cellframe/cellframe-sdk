/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
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

#include "dap_chain_common.h"
#include "dap_chain_net_voting.h"
#include "dap_chain_ledger.h"



#define LOG_TAG "chain_net_voting"

typedef struct dap_chain_net_voting_params_offsets{
    dap_chain_datum_tx_t* voting_tx;
    size_z voting_question_offset;
    dap_list_t* answers_list_offset;
    uint64_t answers_count;
    size_z voting_expire_offset;
    size_z votes_max_count_offset;
    size_z delegate_key_required_offset;
    size_z vote_changing_allowed_offset;
} dap_chain_net_voting_params_offsets_t;

typedef struct dap_chain_net_vote {
    dap_chain_hash_fast_t vote_hash;
    uint8_t answer_id;
    UT_hash_handle hh;
}dap_chain_net_vote_t;

typedef struct dap_chain_net_votings {
    dap_chain_hash_fast_t voting_hash;
    dap_chain_net_voting_params_offsets_t *voting_params;
    dap_chain_net_vote_t *votes;
    UT_hash_handle hh;
} dap_chain_net_votings_t;

static dap_chain_net_votings_t *s_votings;
static  pthread_rwlock_t s_verificators_rwlock;

static bool s_datum_tx_voting_verification_callback(dap_chain_datum_tx_t *a_tx_in);


int dap_chain_datum_tx_voting_init()
{

    dap_chain_ledger_voting_verificator_add(s_datum_tx_voting_verification_callback);

}


bool s_datum_tx_voting_verification_callback(dap_chain_datum_tx_t *a_tx_in)
{
    return false;
}
