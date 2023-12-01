/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020, All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include <stdint.h>
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_time.h"
#include "dap_list.h"
#include "dap_tsd.h"


#define DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH 200
#define DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_LENGTH 100
#define DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT 10


typedef enum dap_chain_datum_voting_tsd_type {
    VOTING_TSD_TYPE_QUESTION = 0x01,
    VOTING_TSD_TYPE_ANSWER,
    VOTING_TSD_TYPE_EXPIRE,
    VOTING_TSD_TYPE_MAX_VOTES_COUNT,
    VOTING_TSD_TYPE_DELEGATED_KEY_REQUIRED,
    VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED
} dap_chain_datum_voting_tsd_type_t;

typedef struct dap_chain_tx_voting {
    dap_chain_tx_item_type_t type;
} DAP_ALIGN_PACKED dap_chain_tx_voting_t;

typedef struct dap_chain_tx_vote {
    dap_chain_tx_item_type_t type;
    dap_chain_hash_fast_t voting_hash;
    uint64_t answer_idx;
} DAP_ALIGN_PACKED dap_chain_tx_vote_t;


typedef struct dap_chain_datum_tx_voting_params {
    char *voting_question;
    dap_list_t *answers_list;
    uint8_t    answers_count;
    dap_time_t voting_expire;
    uint64_t   votes_max_count;
    bool       delegate_key_required;
    bool       vote_changing_allowed;
} dap_chain_datum_tx_voting_params_t;


dap_chain_datum_tx_voting_params_t *dap_chain_voting_parse_tsd(dap_chain_datum_tx_t* a_tx);

dap_chain_tx_tsd_t* dap_chain_datum_voting_question_tsd_create(const char* a_question_str, size_t str_len);
dap_chain_tx_tsd_t* dap_chain_datum_voting_answer_tsd_create(const char* a_answer_str, size_t str_len);
dap_chain_tx_tsd_t* dap_chain_datum_voting_expire_tsd_create(dap_time_t a_expire);
dap_chain_tx_tsd_t* dap_chain_datum_voting_max_votes_count_tsd_create(uint64_t a_max_count);
dap_chain_tx_tsd_t* dap_chain_datum_voting_delegated_key_required_tsd_create(bool a_delegate_key_required);
dap_chain_tx_tsd_t* dap_chain_datum_voting_vote_changing_allowed_tsd_create(bool a_vote_changing_allowed);

dap_chain_tx_voting_t *dap_chain_datum_tx_item_voting_create(void);
json_object *dap_chain_datum_tx_item_voting_tsd_to_json(dap_chain_datum_tx_t* a_tx);


dap_chain_tx_vote_t *dap_chain_datum_tx_item_vote_create(dap_chain_hash_fast_t *a_voting_hash, uint64_t *a_answer_idx);
json_object *dap_chain_datum_tx_item_vote_to_json(dap_chain_tx_vote_t *a_vote);
