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
#include "dap_time.h"
#include "dap_list.h"
#include "dap_tsd.h"


#define DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH 200
#define DAP_CHAIN_DATUM_TX_VOTING_ANSWER_MAX_LENGTH 100
#define DAP_CHAIN_DATUM_TX_VOTING_ANSWER_MAX_COUNT 100


typedef enum dap_chain_datum_voting_tsd_type {
    VOTING_TSD_TYPE_QUESTION = 0x01,
    VOTING_TSD_TYPE_ANSWER,
    VOTING_TSD_TYPE_EXPIRE,
    VOTING_TSD_TYPE_MAX_VOTES_COUNT,
    VOTING_TSD_TYPE_DELEGATE_KEY_REQUIRED,
    VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED
} dap_chain_datum_voting_tsd_type_t;

typedef struct dap_chain_tx_voting {
    dap_chain_tx_item_type_t type;
} DAP_ALIGN_PACKED dap_chain_tx_voting_t;

typedef struct dap_chain_tx_vote {
    dap_chain_tx_item_type_t type;
    dap_chain_hash_fast_t voting_hash;
    uint8_t answer_idx;
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


dap_chain_datum_tx_voting_params_t *dap_chain_voting_parse_tsd(byte_t* a_tsd_data, size_t a_tsd_size);

dap_tsd_t* dap_chain_datum_voting_question_tsd_create(char* a_question_str, size_t str_len);
dap_tsd_t* dap_chain_datum_voting_answer_tsd_create(char* a_answer_str, size_t str_len);
dap_tsd_t* dap_chain_datum_voting_expire_tsd_create(dap_time_t a_expire);
dap_tsd_t* dap_chain_datum_voting_max_votes_count_tsd_create(uint64_t a_max_count);
dap_tsd_t* dap_chain_datum_voting_delegated_key_required_tsd_create(bool a_delegate_key_required);
dap_tsd_t* dap_chain_datum_voting_delegated_key_required_tsd_create(bool a_vote_changing_allowed);



