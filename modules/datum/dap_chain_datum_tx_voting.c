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

#include "dap_chain_datum_tx_voting.h"
#include "dap_chain_common.h"


#define LOG_TAG "datum_tx_voting"


dap_chain_datum_tx_voting_params_t *dap_chain_datum_tx_voting_parse_tsd(dap_chain_datum_tx_t *a_tx)
{
    if (!a_tx)
        return NULL;
    dap_chain_datum_tx_voting_params_t *l_voting_params = DAP_NEW_Z(dap_chain_datum_tx_voting_params_t);
    char *l_buf_string;
    byte_t *l_item; size_t l_tx_item_size;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        if (*l_item != TX_ITEM_TYPE_TSD)
            continue;
        dap_tsd_t *l_tsd = (dap_tsd_t*)((dap_chain_tx_tsd_t*)l_item)->tsd;
        switch(l_tsd->type){
        case VOTING_TSD_TYPE_QUESTION:
            l_buf_string = DAP_NEW_Z_SIZE(char, l_tsd->size + 1);
            l_voting_params->question = memcpy(l_buf_string, l_tsd->data, l_tsd->size);
            break;
        case VOTING_TSD_TYPE_OPTION:
            l_buf_string = DAP_NEW_Z_SIZE(char, l_tsd->size + 1);
            l_voting_params->options = dap_list_append(l_voting_params->options, memcpy(l_buf_string, l_tsd->data, l_tsd->size));
            break;
        case VOTING_TSD_TYPE_EXPIRE:
            l_voting_params->voting_expire = *(dap_time_t*)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_MAX_VOTES_COUNT:
            l_voting_params->votes_max_count = *(uint64_t*)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_DELEGATED_KEY_REQUIRED:
            l_voting_params->delegate_key_required = *l_tsd->data;
            break;
        case VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED:
            l_voting_params->vote_changing_allowed = *l_tsd->data;
            break;
        case VOTING_TSD_TYPE_TOKEN:
            strncpy(l_voting_params->token_ticker, (char*)l_tsd->data, DAP_CHAIN_TICKER_SIZE_MAX - 1);
            l_voting_params->token_ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
            break;
        default:
            break;
        }
    }
    return l_voting_params;
}

void dap_chain_datum_tx_voting_params_delete(dap_chain_datum_tx_voting_params_t *a_params)
{
    if (!a_params)
        return;
    DAP_DELETE(a_params->question);
    dap_list_free_full(a_params->options, NULL);
    DAP_DELETE(a_params);
}

dap_chain_tx_tsd_t* dap_chain_datum_voting_question_tsd_create(const char* a_question_str, size_t str_len)
{
    if (!a_question_str || !str_len)
        return NULL;

    dap_chain_tx_tsd_t* l_tsd = dap_chain_datum_tx_item_tsd_create((void*)a_question_str, VOTING_TSD_TYPE_QUESTION, str_len);

    return l_tsd;
}

dap_chain_tx_tsd_t* dap_chain_datum_voting_answer_tsd_create(const char* a_answer_str, size_t str_len)
{
    if (!a_answer_str || !str_len)
        return NULL;

    dap_chain_tx_tsd_t* l_tsd = dap_chain_datum_tx_item_tsd_create((void*)a_answer_str, VOTING_TSD_TYPE_OPTION, str_len);

    return l_tsd;
}

dap_chain_tx_tsd_t* dap_chain_datum_voting_expire_tsd_create(dap_time_t a_expire)
{
    if (!a_expire)
        return NULL;

    dap_chain_tx_tsd_t* l_tsd = dap_chain_datum_tx_item_tsd_create(&a_expire, VOTING_TSD_TYPE_EXPIRE, sizeof(dap_time_t));

    return l_tsd;
}

dap_chain_tx_tsd_t* dap_chain_datum_voting_max_votes_count_tsd_create(uint64_t a_max_count)
{
    if (!a_max_count)
        return NULL;

    dap_chain_tx_tsd_t* l_tsd = dap_chain_datum_tx_item_tsd_create(&a_max_count, VOTING_TSD_TYPE_MAX_VOTES_COUNT, sizeof(uint64_t));

    return l_tsd;
}

dap_chain_tx_tsd_t* dap_chain_datum_voting_delegated_key_required_tsd_create(bool a_delegated_key_required)
{
    byte_t l_value = a_delegated_key_required;
    dap_chain_tx_tsd_t* l_tsd = dap_chain_datum_tx_item_tsd_create(&l_value, VOTING_TSD_TYPE_DELEGATED_KEY_REQUIRED, sizeof(byte_t));

    return l_tsd;
}

dap_chain_tx_tsd_t* dap_chain_datum_voting_vote_changing_allowed_tsd_create(bool a_vote_changing_allowed)
{
    byte_t l_value = a_vote_changing_allowed;
    dap_chain_tx_tsd_t* l_tsd = dap_chain_datum_tx_item_tsd_create(&l_value, VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED, sizeof(byte_t));

    return l_tsd;
}

dap_chain_tx_tsd_t* dap_chain_datum_voting_cancel_tsd_create(dap_chain_hash_fast_t a_voting_hash)
{   
    dap_chain_tx_tsd_t* l_tsd = dap_chain_datum_tx_item_tsd_create(&a_voting_hash, VOTING_TSD_TYPE_CANCEL, sizeof(dap_chain_hash_fast_t));

    return l_tsd;
}

dap_chain_tx_tsd_t *dap_chain_datum_voting_token_tsd_create(const char *a_token_ticker)
{
    dap_return_val_if_fail(a_token_ticker && *a_token_ticker, NULL);
    size_t l_ticker_len = strlen(a_token_ticker);
    if (l_ticker_len >= DAP_CHAIN_TICKER_SIZE_MAX) {
        log_it(L_ERROR, "Ticker len %zu is too big", l_ticker_len);
        return NULL;
    }
    dap_chain_tx_tsd_t *l_tsd = dap_chain_datum_tx_item_tsd_create((char *)a_token_ticker, VOTING_TSD_TYPE_TOKEN, l_ticker_len);
    return l_tsd;
}

dap_chain_tx_tsd_t* dap_chain_datum_voting_vote_tx_cond_tsd_create(dap_chain_hash_fast_t a_tx_hash, int a_out_idx)
{
    dap_chain_tx_voting_tx_cond_t l_temp = {
        .tx_hash = a_tx_hash,
        .out_idx = a_out_idx
    };

    dap_chain_tx_tsd_t* l_tsd = dap_chain_datum_tx_item_tsd_create(&l_temp, VOTING_TSD_TYPE_VOTE_TX_COND, sizeof(dap_chain_tx_voting_tx_cond_t));

    return l_tsd;
}

dap_chain_tx_voting_t *dap_chain_datum_tx_item_voting_create(void)
{
    dap_chain_tx_voting_t * l_item = DAP_NEW_Z(dap_chain_tx_voting_t);
    l_item->type = TX_ITEM_TYPE_VOTING;
    return l_item;
}

char *dap_chain_datum_tx_voting_get_answer_text_by_idx(dap_chain_datum_tx_t *a_tx, uint64_t a_idx)
{
    byte_t *l_item; size_t l_tx_item_size;
    dap_tsd_t *l_tsd;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        if ( *l_item != TX_ITEM_TYPE_TSD
            || ( l_tsd = (dap_tsd_t*)((dap_chain_tx_tsd_t*)l_item)->tsd, l_tsd->type != VOTING_TSD_TYPE_OPTION )
            || a_idx-- )
            continue;
        char *l_ret = DAP_NEW_Z_SIZE(char, l_tsd->size + 1);
        return memcpy(l_ret, l_tsd->data, l_tsd->size);
    }
    return NULL;
}

json_object *dap_chain_datum_tx_item_voting_tsd_to_json(dap_chain_datum_tx_t* a_tx, int a_version)
{
    if (!a_tx)
        return NULL;

    json_object *l_object = json_object_new_object(), *l_answer_array_object = json_object_new_array();
    byte_t *l_item; size_t l_tx_item_size;
    dap_tsd_t *l_tsd;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        if (*l_item != TX_ITEM_TYPE_TSD)
            continue;
        l_tsd = (dap_tsd_t*)((dap_chain_tx_tsd_t*)l_item)->tsd;
        switch(l_tsd->type) {
        case VOTING_TSD_TYPE_QUESTION:
            json_object_object_add(l_object, a_version == 1 ? "question" : "voting_question", json_object_new_string_len((char*)l_tsd->data, l_tsd->size));
            break;
        case VOTING_TSD_TYPE_OPTION:
            json_object_array_add(l_answer_array_object, json_object_new_string_len((char*)l_tsd->data, l_tsd->size));
            break;
        case VOTING_TSD_TYPE_TOKEN:
            json_object_object_add(l_object, "token", json_object_new_string_len((char*)l_tsd->data, l_tsd->size));
            break;
        case VOTING_TSD_TYPE_EXPIRE:
            json_object_object_add(l_object, a_version == 1 ? "exired" : "voting_expire", json_object_new_uint64(*(uint64_t*)l_tsd->data));
            break;
        case VOTING_TSD_TYPE_MAX_VOTES_COUNT:
            json_object_object_add(l_object, a_version == 1 ? "maxVotes" : "max_votes", json_object_new_uint64(*(uint64_t*)l_tsd->data));
            break;
        case VOTING_TSD_TYPE_DELEGATED_KEY_REQUIRED:
            json_object_object_add(l_object, a_version == 1 ? "delegateKeyRequired" : "delegate_key_required", json_object_new_boolean(*(bool*)l_tsd->data));
            break;
        case VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED:
            json_object_object_add(l_object, a_version == 1 ? "voteChangingAllowed" : "changing_vote", json_object_new_boolean(*(bool*)l_tsd->data));
            break;
        default:
            break;
        }
    }
    json_object_object_add(l_object, a_version == 1 ? "answers" : "answer_options", l_answer_array_object);
    return l_object;
}

dap_chain_tx_vote_t *dap_chain_datum_tx_item_vote_create(dap_chain_hash_fast_t *a_voting_hash, uint64_t *a_answer_idx)
{
    if (!a_voting_hash)
        return NULL;

    dap_chain_tx_vote_t * l_item = DAP_NEW_Z(dap_chain_tx_vote_t);
    l_item->type = TX_ITEM_TYPE_VOTE;
    l_item->answer_idx = *a_answer_idx;
    l_item->voting_hash = *a_voting_hash;
    return l_item;
}

json_object *dap_chain_datum_tx_item_vote_to_json(dap_chain_tx_vote_t *a_vote, int a_version)
{
    json_object *l_object = json_object_new_object();
    char *l_voting_hash_str = dap_hash_fast_to_str_new(&a_vote->voting_hash);
    json_object *l_voting_hash = json_object_new_string(l_voting_hash_str);
    DAP_DELETE(l_voting_hash_str);
    json_object *l_answer_idx = json_object_new_uint64(a_vote->answer_idx);
    json_object_object_add(l_object, a_version == 1 ? "votingHash" : "voting_hash", l_voting_hash);
    json_object_object_add(l_object, "answer_idx", l_answer_idx);
    return l_object;
}