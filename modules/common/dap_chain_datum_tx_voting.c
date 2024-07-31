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


dap_chain_datum_tx_voting_params_t* dap_chain_voting_parse_tsd(dap_chain_datum_tx_t* a_tx)
{
    if (!a_tx)
        return NULL;

    dap_list_t* l_tsd_list = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_TSD, NULL);
    dap_chain_datum_tx_voting_params_t *l_voting_parms = DAP_NEW_Z_SIZE(dap_chain_datum_tx_voting_params_t,
                                                                        sizeof(dap_chain_datum_tx_voting_params_t));
    char *l_buf_string = NULL;
    dap_list_t* l_temp = l_tsd_list;
    while (l_temp){
        dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t*)l_temp->data)->tsd;
        switch(l_tsd->type){
        case VOTING_TSD_TYPE_QUESTION:
            l_buf_string = DAP_NEW_Z_SIZE(char, l_tsd->size + 1);
            memcpy(l_buf_string, l_tsd->data, l_tsd->size);
            l_buf_string[l_tsd->size] = '\0';
            l_voting_parms->voting_question = l_buf_string;
            break;
        case VOTING_TSD_TYPE_ANSWER:
            l_buf_string = DAP_NEW_Z_SIZE(char, l_tsd->size + 1);
            memcpy(l_buf_string, l_tsd->data, l_tsd->size);
            l_buf_string[l_tsd->size] = '\0';
            l_voting_parms->answers_list = dap_list_append(l_voting_parms->answers_list, l_buf_string);
            l_voting_parms->answers_count++;
            break;
        case VOTING_TSD_TYPE_EXPIRE:
            l_voting_parms->voting_expire = *(dap_time_t*)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_MAX_VOTES_COUNT:
            l_voting_parms->votes_max_count = *(uint64_t*)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_DELEGATED_KEY_REQUIRED:
            l_voting_parms->delegate_key_required = *(bool*)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED:
            l_voting_parms->vote_changing_allowed = *(bool*)l_tsd->data;
            break;
        default:
            break;
        }
        l_temp = l_temp->next;
    }
    dap_list_free(l_tsd_list);

    return l_voting_parms;
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

    dap_chain_tx_tsd_t* l_tsd = dap_chain_datum_tx_item_tsd_create((void*)a_answer_str, VOTING_TSD_TYPE_ANSWER, str_len);

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

dap_chain_tx_tsd_t* dap_chain_datum_voting_delegated_key_required_tsd_create(bool a_delegate_key_required)
{
    dap_chain_tx_tsd_t* l_tsd = dap_chain_datum_tx_item_tsd_create(&a_delegate_key_required, VOTING_TSD_TYPE_DELEGATED_KEY_REQUIRED, sizeof(bool));

    return l_tsd;
}

dap_chain_tx_tsd_t* dap_chain_datum_voting_vote_changing_allowed_tsd_create(bool a_vote_changing_allowed)
{
    dap_chain_tx_tsd_t* l_tsd = dap_chain_datum_tx_item_tsd_create(&a_vote_changing_allowed, VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED, sizeof(bool));

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

const char *s_tx_voting_get_answer_text_by_idx(dap_chain_datum_tx_t *a_tx, uint64_t a_idx) {
    size_t l_anwers_count = 0;
    dap_list_t *l_answers_list = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_TSD, NULL);
    for (dap_list_t* l_elem = l_answers_list; l_elem; l_elem = l_elem->next) {
        dap_tsd_t *l_tsd = (dap_tsd_t*)((dap_chain_tx_tsd_t*)l_elem->data)->tsd;
        if ( l_tsd->type == VOTING_TSD_TYPE_ANSWER && !--a_idx ) {
            char *l_ret = DAP_NEW_SIZE(char, l_tsd->size + 1);
            memcpy(l_ret, l_tsd->data, l_tsd->size);
            return dap_list_free(l_answers_list), l_ret;
        }
    }
    return NULL;
}

json_object *dap_chain_datum_tx_item_voting_tsd_to_json(dap_chain_datum_tx_t* a_tx)
{
    if (!a_tx)
        return NULL;

    json_object *l_object = json_object_new_object();
    json_object *l_answer_array_object = json_object_new_array();
    json_object *l_json_obj = NULL;
    dap_list_t* l_tsd_list = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_TSD, NULL);
    dap_list_t* l_temp = l_tsd_list;
    while (l_temp){
        dap_tsd_t* l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t*)l_temp->data)->tsd;
        switch(l_tsd->type){
        case VOTING_TSD_TYPE_QUESTION:
            l_json_obj = json_object_new_string_len((char*)l_tsd->data, l_tsd->size);
            json_object_object_add(l_object, "question", l_json_obj);
            break;
        case VOTING_TSD_TYPE_ANSWER:
            l_json_obj = json_object_new_string_len((char*)l_tsd->data, l_tsd->size);
            json_object_array_add(l_answer_array_object, l_json_obj);
            break;
        case VOTING_TSD_TYPE_EXPIRE:
            l_json_obj = json_object_new_uint64(*(uint64_t*)l_tsd->data);
            json_object_object_add(l_object, "exired", l_json_obj);
            break;
        case VOTING_TSD_TYPE_MAX_VOTES_COUNT:
            l_json_obj = json_object_new_uint64(*(uint64_t*)l_tsd->data);
            json_object_object_add(l_object, "maxVotes", l_json_obj);
            break;
        case VOTING_TSD_TYPE_DELEGATED_KEY_REQUIRED:
            l_json_obj = json_object_new_boolean(*(bool*)l_tsd->data);
            json_object_object_add(l_object, "delegateKeyRequired", l_json_obj);
            break;
        case VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED:
            l_json_obj = json_object_new_boolean(*(bool*)l_tsd->data);
            json_object_object_add(l_object, "voteChangingAllowed", l_json_obj);
            break;
        default:
            break;
        }
        l_temp = l_temp->next;
    }
    dap_list_free(l_tsd_list);

    json_object_object_add(l_object, "answers", l_answer_array_object);
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

const char *s_get_vote_answer_text(dap_hash_fast_t *a_vote, uint64_t a_idx, dap_ledger_t *a_ledger) {
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_ledger, a_vote);
    if (!l_tx || !a_ledger) {
        return NULL;
    }
    return s_tx_voting_get_answer_text_by_idx(l_tx, a_idx);
}

json_object *dap_chain_datum_tx_item_vote_to_json(dap_chain_tx_vote_t *a_vote, dap_ledger_t *a_ledger)
{
    json_object *l_object = json_object_new_object();
    char *l_voting_hash_str = dap_hash_fast_to_str_new(&a_vote->voting_hash);
    json_object *l_voting_hash = json_object_new_string(l_voting_hash_str);
    DAP_DELETE(l_voting_hash_str);
    json_object *l_answer_idx = json_object_new_uint64(a_vote->answer_idx);
    const char *l_answer_text_str = s_get_vote_answer_text(&a_vote->voting_hash, a_vote->answer_idx, a_ledger);
    json_object *l_answer_text = NULL;
    if (!l_answer_text_str) {
        l_answer_text = json_object_new_string("{UNDEFINED}");
    } else {
        l_answer_text = json_object_new_string(l_answer_text_str);
        DAP_DELETE(l_answer_text_str);
    }
    json_object_object_add(l_object, "votingHash", l_voting_hash);
    json_object_object_add(l_object, "answer_idx", l_answer_idx);
    json_object_object_add(l_object, "answer_text", l_answer_text);
    return l_object;
}
