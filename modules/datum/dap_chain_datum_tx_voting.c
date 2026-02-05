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
#include "dap_json.h"


#define LOG_TAG "datum_tx_voting"

static void s_dap_chain_datum_tx_voting_free_str(void *a_str)
{
    DAP_DELETE(a_str);
}


dap_chain_datum_tx_voting_params_t *dap_chain_datum_tx_voting_parse_tsd(dap_chain_datum_tx_t *a_tx)
{
    if (!a_tx)
        return NULL;
    dap_chain_datum_tx_voting_params_t *l_voting_params = DAP_NEW_Z(dap_chain_datum_tx_voting_params_t);
    char *l_buf_string = NULL;
    byte_t *l_item; size_t l_tx_item_size;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        if (*l_item != TX_ITEM_TYPE_TSD)
            continue;
        dap_tsd_t *l_tsd = (dap_tsd_t*)((dap_chain_tx_tsd_t*)l_item)->tsd;
        const byte_t *l_tsd_data = (const byte_t *)(l_tsd + 1);
        switch(l_tsd->type){
        case VOTING_TSD_TYPE_QUESTION:
            l_buf_string = DAP_NEW_Z_SIZE(char, l_tsd->size + 1);
            if (l_buf_string) {
                memcpy(l_buf_string, l_tsd_data, l_tsd->size);
                DAP_DELETE(l_voting_params->question);
                l_voting_params->question = l_buf_string;
            }
            break;
        case VOTING_TSD_TYPE_OPTION:
            l_buf_string = DAP_NEW_Z_SIZE(char, l_tsd->size + 1);
            if (l_buf_string) {
                memcpy(l_buf_string, l_tsd_data, l_tsd->size);
                l_voting_params->options = dap_list_append(l_voting_params->options, l_buf_string);
            }
            break;
        case VOTING_TSD_TYPE_EXPIRE:
            if (l_tsd->size >= sizeof(dap_time_t))
                memcpy(&l_voting_params->voting_expire, l_tsd_data, sizeof(dap_time_t));
            break;
        case VOTING_TSD_TYPE_MAX_VOTES_COUNT:
            if (l_tsd->size >= sizeof(uint64_t))
                memcpy(&l_voting_params->votes_max_count, l_tsd_data, sizeof(uint64_t));
            break;
        case VOTING_TSD_TYPE_DELEGATED_KEY_REQUIRED:
            if (l_tsd->size >= sizeof(byte_t))
                l_voting_params->delegate_key_required = *l_tsd_data;
            break;
        case VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED:
            if (l_tsd->size >= sizeof(byte_t))
                l_voting_params->vote_changing_allowed = *l_tsd_data;
            break;
        case VOTING_TSD_TYPE_TOKEN: {
            size_t l_copy_size = dap_min((size_t)l_tsd->size, (size_t)DAP_CHAIN_TICKER_SIZE_MAX - 1);
            memcpy(l_voting_params->token_ticker, l_tsd_data, l_copy_size);
            l_voting_params->token_ticker[l_copy_size] = '\0';
            break;
        }
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
    dap_list_free_full(a_params->options, s_dap_chain_datum_tx_voting_free_str);
    a_params->options = NULL;
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

dap_chain_tx_tsd_t* dap_chain_datum_voting_cancel_tsd_create(dap_hash_sha3_256_t a_voting_hash)
{
    dap_chain_tx_tsd_t* l_tsd = dap_chain_datum_tx_item_tsd_create(&a_voting_hash, VOTING_TSD_TYPE_CANCEL, sizeof(dap_hash_sha3_256_t));

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

dap_chain_tx_tsd_t* dap_chain_datum_voting_vote_tx_cond_tsd_create(dap_hash_sha3_256_t a_tx_hash, int a_out_idx)
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
        const byte_t *l_tsd_data = (const byte_t *)(l_tsd + 1);
        char *l_ret = DAP_NEW_Z_SIZE(char, l_tsd->size + 1);
        if (!l_ret)
            return NULL;
        memcpy(l_ret, l_tsd_data, l_tsd->size);
        return l_ret;
    }
    return NULL;
}

dap_json_t *dap_chain_datum_tx_item_voting_tsd_to_json(dap_chain_datum_tx_t* a_tx, int a_version)
{
    if (!a_tx)
        return NULL;

    dap_json_t *l_object = dap_json_object_new(), *l_answer_array_object = dap_json_array_new();
    byte_t *l_item; size_t l_tx_item_size;
    dap_tsd_t *l_tsd;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        if (*l_item != TX_ITEM_TYPE_TSD)
            continue;
        l_tsd = (dap_tsd_t*)((dap_chain_tx_tsd_t*)l_item)->tsd;
        const byte_t *l_tsd_data = (const byte_t *)(l_tsd + 1);
        switch(l_tsd->type) {
        case VOTING_TSD_TYPE_QUESTION:
            dap_json_object_add_string_len(l_object, a_version == 1 ? "question" : "voting_question",
                (const char *)l_tsd_data, l_tsd->size);
            break;
        case VOTING_TSD_TYPE_OPTION:
            dap_json_array_add(l_answer_array_object,
                dap_json_object_new_string_len((const char *)l_tsd_data, l_tsd->size));
            break;
        case VOTING_TSD_TYPE_TOKEN:
            dap_json_object_add_string_len(l_object, "token", (const char *)l_tsd_data, l_tsd->size);
            break;
        case VOTING_TSD_TYPE_EXPIRE:
            if (l_tsd->size >= sizeof(dap_time_t)) {
                dap_time_t l_expire = 0;
                memcpy(&l_expire, l_tsd_data, sizeof(l_expire));
                dap_json_object_add_uint64(l_object, a_version == 1 ? "exired" : "voting_expire", (uint64_t)l_expire);
            }
            break;
        case VOTING_TSD_TYPE_MAX_VOTES_COUNT:
            if (l_tsd->size >= sizeof(uint64_t)) {
                uint64_t l_max_votes = 0;
                memcpy(&l_max_votes, l_tsd_data, sizeof(l_max_votes));
                dap_json_object_add_uint64(l_object, a_version == 1 ? "maxVotes" : "max_votes", l_max_votes);
            }
            break;
        case VOTING_TSD_TYPE_DELEGATED_KEY_REQUIRED:
            if (l_tsd->size >= sizeof(bool)) {
                bool l_required = false;
                memcpy(&l_required, l_tsd_data, sizeof(l_required));
                dap_json_object_add_bool(l_object,
                    a_version == 1 ? "delegateKeyRequired" : "delegate_key_required", l_required);
            }
            break;
        case VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED:
            if (l_tsd->size >= sizeof(bool)) {
                bool l_allowed = false;
                memcpy(&l_allowed, l_tsd_data, sizeof(l_allowed));
                dap_json_object_add_bool(l_object,
                    a_version == 1 ? "voteChangingAllowed" : "changing_vote", l_allowed);
            }
            break;
        default:
            break;
        }
    }
    dap_json_object_add_object(l_object, a_version == 1 ? "answers" : "answer_options", l_answer_array_object);
    return l_object;
}

dap_chain_tx_vote_t *dap_chain_datum_tx_item_vote_create(dap_hash_sha3_256_t *a_voting_hash, uint64_t *a_answer_idx)
{
    if (!a_voting_hash)
        return NULL;

    dap_chain_tx_vote_t * l_item = DAP_NEW_Z(dap_chain_tx_vote_t);
    l_item->type = TX_ITEM_TYPE_VOTE;
    l_item->answer_idx = *a_answer_idx;
    l_item->voting_hash = *a_voting_hash;
    return l_item;
}

dap_json_t *dap_chain_datum_tx_item_vote_to_json(dap_chain_tx_vote_t *a_vote, int a_version)
{
    dap_json_t *l_object = dap_json_object_new();
    char *l_voting_hash_str = dap_hash_sha3_256_to_str_new(&a_vote->voting_hash);
    dap_json_t *l_voting_hash = dap_json_object_new_string(l_voting_hash_str);
    DAP_DELETE(l_voting_hash_str);
    dap_json_t *l_answer_idx = dap_json_object_new_uint64(a_vote->answer_idx);
    dap_json_object_add_object(l_object, a_version == 1 ? "votingHash" : "voting_hash", l_voting_hash);
    dap_json_object_add_object(l_object, "answer_idx", l_answer_idx);
    return l_object;
}
