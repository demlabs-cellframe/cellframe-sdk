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


bool s_datum_tx_voting_verification_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in);


int dap_chain_datum_tx_voting_init()
{



}



dap_chain_datum_tx_voting_params_t* dap_chain_voting_parse_tsd(byte_t* a_tsd_data, size_t a_tsd_size)
{
    if (!a_tsd_data || !a_tsd_size)
        return NULL;

    dap_tsd_t *l_tsd = a_tsd_data;
    size_t l_tsd_shift = 0;
    dap_chain_datum_tx_voting_params_t *l_voting_parms = DAP_NEW_Z_SIZE(dap_chain_datum_tx_voting_params_t,
                                                                        sizeof(dap_chain_datum_tx_voting_params_t));

    while (l_tsd_shift < a_tsd_size && l_tsd->size < a_tsd_size){
        switch(l_tsd->type){
        case VOTING_TSD_TYPE_QUESTION:
            char *l_question_string = DAP_NEW_Z_SIZE(char, l_tsd->size);
            memcpy(l_question_string, l_tsd->data, l_tsd->size);
            l_voting_parms->voting_question = l_question_string;
            break;
        case VOTING_TSD_TYPE_ANSWER:
            char *l_answer_string = DAP_NEW_Z_SIZE(char, l_tsd->size);
            memcpy(l_answer_string, l_tsd->data, l_tsd->size);
            dap_list_append(l_voting_parms->answers_list, l_question_string);
            l_voting_parms->answers_count++;
            break;
        case VOTING_TSD_TYPE_EXPIRE:
            l_voting_parms->voting_expire = *(dap_time_t*)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_MAX_VOTES_COUNT:
            l_voting_parms->votes_max_count = *(uint64_t*)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_DELEGATE_KEY_REQUIRED:
            l_voting_parms->delegate_key_required = *(bool*)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED:
            l_voting_parms->delegate_key_required = *(bool*)l_tsd->data;
            break;
        default:
            break;
        }

        l_tsd_shift += dap_tsd_size(l_tsd);
    }


    return l_voting_parms;
}


dap_tsd_t* dap_chain_datum_voting_question_tsd_create(char* a_question_str, size_t str_len)
{
    if (!a_question_str || !str_len)
        return NULL;

    dap_tsd_t* l_tsd = dap_tsd_create(VOTING_TSD_TYPE_QUESTION, a_question_str, str_len);

    return l_tsd;
}

dap_tsd_t* dap_chain_datum_voting_answer_tsd_create(char* a_answer_str, size_t str_len)
{
    if (!a_answer_str || !str_len)
        return NULL;

    dap_tsd_t* l_tsd = dap_tsd_create(VOTING_TSD_TYPE_ANSWER, a_answer_str, str_len);

    return l_tsd;
}

dap_tsd_t* dap_chain_datum_voting_expire_tsd_create(dap_time_t a_expire)
{
    if (!a_expire)
        return NULL;

    dap_tsd_t* l_tsd = dap_tsd_create(VOTING_TSD_TYPE_EXPIRE, &a_expire, sizeof(dap_time_t));

    return l_tsd;
}

dap_tsd_t* dap_chain_datum_voting_max_votes_count_tsd_create(uint64_t a_max_count)
{
    if (!a_max_count)
        return NULL;

    dap_tsd_t* l_tsd = dap_tsd_create(VOTING_TSD_TYPE_MAX_VOTES_COUNT , &a_max_count, sizeof(uint64_t));

    return l_tsd;
}

dap_tsd_t* dap_chain_datum_voting_delegated_key_required_tsd_create(bool a_delegate_key_required)
{
    dap_tsd_t* l_tsd = dap_tsd_create(VOTING_TSD_TYPE_DELEGATE_KEY_REQUIRED, &a_delegate_key_required, sizeof(bool));

    return l_tsd;
}

dap_tsd_t* dap_chain_datum_voting_delegated_key_required_tsd_create(bool a_vote_changing_allowed)
{
    dap_tsd_t* l_tsd = dap_tsd_create(VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED, &a_vote_changing_allowed, sizeof(bool));

    return l_tsd;
}

