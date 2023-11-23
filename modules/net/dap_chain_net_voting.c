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
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "dap_chain_net_voting.h"
#include "uthash.h"
#include "utlist.h"

#define LOG_TAG "chain_net_voting"

typedef struct dap_chain_net_voting_params_offsets{
    dap_chain_datum_tx_t* voting_tx;
    size_t voting_question_offset;
    dap_list_t* answers_list_offset;
    uint64_t answers_count;
    size_t voting_expire_offset;
    size_t votes_max_count_offset;
    size_t delegate_key_required_offset;
    size_t vote_changing_allowed_offset;
} dap_chain_net_voting_params_offsets_t;

typedef struct dap_chain_net_vote {
    dap_chain_hash_fast_t vote_hash;
    dap_chain_hash_fast_t pkey_hash;
    uint64_t answer_idx;
} dap_chain_net_vote_t;

typedef struct dap_chain_net_votings {
    dap_chain_hash_fast_t voting_hash;
    dap_chain_net_voting_params_offsets_t voting_params;
    dap_list_t *votes;

    UT_hash_handle hh;
} dap_chain_net_votings_t;

static dap_chain_net_votings_t *s_votings;
static  pthread_rwlock_t *s_verificators_rwlock;

static bool s_datum_tx_voting_verification_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in);


int dap_chain_net_voting_init()
{
    pthread_rwlock_init(s_verificators_rwlock, NULL);
    dap_chain_ledger_voting_verificator_add(s_datum_tx_voting_verification_callback);
    return 0;
}

uint64_t* dap_chain_net_voting_get_result(dap_ledger_t* a_ledger, dap_chain_hash_fast_t* a_voting_hash)
{
    uint64_t* l_voting_results = NULL;

    dap_chain_net_votings_t * l_voting = NULL;
    pthread_rwlock_rdlock(s_verificators_rwlock);
    HASH_FIND(hh, s_votings, a_voting_hash, sizeof(dap_hash_fast_t), l_voting);
    pthread_rwlock_unlock(s_verificators_rwlock);
    if(!l_voting){
        char* l_hash_str = dap_hash_fast_to_str_new(a_voting_hash);
        log_it(L_ERROR, "Can't find voting with hash %s", l_hash_str);
        DAP_DEL_Z(l_hash_str);
        return NULL;
    }

    l_voting_results = DAP_NEW_Z_SIZE(uint64_t, l_voting->voting_params->answers_count);
    if (!l_voting_results){
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }

    dap_list_t* l_temp = l_voting->votes;
    while(l_temp){
        dap_chain_net_vote_t* l_vote = l_temp->data;
        if (l_vote->answer_idx >= l_voting->voting_params->answers_count)
            continue;

        l_voting_results[l_vote->answer_idx]++;

        l_temp = l_temp->next;
    }


    return l_voting_results;
}



bool s_datum_tx_voting_verification_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in)
{

    dap_hash_fast_t l_hash = NULL;
    dap_hash_fast(a_tx_in, dap_chain_datum_tx_get_size(a_tx_in), &l_hash);

    if (a_type == TX_ITEM_TYPE_VOTING){
        pthread_rwlock_rdlock(s_verificators_rwlock);
        HASH_FIND(hh, s_votings, a_voting_hash, sizeof(dap_hash_fast_t), l_voting);
        pthread_rwlock_unlock(s_verificators_rwlock);
        if(l_voting){
            char* l_hash_str = dap_hash_fast_to_str_new(a_voting_hash);
            log_it(L_ERROR, "Voting with hash %s is already presents.", l_hash_str);
            DAP_DEL_Z(l_hash_str);
            return NULL;
        }

        dap_chain_net_votings_t *l_item = DAP_NEW_Z_SIZE(dap_chain_net_votings_t, sizeof(dap_chain_net_votings_t));
        l_item->voting_params.voting_tx = a_tx_in;

        size_t l_tsd_size = 0;
        dap_tsd_t *l_tsd = (dap_chain_tx_tsd_t *)dap_chain_datum_tx_item_get(a_tx_in, 0, TX_ITEM_TYPE_TSD, &l_tsd_size);
        size_t l_tsd_shift = 0;

        while (l_tsd_shift < a_tsd_size && l_tsd->size < a_tsd_size){
            switch(l_tsd->type){
            case VOTING_TSD_TYPE_QUESTION:
                l_item->voting_params.voting_question_offset = (char*)(l_tsd->data - l_item->voting_params.voting_tx);
                break;
            case VOTING_TSD_TYPE_ANSWER:
                l_buf_string = DAP_NEW_Z_SIZE(char, l_tsd->size);
                memcpy(l_buf_string, l_tsd->data, l_tsd->size);
                dap_list_append(l_voting_parms->answers_list, l_buf_string);
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

        pthread_rwlock_wrlock(s_verificators_rwlock);
        HASH_ADD(hh, s_votings, voting_hash, sizeof(dap_hash_fast_t), l_item);
        pthread_rwlock_unlock(s_verificators_rwlock);

    } else if (a_type == TX_ITEM_TYPE_VOTE){

    } else {
        log_it(L_ERROR, "Item is not supported in votings.");
    }

    return false;
}
