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
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_mempool.h"
#include "uthash.h"
#include "utlist.h"

#define LOG_TAG "chain_net_voting"

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

typedef struct dap_chain_net_vote_option {
    size_t vote_option_offset;
    size_t vote_option_length;
} dap_chain_net_vote_option_t;

typedef struct dap_chain_net_voting_cond_outs {
    dap_chain_hash_fast_t tx_hash;
    int out_idx;

    UT_hash_handle hh;
} dap_chain_net_voting_cond_outs_t;

typedef struct dap_chain_net_vote {
    dap_chain_hash_fast_t vote_hash;
    dap_chain_hash_fast_t pkey_hash;
    uint64_t answer_idx;
    uint256_t weight;
} dap_chain_net_vote_t;

typedef struct dap_chain_net_votings {
    dap_chain_hash_fast_t voting_hash;
    dap_chain_net_voting_params_offsets_t voting_params;
    dap_list_t *votes;
    dap_chain_net_id_t net_id;

    pthread_rwlock_t s_tx_outs_rwlock;
    dap_chain_net_voting_cond_outs_t *voting_spent_cond_outs;

    UT_hash_handle hh;
} dap_chain_net_votings_t;

static dap_chain_net_votings_t *s_votings;
static pthread_rwlock_t s_votings_rwlock;

static int s_datum_tx_voting_coin_check_cond_out(dap_chain_net_t *a_net, dap_hash_fast_t a_voting_hash, dap_hash_fast_t a_tx_cond_hash, int a_cond_out_idx);
/// -1 error, 0 - unspent, 1 - spent
static int s_datum_tx_voting_coin_check_spent(dap_chain_net_t *a_net, dap_hash_fast_t a_voting_hash, dap_hash_fast_t a_tx_prev_hash, int a_out_idx);
static bool s_datum_tx_voting_verification_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in, bool a_apply);
static int s_cli_voting(int argc, char **argv, void **a_obj_reply);

int dap_chain_net_voting_init()
{
    pthread_rwlock_init(&s_votings_rwlock, NULL);
    dap_chain_ledger_voting_verificator_add(s_datum_tx_voting_verification_callback);
    dap_cli_server_cmd_add("voting", s_cli_voting, "Voting commands.", ""
                            "voting create -net <net_name> -question <\"Question_string\"> -options <\"Option0\", \"Option1\" ... \"OptionN\"> [-expire <voting_expire_time_in_RCF822>] [-max_votes_count <Votes_count>] [-delegated_key_required] [-vote_changing_allowed] -fee <value_datoshi> -w <fee_wallet_name>\n"
                            "voting vote -net <net_name> -hash <voting_hash> -option_idx <option_index> [-cert <delegate_cert_name>] -fee <value_datoshi> -w <fee_wallet_name>\n"
                            "voting list -net <net_name>\n"
                            "voting dump -net <net_name> -hash <voting_hash>\n");
    return 0;
}

uint64_t* dap_chain_net_voting_get_result(dap_ledger_t* a_ledger, dap_chain_hash_fast_t* a_voting_hash)
{
    if(!a_voting_hash){
        return NULL;
    }

    uint64_t* l_voting_results = NULL;

    dap_chain_net_votings_t * l_voting = NULL;
    pthread_rwlock_rdlock(&s_votings_rwlock);
    HASH_FIND(hh, s_votings, a_voting_hash, sizeof(dap_hash_fast_t), l_voting);
    pthread_rwlock_unlock(&s_votings_rwlock);
    if(!l_voting || l_voting->net_id.uint64 != a_ledger->net->pub.id.uint64){
        char* l_hash_str = dap_hash_fast_to_str_new(a_voting_hash);
        log_it(L_ERROR, "Can't find voting with hash %s in net %s", l_hash_str, a_ledger->net->pub.name);
        DAP_DEL_Z(l_hash_str);
        return NULL;
    }

    l_voting_results = DAP_NEW_Z_SIZE(uint64_t, sizeof(uint64_t)*dap_list_length(l_voting->voting_params.option_offsets_list));
    if (!l_voting_results){
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }

    dap_list_t* l_temp = l_voting->votes;
    while(l_temp){
        dap_chain_net_vote_t* l_vote = l_temp->data;
        if (l_vote->answer_idx >= dap_list_length(l_voting->voting_params.option_offsets_list))
            continue;

        l_voting_results[l_vote->answer_idx]++;

        l_temp = l_temp->next;
    }


    return l_voting_results;
}



bool s_datum_tx_voting_verification_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in, bool a_apply)
{

    dap_hash_fast_t l_hash = {};
    dap_hash_fast(a_tx_in, dap_chain_datum_tx_get_size(a_tx_in), &l_hash);

    if (a_type == TX_ITEM_TYPE_VOTING){
        if (!a_apply){
            dap_chain_net_votings_t * l_voting = NULL;
            pthread_rwlock_rdlock(&s_votings_rwlock);
            HASH_FIND(hh, s_votings, &l_hash, sizeof(dap_hash_fast_t), l_voting);
            pthread_rwlock_unlock(&s_votings_rwlock);
            if(l_voting && l_voting->net_id.uint64 == a_ledger->net->pub.id.uint64){
                char* l_hash_str = dap_hash_fast_to_str_new(&l_hash);
                log_it(L_ERROR, "Voting with hash %s is already presents in net %s", l_hash_str, a_ledger->net->pub.name);
                DAP_DEL_Z(l_hash_str);
                return false;
            }

            dap_list_t* l_tsd_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_TSD, NULL);
            dap_list_t* l_temp = l_tsd_list;
            size_t l_question_len = 0;
            size_t l_options_count = 0;
            while (l_temp){
                dap_tsd_t* l_tsd = (dap_tsd_t*)((dap_chain_tx_tsd_t*)l_temp->data)->tsd;
                dap_chain_net_vote_option_t *l_vote_option = NULL;
                switch(l_tsd->type){
                case VOTING_TSD_TYPE_QUESTION:
                    l_question_len = l_tsd->size;
                    break;
                case VOTING_TSD_TYPE_ANSWER:
                    l_options_count++;
                    break;
                default:
                    break;
                }
                l_temp = l_temp->next;
            }
            dap_list_free(l_tsd_list);

            if (!l_question_len || !l_options_count)
                return false;

            return true;
        }

        dap_chain_net_votings_t *l_item = DAP_NEW_Z_SIZE(dap_chain_net_votings_t, sizeof(dap_chain_net_votings_t));
        l_item->voting_hash = l_hash;
        l_item->voting_params.voting_tx = a_tx_in;
        l_item->net_id = a_ledger->net->pub.id;
        pthread_rwlock_init(&l_item->s_tx_outs_rwlock, NULL);

        dap_list_t* l_tsd_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_TSD, NULL);
        dap_list_t* l_temp = l_tsd_list;
        while (l_temp){
            dap_tsd_t* l_tsd = (dap_tsd_t*)((dap_chain_tx_tsd_t*)l_temp->data)->tsd;
            dap_chain_net_vote_option_t *l_vote_option = NULL;
            switch(l_tsd->type){
            case VOTING_TSD_TYPE_QUESTION:
                l_item->voting_params.voting_question_offset = (size_t)(l_tsd->data - (byte_t*)l_item->voting_params.voting_tx);
                l_item->voting_params.voting_question_length = l_tsd->size;
                break;
            case VOTING_TSD_TYPE_ANSWER:
                l_vote_option = DAP_NEW_Z(dap_chain_net_vote_option_t);
                l_vote_option->vote_option_offset = (size_t)(l_tsd->data - (byte_t*)l_item->voting_params.voting_tx);
                l_vote_option->vote_option_length = l_tsd->size;
                l_item->voting_params.option_offsets_list = dap_list_append(l_item->voting_params.option_offsets_list, l_vote_option);
                break;
            case VOTING_TSD_TYPE_EXPIRE:
                l_item->voting_params.voting_expire_offset = (size_t)(l_tsd->data - (byte_t*)l_item->voting_params.voting_tx);
                break;
            case VOTING_TSD_TYPE_MAX_VOTES_COUNT:
                l_item->voting_params.votes_max_count_offset = (size_t)(l_tsd->data - (byte_t*)l_item->voting_params.voting_tx);
                break;
            case VOTING_TSD_TYPE_DELEGATED_KEY_REQUIRED:
                l_item->voting_params.delegate_key_required_offset = (size_t)(l_tsd->data - (byte_t*)l_item->voting_params.voting_tx);
                break;
            case VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED:
                l_item->voting_params.vote_changing_allowed_offset = (size_t)(l_tsd->data - (byte_t*)l_item->voting_params.voting_tx);
                break;
            default:
                break;
            }
            l_temp = l_temp->next;
        }
        dap_list_free(l_tsd_list);

        pthread_rwlock_wrlock(&s_votings_rwlock);
        HASH_ADD(hh, s_votings, voting_hash, sizeof(dap_hash_fast_t), l_item);
        pthread_rwlock_unlock(&s_votings_rwlock);
        return true;
    } else if (a_type == TX_ITEM_TYPE_VOTE){
        dap_chain_tx_vote_t *l_vote_tx_item = (dap_chain_tx_vote_t *)dap_chain_datum_tx_item_get(a_tx_in, 0, TX_ITEM_TYPE_VOTE, NULL);
        if(!l_vote_tx_item){
            log_it(L_ERROR, "Can't find vote item");
            return false;
        }

        dap_chain_net_votings_t * l_voting = NULL;
        pthread_rwlock_wrlock(&s_votings_rwlock);
        HASH_FIND(hh, s_votings, &l_vote_tx_item->voting_hash, sizeof(dap_hash_fast_t), l_voting);
        pthread_rwlock_unlock(&s_votings_rwlock);
        if(!l_voting || l_voting->net_id.uint64 != a_ledger->net->pub.id.uint64) {
            char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_hash);
            log_it(L_ERROR, "Can't find voting with hash %s in net %s", l_hash_str, a_ledger->net->pub.name);
            DAP_DELETE(l_hash_str);
            return false;
        }

        if (!a_apply){
            if (l_vote_tx_item->answer_idx > dap_list_length(l_voting->voting_params.option_offsets_list)){
                log_it(L_ERROR, "Invalid vote option index.");
                return false;
            }

            if(l_voting->voting_params.votes_max_count_offset){
                uint64_t l_votes_max_count = *(uint64_t*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.votes_max_count_offset);
                if (l_votes_max_count && dap_list_length(l_voting->votes) >= l_votes_max_count){
                    log_it(L_ERROR, "The required number of votes has been collected.");
                    return false;
                }
            }

            if(l_voting->voting_params.voting_expire_offset){
                dap_time_t l_expire = *(dap_time_t*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.voting_expire_offset);
                if( l_expire && l_expire <= a_tx_in->header.ts_created){
                    log_it(L_ERROR, "The voting has been expired.");
                    return false;
                }
            }

            dap_hash_fast_t pkey_hash = {};
            dap_chain_tx_sig_t *l_vote_sig = NULL;
            int l_item_cnt = 0;
            dap_list_t* l_signs_list = NULL;
            l_signs_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_SIG, &l_item_cnt);

            if(!l_signs_list){
                log_it(L_ERROR, "Can't get sign.");
                return false;
            }
            l_vote_sig = (dap_chain_tx_sig_t *)(dap_list_last(l_signs_list)->data);
            dap_sign_get_pkey_hash((dap_sign_t*)l_vote_sig->sig, &pkey_hash);
            if (l_voting->voting_params.delegate_key_required_offset &&
                *(bool*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.delegate_key_required_offset)){
                if (!dap_chain_net_srv_stake_check_pkey_hash(&pkey_hash)){
                    log_it(L_ERROR, "The voting required a delegated key.");
                    dap_list_free(l_signs_list);
                    return false;
                }
            }

            dap_list_t *l_temp = l_voting->votes;
            while(l_temp){
                if (dap_hash_fast_compare(&((dap_chain_net_vote_t *)l_temp->data)->pkey_hash, &pkey_hash)){
                    if(l_voting->voting_params.vote_changing_allowed_offset &&
                        *(bool*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.vote_changing_allowed_offset)){
                        //delete conditional outputs
                        dap_chain_datum_tx_t *l_old_tx = dap_ledger_tx_find_by_hash(a_ledger, &((dap_chain_net_vote_t *)l_temp->data)->vote_hash);

                        dap_list_t* l_tsd_list = dap_chain_datum_tx_items_get(l_old_tx, TX_ITEM_TYPE_TSD, NULL);
                        dap_list_t* l_tsd_temp = l_tsd_list;
                        while (l_tsd_temp){
                            dap_tsd_t* l_tsd = (dap_tsd_t*)((dap_chain_tx_tsd_t*)l_tsd_temp->data)->tsd;
                            dap_hash_fast_t l_hash = ((dap_chain_tx_voting_tx_cond_t*)l_tsd->data)->tx_hash;
                            if(l_tsd->type == VOTING_TSD_TYPE_VOTE_TX_COND){
                                dap_chain_net_voting_cond_outs_t *l_tx_outs = NULL;
                                pthread_rwlock_wrlock(&l_voting->s_tx_outs_rwlock);
                                HASH_FIND(hh, l_voting->voting_spent_cond_outs, &l_hash, sizeof(dap_hash_fast_t), l_tx_outs);
                                if(l_tx_outs)
                                    HASH_DELETE(hh, l_voting->voting_spent_cond_outs, l_tx_outs);
                                pthread_rwlock_unlock(&l_voting->s_tx_outs_rwlock);
                            }
                            l_tsd_temp = l_tsd_temp->next;
                        }
                        dap_list_free(l_tsd_list);


                        //delete vote
                        l_voting->votes = dap_list_remove(l_voting->votes, l_temp->data);
                        break;
                    } else {
                        log_it(L_ERROR, "The voting don't allow change your vote.");
                        return false;
                    }
                }
                l_temp = l_temp->next;
            }
            dap_list_free(l_signs_list);
        }

        uint256_t l_weight = {};

        // check out conds
        dap_list_t* l_tsd_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_TSD, NULL);
        dap_list_t* l_tsd_temp = l_tsd_list;
        while (l_tsd_temp){
            dap_tsd_t* l_tsd = (dap_tsd_t*)((dap_chain_tx_tsd_t*)l_tsd_temp->data)->tsd;
            dap_hash_fast_t l_hash = ((dap_chain_tx_voting_tx_cond_t*)l_tsd->data)->tx_hash;
            int l_out_idx = ((dap_chain_tx_voting_tx_cond_t*)l_tsd->data)->out_idx;
            if(l_tsd->type == VOTING_TSD_TYPE_VOTE_TX_COND){
                if (s_datum_tx_voting_coin_check_cond_out(a_ledger->net, l_vote_tx_item->voting_hash,
                                                          l_hash, l_out_idx) != 0){
                    l_tsd_temp = l_tsd_temp->next;
                    continue;
                }
                dap_chain_datum_tx_t *l_tx_prev_temp = dap_ledger_tx_find_by_hash(a_ledger, &l_hash);
                dap_chain_tx_out_cond_t *l_prev_out = (dap_chain_tx_out_cond_t*)dap_chain_datum_tx_item_get(l_tx_prev_temp, &l_out_idx, TX_ITEM_TYPE_OUT_COND, NULL);
                if(!l_prev_out || l_prev_out->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK){
                    l_tsd_temp = l_tsd_temp->next;
                    continue;
                }
                SUM_256_256(l_weight, l_prev_out->header.value, &l_weight);

                dap_chain_net_voting_cond_outs_t *l_item = DAP_NEW_Z_SIZE(dap_chain_net_voting_cond_outs_t, sizeof(dap_chain_net_voting_cond_outs_t));
                l_item->tx_hash = l_hash;
                l_item->out_idx = l_out_idx;
                pthread_rwlock_wrlock(&l_voting->s_tx_outs_rwlock);
                HASH_ADD(hh, l_voting->voting_spent_cond_outs, tx_hash, sizeof(dap_hash_fast_t), l_item);
                pthread_rwlock_unlock(&l_voting->s_tx_outs_rwlock);
            }
            l_tsd_temp = l_tsd_temp->next;
        }
        dap_list_free(l_tsd_list);
        // check inputs
        dap_list_t *l_ins_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_IN, NULL);
        if (!l_ins_list){
            log_it(L_ERROR, "Can't get inputs from tx");
            return -1;
        }
        dap_list_t *l_in_temp = l_ins_list;
        while(l_in_temp){
            dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t *)l_in_temp->data;
            if (s_datum_tx_voting_coin_check_spent(a_ledger->net, l_vote_tx_item->voting_hash, l_tx_in->header.tx_prev_hash, l_tx_in->header.tx_out_prev_idx) == 0){
                dap_chain_datum_tx_t *l_tx_prev_temp = dap_ledger_tx_find_by_hash(a_ledger, &l_tx_in->header.tx_prev_hash);
                int l_out_prev_idx = (int)l_tx_in->header.tx_out_prev_idx;
                dap_chain_tx_out_t *l_prev_out_union = (dap_chain_tx_out_t *)dap_chain_datum_tx_out_get_by_out_idx(l_tx_prev_temp, l_out_prev_idx);
                if (!l_prev_out_union){
                    l_in_temp = l_in_temp->next;
                    continue;
                }

                switch (l_prev_out_union->header.type) {
                case TX_ITEM_TYPE_OUT:
                case TX_ITEM_TYPE_OUT_EXT:
                    SUM_256_256(l_weight, l_prev_out_union->header.value, &l_weight);
                }
            }
            l_in_temp = l_in_temp->next;
        }
        dap_list_free(l_ins_list);

        if (IS_ZERO_256(l_weight)){
            log_it(L_ERROR, "No unspent coins");
            return false;
        }


        if (a_apply){
            dap_hash_fast_t pkey_hash = {};
            dap_chain_tx_sig_t *l_vote_sig = NULL;
            int l_item_cnt = 0;
            dap_list_t* l_signs_list = NULL;
            l_signs_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_SIG, &l_item_cnt);

            if(!l_signs_list){
                log_it(L_ERROR, "Can't get sign.");
                return false;
            }
            l_vote_sig = (dap_chain_tx_sig_t *)(dap_list_last(l_signs_list)->data);
            dap_sign_get_pkey_hash((dap_sign_t*)l_vote_sig->sig, &pkey_hash);

            dap_chain_net_vote_t *l_vote_item = DAP_NEW_Z(dap_chain_net_vote_t);
            if (!l_vote_item){
                log_it(L_CRITICAL, "Memory allocate_error!");
                dap_list_free(l_signs_list);
                return false;
            }
            l_vote_item->vote_hash = l_hash;
            l_vote_item->pkey_hash = pkey_hash;
            l_vote_item->answer_idx = l_vote_tx_item->answer_idx;
            l_vote_item->weight = l_weight;

            dap_list_t *l_temp = l_voting->votes;
            while(l_temp){
                if (dap_hash_fast_compare(&((dap_chain_net_vote_t *)l_temp->data)->pkey_hash, &pkey_hash)){
                    if(l_voting->voting_params.vote_changing_allowed_offset &&
                        *(bool*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.vote_changing_allowed_offset)){

                        l_voting->votes = dap_list_append(l_voting->votes, l_vote_item);

                        log_it(L_ERROR, "Vote is changed.");
                        dap_list_free(l_signs_list);
                        return true;
                    } else {
                        log_it(L_ERROR, "The voting don't allow change your vote.");
                        dap_list_free(l_signs_list);
                        DAP_DELETE(l_vote_item);
                        return false;
                    }
                }
                l_temp = l_temp->next;
            }
            dap_list_free(l_signs_list);
            log_it(L_INFO, "Vote is accepted.");
            l_voting->votes = dap_list_append(l_voting->votes, l_vote_item);
        }
        return true;
    } else {
        log_it(L_ERROR, "Item is not supported in votings.");
    }

    return false;
}

static dap_list_t* s_get_options_list_from_str(const char* a_str)
{
    dap_list_t* l_ret = NULL;
    char * l_options_str_dup = strdup(a_str);
    if (!l_options_str_dup) {
        log_it(L_ERROR, "Memory allocation error in %s, line %d", __PRETTY_FUNCTION__, __LINE__);
        return 0;
    }

    size_t l_opt_str_len = strlen(l_options_str_dup);
    char* l_option_start_ptr = l_options_str_dup;
    dap_string_t* l_option_str = dap_string_new(NULL);
    for (size_t i = 0; i <= l_opt_str_len; i++){
        if(i == l_opt_str_len){
            l_option_str = dap_string_append_len(l_option_str, l_option_start_ptr, &l_options_str_dup[i] - l_option_start_ptr);
            char* l_option = dap_string_free(l_option_str, false);
            l_option = dap_strstrip(l_option);// removes leading and trailing spaces
            l_ret = dap_list_append(l_ret, l_option);
            break;
        }
        if (l_options_str_dup [i] == ','){
            if(i > 0 && l_options_str_dup [i-1] == '\\'){
                l_option_str = dap_string_append_len(l_option_str, l_option_start_ptr, i-1);
                l_option_start_ptr = &l_options_str_dup [i];
                continue;
            }
            l_option_str = dap_string_append_len(l_option_str, l_option_start_ptr, &l_options_str_dup[i] - l_option_start_ptr);
            l_option_start_ptr = &l_options_str_dup [i+1];
            char* l_option = dap_string_free(l_option_str, false);
            l_option_str = dap_string_new(NULL);
            l_option = dap_strstrip(l_option);// removes leading and trailing spaces
            l_ret = dap_list_append(l_ret, l_option);
        }
    }

    free(l_options_str_dup);

    return l_ret;
}

static int s_cli_voting(int a_argc, char **a_argv, void **a_obj_reply)
{
    enum {CMD_NONE=0, CMD_CREATE, CMD_VOTE, CMD_LIST, CMD_DUMP};

    char **a_str_reply = (char**)a_obj_reply;
    const char* l_net_str = NULL;
    int arg_index = 1;
    dap_chain_net_t *l_net = NULL;

    const char *l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, 1, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type, "base58"))
        return -1;


    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    // Select chain network
    if(!l_net_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "command requires parameter '-net'");
        return -2;
    } else {
        if((l_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                                              "command requires parameter '-net' to be valid chain network name");
            return -3;
        }
    }

    int l_cmd = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "create", NULL))
        l_cmd = CMD_CREATE;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "vote", NULL))
        l_cmd = CMD_VOTE;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "list", NULL))
        l_cmd = CMD_LIST;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "dump", NULL))
        l_cmd = CMD_DUMP;


    switch(l_cmd){
        case CMD_CREATE:{
            const char* l_question_str = NULL;
            const char* l_options_list_str = NULL;
            const char* l_voting_expire_str = NULL;
            const char* l_max_votes_count_str = NULL;
            const char* l_fee_str = NULL;
            const char* l_wallet_str = NULL;

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-question", &l_question_str);
            if (!l_question_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Voting requires a question parameter to be valid.");
                return -100;
            }

            if (strlen(l_question_str) > DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "The question must contain no more than %d characters", DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH);
                return -101;
            }

            dap_list_t *l_options_list = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-options", &l_options_list_str);
            if (!l_options_list_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Voting requires a question parameter to be valid.");
                return -101;
            }
            // Parse options list
            l_options_list = s_get_options_list_from_str(l_options_list_str);
            if(!l_options_list || dap_list_length(l_options_list) < 2){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Number of options must be 2 or greater.");
                return -102;
            }

            if(dap_list_length(l_options_list)>DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "The voting can contain no more than %d options", DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT);
                return -102;
            }

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-expire", &l_voting_expire_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-max_votes_count", &l_max_votes_count_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_fee_str);
            if (!l_fee_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Voting requires paramete -fee to be valid.");
                return -102;
            }
            uint256_t l_value_fee = dap_chain_balance_scan(l_fee_str);
            if (IS_ZERO_256(l_value_fee)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "command requires parameter '-fee' to be valid uint256");
                return -103;
            }

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
            if (!l_wallet_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Voting requires parameter -w to be valid.");
                return -103;
            }

            dap_enc_key_t *l_priv_key = NULL;
            const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
            dap_chain_wallet_t *l_wallet_fee = dap_chain_wallet_open(l_wallet_str, c_wallets_path);
            if (!l_wallet_fee) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Wallet %s does not exist", l_wallet_str);
                return -112;
            }
            l_priv_key = dap_chain_wallet_get_key(l_wallet_fee, 0);

            const dap_chain_addr_t *l_addr_from = (const dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet_fee, l_net->pub.id);

            if(!l_addr_from) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "source address is invalid");
                return -113;
            }

            const char *l_native_ticker = l_net->pub.native_ticker;
            uint256_t l_net_fee = {}, l_total_fee = {}, l_value_transfer;
            dap_chain_addr_t l_addr_fee = {};
            bool l_net_fee_used = dap_chain_net_tx_get_fee(l_net->pub.id, &l_net_fee, &l_addr_fee);
            SUM_256_256(l_net_fee, l_value_fee, &l_total_fee);

            dap_ledger_t* l_ledger = dap_ledger_by_net_name(l_net->pub.name);
            dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                                     l_addr_from, l_total_fee, &l_value_transfer);
            if (!l_list_used_out) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Not enough funds to transfer");
                return -113;
            }
            // create empty transaction
            dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

            // Add Voting item
            dap_chain_tx_voting_t* l_voting_item = dap_chain_datum_tx_item_voting_create();

            dap_chain_datum_tx_add_item(&l_tx, l_voting_item);
            DAP_DELETE(l_voting_item);

            // Add question to tsd data
            dap_chain_tx_tsd_t* l_question_tsd = dap_chain_datum_voting_question_tsd_create(l_question_str, strlen(l_question_str));
            dap_chain_datum_tx_add_item(&l_tx, l_question_tsd);
            DAP_DELETE(l_question_tsd);

            // Add options to tsd
            dap_list_t *l_temp = l_options_list;
            while(l_temp){
                if(strlen((char*)l_temp->data) > DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_LENGTH){
                    dap_chain_datum_tx_delete(l_tx);
                    dap_list_free_full(l_options_list, NULL);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "The option must contain no more than %d characters", DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_LENGTH);
                    return -114;
                }
                dap_chain_tx_tsd_t* l_option = dap_chain_datum_voting_answer_tsd_create((char*)l_temp->data, strlen((char*)l_temp->data));
                if(!l_option){
                    dap_chain_datum_tx_delete(l_tx);
                    dap_list_free_full(l_options_list, NULL);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create option tsd item.");
                    return -114;
                }
                dap_chain_datum_tx_add_item(&l_tx, l_option);
                DAP_DEL_Z(l_option);

                l_temp = l_temp->next;
            }
            dap_list_free_full(l_options_list, NULL);

            // add voting expire time if needed
            if(l_voting_expire_str){
                dap_time_t l_expired_time = dap_time_from_str_rfc822(l_voting_expire_str);
                if(!l_expired_time){
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't parse expire time");
                    return -114;
                }
                if (l_expired_time < dap_time_now()){
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create voting with expired time");
                    return -114;
                }

                dap_chain_tx_tsd_t* l_expired_item = dap_chain_datum_voting_expire_tsd_create(l_expired_time);
                if(!l_expired_item){
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create expired tsd item.");
                    return -114;
                }
                dap_chain_datum_tx_add_item(&l_tx, l_expired_item);
                DAP_DEL_Z(l_expired_item);
            }

            // Add vote max count if needed
            if(l_max_votes_count_str){
                uint64_t l_max_votes_count = atoll(l_max_votes_count_str);
                dap_chain_tx_tsd_t* l_max_votes_item = dap_chain_datum_voting_max_votes_count_tsd_create(l_max_votes_count);
                if(!l_max_votes_item){
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create expired tsd item.");
                    return -114;
                }
                dap_chain_datum_tx_add_item(&l_tx, l_max_votes_item);
                DAP_DEL_Z(l_max_votes_item);
            }

            if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-delegated_key_required", NULL)){
                dap_chain_tx_tsd_t* l_delegated_key_req_item = dap_chain_datum_voting_delegated_key_required_tsd_create(true);
                if(!l_delegated_key_req_item){
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create delegated key req tsd item.");
                    return -114;
                }
                dap_chain_datum_tx_add_item(&l_tx, l_delegated_key_req_item);
                DAP_DEL_Z(l_delegated_key_req_item);
            }

            if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-vote_changing_allowed", NULL)){
                dap_chain_tx_tsd_t* l_vote_changing_item = dap_chain_datum_voting_vote_changing_allowed_tsd_create(true);
                if(!l_vote_changing_item){
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create delegated key req tsd item.");
                    return -114;
                }
                dap_chain_datum_tx_add_item(&l_tx, l_vote_changing_item);
                DAP_DEL_Z(l_vote_changing_item);
            }

            // add 'in' items
            uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
            assert(EQUAL_256(l_value_to_items, l_value_transfer));
            dap_list_free_full(l_list_used_out, NULL);
            uint256_t l_value_pack = {};
            // Network fee
            if (l_net_fee_used) {
                if (dap_chain_datum_tx_add_out_item(&l_tx, &l_addr_fee, l_net_fee) == 1)
                    SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
                else {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't add net fee out.");
                    return -114;
                }
            }
            // Validator's fee
            if (!IS_ZERO_256(l_value_fee)) {
                if (dap_chain_datum_tx_add_fee_item(&l_tx, l_value_fee) == 1)
                    SUM_256_256(l_value_pack, l_value_fee, &l_value_pack);
                else {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't add net fee out.");
                    return -115;
                }
            }
            // coin back
            uint256_t l_value_back;
            SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
            if(!IS_ZERO_256(l_value_back)) {
                if(dap_chain_datum_tx_add_out_item(&l_tx, l_addr_from, l_value_back) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't add out with value back");
                    return -116;
                }
            }

            // add 'sign' items
            if(dap_chain_datum_tx_add_sign_item(&l_tx, l_priv_key) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't sign tx");
                return -117;
            }

            size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
            dap_hash_fast_t l_tx_hash;
            dap_hash_fast(l_tx, l_tx_size, &l_tx_hash);
            dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
            DAP_DELETE(l_tx);
            dap_chain_t* l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);

            char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
            if (l_ret)
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Datum %s successfully added to mempool", l_ret);
            else
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't add datum to mempool");
            DAP_DELETE(l_datum);
        }break;
        case CMD_VOTE:{
            const char* l_cert_name = NULL;
            const char* l_fee_str = NULL;
            const char* l_wallet_str = NULL;
            const char* l_hash_str = NULL;
            const char* l_option_idx_str = NULL;

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_hash_str);
            if(!l_hash_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'vote' require the parameter -hash");
                return -110;
            }

            dap_hash_fast_t l_voting_hash = {};
            dap_chain_hash_fast_from_str(l_hash_str, &l_voting_hash);


            dap_chain_hash_fast_t l_pkey_hash;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_name);
            dap_cert_t * l_cert = dap_cert_find_by_name(l_cert_name);
            if (l_cert_name){
                if (l_cert == NULL) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find \"%s\" certificate", l_cert_name);
                    return -7;
                }
                if (l_cert->enc_key == NULL) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "No key found in \"%s\" certificate", l_cert_name );
                    return -8;
                }
                // Get publivc key hash
                size_t l_pub_key_size = 0;
                uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(l_cert->enc_key, &l_pub_key_size);;
                if (l_pub_key == NULL) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't serialize public key of certificate \"%s\"", l_cert_name);
                    return -9;
                }

                dap_hash_fast(l_pub_key, l_pub_key_size, &l_pkey_hash);
            }

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_fee_str);
            if (!l_fee_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'vote' requires paramete -fee to be valid.");
                return -102;
            }
            uint256_t l_value_fee = dap_chain_balance_scan(l_fee_str);
            if (IS_ZERO_256(l_value_fee)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "command requires parameter '-fee' to be valid uint256");
                return -103;
            }

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
            if (!l_wallet_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'vote' requires parameter -w to be valid.");
                return -103;
            }

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-option_idx", &l_option_idx_str);
            if (!l_option_idx_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'vote' requires parameter -option_idx to be valid.");
                return -103;
            }

            dap_chain_net_votings_t *l_voting = NULL;
            pthread_rwlock_rdlock(&s_votings_rwlock);
            HASH_FIND(hh, s_votings, &l_voting_hash, sizeof(l_voting_hash),l_voting);
            pthread_rwlock_unlock(&s_votings_rwlock);
            if(!l_voting || l_voting->net_id.uint64 != l_net->pub.id.uint64){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find voting with hash %s", l_hash_str);
                return -111;
            }

            if(l_voting->voting_params.votes_max_count_offset){
                uint64_t l_max_count = *(uint64_t*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.votes_max_count_offset);
                if (l_max_count && dap_list_length(l_voting->votes) >= l_max_count){
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "This voting already received the required number of votes.");
                    return -111;
                }
            }

            if(l_voting->voting_params.voting_expire_offset){
                dap_time_t l_expire = *(dap_time_t*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.voting_expire_offset);
                dap_time_t l_time_now = dap_time_now();
                if (l_expire && l_time_now > l_expire){
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "This voting already expired.");
                    return -111;
                }
            }

            if(l_voting->voting_params.delegate_key_required_offset &&
                *(bool*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.delegate_key_required_offset) ){
                if (!l_cert){
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "This voting required a delegated key.");
                    return -111;
                } else if(!dap_chain_net_srv_stake_check_pkey_hash(&l_pkey_hash)){
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Your key is not delegated.");
                    return -111;
                }
            }

            if(l_cert){
                dap_list_t *l_temp = l_voting->votes;
                while(l_temp){
                    if (dap_hash_fast_compare(&((dap_chain_net_vote_t *)l_temp->data)->pkey_hash, &l_pkey_hash)){
                        if(!l_voting->voting_params.vote_changing_allowed_offset ||
                        !*(bool*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.vote_changing_allowed_offset)){
                            dap_cli_server_cmd_set_reply_text(a_str_reply, "The voting doesn't allow change your vote.");
                            return -113;
                        }
                    }
                    l_temp = l_temp->next;
                }
            }

            dap_enc_key_t *l_priv_key = NULL;
            const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
            dap_chain_wallet_t *l_wallet_fee = dap_chain_wallet_open(l_wallet_str, c_wallets_path);
            if (!l_wallet_fee) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Wallet %s does not exist", l_wallet_str);
                return -112;
            }
            l_priv_key = dap_chain_wallet_get_key(l_wallet_fee, 0);

            const dap_chain_addr_t *l_addr_from = (const dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet_fee, l_net->pub.id);

            if(!l_addr_from) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "source address is invalid");
                return -113;
            }

            const char *l_native_ticker = l_net->pub.native_ticker;
            uint256_t l_net_fee = {}, l_total_fee = {}, l_value_transfer;
            dap_chain_addr_t l_addr_fee = {};
            bool l_net_fee_used = dap_chain_net_tx_get_fee(l_net->pub.id, &l_net_fee, &l_addr_fee);
            SUM_256_256(l_net_fee, l_value_fee, &l_total_fee);

            dap_ledger_t* l_ledger = dap_ledger_by_net_name(l_net->pub.name);
            dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs(l_ledger, l_native_ticker, l_addr_from, &l_value_transfer);
            if (!l_list_used_out || compare256(l_value_transfer, l_total_fee) <= 0) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Not enough funds to transfer");
                return -113;
            }


            // check outputs UTXOs
            dap_list_t *l_utxo_temp = l_list_used_out;
            uint256_t l_value_transfer_new = {};
            while(l_utxo_temp){
                dap_chain_tx_used_out_item_t *l_out = (dap_chain_tx_used_out_item_t *)l_utxo_temp->data;
                if (s_datum_tx_voting_coin_check_spent(l_net, l_voting_hash, l_out->tx_hash_fast, l_out->num_idx_out) != 0 &&
                    (!l_voting->voting_params.vote_changing_allowed_offset ||
                    !*(bool*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.vote_changing_allowed_offset))){
                    dap_list_t *l_temp = l_utxo_temp;
                    l_utxo_temp = l_utxo_temp->next;
                    dap_list_delete_link(l_list_used_out, l_temp);
                    continue;
                }
                SUM_256_256(l_value_transfer_new, l_out->value, &l_value_transfer_new);
                l_utxo_temp = l_utxo_temp->next;
            }

            if (IS_ZERO_256(l_value_transfer_new) || compare256(l_value_transfer_new, l_total_fee) <= 0){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "You have not unspent UTXO for participation in this voting.");
                return -113;
            }

            l_value_transfer = l_value_transfer_new;

            // create empty transaction
            dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

            // Add vote item
            uint64_t l_option_idx_count = atoll(l_option_idx_str);
            if (l_option_idx_count > dap_list_length(l_voting->voting_params.option_offsets_list)){
                dap_chain_datum_tx_delete(l_tx);
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid option index.");
                return -114;
            }
            dap_chain_tx_vote_t* l_vote_item = dap_chain_datum_tx_item_vote_create(&l_voting_hash, &l_option_idx_count);
            if(!l_vote_item){
                dap_chain_datum_tx_delete(l_tx);
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create vote item.");
                return -114;
            }
            dap_chain_datum_tx_add_item(&l_tx, l_vote_item);
            DAP_DEL_Z(l_vote_item);

            // add stake out conds items
            dap_list_t *l_outs = dap_ledger_get_list_tx_cond_outs(l_ledger, l_net->pub.native_ticker,  l_addr_from,
                                                                  DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, NULL);
            dap_list_t *l_temp = l_outs;
            while(l_temp){
                dap_chain_tx_used_out_item_t *l_out_item = (dap_chain_tx_used_out_item_t *)l_temp->data;
                if (dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &l_out_item->tx_hash_fast, l_out_item->num_idx_out, NULL) ||
                    s_datum_tx_voting_coin_check_cond_out(l_net, l_voting_hash, l_out_item->tx_hash_fast, l_out_item->num_idx_out ) != 0){
                    l_temp = l_temp->next;
                    continue;
                }
                dap_chain_tx_tsd_t *l_item = dap_chain_datum_voting_vote_tx_cond_tsd_create(l_out_item->tx_hash_fast, l_out_item->num_idx_out);
                if(!l_item){
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create tsd tx cond item.");
                    dap_list_free_full(l_outs, NULL);
                    return -114;
                }
                dap_chain_datum_tx_add_item(&l_tx, l_item);
                DAP_DEL_Z(l_item);
                l_temp = l_temp->next;
            }
            dap_list_free_full(l_outs, NULL);

            // add 'in' items
            uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
            assert(EQUAL_256(l_value_to_items, l_value_transfer));
            dap_list_free_full(l_list_used_out, NULL);
            uint256_t l_value_pack = {};
            // Network fee
            if (l_net_fee_used) {
                if (dap_chain_datum_tx_add_out_item(&l_tx, &l_addr_fee, l_net_fee) == 1)
                    SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
                else {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't add net fee out.");
                    return -114;
                }
            }
            // Validator's fee
            if (!IS_ZERO_256(l_value_fee)) {
                if (dap_chain_datum_tx_add_fee_item(&l_tx, l_value_fee) == 1)
                    SUM_256_256(l_value_pack, l_value_fee, &l_value_pack);
                else {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't add net fee out.");
                    return -115;
                }
            }
            // coin back
            uint256_t l_value_back;
            SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
            if(!IS_ZERO_256(l_value_back)) {
                if(dap_chain_datum_tx_add_out_item(&l_tx, l_addr_from, l_value_back) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't add out with value back");
                    return -116;
                }
            }

            // add 'sign' items with wallet sign
            if(dap_chain_datum_tx_add_sign_item(&l_tx, l_priv_key) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't sign tx");
                return -117;
            }

            // add 'sign' items with delegated key if needed
            if(l_cert){
                if(dap_chain_datum_tx_add_sign_item(&l_tx, l_cert->enc_key) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't sign tx");
                    return -117;
                }
            }

            size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
            dap_hash_fast_t l_tx_hash;
            dap_hash_fast(l_tx, l_tx_size, &l_tx_hash);
            dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
            DAP_DELETE(l_tx);
            dap_chain_t* l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);

            char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
            if (l_ret)
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Datum %s successfully added to mempool", l_ret);
            else
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't add datum to mempool");
            DAP_DELETE(l_datum);


        }break;
        case CMD_LIST:{
            dap_string_t *l_str_out = dap_string_new(NULL);
            dap_string_append_printf(l_str_out, "List of votings in net %s:\n\n", l_net->pub.name);
            dap_chain_net_votings_t *l_voting = NULL, *l_tmp;
            pthread_rwlock_rdlock(&s_votings_rwlock);
            HASH_ITER(hh, s_votings, l_voting, l_tmp){
                if (l_voting->net_id.uint64 != l_net->pub.id.uint64)
                    continue;

                char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_voting->voting_hash);
                dap_string_append_printf(l_str_out, "Voting hash: %s\n", l_hash_str);
                DAP_DELETE(l_hash_str);
                dap_string_append(l_str_out, "Voting question:\n");
                char* l_voting_question = (char*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.voting_question_offset);
                dap_string_append_len(l_str_out,
                                      l_voting_question,
                                      l_voting->voting_params.voting_question_length > strlen(l_voting_question) ? strlen(l_voting_question) : l_voting->voting_params.voting_question_length);
                dap_string_append(l_str_out, "\n\n");
            }
            pthread_rwlock_unlock(&s_votings_rwlock);

            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_out->str);
            dap_string_free(l_str_out, true);
        }break;
        case CMD_DUMP:{
            const char* l_hash_str = NULL;

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_hash_str);
            if(!l_hash_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'results' require the parameter -hash");
                return -110;
            }

            dap_hash_fast_t l_voting_hash = {};
            dap_chain_hash_fast_from_str(l_hash_str, &l_voting_hash);
            dap_chain_net_votings_t *l_voting = NULL;
            pthread_rwlock_rdlock(&s_votings_rwlock);
            HASH_FIND(hh, s_votings, &l_voting_hash, sizeof(l_voting_hash),l_voting);
            pthread_rwlock_unlock(&s_votings_rwlock);
            if(!l_voting){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find voting with hash %s", l_hash_str);
                return -111;
            }

            uint64_t l_options_count = 0;
            l_options_count = dap_list_length(l_voting->voting_params.option_offsets_list);
            if(!l_options_count){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "No options. May be datum is crashed.");
                return -111;
            }

            struct voting_results {uint64_t num_of_votes; uint256_t weights;};

            struct voting_results* l_results = DAP_NEW_Z_SIZE(struct voting_results, sizeof(struct voting_results)*l_options_count);
            if(!l_results){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Memlory allocation error!");
                return -111;
            }
            dap_list_t* l_list_tmp = l_voting->votes;
            uint256_t l_total_weight = {};
            while(l_list_tmp){
                dap_chain_net_vote_t *l_vote = l_list_tmp->data;
                l_results[l_vote->answer_idx].num_of_votes++;
                SUM_256_256(l_results[l_vote->answer_idx].weights, l_vote->weight, &l_results[l_vote->answer_idx].weights);
                l_list_tmp = l_list_tmp->next;
                SUM_256_256(l_total_weight, l_vote->weight, &l_total_weight);
            }

            uint64_t l_votes_count = 0;
            l_votes_count = dap_list_length(l_voting->votes);
            dap_string_t *l_str_out = dap_string_new(NULL);
            dap_string_append_printf(l_str_out, "Dump of voting %s:\n\n", l_hash_str);
            dap_string_append_len(l_str_out,
                                  (char*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.voting_question_offset),
                                  l_voting->voting_params.voting_question_length);
            dap_string_append(l_str_out, "\n\n");

            if(l_voting->voting_params.voting_expire_offset){
                char l_tmp_buf[70];
                dap_time_t l_expire = *(dap_time_t*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.voting_expire_offset);
                dap_string_append_printf(l_str_out, "\t Voting expire: %s", dap_ctime_r(&l_expire, l_tmp_buf));
                dap_string_truncate(l_str_out, l_str_out->len - 1);
                dap_string_append_printf(l_str_out, " (%s)\n", l_expire > dap_time_now() ? "active" : "expired");
            }
            if (l_voting->voting_params.votes_max_count_offset){
                uint64_t l_max_count = *(uint64_t*)((byte_t*)l_voting->voting_params.voting_tx + l_voting->voting_params.votes_max_count_offset);
                dap_string_append_printf(l_str_out, "\t Votes max count: %"DAP_UINT64_FORMAT_U" (%s)\n", l_max_count, l_max_count <= l_votes_count ? "closed" : "active");
            }
            dap_string_append_printf(l_str_out, "\t Changing vote is %s available.\n", l_voting->voting_params.vote_changing_allowed_offset ? "" : "not");
            dap_string_append_printf(l_str_out, "\t A delegated key is%s required to participate in voting. \n", l_voting->voting_params.delegate_key_required_offset ? "" : " not");
            dap_string_append_printf(l_str_out, "\n\nResults:\n\n");
            for (uint64_t i = 0; i < dap_list_length(l_voting->voting_params.option_offsets_list); i++){
                dap_string_append_printf(l_str_out, "%"DAP_UINT64_FORMAT_U")  ", i);
                dap_list_t* l_option = dap_list_nth(l_voting->voting_params.option_offsets_list, (uint64_t)i);
                dap_chain_net_vote_option_t* l_vote_option = (dap_chain_net_vote_option_t*)l_option->data;
                dap_string_append_len(l_str_out,
                                      (char*)((byte_t*)l_voting->voting_params.voting_tx + l_vote_option->vote_option_offset),
                                      l_vote_option->vote_option_length);
                float l_percentage = l_votes_count ? ((float)l_results[i].num_of_votes/l_votes_count)*100 : 0;
                uint256_t l_weight_percentage = {};

                DIV_256_COIN(l_results[i].weights, l_total_weight, &l_weight_percentage);
                MULT_256_COIN(l_weight_percentage, dap_chain_coins_to_balance("100.0"), &l_weight_percentage);
                char *l_weight_percentage_str = dap_uint256_decimal_to_round_char(l_weight_percentage, 2, true);
                dap_string_append_printf(l_str_out, "\nVotes: %"DAP_UINT64_FORMAT_U" (%.2f%%)\nWeight: %s (%s) %s (%s%%)\n", l_results[i].num_of_votes, l_percentage,
                                         dap_chain_balance_to_coins(l_results[i].weights), dap_chain_balance_print(l_results[i].weights), l_net->pub.native_ticker,
                                                                l_weight_percentage_str);
            }
            DAP_DELETE(l_results);
            dap_string_append_printf(l_str_out, "\nTotal number of votes: %"DAP_UINT64_FORMAT_U, l_votes_count);
            dap_string_append_printf(l_str_out, "\nTotal weight: %s (%s) %s\n\n", dap_chain_balance_to_coins(l_total_weight), dap_chain_balance_print(l_total_weight), l_net->pub.native_ticker);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_out->str);
            dap_string_free(l_str_out, true);
        }break;
        default:{

        }break;
    }

    return 0;
}

static int s_datum_tx_voting_coin_check_spent(dap_chain_net_t *a_net, dap_hash_fast_t a_voting_hash, dap_hash_fast_t a_tx_prev_hash, int a_out_idx)
{
    int l_coin_is_spent = 0;


    dap_ledger_t *l_ledger = a_net->pub.ledger;
    if(!l_ledger){
        log_it(L_ERROR, "Can't find ledger");
        return -1;
    }

    dap_chain_datum_tx_t *l_voting_tx = dap_ledger_tx_find_by_hash(l_ledger, &a_voting_hash);
    const char *l_native_ticker = a_net->pub.native_ticker;

    dap_list_t *l_tx_list = NULL; // "stack" for saving txs on up level
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(l_ledger, &a_tx_prev_hash);
    if (!l_tx){
        log_it(L_ERROR, "Can't find tx");
        return -1;
    }

    if (l_tx->header.ts_created < l_voting_tx->header.ts_created){
        return 0;
    }

    if (s_datum_tx_voting_coin_check_cond_out(a_net, a_voting_hash, a_tx_prev_hash, a_out_idx) != 0){
        return 1;
    }

    dap_chain_tx_vote_t *l_vote =(dap_chain_tx_vote_t *) dap_chain_datum_tx_item_get(l_tx, NULL, TX_ITEM_TYPE_VOTE, NULL);
    if(l_vote && dap_hash_fast_compare(&l_vote->voting_hash, &a_voting_hash)){
        dap_chain_net_votings_t *l_voting = NULL;
        pthread_rwlock_wrlock(&s_votings_rwlock);
        HASH_FIND(hh, s_votings, &a_voting_hash, sizeof(dap_hash_fast_t), l_voting);
        pthread_rwlock_unlock(&s_votings_rwlock);
        if (l_voting)
        {
                dap_list_t *l_temp = l_voting->votes;
                while (l_temp){
                    dap_chain_net_vote_t *l_vote = (dap_chain_net_vote_t *)l_temp->data;
                    if (dap_hash_fast_compare(&l_vote->vote_hash, &a_tx_prev_hash)){
                        l_coin_is_spent = 1;
                        return 1;
                    }
                    l_temp = l_temp->next;
                }
        }
    }


    dap_list_t *l_ins_list_temp = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN, NULL);
    dap_list_t *l_cond_ins_list = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN_COND, NULL);
    if (!l_ins_list_temp && !l_cond_ins_list){
        log_it(L_ERROR, "Can't get inputs from tx");
        return -1;
    }

    dap_list_t *l_ins_list = NULL;
    l_ins_list = dap_list_concat(l_ins_list, l_ins_list_temp);
    l_ins_list = dap_list_concat(l_ins_list, l_cond_ins_list);

    l_tx_list = dap_list_append(l_tx_list, l_ins_list);
    dap_list_t* l_tx_temp = dap_list_last(l_tx_list);

    while(l_tx_temp && !l_coin_is_spent){
        if (l_tx_temp->data == NULL){
            l_tx_list = dap_list_delete_link(l_tx_list, l_tx_temp);
            l_tx_temp = l_tx_list ? dap_list_last(l_tx_list) : NULL;
            continue;
        }
        dap_list_t *l_ins_list = (dap_list_t*)l_tx_temp->data;
        dap_chain_tx_in_t* l_temp_in = (dap_chain_tx_in_t*)l_ins_list->data;
        dap_chain_datum_tx_t *l_tx_prev_temp = dap_ledger_tx_find_by_hash(l_ledger, &l_temp_in->header.tx_prev_hash);
        int l_out_prev_idx = (int)l_temp_in->header.tx_out_prev_idx;

        const char* l_tx_token = NULL;
        dap_chain_tx_out_t *l_prev_out_union = (dap_chain_tx_out_t*)dap_chain_datum_tx_out_get_by_out_idx(l_tx_prev_temp, l_out_prev_idx);
        if (!l_prev_out_union){
            l_tx_temp->data = dap_list_remove(l_tx_temp->data, l_temp_in);
            if (l_tx_temp->data == NULL){
                l_tx_list = dap_list_delete_link(l_tx_list, l_tx_temp);
                l_tx_temp = l_tx_list ? dap_list_last(l_tx_list) : NULL;
            }
            continue;
        }

        switch (l_prev_out_union->header.type) {
            case TX_ITEM_TYPE_OUT:{
                l_tx_token = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_temp_in->header.tx_prev_hash);
            }break;
            case TX_ITEM_TYPE_OUT_EXT:{
                dap_chain_tx_out_ext_t *l_temp_out = (dap_chain_tx_out_ext_t *)l_prev_out_union;
                l_tx_token = l_temp_out->token;
            }break;
            case TX_ITEM_TYPE_OUT_COND:{
                dap_chain_tx_out_cond_t *l_temp_out = (dap_chain_tx_out_cond_t*)l_prev_out_union;
                if (l_temp_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK ||
                    s_datum_tx_voting_coin_check_cond_out(a_net, a_voting_hash, l_temp_in->header.tx_prev_hash, l_temp_in->header.tx_out_prev_idx) == 0)
                    break;
            }
            default:
                l_tx_temp->data = dap_list_remove((dap_list_t*)l_tx_temp->data, l_temp_in);
                if (l_tx_temp->data == NULL){
                    l_tx_list = dap_list_delete_link(l_tx_list, l_tx_temp);
                    l_tx_temp = l_tx_list ? dap_list_last(l_tx_list) : NULL;
                }
                continue;
        }

        if (l_tx_prev_temp->header.ts_created < l_voting_tx->header.ts_created ||
                                            dap_strcmp(l_tx_token, l_native_ticker)){
            l_tx_temp->data = dap_list_remove((dap_list_t*)l_tx_temp->data, l_temp_in);
            if (l_tx_temp->data == NULL){
                l_tx_list = dap_list_delete_link(l_tx_list, l_tx_temp);
                l_tx_temp = l_tx_list ? dap_list_last(l_tx_list) : NULL;
            }
            continue;
        }


        dap_chain_tx_vote_t *l_vote =(dap_chain_tx_vote_t *) dap_chain_datum_tx_item_get(l_tx_prev_temp, NULL, TX_ITEM_TYPE_VOTE, NULL);
        if(l_vote && dap_hash_fast_compare(&l_vote->voting_hash, &a_voting_hash)){
            dap_chain_net_votings_t *l_voting = NULL;
            pthread_rwlock_wrlock(&s_votings_rwlock);
            HASH_FIND(hh, s_votings, &a_voting_hash, sizeof(dap_hash_fast_t), l_voting);
            pthread_rwlock_unlock(&s_votings_rwlock);
            dap_list_t *l_temp = NULL;
            while (l_temp){
                dap_chain_net_vote_t *l_vote = (dap_chain_net_vote_t *)l_temp->data;
                if (dap_hash_fast_compare(&l_vote->vote_hash, &l_temp_in->header.tx_prev_hash)){
                    l_coin_is_spent = 1;
                    break;
                }
                l_temp = l_temp->next;
            }
        }


        l_ins_list = dap_chain_datum_tx_items_get(l_tx_prev_temp, TX_ITEM_TYPE_IN, NULL);
        l_tx_list = dap_list_append(l_tx_list, l_ins_list);
        l_tx_temp->data = dap_list_remove((dap_list_t*)l_tx_temp->data, l_temp_in);
        l_tx_temp = l_tx_list ? dap_list_last(l_tx_list) : NULL;

    }

    if(l_tx_list){
        l_tx_temp = l_tx_list;
        while(l_tx_temp){
            if (l_tx_temp->data)
                dap_list_free((dap_list_t*)l_tx_temp->data);
            l_tx_list = dap_list_delete_link(l_tx_list, l_tx_temp);
            l_tx_temp = dap_list_first(l_tx_list);
        }
    }

    return l_coin_is_spent;
}

static int s_datum_tx_voting_coin_check_cond_out(dap_chain_net_t *a_net, dap_hash_fast_t a_voting_hash, dap_hash_fast_t a_tx_cond_hash, int a_cond_out_idx)
{

    dap_chain_net_votings_t * l_voting = NULL;
    pthread_rwlock_wrlock(&s_votings_rwlock);
    HASH_FIND(hh, s_votings, &a_voting_hash, sizeof(dap_hash_fast_t), l_voting);
    pthread_rwlock_unlock(&s_votings_rwlock);
    if(!l_voting || l_voting->net_id.uint64 != a_net->pub.id.uint64) {
        char *l_hash_str = dap_chain_hash_fast_to_str_new(&a_voting_hash);
        log_it(L_ERROR, "Can't find voting with hash %s in net %s", l_hash_str, a_net->pub.name);
        DAP_DELETE(l_hash_str);
        return -1;
    }

    dap_chain_net_voting_cond_outs_t *l_tx_outs = NULL;
    pthread_rwlock_wrlock(&l_voting->s_tx_outs_rwlock);
    HASH_FIND(hh, l_voting->voting_spent_cond_outs, &a_tx_cond_hash, sizeof(dap_hash_fast_t), l_tx_outs);
    pthread_rwlock_unlock(&l_voting->s_tx_outs_rwlock);

    if (!l_tx_outs || l_tx_outs->out_idx != a_cond_out_idx){
        return 0;
    }

    return 1;
}
