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
#include "uthash.h"
#include "utlist.h"

#define LOG_TAG "chain_net_voting"

typedef struct dap_chain_net_voting_params_offsets{
    dap_chain_datum_tx_t* voting_tx;
    size_t voting_question_offset;
    size_t voting_question_length;
    dap_list_t* option_offsets_list;
    uint64_t options_count;
    size_t voting_expire_offset;
    size_t votes_max_count_offset;
    size_t delegate_key_required_offset;
    size_t vote_changing_allowed_offset;
} dap_chain_net_voting_params_offsets_t;

typedef struct dap_chain_net_vote_option {
    size_t vote_option_offset;
    size_t vote_option_length;
} dap_chain_net_vote_option_t;

typedef struct dap_chain_net_vote {
    dap_chain_hash_fast_t vote_hash;
    dap_chain_hash_fast_t pkey_hash;
    uint64_t answer_idx;
} dap_chain_net_vote_t;

typedef struct dap_chain_net_votings {
    dap_chain_hash_fast_t voting_hash;
    dap_chain_net_voting_params_offsets_t voting_params;
    dap_list_t *votes;
    dap_chain_net_id_t net_id;

    UT_hash_handle hh;
} dap_chain_net_votings_t;

static dap_chain_net_votings_t *s_votings;
static  pthread_rwlock_t s_votings_rwlock;

static bool s_datum_tx_voting_verification_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in);
static int s_cli_voting(int argc, char **argv, char **a_str_reply);

int dap_chain_net_voting_init()
{
    pthread_rwlock_init(&s_votings_rwlock, NULL);
    dap_chain_ledger_voting_verificator_add(s_datum_tx_voting_verification_callback);
    dap_cli_server_cmd_add("voting", s_cli_voting, "Voting commands", "");
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
    if(!l_voting || l_voting->net_id.uint64 != a_ledger->net_id.uint64){
        char* l_hash_str = dap_hash_fast_to_str_new(a_voting_hash);
        log_it(L_ERROR, "Can't find voting with hash %s in net %s", l_hash_str, dap_chain_net_by_id(a_ledger->net_id)->pub.name);
        DAP_DEL_Z(l_hash_str);
        return NULL;
    }

    l_voting_results = DAP_NEW_Z_SIZE(uint64_t, sizeof(uint64_t)*l_voting->voting_params.options_count);
    if (!l_voting_results){
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }

    dap_list_t* l_temp = l_voting->votes;
    while(l_temp){
        dap_chain_net_vote_t* l_vote = l_temp->data;
        if (l_vote->answer_idx >= l_voting->voting_params.options_count)
            continue;

        l_voting_results[l_vote->answer_idx]++;

        l_temp = l_temp->next;
    }


    return l_voting_results;
}



bool s_datum_tx_voting_verification_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in)
{

    dap_hash_fast_t l_hash = {};
    dap_hash_fast(a_tx_in, dap_chain_datum_tx_get_size(a_tx_in), &l_hash);

    if (a_type == TX_ITEM_TYPE_VOTING){
        dap_chain_net_votings_t * l_voting = NULL;
        pthread_rwlock_rdlock(&s_votings_rwlock);
        HASH_FIND(hh, s_votings, &l_hash, sizeof(dap_hash_fast_t), l_voting);
        pthread_rwlock_unlock(&s_votings_rwlock);
        if(l_voting || l_voting->net_id.uint64 != a_ledger->net_id.uint64){
            char* l_hash_str = dap_hash_fast_to_str_new(&l_hash);
            log_it(L_ERROR, "Voting with hash %s is already presents in net %s", l_hash_str, dap_chain_net_by_id(a_ledger->net_id)->pub.name);
            DAP_DEL_Z(l_hash_str);
            return NULL;
        }

        dap_chain_net_votings_t *l_item = DAP_NEW_Z_SIZE(dap_chain_net_votings_t, sizeof(dap_chain_net_votings_t));
        l_item->voting_hash = l_hash;
        l_item->voting_params.voting_tx = a_tx_in;
        l_item->net_id = a_ledger->net_id;

        int l_tsd_size = 0;
        dap_chain_tx_tsd_t *l_tx_tsd_item = (dap_chain_tx_tsd_t *)dap_chain_datum_tx_item_get(a_tx_in, 0, TX_ITEM_TYPE_TSD, &l_tsd_size);
        dap_tsd_t *l_tsd = (dap_tsd_t *)l_tx_tsd_item->tsd;
        int l_tsd_shift = 0;

        while (l_tsd_shift < l_tsd_size && l_tsd->size < (uint32_t)l_tsd_size){
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
                dap_list_append(l_item->voting_params.option_offsets_list, l_vote_option);
                l_item->voting_params.options_count++;
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
            l_tsd_shift += dap_tsd_size(l_tsd);
        }

        pthread_rwlock_wrlock(&s_votings_rwlock);
        HASH_ADD(hh, s_votings, voting_hash, sizeof(dap_hash_fast_t), l_item);
        pthread_rwlock_unlock(&s_votings_rwlock);
        return true;
    } else if (a_type == TX_ITEM_TYPE_VOTE){
        dap_chain_tx_vote_t *l_vote_tx_item = (dap_chain_tx_vote_t *)dap_chain_datum_tx_item_get(a_tx_in, 0, TX_ITEM_TYPE_VOTE, NULL);
        if(!l_vote_tx_item){
            log_it(L_ERROR, "Can't find vote item");
            pthread_rwlock_unlock(&s_votings_rwlock);
            return false;
        }
        dap_chain_net_votings_t * l_voting = NULL;
        pthread_rwlock_wrlock(&s_votings_rwlock);
        HASH_FIND(hh, s_votings, &l_vote_tx_item->voting_hash, sizeof(dap_hash_fast_t), l_voting);
        if(!l_voting || l_voting->net_id.uint64 != a_ledger->net_id.uint64) {
            char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_hash);
            log_it(L_ERROR, "Can't find voting with hash %s in net %s", l_hash_str, dap_chain_net_by_id(a_ledger->net_id)->pub.name);
            DAP_DELETE(l_hash_str);
            pthread_rwlock_unlock(&s_votings_rwlock);
            return false;
        }

        if (l_vote_tx_item->answer_idx > l_voting->voting_params.options_count){
            log_it(L_ERROR, "Invalid vote option index.");
            pthread_rwlock_unlock(&s_votings_rwlock);
            return false;
        }

        if (dap_list_length(l_voting->votes) > *(uint64_t*)(l_voting->voting_params.voting_tx + l_voting->voting_params.votes_max_count_offset)){
            log_it(L_ERROR, "The required number of votes has been collected.");
            pthread_rwlock_unlock(&s_votings_rwlock);
            return false;
        }

        if(*(dap_time_t*)(l_voting->voting_params.voting_tx + l_voting->voting_params.voting_expire_offset) < dap_time_now()){
            log_it(L_ERROR, "The voting has been expired.");
            pthread_rwlock_unlock(&s_votings_rwlock);
            return false;
        }

        dap_hash_fast_t pkey_hash = {};
        dap_chain_tx_sig_t *l_vote_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx_in, 0, TX_ITEM_TYPE_VOTE, NULL);
        dap_sign_get_pkey_hash((dap_sign_t*)l_vote_sig->sig, &pkey_hash);
        if (*(bool*)(l_voting->voting_params.voting_tx + l_voting->voting_params.delegate_key_required_offset)){
            if (!dap_chain_net_srv_stake_check_pkey_hash(&pkey_hash)){
                log_it(L_ERROR, "The voting required a delegated key.");
                pthread_rwlock_unlock(&s_votings_rwlock);
                return false;
            }
        }

        dap_chain_net_vote_t *l_vote_item = DAP_NEW_Z(dap_chain_net_vote_t);
        if (l_vote_item){
            log_it(L_CRITICAL, "Memory allocate_error!");
            pthread_rwlock_unlock(&s_votings_rwlock);
            return false;
        }
        l_vote_item->vote_hash = l_hash;
        l_vote_item->pkey_hash = pkey_hash;
        l_vote_item->answer_idx = l_vote_tx_item->answer_idx;

        dap_list_t *l_temp = l_voting->votes;
        while(l_temp){
            if (dap_hash_fast_compare(&((dap_chain_net_vote_t *)l_temp->data)->pkey_hash, &pkey_hash)){
                if(*(bool*)(l_voting->voting_params.voting_tx + l_voting->voting_params.vote_changing_allowed_offset)){
                    int idx = dap_list_index(l_voting->votes, l_temp);
                    dap_list_remove(l_voting->votes, l_temp);
                    dap_list_insert(l_voting->votes, l_vote_item, idx);
                    log_it(L_ERROR, "Vote is changed.");
                    pthread_rwlock_unlock(&s_votings_rwlock);
                    return true;
                } else {
                    log_it(L_ERROR, "The voting don't allow change your vote.");
                    DAP_DELETE(l_vote_item);
                    pthread_rwlock_unlock(&s_votings_rwlock);
                    return false;
                }
            }
            l_temp = l_temp->next;
        }
        log_it(L_ERROR, "Vote is accepted.");
        dap_list_append(l_voting->votes, l_vote_item);
        pthread_rwlock_unlock(&s_votings_rwlock);
        return true;
    } else {
        log_it(L_ERROR, "Item is not supported in votings.");
    }

    return false;
}

static int s_cli_voting(int a_argc, char **a_argv, char **a_str_reply)
{
    enum {CMD_NONE=0, CMD_CREATE, CMD_VOTE, CMD_LIST, CMD_RESULTS};

    const char* l_net_str = NULL;
    int arg_index = 1;
    dap_chain_net_t *l_net = NULL;


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
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "results", NULL))
        l_cmd = CMD_RESULTS;


    switch(l_cmd){
        case CMD_CREATE:{
            const char* l_question_str = NULL;
            const char* l_options_list_str = NULL;
            const char* l_voting_expire_str = NULL;
            const char* l_max_votes_count_str = NULL;
            const char* l_cert = NULL;
            const char* l_fee_str = NULL;
            const char* l_wallet_str = NULL;

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-question", &l_question_str);
            if (!l_question_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Voting requires a question parameter to be valid.");
                return -100;
            }

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-options", &l_options_list_str);
            if (!l_options_list_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Voting requires a question parameter to be valid.");
                return -101;
            } else {
                // Parse options list
            }

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-expire", &l_voting_expire_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-max_votes_count", &l_max_votes_count_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-delegated_key_required", NULL);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-vote_changing_allowed", NULL);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert);

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

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_voting_expire_str);
            if (!l_question_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Voting requires parameter -w to be valid.");
                return -103;
            }

            uint256_t l_net_fee = {}, l_total_fee = {}, l_value_transfer;
            dap_chain_addr_t l_addr_fee = {};
            bool l_net_fee_used = dap_chain_net_tx_get_fee(l_net->pub.id, &l_net_fee, &l_addr_fee);
            SUM_256_256(l_net_fee, l_value_fee, &l_total_fee);


            dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, a_token_ticker,
                                                                                     a_addr_from, l_total_fee, &l_value_transfer);
            if (!l_list_used_out) {
                log_it(L_WARNING, "Not enough funds to transfer");
                return NULL;
            }
            // create empty transaction
            dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
            // add 'in' items
            {
                uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
                assert(EQUAL_256(l_value_to_items, l_value_transfer));
                dap_list_free_full(l_list_used_out, NULL);
                if (l_list_fee_out) {
                uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
                assert(EQUAL_256(l_value_fee_items, l_fee_transfer));
                dap_list_free_full(l_list_fee_out, NULL);
                }

            }

            // Network fee
            if (l_net_fee_used) {
                if (dap_chain_datum_tx_add_out_item(&l_tx, &l_addr_fee, l_net_fee) == 1)
                    SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
                else {
                    dap_chain_datum_tx_delete(l_tx);
                    return NULL;
                }
            }
            // Validator's fee
            if (!IS_ZERO_256(a_value_fee)) {
                if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) == 1)
                    SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
                else {
                    dap_chain_datum_tx_delete(l_tx);
                    return NULL;
                }
            }
            // coin back
            uint256_t l_value_back;
            SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
            if(!IS_ZERO_256(l_value_back)) {
                if(dap_chain_datum_tx_add_out_item(&l_tx, a_addr_from, l_value_back) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    return NULL;
                }
            }

            // add 'sign' items
            if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }

            size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
            dap_hash_fast_t l_tx_hash;
            dap_hash_fast(l_tx, l_tx_size, &l_tx_hash);
            dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
            DAP_DELETE(l_tx);
            char *l_ret = dap_chain_mempool_datum_add(l_datum, a_chain, a_hash_out_type);
            DAP_DELETE(l_datum);
        }break;
        case CMD_VOTE:{

        }break;
        case CMD_LIST:{

        }break;
        case CMD_RESULTS:{

        }break;
        default:{

        }break;
    }

    return 0;
}
