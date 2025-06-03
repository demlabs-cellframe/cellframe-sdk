/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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

#include "dap_chain_net_srv_voting.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_mempool.h"
#include "uthash.h"
#include "utlist.h"
#include "dap_cli_server.h"
#include "dap_chain_wallet_cache.h"

#define LOG_TAG "chain_net_voting"

typedef struct dap_chain_net_voting_params_offsets{
    dap_chain_datum_tx_t* voting_tx;
    size_t voting_question_offset;
    size_t voting_question_length;
    dap_list_t *option_offsets_list;
    dap_time_t voting_expire;
    uint64_t votes_max_count;
    bool delegate_key_required;
    bool vote_changing_allowed;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
} dap_chain_net_voting_params_offsets_t;

typedef struct dap_chain_net_vote_option {
    size_t vote_option_offset;
    size_t vote_option_length;
} dap_chain_net_vote_option_t;

typedef struct dap_chain_net_voting_cond_outs {
    dap_chain_hash_fast_t tx_hash;
    int out_idx;
    dap_hash_fast_t pkey_hash;
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

static int s_datum_tx_voting_coin_check_cond_out(dap_chain_net_t *a_net, dap_hash_fast_t a_voting_hash, dap_hash_fast_t a_tx_cond_hash, int a_cond_out_idx, dap_hash_fast_t *a_vote_hash);
/// -1 error, 0 - unspent, 1 - spent
static int s_datum_tx_voting_coin_check_spent(dap_chain_net_t *a_net, dap_hash_fast_t a_voting_hash,
                                              dap_hash_fast_t a_tx_prev_hash, int a_out_idx, dap_hash_fast_t *a_pkey_hash);
static int s_datum_tx_voting_verification_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_hash, bool a_apply);
static bool s_datum_tx_voting_verification_delete_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in);
static int s_cli_voting(int argc, char **argv, void **a_str_reply);

static bool s_tag_check_voting(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,  dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action)
{
    //voting open 
    if (a_items_grp->items_voting) {
        *a_action = DAP_CHAIN_TX_TAG_ACTION_OPEN;
        return true;
    }

    //voting use
    if (a_items_grp->items_vote) {
        *a_action = DAP_CHAIN_TX_TAG_ACTION_USE;
        return true;
    }

    return false;
}

int dap_chain_net_srv_voting_init()
{
    pthread_rwlock_init(&s_votings_rwlock, NULL);
    dap_chain_ledger_voting_verificator_add(s_datum_tx_voting_verification_callback, s_datum_tx_voting_verification_delete_callback);
    dap_cli_cmd_t *l_poll_cmd = dap_cli_server_cmd_add(
                "poll", s_cli_voting, "Voting/poll commands",
                            "poll create -net <net_name> -question <\"Question_string\"> -options <\"Option0\", \"Option1\" ... \"OptionN\"> [-expire <poll_expire_time_in_RCF822>]"
                                           " [-max_votes_count <Votes_count>] [-delegated_key_required] [-vote_changing_allowed] -fee <value_datoshi> -w <fee_wallet_name> [-token <ticker>]\n"
                            "poll vote -net <net_name> -hash <poll_hash> -option_idx <option_index> [-cert <delegate_cert_name>] -fee <value_datoshi> -w <fee_wallet_name>\n"
                            "poll list -net <net_name>\n"
                            "poll dump -net <net_name> -hash <poll_hash>\n"
                            "Hint:\n"
                            "\texample value_coins (only natural) 1.0 123.4567\n"
                            "\texample value_datoshi (only integer) 1 20 0.4321e+4\n");
    dap_cli_server_alias_add(l_poll_cmd, NULL, "voting");
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_VOTING_ID };
    dap_ledger_service_add(l_uid, "poll", s_tag_check_voting);

    return 0;
}

void dap_chain_net_srv_voting_deinit()
{

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
        log_it(L_ERROR, "Can't find poll with hash %s in net %s", l_hash_str, a_ledger->net->pub.name);
        DAP_DEL_Z(l_hash_str);
        return NULL;
    }

    l_voting_results = DAP_NEW_Z_SIZE(uint64_t, sizeof(uint64_t)*dap_list_length(l_voting->voting_params.option_offsets_list));
    if (!l_voting_results){
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
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

static int s_voting_verificator(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_hash, bool a_apply)
{
    if (!a_apply) {
        dap_chain_net_votings_t * l_voting = NULL;
        pthread_rwlock_rdlock(&s_votings_rwlock);
        HASH_FIND(hh, s_votings, a_tx_hash, sizeof(dap_hash_fast_t), l_voting);
        pthread_rwlock_unlock(&s_votings_rwlock);
        if (l_voting && l_voting->net_id.uint64 == a_ledger->net->pub.id.uint64) {
            log_it(L_DEBUG, "Poll with hash %s is already presents in net %s",  dap_hash_fast_to_str_static(a_tx_hash), a_ledger->net->pub.name);
            return -1;
        }

        dap_list_t* l_tsd_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_TSD, NULL);
        size_t l_question_len = 0, l_options_count = 0;
        for (dap_list_t *it = l_tsd_list; it; it = it->next) {
            dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t *)it->data)->tsd;
            switch (l_tsd->type) {
            case VOTING_TSD_TYPE_QUESTION:
                l_question_len = l_tsd->size;
                break;
            case VOTING_TSD_TYPE_ANSWER:
                l_options_count++;
                break;
            default:
                break;
            }
        }
        dap_list_free(l_tsd_list);

        if (!l_question_len || !l_options_count) {
            log_it(L_WARNING, "Poll with hash %s contain no question or answer options", dap_hash_fast_to_str_static(a_tx_hash));
            return -2;
        }

        return DAP_LEDGER_CHECK_OK;
    }

    dap_chain_net_votings_t *l_item = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_net_votings_t, -DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
    l_item->voting_hash = *a_tx_hash;
    l_item->voting_params.voting_tx = a_tx_in;
    l_item->net_id = a_ledger->net->pub.id;
    pthread_rwlock_init(&l_item->s_tx_outs_rwlock, NULL);

    dap_list_t* l_tsd_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_TSD, NULL);
    for (dap_list_t *it = l_tsd_list; it; it = it->next) {
        dap_chain_tx_tsd_t *l_tx_tsd = it->data;
        dap_tsd_t *l_tsd = (dap_tsd_t *)l_tx_tsd->tsd;
        if (l_tx_tsd->header.size < sizeof(dap_tsd_t) ||
                l_tx_tsd->header.size != dap_tsd_size(l_tsd)) {
            log_it(L_WARNING, "Incorrect size %" DAP_UINT64_FORMAT_U " of TX_TSD item for poll %s",
                   l_tx_tsd->header.size, dap_hash_fast_to_str_static(a_tx_hash));
            return -DAP_LEDGER_CHECK_INVALID_SIZE;
        }
        dap_chain_net_vote_option_t *l_vote_option = NULL;
        switch(l_tsd->type){
        case VOTING_TSD_TYPE_QUESTION:
            if (!l_tsd->size) {
                log_it(L_WARNING, "Incorrect size %u of TSD section QUESTION for poll %s", l_tsd->size, dap_hash_fast_to_str_static(a_tx_hash));
                return -DAP_LEDGER_CHECK_INVALID_SIZE;
            }
            l_item->voting_params.voting_question_offset = (size_t)(l_tsd->data - (byte_t*)l_item->voting_params.voting_tx);
            l_item->voting_params.voting_question_length = l_tsd->size;
            break;
        case VOTING_TSD_TYPE_ANSWER:
            if (!l_tsd->size) {
                log_it(L_WARNING, "Incorrect size %u of TSD section ANSWER for poll %s", l_tsd->size, dap_hash_fast_to_str_static(a_tx_hash));
                return -DAP_LEDGER_CHECK_INVALID_SIZE;
            }
            l_vote_option = DAP_NEW_Z(dap_chain_net_vote_option_t);
            l_vote_option->vote_option_offset = (size_t)(l_tsd->data - (byte_t*)l_item->voting_params.voting_tx);
            l_vote_option->vote_option_length = l_tsd->size;
            l_item->voting_params.option_offsets_list = dap_list_append(l_item->voting_params.option_offsets_list, l_vote_option);
            break;
        case VOTING_TSD_TYPE_EXPIRE:
            if (l_tsd->size != sizeof(dap_time_t)) {
                log_it(L_WARNING, "Incorrect size %u of TSD section EXPIRE for poll %s", l_tsd->size, dap_hash_fast_to_str_static(a_tx_hash));
                return -DAP_LEDGER_CHECK_INVALID_SIZE;
            }
            l_item->voting_params.voting_expire = *(dap_time_t *)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_MAX_VOTES_COUNT:
            if (l_tsd->size != sizeof(uint64_t)) {
                log_it(L_WARNING, "Incorrect size %u of TSD section MAX_VOTES_COUNT for poll %s", l_tsd->size, dap_hash_fast_to_str_static(a_tx_hash));
                return -DAP_LEDGER_CHECK_INVALID_SIZE;
            }
            l_item->voting_params.votes_max_count = *(uint64_t *)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_DELEGATED_KEY_REQUIRED:
            if (l_tsd->size != sizeof(byte_t)) {
                log_it(L_WARNING, "Incorrect size %u of TSD section DELEGATED_KEY_REQUIRED for poll %s", l_tsd->size, dap_hash_fast_to_str_static(a_tx_hash));
                return -DAP_LEDGER_CHECK_INVALID_SIZE;
            }
            l_item->voting_params.delegate_key_required = *(byte_t *)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED:
            if (l_tsd->size != sizeof(byte_t)) {
                log_it(L_WARNING, "Incorrect size %u of TSD section VOTE_CHANGING_ALLOWED for poll %s", l_tsd->size, dap_hash_fast_to_str_static(a_tx_hash));
                return -DAP_LEDGER_CHECK_INVALID_SIZE;
            }
            l_item->voting_params.vote_changing_allowed = *(byte_t *)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_TOKEN:
            if (!l_tsd->size || l_tsd->size >= DAP_CHAIN_TICKER_SIZE_MAX) {
                log_it(L_WARNING, "Incorrect size %u of TSD section TOKEN for poll %s", l_tsd->size, dap_hash_fast_to_str_static(a_tx_hash));
                return -DAP_LEDGER_CHECK_INVALID_SIZE;
            }
            strcpy(l_item->voting_params.token_ticker, (char *)l_tsd->data);
        default:
            break;
        }
    }
    dap_list_free(l_tsd_list);

    if (!*l_item->voting_params.token_ticker)
        strcpy(l_item->voting_params.token_ticker, a_ledger->net->pub.native_ticker);
    if (!*l_item->voting_params.token_ticker)
        strcpy(l_item->voting_params.token_ticker, a_ledger->net->pub.native_ticker);
    pthread_rwlock_wrlock(&s_votings_rwlock);
    HASH_ADD(hh, s_votings, voting_hash, sizeof(dap_hash_fast_t), l_item);
    pthread_rwlock_unlock(&s_votings_rwlock);
    log_it(L_NOTICE, "Poll with hash %s succefully added to ledger", dap_hash_fast_to_str_static(a_tx_hash));
    return DAP_LEDGER_CHECK_OK;
}

static int s_vote_verificator(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_hash, bool a_apply)
{
    dap_chain_tx_vote_t *l_vote_tx_item = (dap_chain_tx_vote_t*)dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_VOTE, NULL);
    if (!l_vote_tx_item) {
        log_it(L_ERROR, "Can't find vote item for tx %s", dap_chain_hash_fast_to_str_static(a_tx_hash));
        return -4;
    }

    dap_chain_net_votings_t *l_voting = NULL;
    pthread_rwlock_wrlock(&s_votings_rwlock);
    HASH_FIND(hh, s_votings, &l_vote_tx_item->voting_hash, sizeof(dap_hash_fast_t), l_voting);
    pthread_rwlock_unlock(&s_votings_rwlock);
    if (!l_voting || l_voting->net_id.uint64 != a_ledger->net->pub.id.uint64) {
        log_it(L_ERROR, "Can't find poll with hash %s in net %s",
               dap_chain_hash_fast_to_str_static(&l_vote_tx_item->voting_hash), a_ledger->net->pub.name);
        return -5;
    }

    // Get last sign item from transaction
    dap_hash_fast_t l_pkey_hash = {};
    dap_sign_t *l_pkey_sign = NULL, *l_wallet_sign = NULL;
    uint8_t *l_tx_item = NULL; size_t l_size; int i, l_sign_num = 0;
    TX_ITEM_ITER_TX_TYPE(l_tx_item, TX_ITEM_TYPE_SIG, l_size, i, a_tx_in) {
        l_pkey_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_item);
        if (!l_wallet_sign)
            l_wallet_sign = l_pkey_sign;
        l_sign_num++;
    }
    dap_sign_get_pkey_hash(l_pkey_sign, &l_pkey_hash);
    if (--l_sign_num && dap_chain_datum_tx_verify_sign(a_tx_in, l_sign_num)) {
        log_it(L_WARNING, "Last vote tx %s sign verification failed", dap_chain_hash_fast_to_str_static(a_tx_hash));
        return -22;
    }

    if (l_vote_tx_item->answer_idx > dap_list_length(l_voting->voting_params.option_offsets_list)) {
        log_it(L_WARNING, "Invalid vote option index %" DAP_UINT64_FORMAT_U " for vote tx %s",
                                                l_vote_tx_item->answer_idx, dap_chain_hash_fast_to_str_static(a_tx_hash));
        return -6;
    }
    if (l_voting->voting_params.votes_max_count && dap_list_length(l_voting->votes) >= l_voting->voting_params.votes_max_count){
        log_it(L_WARNING, "The required number of votes has been collected for poll %s", dap_chain_hash_fast_to_str_static(&l_voting->voting_hash));
        return -7;
    }
    if (l_voting->voting_params.voting_expire && l_voting->voting_params.voting_expire <= a_tx_in->header.ts_created) {
        log_it(L_WARNING, "The voting %s has been expired", dap_chain_hash_fast_to_str_static(&l_voting->voting_hash));
        return -8;
    }

    if (l_voting->voting_params.delegate_key_required &&
            !dap_chain_net_srv_stake_check_pkey_hash(a_ledger->net->pub.id, &l_pkey_hash)){
        log_it(L_WARNING, "Poll %s required a delegated key", dap_chain_hash_fast_to_str_static(&l_voting->voting_hash));
        return -10;
    }

    dap_list_t *l_old_vote = NULL;
    for (dap_list_t *it = l_voting->votes; it; it = it->next) {
        if (dap_hash_fast_compare(&((dap_chain_net_vote_t *)it->data)->pkey_hash, &l_pkey_hash)) {
            dap_hash_fast_t *l_vote_hash = &((dap_chain_net_vote_t *)it->data)->vote_hash;
            if (!l_voting->voting_params.vote_changing_allowed) {
                char l_vote_hash_str[DAP_HASH_FAST_STR_SIZE];
                dap_hash_fast_to_str(l_vote_hash, l_vote_hash_str, DAP_HASH_FAST_STR_SIZE);
                log_it(L_WARNING, "The poll %s don't allow change your vote %s",
                       dap_hash_fast_to_str_static(&l_voting->voting_hash), l_vote_hash_str);
                return -11;
            }
            l_old_vote = it;
            break;
        }
    }

    uint256_t l_weight = {};
    // check inputs
    dap_list_t *l_ins_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_IN, NULL);
    if (!l_ins_list) {
        log_it(L_WARNING, "Can't get inputs from vote tx %s", dap_chain_hash_fast_to_str_static(a_tx_hash));
        return -12;
    }
    for (dap_list_t *it = l_ins_list; it; it = it->next) {
        dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t *)it->data;
        dap_chain_datum_tx_t *l_tx_prev_temp = dap_ledger_tx_find_by_hash(a_ledger, &l_tx_in->header.tx_prev_hash);
        dap_chain_tx_out_ext_t *l_prev_out_union = (dap_chain_tx_out_ext_t *)dap_chain_datum_tx_out_get_by_out_idx(
                                                    l_tx_prev_temp, l_tx_in->header.tx_out_prev_idx);
        if (!l_prev_out_union)
            return -18;
        const char *l_ticker_in = NULL;
        switch (l_prev_out_union->header.type) {
        case TX_ITEM_TYPE_OUT:
            l_ticker_in = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_tx_in->header.tx_prev_hash);
            break;
        case TX_ITEM_TYPE_OUT_EXT:
            l_ticker_in = l_prev_out_union->token;
            break;
        default:
            log_it(L_WARNING, "Unexpected tx item %d in vote tx %s", l_prev_out_union->header.type, dap_hash_fast_to_str_static(a_tx_hash));
            return -19;
        }
        if (dap_strcmp(l_ticker_in, l_voting->voting_params.token_ticker))
            continue;
        if (s_datum_tx_voting_coin_check_spent(a_ledger->net, l_vote_tx_item->voting_hash,
                                               l_tx_in->header.tx_prev_hash, l_tx_in->header.tx_out_prev_idx,
                                               l_old_vote ? &l_pkey_hash : NULL)) {
            log_it(L_WARNING, "Coin with out number %u for tx %s is spent for poll %s", l_tx_in->header.tx_out_prev_idx,
                                        dap_hash_fast_to_str_static(a_tx_hash), dap_hash_fast_to_str_static(&l_vote_tx_item->voting_hash));
            return -20;
        }
        if (SUM_256_256(l_weight, l_prev_out_union->header.value, &l_weight)) {
            log_it(L_WARNING, "Integer overflow while parsing vote tx %s", dap_chain_hash_fast_to_str_static(a_tx_hash));
            return -DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
        }
    }
    dap_list_free(l_ins_list);

    if (IS_ZERO_256(l_weight)) {
        log_it(L_ERROR, "No unspent coins found in vote tx %s", dap_chain_hash_fast_to_str_static(a_tx_hash));
        return -13;
    }

    // check out conds
    dap_list_t *l_tsd_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_TSD, NULL);
    for (dap_list_t *it = l_tsd_list; it; it = it->next) {
        dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t*)it->data)->tsd;
        dap_hash_fast_t l_hash = ((dap_chain_tx_voting_tx_cond_t*)l_tsd->data)->tx_hash;
        int l_out_idx = ((dap_chain_tx_voting_tx_cond_t*)l_tsd->data)->out_idx;
        if (l_tsd->type != VOTING_TSD_TYPE_VOTE_TX_COND)
            return dap_list_free(l_tsd_list), -14;
        dap_chain_datum_tx_t *l_tx_prev_temp = dap_ledger_tx_find_by_hash(a_ledger, &l_hash);
        dap_chain_tx_out_cond_t *l_prev_out = (dap_chain_tx_out_cond_t *)dap_chain_datum_tx_out_get_by_out_idx(l_tx_prev_temp, l_out_idx);
        if (!l_prev_out || l_prev_out->header.item_type != TX_ITEM_TYPE_OUT_COND ||
                l_prev_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
            return dap_list_free(l_tsd_list), -16;
        if (!dap_ledger_check_condition_owner(a_ledger, &l_hash, l_prev_out->header.subtype, l_out_idx, l_wallet_sign)) {
            log_it(L_WARNING, "TX hash %s out #%d owner verification error", dap_hash_fast_to_str_static(&l_hash), l_out_idx);
            return dap_list_free(l_tsd_list), -17;
        }
        if (s_datum_tx_voting_coin_check_cond_out(a_ledger->net, l_vote_tx_item->voting_hash, l_hash, l_out_idx,
                                                  l_old_vote ? &l_pkey_hash : NULL))
            return dap_list_free(l_tsd_list), -15;
        if (SUM_256_256(l_weight, l_prev_out->header.value, &l_weight)) {
            log_it(L_WARNING, "Integer overflow while parsing vote tx %s", dap_chain_hash_fast_to_str_static(a_tx_hash));
            return dap_list_free(l_tsd_list), -DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
        }
    }

    if (a_apply) {
        // Mark conditional outs
        pthread_rwlock_wrlock(&l_voting->s_tx_outs_rwlock);
        if (l_old_vote) {
            dap_hash_fast_t *l_vote_hash = &((dap_chain_net_vote_t *)l_old_vote->data)->vote_hash;
            dap_chain_net_voting_cond_outs_t *it = NULL, *tmp;
            HASH_ITER(hh, l_voting->voting_spent_cond_outs, it, tmp) {
                if (!dap_hash_fast_compare(l_vote_hash, &it->pkey_hash))
                    continue;
                HASH_DEL(l_voting->voting_spent_cond_outs, it);
                DAP_DELETE(it);
            }
        }
        for (dap_list_t *it = l_tsd_list; it; it = it->next) {
            dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t *)it->data)->tsd;
            if (l_tsd->type != VOTING_TSD_TYPE_VOTE_TX_COND)
                continue;
            dap_chain_net_voting_cond_outs_t *l_tx_out = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_net_voting_cond_outs_t, -DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            l_tx_out->tx_hash = ((dap_chain_tx_voting_tx_cond_t *)l_tsd->data)->tx_hash;
            l_tx_out->out_idx = ((dap_chain_tx_voting_tx_cond_t *)l_tsd->data)->out_idx;
            l_tx_out->pkey_hash = l_pkey_hash;
            HASH_ADD(hh, l_voting->voting_spent_cond_outs, tx_hash, sizeof(dap_hash_fast_t), l_tx_out);
        }
        pthread_rwlock_unlock(&l_voting->s_tx_outs_rwlock);

        // Mark conditional outs
        pthread_rwlock_wrlock(&l_voting->s_tx_outs_rwlock);
        if (l_old_vote) {
            dap_hash_fast_t *l_vote_hash = &((dap_chain_net_vote_t *)l_old_vote->data)->vote_hash;
            dap_chain_net_voting_cond_outs_t *it = NULL, *tmp;
            HASH_ITER(hh, l_voting->voting_spent_cond_outs, it, tmp) {
                if (!dap_hash_fast_compare(l_vote_hash, &it->pkey_hash))
                    continue;
                HASH_DEL(l_voting->voting_spent_cond_outs, it);
                DAP_DELETE(it);
            }
        }
        for (dap_list_t *it = l_tsd_list; it; it = it->next) {
            dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t *)it->data)->tsd;
            if (l_tsd->type != VOTING_TSD_TYPE_VOTE_TX_COND)
                continue;
            dap_chain_net_voting_cond_outs_t *l_tx_out = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_net_voting_cond_outs_t, -DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
            l_tx_out->tx_hash = ((dap_chain_tx_voting_tx_cond_t *)l_tsd->data)->tx_hash;
            l_tx_out->out_idx = ((dap_chain_tx_voting_tx_cond_t *)l_tsd->data)->out_idx;
            l_tx_out->pkey_hash = l_pkey_hash;
            HASH_ADD(hh, l_voting->voting_spent_cond_outs, tx_hash, sizeof(dap_hash_fast_t), l_tx_out);
        }
        pthread_rwlock_unlock(&l_voting->s_tx_outs_rwlock);

        dap_chain_net_vote_t *l_vote_item = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_net_vote_t, -DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY);
        l_vote_item->vote_hash = *a_tx_hash;
        l_vote_item->pkey_hash = l_pkey_hash;
        l_vote_item->answer_idx = l_vote_tx_item->answer_idx;
        l_vote_item->weight = l_weight;

        if (l_old_vote) {
            // change vote & move it to the end of list
            const char *l_vote_hash_str = dap_hash_fast_to_str_static(&((dap_chain_net_vote_t *)l_old_vote->data)->vote_hash);
            DAP_DELETE(l_old_vote->data);
            l_voting->votes = dap_list_delete_link(l_voting->votes, l_old_vote);
            log_it(L_NOTICE, "Vote %s of poll %s has been changed", l_vote_hash_str, dap_hash_fast_to_str_static(&l_voting->voting_hash));
        } else {
            const char *l_vote_hash_str = dap_hash_fast_to_str_static(a_tx_hash);
            log_it(L_NOTICE, "Vote %s of poll %s has been accepted", l_vote_hash_str, dap_hash_fast_to_str_static(&l_voting->voting_hash));
        }

        l_voting->votes = dap_list_append(l_voting->votes, l_vote_item);
    }
    dap_list_free(l_tsd_list);

    return DAP_LEDGER_CHECK_OK;
}

int s_datum_tx_voting_verification_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_hash, bool a_apply)
{
    if (a_type == TX_ITEM_TYPE_VOTING)
        return s_voting_verificator(a_ledger, a_type, a_tx_in, a_tx_hash, a_apply);
    if (a_type == TX_ITEM_TYPE_VOTE)
        return s_vote_verificator(a_ledger, a_type, a_tx_in, a_tx_hash, a_apply);
    log_it(L_ERROR, "Item %d is not supported in polls", a_type);
    return -3;
}

static bool s_datum_tx_voting_verification_delete_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in)
{
    dap_hash_fast_t l_hash = {};
    dap_hash_fast(a_tx_in, dap_chain_datum_tx_get_size(a_tx_in), &l_hash);

    if (a_type == TX_ITEM_TYPE_VOTING){
        dap_chain_net_votings_t * l_voting = NULL;
        pthread_rwlock_wrlock(&s_votings_rwlock);
        HASH_FIND(hh, s_votings, &l_hash, sizeof(dap_hash_fast_t), l_voting);
        if(!l_voting){
            char* l_hash_str = dap_hash_fast_to_str_new(&l_hash);
            log_it(L_ERROR, "Can't find poll with hash %s in net %s", l_hash_str, a_ledger->net->pub.name);
            DAP_DEL_Z(l_hash_str);
            pthread_rwlock_unlock(&s_votings_rwlock);
            return false;
        }
        HASH_DEL(s_votings, l_voting);
        pthread_rwlock_unlock(&s_votings_rwlock);

        if (l_voting->voting_params.option_offsets_list)
            dap_list_free_full(l_voting->voting_params.option_offsets_list, NULL);

        if(l_voting->votes)
            dap_list_free_full(l_voting->votes, NULL);

        dap_chain_net_voting_cond_outs_t *l_el = NULL, *l_tmp = NULL;
        if(l_voting->voting_spent_cond_outs && l_voting->voting_spent_cond_outs->hh.tbl->num_items){
            HASH_ITER(hh, l_voting->voting_spent_cond_outs, l_el, l_tmp){
                if (l_el){
                    HASH_DEL(l_voting->voting_spent_cond_outs, l_el);
                    DAP_DELETE(l_el);
                }
            }
        }

        DAP_DELETE(l_voting);

        return true;
    } else if (a_type == TX_ITEM_TYPE_VOTE){
        dap_chain_tx_vote_t *l_vote_tx_item = (dap_chain_tx_vote_t *)dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_VOTE, NULL);
        if(!l_vote_tx_item){
            log_it(L_ERROR, "Can't find vote item");
            return false;
        }

        dap_chain_net_votings_t *l_voting = NULL;
        pthread_rwlock_wrlock(&s_votings_rwlock);
        HASH_FIND(hh, s_votings, &l_vote_tx_item->voting_hash, sizeof(dap_hash_fast_t), l_voting);
        pthread_rwlock_unlock(&s_votings_rwlock);
        if(!l_voting || l_voting->net_id.uint64 != a_ledger->net->pub.id.uint64) {
            char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_hash);
            log_it(L_ERROR, "Can't find poll with hash %s in net %s", l_hash_str, a_ledger->net->pub.name);
            DAP_DELETE(l_hash_str);
            return false;
        }

        for (dap_list_t *l_vote = l_voting->votes; l_vote; l_vote = l_vote->next) {
            if (dap_hash_fast_compare(&((dap_chain_net_vote_t *)l_vote->data)->vote_hash, &l_hash)){
                // Delete vote
                DAP_DELETE(l_vote->data);
                l_voting->votes = dap_list_remove(l_voting->votes, l_vote->data);
                break;
            }
        }
    }

    return true;
}

dap_list_t* dap_get_options_list_from_str(const char* a_str)
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

static int s_cli_voting(int a_argc, char **a_argv, void **a_str_reply)
{
    json_object **json_arr_reply = (json_object **)a_str_reply;
    enum {CMD_NONE=0, CMD_CREATE, CMD_VOTE, CMD_LIST, CMD_DUMP};

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
        dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_NET_PARAM_MISSING, "command requires parameter '-net'");
        return -DAP_CHAIN_NET_VOTE_VOTING_NET_PARAM_MISSING;
    } else {
        if((l_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_NET_PARAM_NOT_VALID, "command requires parameter '-net' to be valid chain network name");            
            return -DAP_CHAIN_NET_VOTE_VOTING_NET_PARAM_NOT_VALID;
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
        const char *l_token_str = NULL;

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-question", &l_question_str);
        if (!l_question_str){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_QUESTION_PARAM_MISSING, "Poll requires a question parameter to be valid.");
            return -DAP_CHAIN_NET_VOTE_CREATE_QUESTION_PARAM_MISSING;
        }

        if (strlen(l_question_str) > DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_QUESTION_CONTAIN_MAX_CHARACTERS, 
            "The question must contain no more than %d characters", DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH);
            return -DAP_CHAIN_NET_VOTE_CREATE_QUESTION_CONTAIN_MAX_CHARACTERS;
        }

        dap_list_t *l_options_list = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-options", &l_options_list_str);
        if (!l_options_list_str){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_OPTION_PARAM_MISSING, "Poll requires a question parameter to be valid.");
            return -DAP_CHAIN_NET_VOTE_CREATE_OPTION_PARAM_MISSING;
        }
        // Parse options list
        l_options_list = dap_get_options_list_from_str(l_options_list_str);
        if(!l_options_list || dap_list_length(l_options_list) < 2){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_NUMBER_OPTIONS_ERROR, "Number of options must be 2 or greater.");
            return -DAP_CHAIN_NET_VOTE_CREATE_NUMBER_OPTIONS_ERROR;
        }

        if(dap_list_length(l_options_list)>DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_CONTAIN_MAX_OPTIONS, 
            "The voting can contain no more than %d options", DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT);            
            return -DAP_CHAIN_NET_VOTE_CREATE_CONTAIN_MAX_OPTIONS;
        }

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_fee_str);
        if (!l_fee_str){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_FEE_PARAM_NOT_VALID, "Poll requires parameter -fee to be valid.");
            return -DAP_CHAIN_NET_VOTE_CREATE_FEE_PARAM_NOT_VALID;
        }
        uint256_t l_value_fee = dap_chain_balance_scan(l_fee_str);

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
        if (!l_wallet_str){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_WALLET_PARAM_NOT_VALID, "Poll requires parameter -w to be valid.");
            return -DAP_CHAIN_NET_VOTE_CREATE_WALLET_PARAM_NOT_VALID;
        }

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-expire", &l_voting_expire_str);
        dap_time_t l_time_expire = 0;
        if (l_voting_expire_str)
            l_time_expire = dap_time_from_str_rfc822(l_voting_expire_str);
        if (l_voting_expire_str && !l_time_expire){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_WRONG_TIME_FORMAT, 
                                    "Wrong time format. -expire parameter must be in format \"Day Month Year HH:MM:SS Timezone\" e.g. \"19 August 2024 22:00:00 +00\"");
            return -DAP_CHAIN_NET_VOTE_CREATE_WRONG_TIME_FORMAT;
        }

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-max_votes_count", &l_max_votes_count_str);
        uint64_t l_max_count = 0;
        if (l_max_votes_count_str)
            l_max_count = strtoul(l_max_votes_count_str, NULL, 10);

        bool l_is_delegated_key = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-delegated_key_required", NULL) ? true : false;
        bool l_is_vote_changing_allowed = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-vote_changing_allowed", NULL) ? true : false;
        const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
        dap_chain_wallet_t *l_wallet_fee = dap_chain_wallet_open(l_wallet_str, c_wallets_path,NULL);
        if (!l_wallet_fee) {
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_WALLET_DOES_NOT_EXIST, "Wallet %s does not exist", l_wallet_str);
            return -DAP_CHAIN_NET_VOTE_CREATE_WALLET_DOES_NOT_EXIST;
        }


        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-token", &l_token_str);
        if (l_token_str && !dap_ledger_token_ticker_check(l_net->pub.ledger, l_token_str)) {
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_WRONG_TOKEN, "Token %s does not exist", l_token_str);
            return -DAP_CHAIN_NET_VOTE_CREATE_WRONG_TOKEN;
        }

        char *l_hash_ret = NULL;
        int res = dap_chain_net_vote_create(l_question_str,
                                            l_options_list,
                                            l_time_expire,
                                            l_max_count,
                                            l_value_fee,
                                            l_is_delegated_key,
                                            l_is_vote_changing_allowed,
                                            l_wallet_fee,
                                            l_net,
                                            l_token_str,
                                            l_hash_out_type,
                                            &l_hash_ret);
        dap_list_free(l_options_list);
        dap_chain_wallet_close(l_wallet_fee);

        switch (res) {
            case DAP_CHAIN_NET_VOTE_CREATE_OK: {
                json_object* json_obj_inf = json_object_new_object();
                json_object_object_add(json_obj_inf, "datum_add_successfully", json_object_new_string(l_hash_ret));
                json_object_array_add(*json_arr_reply, json_obj_inf);
                DAP_DELETE(l_hash_ret);
                return DAP_CHAIN_NET_VOTE_CREATE_OK;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_LENGTH_QUESTION_OVERSIZE_MAX: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_LENGTH_QUESTION_OVERSIZE_MAX, "The question must contain no more than %d characters",
                                                  DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH);
                return DAP_CHAIN_NET_VOTE_CREATE_LENGTH_QUESTION_OVERSIZE_MAX;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_COUNT_OPTION_OVERSIZE_MAX: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_COUNT_OPTION_OVERSIZE_MAX, "The poll can contain no more than %d options",
                                                  DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT);
                return DAP_CHAIN_NET_VOTE_CREATE_COUNT_OPTION_OVERSIZE_MAX;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_FEE_IS_ZERO: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_FEE_IS_ZERO, "The commission amount must be greater than zero");
                return DAP_CHAIN_NET_VOTE_CREATE_FEE_IS_ZERO;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_SOURCE_ADDRESS_IS_INVALID: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_SOURCE_ADDRESS_IS_INVALID, "Source address is invalid");
                return DAP_CHAIN_NET_VOTE_CREATE_SOURCE_ADDRESS_IS_INVALID;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_NOT_ENOUGH_FUNDS_TO_TRANSFER: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_NOT_ENOUGH_FUNDS_TO_TRANSFER, "Not enough funds to transfer");
                return DAP_CHAIN_NET_VOTE_CREATE_NOT_ENOUGH_FUNDS_TO_TRANSFER;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_MAX_COUNT_OPTION_EXCEEDED: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_MAX_COUNT_OPTION_EXCEEDED, "The option must contain no more than %d characters",
                                                  DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_LENGTH);
                return DAP_CHAIN_NET_VOTE_CREATE_MAX_COUNT_OPTION_EXCEEDED;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_OPTION_TSD_ITEM: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_OPTION_TSD_ITEM, "Can't create poll with expired time");
                return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_OPTION_TSD_ITEM;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_INPUT_TIME_MORE_CURRENT_TIME: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_INPUT_TIME_MORE_CURRENT_TIME, "Can't create poll with expired time");
                return DAP_CHAIN_NET_VOTE_CREATE_INPUT_TIME_MORE_CURRENT_TIME;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_EXPIRE_TIME: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_EXPIRE_TIME, "Can't create expired tsd item.");
                return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_EXPIRE_TIME;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_DELEGATE_KEY: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_DELEGATE_KEY, "Can't create delegated key req tsd item.");
                return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_DELEGATE_KEY;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_ADD_NET_FEE_OUT: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_ADD_NET_FEE_OUT, "Can't add net fee out.");
                return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_ADD_NET_FEE_OUT;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_ADD_OUT_WITH_VALUE_BACK: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_ADD_OUT_WITH_VALUE_BACK, "Can't add out with value back");
                return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_ADD_OUT_WITH_VALUE_BACK;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_SIGNED_TX: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_SIGNED_TX, "Can not sign transaction");
                return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_SIGNED_TX;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_POOL_DATUM_IN_MEMPOOL: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_POOL_DATUM_IN_MEMPOOL, "Can not pool transaction in mempool");
                return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_POOL_DATUM_IN_MEMPOOL;
            } break;
            default: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_UNKNOWN_ERR, "Unknown error. Code: %d", res);
                return -DAP_CHAIN_NET_VOTE_CREATE_UNKNOWN_ERR;
            }
        }
    }break;
    case CMD_VOTE:{
        const char* l_cert_name = NULL;
        const char* l_fee_str = NULL;
        const char* l_wallet_str = NULL;
        const char* l_hash_str = NULL;
        const char* l_option_idx_str = NULL;

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_hash_str);
        if(!l_hash_str){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_HASH_NOT_FOUND, "Command 'vote' require the parameter -hash");
            return -DAP_CHAIN_NET_VOTE_VOTING_HASH_NOT_FOUND;
        }

        dap_hash_fast_t l_voting_hash = {};
        if (dap_chain_hash_fast_from_str(l_hash_str, &l_voting_hash)) {
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_HASH_INVALID, "Hash string is not recognozed as hex of base58 hash");
            return -DAP_CHAIN_NET_VOTE_VOTING_HASH_INVALID;
        }

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_name);
        dap_cert_t * l_cert = dap_cert_find_by_name(l_cert_name);
        if (l_cert_name){
            if (l_cert == NULL) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_FIND_CERT, "Can't find \"%s\" certificate", l_cert_name);
                return -DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_FIND_CERT;
            }
        }

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_fee_str);
        if (!l_fee_str){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_FEE_PARAM_NOT_VALID, "Command 'vote' requires paramete -fee to be valid.");
            return -DAP_CHAIN_NET_VOTE_VOTING_FEE_PARAM_NOT_VALID;
        }
        uint256_t l_value_fee = dap_chain_balance_scan(l_fee_str);
        if (IS_ZERO_256(l_value_fee)) {
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_FEE_PARAM_BAD_TYPE, "command requires parameter '-fee' to be valid uint256");            
            return -DAP_CHAIN_NET_VOTE_VOTING_FEE_PARAM_BAD_TYPE;
        }

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
        if (!l_wallet_str){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_WALLET_PARAM_NOT_VALID, "Command 'vote' requires parameter -w to be valid.");
            return -DAP_CHAIN_NET_VOTE_VOTING_WALLET_PARAM_NOT_VALID;
        }

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-option_idx", &l_option_idx_str);
        if (!l_option_idx_str){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_OPTION_IDX_PARAM_NOT_VALID, "Command 'vote' requires parameter -option_idx to be valid.");
            return -DAP_CHAIN_NET_VOTE_VOTING_OPTION_IDX_PARAM_NOT_VALID;
        }

        const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, c_wallets_path,NULL);
        if (!l_wallet) {
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_WALLET_DOES_NOT_EXIST, "Wallet %s does not exist", l_wallet_str);
            return -DAP_CHAIN_NET_VOTE_VOTING_WALLET_DOES_NOT_EXIST;
        }

        uint64_t l_option_idx_count = strtoul(l_option_idx_str, NULL, 10);

        char *l_hash_tx;

        int res = dap_chain_net_vote_voting(l_cert, l_value_fee, l_wallet, l_voting_hash, l_option_idx_count,
                                            l_net, l_hash_out_type, &l_hash_tx);
        dap_chain_wallet_close(l_wallet);

        switch (res) {
            case DAP_CHAIN_NET_VOTE_VOTING_OK: {
                json_object* json_obj_inf = json_object_new_object();
                json_object_object_add(json_obj_inf, "datum_add_successfully_to_mempool", json_object_new_string(l_hash_tx));
                json_object_array_add(*json_arr_reply, json_obj_inf);
                DAP_DELETE(l_hash_tx);
                return DAP_CHAIN_NET_VOTE_CREATE_OK;
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_FIND_VOTE: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_FIND_VOTE, "Can't find poll with hash %s", l_hash_str);
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_THIS_VOTING_HAVE_MAX_VALUE_VOTES: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_THIS_VOTING_HAVE_MAX_VALUE_VOTES, 
                                                  "This poll already received the required number of votes.");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_ALREADY_EXPIRED: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_ALREADY_EXPIRED, "This poll is already expired.");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_NO_KEY_FOUND_IN_CERT: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_NO_KEY_FOUND_IN_CERT, 
                                                    "No key found in \"%s\" certificate", l_cert_name);                
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_CERT_REQUIRED: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_CERT_REQUIRED, 
                                                    "This poll required a delegated key. Parameter -cert must contain a valid certificate name");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_KEY_IS_NOT_DELEGATED: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_KEY_IS_NOT_DELEGATED, "Your key is not delegated.");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_DOES_NOT_ALLOW_CHANGE_YOUR_VOTE: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_DOES_NOT_ALLOW_CHANGE_YOUR_VOTE, "The poll doesn't allow change your vote.");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_SOURCE_ADDRESS_INVALID: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_SOURCE_ADDRESS_INVALID, "source address is invalid");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_NOT_ENOUGH_FUNDS_TO_TRANSFER: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_NOT_ENOUGH_FUNDS_TO_TRANSFER, "Not enough funds to transfer");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_UNSPENT_UTX0_FOR_PARTICIPATION_THIS_VOTING: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_UNSPENT_UTX0_FOR_PARTICIPATION_THIS_VOTING, 
                                                  "You have not unspent UTXO for participation in this voting.");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_INVALID_OPTION_INDEX: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_INVALID_OPTION_INDEX, "Invalid option index.");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_VOTE_ITEM: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_VOTE_ITEM, "Can't create vote item.");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_TSD_TX_COND_ITEM: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_TSD_TX_COND_ITEM, "Can't create tsd tx cond item.");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_NET_FEE_OUT: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_NET_FEE_OUT, "Can't add net fee out.");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_OUT_WITH_VALUE_BACK: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_OUT_WITH_VALUE_BACK, "Can't add out with value back");
            }
                break;
            case DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_SIGN_TX: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_SIGN_TX, "Can't sign tx");
            }
                break;
            case DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_POOL_IN_MEMPOOL: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_POOL_IN_MEMPOOL, "Can't add datum to mempool");
            }
                break;
            default: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_UNKNOWN_ERR, "Undefined error code: %d", res);
            } break;
        }
        return res;
    }break;
    case CMD_LIST:{
        json_object* json_vote_out = json_object_new_object();
        json_object_object_add(json_vote_out, "list_of_polls", json_object_new_string(l_net->pub.name));
        json_object* json_arr_voting_out = json_object_new_array();
        dap_chain_net_votings_t *l_voting = NULL, *l_tmp;
        pthread_rwlock_rdlock(&s_votings_rwlock);
        HASH_ITER(hh, s_votings, l_voting, l_tmp){
            if (l_voting->net_id.uint64 != l_net->pub.id.uint64)
                continue;
            json_object* json_obj_vote = json_object_new_object();
            json_object_object_add( json_obj_vote, "poll_tx",
                                    json_object_new_string(dap_chain_hash_fast_to_str_static(&l_voting->voting_hash)));            
            char* l_voting_question = (char*)l_voting->voting_params.voting_tx + l_voting->voting_params.voting_question_offset;
            json_object_object_add( json_obj_vote, "question", 
                                    json_object_new_string_len(l_voting_question, l_voting->voting_params.voting_question_length) );
            json_object_object_add(json_obj_vote, "token", json_object_new_string(l_voting->voting_params.token_ticker));
            json_object_array_add(json_arr_voting_out, json_obj_vote);
        }
        pthread_rwlock_unlock(&s_votings_rwlock);
        json_object_array_add(*json_arr_reply, json_arr_voting_out);
    }break;
    case CMD_DUMP:{
        const char* l_hash_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_hash_str);
        if(!l_hash_str){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_DUMP_HASH_PARAM_NOT_FOUND, "Command 'results' require the parameter -hash");
            return -DAP_CHAIN_NET_VOTE_DUMP_HASH_PARAM_NOT_FOUND;
        }

        bool l_need_vote_list  = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-need_vote_list", NULL);
        dap_hash_fast_t l_voting_hash = {};
        if (dap_chain_hash_fast_from_str(l_hash_str, &l_voting_hash)) {
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_DUMP_HASH_PARAM_INVALID,
                                   "Can't recognize hash string as a valid HEX or BASE58 format hash");
            return -DAP_CHAIN_NET_VOTE_DUMP_HASH_PARAM_INVALID;
        }
        dap_chain_net_votings_t *l_voting = NULL;
        pthread_rwlock_rdlock(&s_votings_rwlock);
        HASH_FIND(hh, s_votings, &l_voting_hash, sizeof(l_voting_hash), l_voting);
        pthread_rwlock_unlock(&s_votings_rwlock);
        if (!l_voting) {
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_DUMP_CAN_NOT_FIND_VOTE, "Can't find poll with hash %s", l_hash_str);
            return -DAP_CHAIN_NET_VOTE_DUMP_CAN_NOT_FIND_VOTE;
        }

        uint64_t l_options_count = 0;
        l_options_count = dap_list_length(l_voting->voting_params.option_offsets_list);
        if(!l_options_count){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_DUMP_NO_OPTIONS, "No options. May be datum is crashed.");
            return -DAP_CHAIN_NET_VOTE_DUMP_NO_OPTIONS;
        }

        struct voting_results { 
            uint256_t weights; uint64_t num_of_votes;
        } l_results[l_options_count];
        memset(l_results, 0, sizeof(l_results));

        uint256_t l_total_weight = { };
        int l_votes_count = 0, i = 0;
        json_object* l_json_arr_vote_list = json_object_new_array();
        for (dap_list_t *l_vote_item = l_voting->votes; l_vote_item; l_vote_item = l_vote_item->next, ++l_votes_count) {
            dap_chain_net_vote_t *l_vote = l_vote_item->data;
            ++l_results[l_vote->answer_idx].num_of_votes;
            SUM_256_256(l_results[l_vote->answer_idx].weights, l_vote->weight, &l_results[l_vote->answer_idx].weights);
            SUM_256_256(l_total_weight, l_vote->weight, &l_total_weight);
            if (l_need_vote_list) {
                json_object* l_json_obj = json_object_new_object();
                json_object_object_add(l_json_obj, "vote_hash", json_object_new_string(dap_hash_fast_to_str_static(&l_vote->vote_hash)));
                json_object_object_add(l_json_obj, "pkey_hash", json_object_new_string(dap_hash_fast_to_str_static(&l_vote->pkey_hash)));
                json_object_object_add(l_json_obj, "answer_idx", json_object_new_int(l_vote->answer_idx));
                json_object_object_add(l_json_obj, "weight", json_object_new_string(dap_uint256_to_char(l_vote->weight, NULL)));
                json_object_array_add(l_json_arr_vote_list, l_json_obj);
            }
        }

        json_object* json_vote_out = json_object_new_object();
        json_object_object_add(json_vote_out, "poll_tx", json_object_new_string(l_hash_str));
        json_object_object_add(json_vote_out, "question", 
                               json_object_new_string_len((char*)l_voting->voting_params.voting_tx + l_voting->voting_params.voting_question_offset,
                               l_voting->voting_params.voting_question_length));
        json_object_object_add(json_vote_out, "token", json_object_new_string(l_voting->voting_params.token_ticker));
        if (l_voting->voting_params.voting_expire) {
            char l_tmp_buf[DAP_TIME_STR_SIZE];
            dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_voting->voting_params.voting_expire);
            json_object_object_add(json_vote_out, "expiration", 
                                    json_object_new_string(l_tmp_buf));
            json_object_object_add(json_vote_out, "status",
                                   json_object_new_string( l_voting->voting_params.voting_expire >= dap_time_now() ? "active" : "expired" ));
        }
        if (l_voting->voting_params.votes_max_count){
            json_object_object_add(json_vote_out, "votes_max",
                                   json_object_new_uint64( l_voting->voting_params.votes_max_count ));
            json_object_object_add( json_vote_out, "votes_available",
                                    json_object_new_uint64( l_voting->voting_params.votes_max_count - l_votes_count ));
        }
        
        json_object_object_add(json_vote_out, "can_change_status",
                               json_object_new_boolean(l_voting->voting_params.vote_changing_allowed));
        json_object_object_add(json_vote_out, "delegated_key_required",
                               json_object_new_boolean(l_voting->voting_params.delegate_key_required));
        json_object* json_arr_vote_out = json_object_new_array();
        
        for (dap_list_t *l_option = l_voting->voting_params.option_offsets_list; l_option; l_option = l_option->next, ++i) {
            json_object* json_vote_obj = json_object_new_object();
            json_object_object_add(json_vote_obj, "option_id", json_object_new_int(i));
            dap_chain_net_vote_option_t* l_vote_option = (dap_chain_net_vote_option_t*)l_option->data;
            json_object_object_add( json_vote_obj, "option_text",
                                    json_object_new_string_len((char*)l_voting->voting_params.voting_tx + l_vote_option->vote_option_offset,
                                                                l_vote_option->vote_option_length) );
            json_object_object_add(json_vote_obj, "votes_count", json_object_new_uint64( l_results[i].num_of_votes) );
            int l_percentage = l_votes_count ? ((double)(l_results[i].num_of_votes * 100))/l_votes_count + 0.5 : 0;
            json_object_object_add(json_vote_obj, "votes_percent", json_object_new_int(l_percentage) );
            uint256_t l_weight_percentage = { };
            DIV_256_COIN(l_results[i].weights, l_total_weight, &l_weight_percentage);
            MULT_256_COIN(l_weight_percentage, dap_chain_coins_to_balance("100.0"), &l_weight_percentage);
            const char *l_weight_percentage_str = dap_uint256_decimal_to_round_char(l_weight_percentage, 2, true),
                       *l_w_coins, *l_w_datoshi = dap_uint256_to_char(l_results[i].weights, &l_w_coins);
            json_object_object_add(json_vote_obj, "votes_sum", json_object_new_string(l_w_coins));
            json_object_object_add(json_vote_obj, "votes_sum_datoshi", json_object_new_string(l_w_datoshi));
            json_object_object_add(json_vote_obj, "votes_sum_weight", json_object_new_string(l_weight_percentage_str));
            json_object_array_add(json_arr_vote_out, json_vote_obj);
        }
        json_object_object_add(json_vote_out, "results", json_arr_vote_out);
        json_object_object_add(json_vote_out, "votes_count", json_object_new_uint64(l_votes_count));
        const char *l_tw_coins, *l_tw_datoshi = dap_uint256_to_char(l_total_weight, &l_tw_coins);
        json_object_object_add(json_vote_out, "total_sum", json_object_new_string(l_tw_coins));
        json_object_object_add(json_vote_out, "total_sum_datoshi", json_object_new_string(l_tw_datoshi));
        if (l_need_vote_list) {
            if (json_object_array_length(l_json_arr_vote_list) > 0 ) {
                json_object_object_add(json_vote_out, "votes_list", l_json_arr_vote_list);
            } else {
                json_object_object_add(json_vote_out, "votes_list", json_object_new_string("empty"));
            }
        }
        json_object_array_add(*json_arr_reply, json_vote_out);
    } break;
    default:
        break;
    }
    return 0;
}

static int s_tx_is_spent(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash, dap_hash_fast_t *a_voting_hash,
                         dap_hash_fast_t *a_pkey_hash, dap_chain_net_votings_t *a_voting, dap_time_t a_voting_ts)
{
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_ledger, a_tx_hash);
    if (!l_tx) {
        log_it(L_ERROR, "Can't find tx %s", dap_hash_fast_to_str_static(a_tx_hash));
        return -3;
    }

    if (l_tx->header.ts_created < a_voting_ts)
        return 0;

    dap_chain_tx_vote_t *l_vote = (dap_chain_tx_vote_t *)dap_chain_datum_tx_item_get(l_tx, NULL, NULL, TX_ITEM_TYPE_VOTE, NULL);
    if (l_vote && dap_hash_fast_compare(&l_vote->voting_hash, &a_voting->voting_hash)) {
        for (dap_list_t *it = a_voting->votes; it; it = it->next) {
            dap_chain_net_vote_t *l_vote = (dap_chain_net_vote_t *)it->data;
            if (dap_hash_fast_compare(&l_vote->vote_hash, a_tx_hash)) {
                if (a_voting->voting_params.vote_changing_allowed &&
                        !dap_hash_fast_is_blank(a_pkey_hash) &&
                        dap_hash_fast_compare(&l_vote->pkey_hash, a_pkey_hash))
                    break;  // it's vote changing, allow it
                return 1;
            }
        }
    }

    dap_list_t *l_ins_list = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN, NULL);
    l_ins_list = dap_list_concat(l_ins_list, dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN_COND, NULL));
    if (!l_ins_list) // it's emisssion or reward TX, not marked yet
        return 0;

    dap_hash_fast_t l_prev_hash = {};
    for (dap_list_t *it = l_ins_list; it; it = it->next) {
        uint32_t l_prev_idx = -1;
        if (*(byte_t *)it->data == TX_ITEM_TYPE_IN_COND) {
            dap_chain_tx_in_cond_t *in = it->data;
            l_prev_hash = in->header.tx_prev_hash;
            l_prev_idx = in->header.tx_out_prev_idx;
        } else {
            dap_chain_tx_in_t *in = it->data;
            l_prev_hash = in->header.tx_prev_hash;
            l_prev_idx = in->header.tx_out_prev_idx;
        }
        dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash(a_ledger, &l_prev_hash);

        const char* l_tx_token = NULL;
        byte_t *l_prev_out_union = dap_chain_datum_tx_out_get_by_out_idx(l_tx_prev, l_prev_idx);
        switch (*l_prev_out_union) {
        case TX_ITEM_TYPE_OUT:{
            dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t *)l_prev_out_union;
            l_tx_token = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_prev_hash);
        }break;
        case TX_ITEM_TYPE_OUT_EXT:{
            dap_chain_tx_out_ext_t *l_out = (dap_chain_tx_out_ext_t *)l_prev_out_union;
            l_tx_token = l_out->token;
        }break;
        case TX_ITEM_TYPE_OUT_COND:{
            dap_chain_tx_out_cond_t *l_out = (dap_chain_tx_out_cond_t *)l_prev_out_union;
            if (l_out->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                l_tx_token = a_ledger->net->pub.native_ticker;
                break;
            }
            if (s_datum_tx_voting_coin_check_cond_out(a_ledger->net, *a_voting_hash, l_prev_hash, l_prev_idx, a_pkey_hash) != 0) {
                dap_list_free(l_ins_list);
                return 1;
            }
            l_tx_token = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_prev_hash);
        }
        default:
            break;
        }
        if (dap_strcmp(l_tx_token, a_voting->voting_params.token_ticker))
            continue;
    }
    dap_list_free(l_ins_list);
    return s_tx_is_spent(a_ledger, &l_prev_hash, a_voting_hash, a_pkey_hash, a_voting, a_voting_ts);
}


static int s_datum_tx_voting_coin_check_spent(dap_chain_net_t *a_net, dap_hash_fast_t a_voting_hash,
                                              dap_hash_fast_t a_tx_prev_hash, int a_out_idx, dap_hash_fast_t *a_pkey_hash)
{
    int l_coin_is_spent = 0;

    dap_chain_net_votings_t *l_voting = NULL;
    pthread_rwlock_wrlock(&s_votings_rwlock);
    HASH_FIND(hh, s_votings, &a_voting_hash, sizeof(dap_hash_fast_t), l_voting);
    pthread_rwlock_unlock(&s_votings_rwlock);
    if (!l_voting) {
        log_it(L_ERROR, "Can't find poll %s", dap_hash_fast_to_str_static(&a_voting_hash));
        return -1;
    }

    dap_ledger_t *l_ledger = a_net->pub.ledger;
    dap_chain_datum_tx_t *l_voting_tx = dap_ledger_tx_find_by_hash(l_ledger, &a_voting_hash);
    if (!l_voting_tx) {
        log_it(L_ERROR, "Can't find poll tx %s", dap_hash_fast_to_str_static(&a_voting_hash));
        return -2;
    }

    if (s_datum_tx_voting_coin_check_cond_out(a_net, a_voting_hash, a_tx_prev_hash, a_out_idx, a_pkey_hash) != 0)
        return 1;

    return s_tx_is_spent(l_ledger, &a_tx_prev_hash, &a_voting_hash, a_pkey_hash, l_voting, l_voting_tx->header.ts_created);

}

static int s_datum_tx_voting_coin_check_cond_out(dap_chain_net_t *a_net, dap_hash_fast_t a_voting_hash,
                                                 dap_hash_fast_t a_tx_cond_hash, int a_cond_out_idx,
                                                 dap_hash_fast_t *a_pkey_hash)
{

    dap_chain_net_votings_t * l_voting = NULL;
    pthread_rwlock_wrlock(&s_votings_rwlock);
    HASH_FIND(hh, s_votings, &a_voting_hash, sizeof(dap_hash_fast_t), l_voting);
    pthread_rwlock_unlock(&s_votings_rwlock);
    if(!l_voting || l_voting->net_id.uint64 != a_net->pub.id.uint64) {
        log_it(L_ERROR, "Can't find poll with hash %s in net %s",
            dap_chain_hash_fast_to_str_static(&a_voting_hash), a_net->pub.name);
        return -1;
    }

    dap_chain_net_voting_cond_outs_t *l_tx_out = NULL;
    pthread_rwlock_wrlock(&l_voting->s_tx_outs_rwlock);
    HASH_FIND(hh, l_voting->voting_spent_cond_outs, &a_tx_cond_hash, sizeof(dap_hash_fast_t), l_tx_out);
    pthread_rwlock_unlock(&l_voting->s_tx_outs_rwlock);

    if (l_tx_out && l_tx_out->out_idx == a_cond_out_idx)
        return a_pkey_hash ? !dap_hash_fast_compare(a_pkey_hash, &l_tx_out->pkey_hash) : 1;

    return 0;
}

int dap_chain_net_vote_create(const char *a_question, dap_list_t *a_options, dap_time_t a_expire_vote,
                              uint64_t a_max_vote, uint256_t a_fee, bool a_delegated_key_required,
                              bool a_vote_changing_allowed, dap_chain_wallet_t *a_wallet,
                              dap_chain_net_t *a_net, const char *a_token_ticker,
                              const char *a_hash_out_type, char **a_hash_output) {

    if (strlen(a_question) > DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH){
        return DAP_CHAIN_NET_VOTE_CREATE_LENGTH_QUESTION_OVERSIZE_MAX;
    }

    // Parse options list

    if(dap_list_length(a_options) > DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT){
        return DAP_CHAIN_NET_VOTE_CREATE_COUNT_OPTION_OVERSIZE_MAX;
    }

    if (IS_ZERO_256(a_fee)) {
        return DAP_CHAIN_NET_VOTE_CREATE_FEE_IS_ZERO;
    }

    dap_enc_key_t *l_priv_key = NULL;
    l_priv_key = dap_chain_wallet_get_key(a_wallet, 0);

    const dap_chain_addr_t *l_addr_from = (const dap_chain_addr_t *) dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);

    if(!l_addr_from) {
        return DAP_CHAIN_NET_VOTE_CREATE_SOURCE_ADDRESS_IS_INVALID;
    }

    const char *l_native_ticker = a_net->pub.native_ticker;
    uint256_t l_net_fee = {}, l_total_fee = {}, l_value_transfer;
    dap_chain_addr_t l_addr_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_addr_fee);
    SUM_256_256(l_net_fee, a_fee, &l_total_fee);

    dap_ledger_t* l_ledger = a_net->pub.ledger;
    dap_list_t *l_list_used_out = NULL;
    if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_native_ticker, l_addr_from, &l_list_used_out, l_total_fee, &l_value_transfer) == -101)
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker, l_addr_from, l_total_fee, &l_value_transfer);
    if (!l_list_used_out) {
        return DAP_CHAIN_NET_VOTE_CREATE_NOT_ENOUGH_FUNDS_TO_TRANSFER;
    }
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // Add Voting item
    dap_chain_tx_voting_t* l_voting_item = dap_chain_datum_tx_item_voting_create();

    dap_chain_datum_tx_add_item(&l_tx, l_voting_item);
    DAP_DELETE(l_voting_item);

    // Add question to tsd data
    dap_chain_tx_tsd_t* l_question_tsd = dap_chain_datum_voting_question_tsd_create(a_question, strlen(a_question));
    dap_chain_datum_tx_add_item(&l_tx, l_question_tsd);

    // Add options to tsd
    dap_list_t *l_temp = a_options;
    while(l_temp){
        if(strlen((char*)l_temp->data) > DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_LENGTH){
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_CREATE_MAX_COUNT_OPTION_EXCEEDED;
        }
        dap_chain_tx_tsd_t* l_option = dap_chain_datum_voting_answer_tsd_create((char*)l_temp->data, strlen((char*)l_temp->data));
        if(!l_option){
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_OPTION_TSD_ITEM;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_option);
        DAP_DEL_Z(l_option);

        l_temp = l_temp->next;
    }

    // add voting expire time if needed
    if(a_expire_vote != 0){
        dap_time_t l_expired_vote = a_expire_vote;
        if (l_expired_vote < dap_time_now()){
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_CREATE_INPUT_TIME_MORE_CURRENT_TIME;
        }

        dap_chain_tx_tsd_t* l_expired_item = dap_chain_datum_voting_expire_tsd_create(l_expired_vote);
        if(!l_expired_item){
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_EXPIRE_TIME;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_expired_item);
        DAP_DEL_Z(l_expired_item);
    }

    // Add vote max count if needed
    if (a_max_vote != 0) {
        dap_chain_tx_tsd_t* l_max_votes_item = dap_chain_datum_voting_max_votes_count_tsd_create(a_max_vote);
        if(!l_max_votes_item){
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_EXPIRE_TIME;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_max_votes_item);
        DAP_DEL_Z(l_max_votes_item);
    }

    if (a_delegated_key_required) {
        dap_chain_tx_tsd_t* l_delegated_key_req_item = dap_chain_datum_voting_delegated_key_required_tsd_create(true);
        if(!l_delegated_key_req_item){
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_DELEGATE_KEY;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_delegated_key_req_item);
        DAP_DEL_Z(l_delegated_key_req_item);
    }

    if(a_vote_changing_allowed){
        dap_chain_tx_tsd_t* l_vote_changing_item = dap_chain_datum_voting_vote_changing_allowed_tsd_create(true);
        if(!l_vote_changing_item){
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_DELEGATE_KEY;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_vote_changing_item);
        DAP_DEL_Z(l_vote_changing_item);
    }

    if (a_token_ticker) {
        dap_chain_tx_tsd_t *l_voting_token_item = dap_chain_datum_voting_token_tsd_create(a_token_ticker);
        if (!l_voting_token_item) {
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_CREATE_TSD_TOKEN;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_voting_token_item);
        DAP_DEL_Z(l_voting_token_item);
    }

    // add 'in' items
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    assert(EQUAL_256(l_value_to_items, l_value_transfer));
    dap_list_free_full(l_list_used_out, NULL);
    uint256_t l_value_pack = {};
    // Network fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, l_native_ticker) == 1)
            SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
        else {
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_ADD_NET_FEE_OUT;
        }
    }
    // Validator's fee
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) == 1)
            SUM_256_256(l_value_pack, a_fee, &l_value_pack);
        else {
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_ADD_NET_FEE_OUT;
        }
    }
    // coin back
    uint256_t l_value_back;
    SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
    if(!IS_ZERO_256(l_value_back)) {
        if(dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_from, l_value_back, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_ADD_OUT_WITH_VALUE_BACK;
        }
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, l_priv_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_SIGNED_TX;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_hash_fast_t l_tx_hash;
    dap_hash_fast(l_tx, l_tx_size, &l_tx_hash);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    DAP_DELETE(l_tx);
    dap_chain_t* l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);

    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    if (l_ret) {
        *a_hash_output = l_ret;
        return DAP_CHAIN_NET_VOTE_CREATE_OK;
    } else {
        return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_POOL_DATUM_IN_MEMPOOL;
    }
}

int dap_chain_net_vote_voting(dap_cert_t *a_cert, uint256_t a_fee, dap_chain_wallet_t *a_wallet, dap_hash_fast_t a_hash,
                              uint64_t a_option_idx, dap_chain_net_t *a_net, const char *a_hash_out_type,
                              char **a_hash_tx_out) {


    dap_chain_net_votings_t *l_voting = NULL;
    pthread_rwlock_rdlock(&s_votings_rwlock);
    HASH_FIND(hh, s_votings, &a_hash, sizeof(dap_hash_fast_t),l_voting);
    pthread_rwlock_unlock(&s_votings_rwlock);
    if (!l_voting || l_voting->net_id.uint64 != a_net->pub.id.uint64)
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_FIND_VOTE;

    if (l_voting->voting_params.votes_max_count && dap_list_length(l_voting->votes) >= l_voting->voting_params.votes_max_count)
        return DAP_CHAIN_NET_VOTE_VOTING_THIS_VOTING_HAVE_MAX_VALUE_VOTES;

    if (l_voting->voting_params.voting_expire && dap_time_now() > l_voting->voting_params.voting_expire)
        return DAP_CHAIN_NET_VOTE_VOTING_ALREADY_EXPIRED;

    dap_chain_addr_t *l_addr_from = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_addr_from)
        return DAP_CHAIN_NET_VOTE_VOTING_SOURCE_ADDRESS_INVALID;

    dap_hash_fast_t l_pkey_hash = {0};
    if (l_voting->voting_params.delegate_key_required) {
        if (!a_cert)
            return DAP_CHAIN_NET_VOTE_VOTING_CERT_REQUIRED;
        if (dap_cert_get_pkey_hash(a_cert, &l_pkey_hash))
            return DAP_CHAIN_NET_VOTE_VOTING_NO_KEY_FOUND_IN_CERT;
        if (!dap_chain_net_srv_stake_check_pkey_hash(a_net->pub.id, &l_pkey_hash))
            return DAP_CHAIN_NET_VOTE_VOTING_KEY_IS_NOT_DELEGATED;
    } else
        l_pkey_hash = l_addr_from->data.hash_fast;

    bool l_vote_changed = false;
    for (dap_list_t *it = l_voting->votes; it; it = it->next)
        if (dap_hash_fast_compare(&((dap_chain_net_vote_t *)it->data)->pkey_hash, &l_pkey_hash)) {
            if (!l_voting->voting_params.vote_changing_allowed)
                return DAP_CHAIN_NET_VOTE_VOTING_DOES_NOT_ALLOW_CHANGE_YOUR_VOTE;
            l_vote_changed = true;
            break;
        }

    const char *l_token_ticker = l_voting->voting_params.token_ticker;
    uint256_t l_net_fee = {}, l_total_fee = a_fee, l_value_transfer, l_fee_transfer;
    dap_chain_addr_t l_addr_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_addr_fee);
    if (l_net_fee_used)
        SUM_256_256(l_net_fee, a_fee, &l_total_fee);

    bool l_native_tx = !dap_strcmp(l_token_ticker, a_net->pub.native_ticker);
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs(l_ledger, l_token_ticker, l_addr_from, &l_value_transfer);
    if (!l_list_used_out || (l_native_tx && compare256(l_value_transfer, l_total_fee) < 0)) {
        dap_list_free_full(l_list_used_out, NULL);
        return DAP_CHAIN_NET_VOTE_VOTING_NOT_ENOUGH_FUNDS_TO_TRANSFER;
    }

    // check outputs UTXOs
    uint256_t l_value_transfer_new = {};
    dap_list_t *it, *tmp;
    DL_FOREACH_SAFE(l_list_used_out, it, tmp) {
        dap_chain_tx_used_out_item_t *l_out = (dap_chain_tx_used_out_item_t *)it->data;
        if (s_datum_tx_voting_coin_check_spent(a_net, a_hash, l_out->tx_hash_fast, l_out->num_idx_out,
                                               l_vote_changed ? &l_pkey_hash : NULL)) {
            l_list_used_out = dap_list_delete_link(l_list_used_out, it);
            continue;
        }
        if (SUM_256_256(l_value_transfer_new, l_out->value, &l_value_transfer_new))
            return DAP_CHAIN_NET_VOTE_VOTING_INTEGER_OVERFLOW;
    }

    if (IS_ZERO_256(l_value_transfer_new) || (l_native_tx && compare256(l_value_transfer_new, l_total_fee) <= 0))
        return DAP_CHAIN_NET_VOTE_VOTING_UNSPENT_UTX0_FOR_PARTICIPATION_THIS_VOTING;

    l_value_transfer = l_value_transfer_new;

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    uint256_t l_value_back = l_value_transfer, l_fee_back = {};
    if (!l_native_tx) {
        dap_list_t *l_list_fee_outs = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_net->pub.native_ticker, l_addr_from, l_total_fee, &l_fee_transfer);
        if (!l_list_fee_outs) {
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_VOTING_NOT_ENOUGH_FUNDS_TO_TRANSFER;
        }
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_outs);
        assert(EQUAL_256(l_value_fee_items, l_fee_transfer));
        dap_list_free_full(l_list_fee_outs, NULL);
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_fee_back);
    } else
        SUBTRACT_256_256(l_value_transfer, l_total_fee, &l_value_back);

    // add 'in' items
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    assert(EQUAL_256(l_value_to_items, l_value_transfer));
    dap_list_free_full(l_list_used_out, NULL);

    // Add vote item
    if (a_option_idx > dap_list_length(l_voting->voting_params.option_offsets_list)){
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_INVALID_OPTION_INDEX;
    }
    dap_chain_tx_vote_t* l_vote_item = dap_chain_datum_tx_item_vote_create(&a_hash, &a_option_idx);
    if(!l_vote_item){
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_VOTE_ITEM;
    }
    dap_chain_datum_tx_add_item(&l_tx, l_vote_item);
    DAP_DEL_Z(l_vote_item);

    // add out conds items
    dap_list_t *l_outs = dap_ledger_get_list_tx_cond_outs(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_ALL, l_token_ticker, l_addr_from);
    for (dap_list_t *it = l_outs; it; it = it->next) {
        dap_chain_tx_used_out_item_t *l_out_item = (dap_chain_tx_used_out_item_t *)it->data;
        if (s_datum_tx_voting_coin_check_cond_out(a_net, a_hash, l_out_item->tx_hash_fast, l_out_item->num_idx_out,
                                                  l_vote_changed ? &l_pkey_hash : NULL) != 0)
            continue;
        dap_chain_tx_tsd_t *l_item = dap_chain_datum_voting_vote_tx_cond_tsd_create(l_out_item->tx_hash_fast, l_out_item->num_idx_out);
        if(!l_item){
            dap_chain_datum_tx_delete(l_tx);

            dap_list_free_full(l_outs, NULL);
            return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_TSD_TX_COND_ITEM;
        }
        dap_chain_datum_tx_add_item(&l_tx, l_item);
        DAP_DEL_Z(l_item);
    }
    dap_list_free_full(l_outs, NULL);

    // Network fee
    if (l_net_fee_used && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, a_net->pub.native_ticker) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_NET_FEE_OUT;
    }

    // Validator's fee
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_NET_FEE_OUT;
    }

    // coin back
    if (!IS_ZERO_256(l_value_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_from, l_value_back, l_token_ticker) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_OUT_WITH_VALUE_BACK;
    }
    if (!IS_ZERO_256(l_fee_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_from, l_fee_back, a_net->pub.native_ticker) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_OUT_WITH_VALUE_BACK;
    }

    dap_enc_key_t *l_priv_key = dap_chain_wallet_get_key(a_wallet, 0);
    // add 'sign' items with wallet sign
    if (dap_chain_datum_tx_add_sign_item(&l_tx, l_priv_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_enc_key_delete(l_priv_key);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_SIGN_TX;
    }
    dap_enc_key_delete(l_priv_key);

    // add 'sign' items with delegated key if needed
    if (a_cert && dap_chain_datum_tx_add_sign_item(&l_tx, a_cert->enc_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_SIGN_TX;
    }
    json_object * l_retj = json_object_new_object();
    dap_chain_net_tx_to_json(l_tx, l_retj);
    const char * l_str = json_object_to_json_string(l_retj);
    log_it(L_ATT, "/n %s", l_str);

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_hash_fast_t l_tx_hash;
    dap_hash_fast(l_tx, l_tx_size, &l_tx_hash);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    DAP_DELETE(l_tx);
    dap_chain_t* l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);

    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    if (l_ret) {
        *a_hash_tx_out = l_ret;
        return DAP_CHAIN_NET_VOTE_VOTING_OK;
    } else {
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_POOL_IN_MEMPOOL;
    }
}

dap_chain_net_vote_info_t *s_dap_chain_net_vote_extract_info(dap_chain_net_votings_t *a_voting) {
    if (!a_voting) {
        return NULL;
    }
    dap_chain_net_vote_info_t *l_info = DAP_NEW(dap_chain_net_vote_info_t);

    l_info->question.question_size = a_voting->voting_params.voting_question_length;
    l_info->question.question_str = (char*)((byte_t*)a_voting->voting_params.voting_tx + a_voting->voting_params.voting_question_offset);
    l_info->hash = a_voting->voting_hash;
    l_info->is_expired = (l_info->expired = a_voting->voting_params.voting_expire);
    l_info->is_max_count_votes = (l_info->max_count_votes = a_voting->voting_params.votes_max_count);
    l_info->is_changing_allowed = a_voting->voting_params.vote_changing_allowed;
    l_info->is_delegate_key_required = a_voting->voting_params.delegate_key_required;
    l_info->options.count_option = dap_list_length(a_voting->voting_params.option_offsets_list);
    dap_chain_net_vote_info_option_t **l_options = DAP_NEW_Z_COUNT(dap_chain_net_vote_info_option_t*, l_info->options.count_option);
    for (uint64_t i = 0; i < l_info->options.count_option; i++){
        dap_list_t* l_option = dap_list_nth(a_voting->voting_params.option_offsets_list, (uint64_t)i);
        dap_chain_net_vote_option_t* l_vote_option = (dap_chain_net_vote_option_t*)l_option->data;
        dap_chain_net_vote_info_option_t *l_option_info = DAP_NEW(dap_chain_net_vote_info_option_t);
        l_option_info->option_idx = i;
        l_option_info->description_size = l_vote_option->vote_option_length;
        l_option_info->description = (char*)((byte_t*)a_voting->voting_params.voting_tx + l_vote_option->vote_option_offset);
        l_option_info->votes_count = 0;
        l_option_info->weight = uint256_0;
        l_option_info->hashes_tx_votes = NULL;
        for (dap_list_t *it = a_voting->votes; it; it = it->next) {
            dap_chain_net_vote_t *l_vote = it->data;
            if (l_option_info->option_idx  != l_vote->answer_idx) {
                continue;
            }
            l_option_info->votes_count++;
            SUM_256_256(l_option_info->weight, l_vote->weight, &l_option_info->weight);
            l_option_info->hashes_tx_votes = dap_list_append(l_option_info->hashes_tx_votes, &l_vote->vote_hash);
        }
        l_options[i] = l_option_info;
    }
    l_info->options.options = l_options;
    return l_info;
}

dap_list_t *dap_chain_net_vote_list(dap_chain_net_t *a_net) {
    if (!a_net)
        return NULL;
    dap_chain_net_votings_t *l_voting = NULL, *l_tmp;
    dap_list_t *l_list = NULL;
    pthread_rwlock_rdlock(&s_votings_rwlock);
    HASH_ITER(hh, s_votings, l_voting, l_tmp){
        if (l_voting->net_id.uint64 != a_net->pub.id.uint64)
            continue;
        dap_chain_net_vote_info_t *l_info = s_dap_chain_net_vote_extract_info(l_voting);
        if (!l_info)
            continue;
        l_list = dap_list_append(l_list, l_info);
    }
    pthread_rwlock_unlock(&s_votings_rwlock);
    return l_list;
}

dap_chain_net_vote_info_t *dap_chain_net_vote_extract_info(dap_chain_net_t *a_net, dap_hash_fast_t *a_voting)
{
    if (!a_net || !a_voting)
        return NULL;
    dap_chain_net_votings_t *l_voting = NULL;
    pthread_rwlock_rdlock(&s_votings_rwlock);
    HASH_FIND(hh, s_votings, a_voting, sizeof(dap_hash_fast_t), l_voting);
    pthread_rwlock_unlock(&s_votings_rwlock);
    return l_voting ? s_dap_chain_net_vote_extract_info(l_voting) : NULL;
}

void dap_chain_net_vote_info_free(dap_chain_net_vote_info_t *a_info){
    size_t l_count_options = a_info->options.count_option;
    for (size_t i = 0; i < l_count_options; i++) {
        dap_chain_net_vote_info_option_t *l_option = a_info->options.options[i];
        DAP_DELETE(l_option);
    }
    DAP_DELETE(a_info->options.options);
    DAP_DELETE(a_info);
}

// json_object* dap_chain_net_get_vote_list_json(dap_chain_net_t *a_net, dap_hash_fast_t *a_voting) {
//     if (!a_net || !a_voting)
//         return NULL;
//     json_object * l_json_response = json_object_new_object();
//     dap_chain_net_votings_t *l_voting = NULL;
//     pthread_rwlock_rdlock(&s_votings_rwlock);
//     HASH_FIND(hh, s_votings, a_voting, sizeof(dap_hash_fast_t), l_voting);
//     pthread_rwlock_unlock(&s_votings_rwlock);
//     if (!l_voting) {
//         json_object_put(l_json_response);
//         return NULL;
//     }

//     pthread_rwlock_wrlock(&l_voting->s_tx_outs_rwlock);
//     dap_chain_net_voting_cond_outs_t *it = NULL, *tmp;
//     HASH_ITER(hh, l_voting->voting_spent_cond_outs, it, tmp) {
//         json_object *l_json_obj = json_object_new_object();
//         json_object_object_add(l_json_obj, "tx_hash", json_object_new_string(dap_hash_fast_to_str_static(&it->tx_hash)));
//         json_object_object_add(l_json_obj, "out_idx", json_object_new_int(it->out_idx));
//         json_object_object_add(l_json_obj, "pkey_hash", json_object_new_string(dap_hash_fast_to_str_static(&it->pkey_hash)));

//         json_object_array_add(l_json_response, l_json_obj);
//     }
//     pthread_rwlock_unlock(&l_voting->s_tx_outs_rwlock);



//     for (dap_list_t *l_list = l_voting->votes; l_list; l_list = dap_list_next(l_list)) {
//         dap_chain_net_vote_info_t *l_info = l_list->data;
//         json_object *l_json_obj = json_object_new_object();
//         json_object_object_add(l_json_obj, "question", json_object_new_string(a_vote->question.question_str));
//         json_object_object_add(l_json_obj, "options", json_object_new_array());
//         json_object_array_add(l_json_response, l_json_obj);
//     }
//     return l_json_response;
// }


