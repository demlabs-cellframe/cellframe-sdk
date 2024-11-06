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

#include "dap_common.h"
#include "dap_chain_net_srv_voting.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_mempool.h"
#include "uthash.h"
#include "dap_chain_srv.h"
#include "dap_cli_server.h"
#include "dap_chain_datum_tx_voting.h"

#define LOG_TAG "chain_net_voting"

struct vote_option {
    char *option;
    size_t option_length;
};

struct voting_params {
    char *question;
    size_t question_length;
    dap_list_t *options;            // list of vote_option records
    dap_time_t voting_begin;
    dap_time_t voting_expire;
    uint64_t votes_max_count;
    bool delegate_key_required;
    bool vote_changing_allowed;
};

struct voting_cond_outs {
    dap_chain_hash_fast_t tx_hash;
    int out_idx;
    UT_hash_handle hh;
};

struct vote {
    dap_chain_hash_fast_t vote_hash;
    dap_chain_hash_fast_t pkey_hash;
    uint64_t answer_idx;
    uint256_t weight;
};

struct voting {
    dap_chain_hash_fast_t hash;
    dap_list_t *votes;
    struct voting_params params;
    struct voting_cond_outs *spent_cond_outs;
    UT_hash_handle hh;
};

struct srv_voting {
    struct voting *ht;
};

static void *s_callback_start(dap_chain_net_id_t UNUSED_ARG a_net_id, dap_config_t UNUSED_ARG *a_config);
static void s_callback_delete(void *a_service_internal);

static int s_cond_out_check_colored(dap_chain_net_t *a_net, dap_hash_fast_t *a_voting_hash, dap_hash_fast_t *a_tx_cond_hash, int a_cond_out_idx);
/// -1 error, 0 - unspent, 1 - spent
static int s_coin_check_colored(dap_chain_net_t *a_net, dap_hash_fast_t *a_voting_hash, dap_hash_fast_t *a_tx_prev_hash, int a_out_idx, dap_hash_fast_t *a_pkey_hash);
static int s_datum_tx_voting_verification_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_hash, bool a_apply);
static bool s_datum_tx_voting_verification_delete_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_hash);
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
    dap_ledger_voting_verificator_add(s_datum_tx_voting_verification_callback, s_datum_tx_voting_verification_delete_callback);
    dap_cli_server_cmd_add("voting", s_cli_voting, "Voting commands.",
                            "voting create -net <net_name> -question <\"Question_string\"> -options <\"Option0\", \"Option1\" ... \"OptionN\"> [-expire <voting_expire_time_in_RCF822>] [-max_votes_count <Votes_count>] [-delegated_key_required] [-vote_changing_allowed] -fee <value> -w <fee_wallet_name>\n"
                            "voting vote -net <net_name> -hash <voting_hash> -option_idx <option_index> [-cert <delegate_cert_name>] -fee <value> -w <fee_wallet_name>\n"
                            "voting list -net <net_name>\n"
                            "voting dump -net <net_name> -hash <voting_hash>\n"
                            "Hint:\n"
                            "\texample value_coins (only natural) 1.0 123.4567\n"
                            "\texample value_datoshi (only integer) 1 20 0.4321e+4\n");

    
    dap_chain_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_VOTING_ID };
    dap_chain_static_srv_callbacks_t l_srv_callbacks = { .start = s_callback_start, .delete = s_callback_delete };
    int ret = dap_chain_srv_add(l_uid, "voting", &l_srv_callbacks);
    if (ret) {
        log_it(L_ERROR, "Can't register voting service");
        return ret;
    }
    dap_ledger_service_add(l_uid, "voting", s_tag_check_voting);

    return 0;
}

void dap_chain_net_srv_voting_deinit()
{

}

static void s_voting_clear(struct voting *a_voting)
{
    if (a_voting->params.options)
        dap_list_free_full(a_voting->params.options, NULL);

    if (a_voting->votes)
        dap_list_free_full(a_voting->votes, NULL);

    struct voting_cond_outs *l_el = NULL, *l_tmp = NULL;
    HASH_ITER(hh, a_voting->spent_cond_outs, l_el, l_tmp) {
        HASH_DEL(a_voting->spent_cond_outs, l_el);
        DAP_DELETE(l_el);

    }
}

static void *s_callback_start(dap_chain_net_id_t UNUSED_ARG a_net_id, dap_config_t UNUSED_ARG *a_config)
{
    struct srv_voting *l_service_internal = DAP_NEW_Z(struct srv_voting);
    return l_service_internal;
}

static void s_callback_delete(void *a_service_internal)
{
    struct srv_voting *l_service_internal = a_service_internal;
    struct voting *it = NULL, *tmp;
    HASH_ITER(hh, l_service_internal->ht, it, tmp) {
        HASH_DEL(l_service_internal->ht, it);
        s_voting_clear(it);
        DAP_DELETE(it);
    }
    DAP_DELETE(l_service_internal);
}

static inline struct voting *s_votings_ht_get(dap_chain_net_id_t a_net_id)
{
    struct srv_voting *l_service_internal = dap_chain_srv_get_internal(a_net_id, (dap_chain_srv_uid_t) { .uint64 = DAP_CHAIN_NET_SRV_VOTING_ID });
    return l_service_internal ? l_service_internal->ht : NULL;
}

static inline struct voting *s_voting_find(dap_chain_net_id_t a_net_id, dap_hash_fast_t *a_voting_hash)
{
    struct voting *l_voting = NULL, *votings_ht = s_votings_ht_get(a_net_id);
    if (!votings_ht)
        return NULL;
    HASH_FIND(hh, votings_ht, a_voting_hash, sizeof(dap_hash_fast_t), l_voting);
    return l_voting;
}

static inline int s_voting_add(dap_chain_net_id_t a_net_id, struct voting *a_voting)
{
    struct srv_voting *l_service_internal = dap_chain_srv_get_internal(a_net_id, (dap_chain_srv_uid_t) { .uint64 = DAP_CHAIN_NET_SRV_VOTING_ID });
    if (!l_service_internal)
        return -1;
    // Assert a tx_hash is unique guaranteed by ledger
    HASH_ADD(hh, l_service_internal->ht, hash, sizeof(dap_hash_fast_t), a_voting);

    return 0;
}

static inline bool s_voting_delete(dap_chain_net_id_t a_net_id, dap_hash_fast_t *a_voting_hash)
{
    struct srv_voting *l_service_internal = dap_chain_srv_get_internal(a_net_id, (dap_chain_srv_uid_t) { .uint64 = DAP_CHAIN_NET_SRV_VOTING_ID });
    if (!l_service_internal) {
        log_it(L_ERROR, "Can't find voting service for net id 0x%016" DAP_UINT64_FORMAT_x, a_net_id.uint64);
        return false;
    }
    struct voting *l_voting = NULL;
    HASH_FIND(hh, l_service_internal->ht, a_voting_hash, sizeof(dap_hash_fast_t), l_voting);
    if (!l_voting) {
        log_it(L_ERROR, "Can't find voting %s", dap_hash_fast_to_str_static(a_voting_hash));
        return false;
    }
    HASH_DEL(l_service_internal->ht, l_voting);
    s_voting_clear(l_voting);
    DAP_DELETE(l_voting);

    return true;
}

uint64_t *dap_chain_net_srv_voting_get_result(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_voting_hash)
{
    dap_return_val_if_fail(a_ledger && a_voting_hash, NULL);
    struct voting *l_voting = s_voting_find(a_ledger->net->pub.id, a_voting_hash);
    if (!l_voting) {
        log_it(L_ERROR, "Can't find voting with hash %s in net %s", dap_hash_fast_to_str_static(a_voting_hash), a_ledger->net->pub.name);
        return NULL;
    }
    size_t l_options_count = dap_list_length(l_voting->params.options);
    uint64_t *l_voting_results;
    DAP_NEW_Z_COUNT_RET_VAL(l_voting_results, uint64_t, l_options_count, NULL, NULL);

    for (dap_list_t *it = l_voting->votes; it; it = it->next) {
        struct vote *l_vote = it->data;
        if (l_vote->answer_idx >= l_options_count) {
            log_it(L_ERROR, "Answers option index %" DAP_UINT64_FORMAT_U " is higher than options count %zu for voting %s",
                                        l_vote->answer_idx, l_options_count, dap_hash_fast_to_str_static(a_voting_hash));
            continue;
        }
        l_voting_results[l_vote->answer_idx]++;
    }
    return l_voting_results;
}

static int s_voting_verificator(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_hash, bool a_apply)
{
    if (!a_apply) {
        dap_list_t *l_tsd_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_TSD, NULL);
        bool l_question_present = false, l_options_present = false;
        for (dap_list_t *it = l_tsd_list; it; it = it->next) {
            dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t *)it->data)->tsd;
            switch(l_tsd->type) {
            case VOTING_TSD_TYPE_QUESTION:
                if (!l_tsd->size || !memchr(l_tsd->data, '\0', l_tsd->size || *l_tsd->data == '\0')) {
                    log_it(L_WARNING, "Invalid content for string TSD section QUESTION of voting %s", dap_hash_fast_to_str_static(a_tx_hash));
                    return -DAP_LEDGER_CHECK_PARSE_ERROR;
                }
                l_question_present = true;
                break;
            case VOTING_TSD_TYPE_ANSWER:
                if (!l_tsd->size || !memchr(l_tsd->data, '\0', l_tsd->size || *l_tsd->data == '\0')) {
                    log_it(L_WARNING, "Invalid content for string TSD section ANSWER of voting %s", dap_hash_fast_to_str_static(a_tx_hash));
                    return -DAP_LEDGER_CHECK_PARSE_ERROR;
                }
                l_options_present = true;
                break;
            case VOTING_TSD_TYPE_EXPIRE:
                if (l_tsd->size != sizeof(dap_time_t)) {
                    log_it(L_WARNING, "Incorrect size %u of TSD section EXPIRE of voting %s", l_tsd->size, dap_hash_fast_to_str_static(a_tx_hash));
                    return -DAP_LEDGER_CHECK_INVALID_SIZE;
                }
                break;
            case VOTING_TSD_TYPE_MAX_VOTES_COUNT:
                if (l_tsd->size != sizeof(uint64_t)) {
                    log_it(L_WARNING, "Incorrect size %u of TSD section MAX_VOTES_COUNT of voting %s", l_tsd->size, dap_hash_fast_to_str_static(a_tx_hash));
                    return -DAP_LEDGER_CHECK_INVALID_SIZE;
                }
                break;
            case VOTING_TSD_TYPE_DELEGATED_KEY_REQUIRED:
                if (l_tsd->size != sizeof(byte_t)) {
                    log_it(L_WARNING, "Incorrect size %u of TSD section DELEGATED_KEY_REQUIRED of voting %s", l_tsd->size, dap_hash_fast_to_str_static(a_tx_hash));
                    return -DAP_LEDGER_CHECK_INVALID_SIZE;
                }
                break;
            case VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED:
                if (l_tsd->size != sizeof(byte_t)) {
                    log_it(L_WARNING, "Incorrect size %u of TSD section VOTE_CHANGING_ALLOWED of voting %s", l_tsd->size, dap_hash_fast_to_str_static(a_tx_hash));
                    return -DAP_LEDGER_CHECK_INVALID_SIZE;
                }
                break;
            default:
                break;
            }
        }
        dap_list_free(l_tsd_list);

        if (!l_question_present || !l_options_present) {
            log_it(L_WARNING, "Voting with hash %s contain no question or answer options", dap_hash_fast_to_str_static(a_tx_hash));
            return -2;
        }

        return DAP_LEDGER_CHECK_OK;
    }

    struct voting *l_item;
    DAP_NEW_Z_RET_VAL(l_item, struct voting, -DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY, NULL);
    l_item->hash = *a_tx_hash;
    l_item->params.voting_begin = a_tx_in->header.ts_created;

    dap_list_t *l_tsd_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_TSD, NULL);
    for (dap_list_t *it = l_tsd_list; it; it = it->next) {
        dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t *)it->data)->tsd;
        struct vote_option *l_vote_option = NULL;
        switch(l_tsd->type){
        case VOTING_TSD_TYPE_QUESTION:
            l_item->params.question = (char *)l_tsd->data;
            l_item->params.question_length = l_tsd->size;
            break;
        case VOTING_TSD_TYPE_ANSWER:
            DAP_NEW_Z_RET_VAL(l_vote_option, struct vote_option, -DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY, NULL);
            l_vote_option->option = (char *)l_tsd->data;
            l_vote_option->option_length = l_tsd->size;
            l_item->params.options = dap_list_append(l_item->params.options, l_vote_option);
            break;
        case VOTING_TSD_TYPE_EXPIRE:
            l_item->params.voting_expire = *(dap_time_t *)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_MAX_VOTES_COUNT:
            l_item->params.votes_max_count = *(uint64_t *)l_tsd->data;
            break;
        case VOTING_TSD_TYPE_DELEGATED_KEY_REQUIRED:
            l_item->params.delegate_key_required = *l_tsd->data;
            break;
        case VOTING_TSD_TYPE_VOTE_CHANGING_ALLOWED:
            l_item->params.vote_changing_allowed = *l_tsd->data;
            break;
        default:
            break;
        }
    }
    dap_list_free(l_tsd_list);

    s_voting_add(a_ledger->net->pub.id, l_item);

    return DAP_LEDGER_CHECK_OK;
}

static int s_vote_verificator(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_hash, bool a_apply)
{
    dap_chain_tx_vote_t *l_vote_tx_item = (dap_chain_tx_vote_t *)dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_VOTE, NULL);
    assert(l_vote_tx_item);

    struct voting *l_voting = s_voting_find(a_ledger->net->pub.id, &l_vote_tx_item->voting_hash);
    if (!l_voting) {
        log_it(L_ERROR, "Can't find voting with hash %s in net %s",
               dap_chain_hash_fast_to_str_static(&l_vote_tx_item->voting_hash), a_ledger->net->pub.name);
        return -5;
    }

    dap_hash_fast_t pkey_hash = {};
    int l_item_cnt = 0;
    dap_list_t *l_signs_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_SIG, &l_item_cnt);

    if (!l_signs_list) {
        log_it(L_WARNING, "Can't get signs from tx %s", dap_chain_hash_fast_to_str_static(a_tx_hash));
        return -9;
    }
    dap_chain_tx_sig_t *l_vote_sig = (dap_chain_tx_sig_t *)(dap_list_last(l_signs_list)->data);
    dap_sign_get_pkey_hash((dap_sign_t*)l_vote_sig->sig, &pkey_hash);
    dap_list_free(l_signs_list);

    if (!a_apply) {
        if (l_vote_tx_item->answer_idx > dap_list_length(l_voting->params.options)) {
            log_it(L_WARNING, "Invalid vote option index %" DAP_UINT64_FORMAT_U " for vote tx %s",
                                                    l_vote_tx_item->answer_idx, dap_chain_hash_fast_to_str_static(a_tx_hash));
            return -6;
        }
        if (l_voting->params.votes_max_count && dap_list_length(l_voting->votes) >= l_voting->params.votes_max_count){
            log_it(L_WARNING, "The required number of votes has been collected for voting %s", dap_chain_hash_fast_to_str_static(&l_voting->hash));
            return -7;
        }
        if (l_voting->params.voting_expire && l_voting->params.voting_expire <= a_tx_in->header.ts_created) {
            log_it(L_WARNING, "The voting %s has been expired", dap_chain_hash_fast_to_str_static(&l_voting->hash));
            return -8;
        }

        if (l_voting->params.delegate_key_required &&
                !dap_chain_net_srv_stake_check_pkey_hash(a_ledger->net->pub.id, &pkey_hash)){
            log_it(L_WARNING, "Voting %s required a delegated key", dap_chain_hash_fast_to_str_static(&l_voting->hash));
            return -10;
        }

        for (dap_list_t *it = l_voting->votes; it; it = it->next) {
            if (dap_hash_fast_compare(&((struct vote *)it->data)->pkey_hash, &pkey_hash)) {
                dap_hash_fast_t *l_vote_hash = &((struct vote *)it->data)->vote_hash;
                if (!l_voting->params.vote_changing_allowed) {
                    char l_vote_hash_str[DAP_HASH_FAST_STR_SIZE];
                    dap_hash_fast_to_str(l_vote_hash, l_vote_hash_str, DAP_HASH_FAST_STR_SIZE);
                    log_it(L_WARNING, "The voting %s don't allow change your vote %s",
                           dap_hash_fast_to_str_static(&l_voting->hash), l_vote_hash_str);
                    return -11;
                }
                break;
            }
        }
    }

    uint256_t l_weight = {};

    // check out conds
    dap_list_t *l_tsd_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_TSD, NULL);
    for (dap_list_t *it = l_tsd_list; it; it = it->next) {
        dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t*)it->data)->tsd;
        dap_hash_fast_t l_hash = ((dap_chain_tx_voting_tx_cond_t*)l_tsd->data)->tx_hash;
        int l_out_idx = ((dap_chain_tx_voting_tx_cond_t*)l_tsd->data)->out_idx;
        if (l_tsd->type == VOTING_TSD_TYPE_VOTE_TX_COND) {
            if (s_cond_out_check_colored(a_ledger->net, &l_vote_tx_item->voting_hash, &l_hash, l_out_idx))
                continue;
            dap_chain_datum_tx_t *l_tx_prev_temp = dap_ledger_tx_find_by_hash(a_ledger, &l_hash);
            dap_chain_tx_out_cond_t *l_prev_out = (dap_chain_tx_out_cond_t*)dap_chain_datum_tx_item_get(l_tx_prev_temp, &l_out_idx, NULL, TX_ITEM_TYPE_OUT_COND, NULL);
            if (!l_prev_out || l_prev_out->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK)
                continue;
            if (SUM_256_256(l_weight, l_prev_out->header.value, &l_weight)) {
                log_it(L_WARNING, "Integer overflow while parsing vote tx %s", dap_chain_hash_fast_to_str_static(a_tx_hash));
                return -DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
            }

            struct voting_cond_outs *l_item;
            DAP_NEW_Z_SIZE_RET_VAL(l_item, struct voting_cond_outs, sizeof(struct voting_cond_outs), -DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY, NULL);
            l_item->tx_hash = l_hash;
            l_item->out_idx = l_out_idx;
            HASH_ADD(hh, l_voting->spent_cond_outs, tx_hash, sizeof(dap_hash_fast_t), l_item);
        }
    }
    dap_list_free(l_tsd_list);
    // check inputs
    dap_list_t *l_ins_list = dap_chain_datum_tx_items_get(a_tx_in, TX_ITEM_TYPE_IN, NULL);
    if (!l_ins_list) {
        log_it(L_WARNING, "Can't get inputs from vote tx %s", dap_chain_hash_fast_to_str_static(a_tx_hash));
        return -12;
    }
    for (dap_list_t *it = l_ins_list; it; it = it->next) {
        dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t *)it->data;
        if (!s_coin_check_colored(a_ledger->net, &l_vote_tx_item->voting_hash,
                                                &l_tx_in->header.tx_prev_hash, l_tx_in->header.tx_out_prev_idx, &pkey_hash)) {
            dap_chain_datum_tx_t *l_tx_prev_temp = dap_ledger_tx_find_by_hash(a_ledger, &l_tx_in->header.tx_prev_hash);
            dap_chain_tx_out_t *l_prev_out_union = (dap_chain_tx_out_t *)dap_chain_datum_tx_out_get_by_out_idx(l_tx_prev_temp, l_tx_in->header.tx_out_prev_idx);
            if (!l_prev_out_union)
                continue;
            if ((l_prev_out_union->header.type == TX_ITEM_TYPE_OUT || l_prev_out_union->header.type == TX_ITEM_TYPE_OUT_EXT) &&
                    SUM_256_256(l_weight, l_prev_out_union->header.value, &l_weight)) {
                log_it(L_WARNING, "Integer overflow while parsing vote tx %s", dap_chain_hash_fast_to_str_static(a_tx_hash));
                return -DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
            }
        }
    }
    dap_list_free(l_ins_list);

    if (IS_ZERO_256(l_weight)) {
        log_it(L_ERROR, "No unspent coins found in vote tx %s", dap_chain_hash_fast_to_str_static(a_tx_hash));
        return -13;
    }

    if (a_apply) {

        struct vote *l_vote_item;
        DAP_NEW_Z_RET_VAL(l_vote_item, struct vote, -DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY, NULL);
        l_vote_item->vote_hash = *a_tx_hash;
        l_vote_item->pkey_hash = pkey_hash;
        l_vote_item->answer_idx = l_vote_tx_item->answer_idx;
        l_vote_item->weight = l_weight;

        // cycle is safe cause return after link deletion
        for (dap_list_t *it = l_voting->votes; it; it = it->next) {
            if (dap_hash_fast_compare(&((struct vote *)it->data)->pkey_hash, &pkey_hash)) {
                dap_hash_fast_t *l_vote_hash = &((struct vote *)it->data)->vote_hash;
                //delete conditional outputs
                dap_chain_datum_tx_t *l_old_tx = dap_ledger_tx_find_by_hash(a_ledger, l_vote_hash);
                if (!l_old_tx) {
                    char l_vote_hash_str[DAP_HASH_FAST_STR_SIZE];
                    dap_hash_fast_to_str(l_vote_hash, l_vote_hash_str, DAP_HASH_FAST_STR_SIZE);
                    log_it(L_ERROR, "Can't find old vote %s of voting %s in ledger",
                           l_vote_hash_str, dap_hash_fast_to_str_static(&l_voting->hash));
                }
                dap_list_t* l_tsd_list = dap_chain_datum_tx_items_get(l_old_tx, TX_ITEM_TYPE_TSD, NULL);
                for (dap_list_t *it_tsd = l_tsd_list; it_tsd; it_tsd = it_tsd->next) {
                    dap_tsd_t* l_tsd = (dap_tsd_t*)((dap_chain_tx_tsd_t*)it_tsd->data)->tsd;
                    dap_hash_fast_t *l_hash = &((dap_chain_tx_voting_tx_cond_t*)l_tsd->data)->tx_hash;
                    if (l_tsd->type == VOTING_TSD_TYPE_VOTE_TX_COND) {
                        struct voting_cond_outs *l_tx_outs = NULL;
                        HASH_FIND(hh, l_voting->spent_cond_outs, l_hash, sizeof(dap_hash_fast_t), l_tx_outs);
                        if (l_tx_outs)
                            HASH_DELETE(hh, l_voting->spent_cond_outs, l_tx_outs);
                    }
                }
                dap_list_free(l_tsd_list);
                // change vote & move it to the end of list
                l_voting->votes = dap_list_remove_link(l_voting->votes, it);
                l_voting->votes = dap_list_append(l_voting->votes, l_vote_item);
                char l_vote_hash_str[DAP_HASH_FAST_STR_SIZE];
                dap_hash_fast_to_str(&((struct vote *)it->data)->vote_hash, l_vote_hash_str, DAP_HASH_FAST_STR_SIZE);
                DAP_DELETE(it->data);
                log_it(L_INFO, "Vote %s of voting %s has been changed", l_vote_hash_str, dap_hash_fast_to_str_static(&l_voting->hash));
                return DAP_LEDGER_CHECK_OK;
            }
        }
        l_voting->votes = dap_list_append(l_voting->votes, l_vote_item);
        char l_vote_hash_str[DAP_HASH_FAST_STR_SIZE];
        dap_hash_fast_to_str(a_tx_hash, l_vote_hash_str, DAP_HASH_FAST_STR_SIZE);
        log_it(L_INFO, "Vote %s of voting %s has been accepted", l_vote_hash_str, dap_hash_fast_to_str_static(&l_voting->hash));
    }
    return DAP_LEDGER_CHECK_OK;
}

int s_datum_tx_voting_verification_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_hash, bool a_apply)
{
    if (a_type == TX_ITEM_TYPE_VOTING)
        return s_voting_verificator(a_ledger, a_tx_in, a_tx_hash, a_apply);
    if (a_type == TX_ITEM_TYPE_VOTE)
        return s_vote_verificator(a_ledger, a_tx_in, a_tx_hash, a_apply);
    log_it(L_ERROR, "Item %d is not supported in votings", a_type);
    return -3;
}

static inline bool s_vote_delete(dap_chain_net_id_t a_net_id, dap_chain_datum_tx_t *a_vote_tx, dap_hash_fast_t *a_vote_tx_hash)
{
    dap_chain_tx_vote_t *l_vote_tx_item = (dap_chain_tx_vote_t *)dap_chain_datum_tx_item_get(a_vote_tx, NULL, NULL, TX_ITEM_TYPE_VOTE, NULL);
    assert(l_vote_tx_item);
    struct voting * l_voting = s_voting_find(a_net_id, &l_vote_tx_item->voting_hash);
    if (!l_voting) {
        log_it(L_ERROR, "Can't find voting with hash %s in net id 0x%016" DAP_UINT64_FORMAT_x,
                                dap_chain_hash_fast_to_str_static(a_vote_tx_hash), a_net_id.uint64);
        return false;
    }
    for (dap_list_t *l_vote = l_voting->votes; l_vote; l_vote = l_vote->next) {
        if (dap_hash_fast_compare(&((struct vote *)l_vote->data)->vote_hash, a_vote_tx_hash)) {
            // Delete vote
            DAP_DELETE(l_vote->data);
            l_voting->votes = dap_list_remove(l_voting->votes, l_vote->data);
            return true;
        }
    }
    return false;
}

static bool s_datum_tx_voting_verification_delete_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_hash)
{
    if (a_type == TX_ITEM_TYPE_VOTING)
        return s_voting_delete(a_ledger->net->pub.id, a_tx_hash);

    if (a_type == TX_ITEM_TYPE_VOTE)
        return s_vote_delete(a_ledger->net->pub.id, a_tx_in, a_tx_hash);

    log_it(L_ERROR, "Unknown voting type %d fot tx_hash %s", a_type, dap_chain_hash_fast_to_str_static(a_tx_hash));
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

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-question", &l_question_str);
        if (!l_question_str){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_QUESTION_PARAM_MISSING, "Voting requires a question parameter to be valid.");
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
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_OPTION_PARAM_MISSING, "Voting requires a question parameter to be valid.");
            return -DAP_CHAIN_NET_VOTE_CREATE_OPTION_PARAM_MISSING;
        }
        // Parse options list
        l_options_list = s_get_options_list_from_str(l_options_list_str);
        if(!l_options_list || dap_list_length(l_options_list) < 2){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_NUMBER_OPTIONS_ERROR, "Number of options must be 2 or greater.");
            return -DAP_CHAIN_NET_VOTE_CREATE_NUMBER_OPTIONS_ERROR;
        }

        if(dap_list_length(l_options_list)>DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_CONTAIN_MAX_OPTIONS, 
            "The voting can contain no more than %d options", DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT);            
            return -DAP_CHAIN_NET_VOTE_CREATE_CONTAIN_MAX_OPTIONS;
        }

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-expire", &l_voting_expire_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-max_votes_count", &l_max_votes_count_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_fee_str);
        if (!l_fee_str){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_FEE_PARAM_NOT_VALID, "Voting requires paramete -fee to be valid.");
            return -DAP_CHAIN_NET_VOTE_CREATE_FEE_PARAM_NOT_VALID;
        }
        uint256_t l_value_fee = dap_chain_balance_scan(l_fee_str);

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
        if (!l_wallet_str){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_WALLET_PARAM_NOT_VALID, "Voting requires parameter -w to be valid.");
            return -DAP_CHAIN_NET_VOTE_CREATE_WALLET_PARAM_NOT_VALID;
        }

        dap_time_t l_time_expire = 0;
        if (l_voting_expire_str)
            l_time_expire = dap_time_from_str_rfc822(l_voting_expire_str);
        if (l_voting_expire_str && !l_time_expire){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_WRONG_TIME_FORMAT, 
                                    "Wrong time format. -expire parameter must be in format \"Day Month Year HH:MM:SS Timezone\" e.g. \"19 August 2024 22:00:00 +00\"");
            return -DAP_CHAIN_NET_VOTE_CREATE_WRONG_TIME_FORMAT;
        }
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

        char *l_hash_ret = NULL;
        int res = dap_chain_net_srv_voting_create(l_question_str, l_options_list, l_time_expire, l_max_count, l_value_fee, l_is_delegated_key, l_is_vote_changing_allowed, l_wallet_fee, l_net, l_hash_out_type, &l_hash_ret);
        dap_list_free(l_options_list);
        dap_chain_wallet_close(l_wallet_fee);

        switch (res) {
            case DAP_CHAIN_NET_VOTE_CREATE_OK: {
                json_object* json_obj_inf = json_object_new_object();
                json_object_object_add(json_obj_inf, "Datum add successfully", json_object_new_string(l_hash_ret));
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
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_COUNT_OPTION_OVERSIZE_MAX, "The voting can contain no more than %d options",
                                                  DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT);
                return DAP_CHAIN_NET_VOTE_CREATE_COUNT_OPTION_OVERSIZE_MAX;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_FEE_IS_ZERO: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_FEE_IS_ZERO, "The commission amount must be greater than zero");
                return DAP_CHAIN_NET_VOTE_CREATE_FEE_IS_ZERO;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_SOURCE_ADDRESS_IS_INVALID: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_SOURCE_ADDRESS_IS_INVALID, "source address is invalid");
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
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_OPTION_TSD_ITEM, "Can't create voting with expired time");
                return DAP_CHAIN_NET_VOTE_CREATE_CAN_NOT_OPTION_TSD_ITEM;
            } break;
            case DAP_CHAIN_NET_VOTE_CREATE_INPUT_TIME_MORE_CURRENT_TIME: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_CREATE_INPUT_TIME_MORE_CURRENT_TIME, "Can't create voting with expired time");
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
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_VOTING_UNKNOWN_ERR, "Unknown error. Code: %d", res);
                return -DAP_CHAIN_NET_SRV_VOTING_UNKNOWN_ERR;
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
        dap_chain_hash_fast_from_str(l_hash_str, &l_voting_hash);


        dap_chain_hash_fast_t l_pkey_hash;
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
        dap_chain_wallet_t *l_wallet_fee = dap_chain_wallet_open(l_wallet_str, c_wallets_path,NULL);
        if (!l_wallet_fee) {
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_WALLET_DOES_NOT_EXIST, "Wallet %s does not exist", l_wallet_str);
            return -DAP_CHAIN_NET_VOTE_VOTING_WALLET_DOES_NOT_EXIST;
        }

        uint64_t l_option_idx_count = strtoul(l_option_idx_str, NULL, 10);

        char *l_hash_tx;

        int res = dap_chain_net_srv_vote_create(l_cert, l_value_fee, l_wallet_fee, &l_voting_hash, l_option_idx_count,
                                            l_net, l_hash_out_type, &l_hash_tx);
        dap_chain_wallet_close(l_wallet_fee);

        switch (res) {
            case DAP_CHAIN_NET_VOTE_VOTING_OK: {
                json_object* json_obj_inf = json_object_new_object();
                json_object_object_add(json_obj_inf, "Datum add successfully to mempool", json_object_new_string(l_hash_tx));
                json_object_array_add(*json_arr_reply, json_obj_inf);
                DAP_DELETE(l_hash_tx);
                return DAP_CHAIN_NET_VOTE_CREATE_OK;
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_FIND_VOTE: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_FIND_VOTE, "Can't find voting with hash %s", l_hash_str);
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_THIS_VOTING_HAVE_MAX_VALUE_VOTES: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_THIS_VOTING_HAVE_MAX_VALUE_VOTES, 
                                                  "This voting already received the required number of votes.");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_ALREADY_EXPIRED: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_ALREADY_EXPIRED, "This voting already expired.");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_NO_KEY_FOUND_IN_CERT: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_NO_KEY_FOUND_IN_CERT, 
                                                    "No key found in \"%s\" certificate", l_cert_name);                
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_CERT_REQUIRED: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_CERT_REQUIRED, 
                                                    "This voting required a delegated key. Parameter -cert must contain a valid certificate name");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_NO_PUBLIC_KEY_IN_CERT: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_NO_PUBLIC_KEY_IN_CERT, 
                                                    "Can't serialize public key of certificate \"%s\"",
                                                    l_cert_name);
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_KEY_IS_NOT_DELEGATED: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_KEY_IS_NOT_DELEGATED, "Your key is not delegated.");
            } break;
            case DAP_CHAIN_NET_VOTE_VOTING_DOES_NOT_ALLOW_CHANGE_YOUR_VOTE: {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_VOTING_DOES_NOT_ALLOW_CHANGE_YOUR_VOTE, "The voting doesn't allow change your vote.");
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
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_VOTING_UNKNOWN_ERR, "Undefined error code: %d", res);
            } break;
        }
        return res;
    } break;

    case CMD_LIST: {
        json_object* json_vote_out = json_object_new_object();
        json_object_object_add(json_vote_out, "List of votings in net", json_object_new_string(l_net->pub.name));
        json_object* json_arr_voting_out = json_object_new_array();
        struct voting *votings_ht = s_votings_ht_get(l_net->pub.id);
        for (struct voting *it = votings_ht; it; it = it->hh.next) {
            json_object* json_obj_vote = json_object_new_object();
            json_object_object_add(json_obj_vote, "Voting hash", 
                                    json_object_new_string(dap_chain_hash_fast_to_str_static(&it->hash)));
            json_object_object_add(json_obj_vote, "Voting question", json_object_new_string((char *)it->params.question));
            json_object_array_add(json_arr_voting_out, json_obj_vote);
        }
        json_object_array_add(*json_arr_reply, json_arr_voting_out);
    } break;

    case CMD_DUMP: {
        const char* l_hash_str = NULL;

        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_hash_str);
        if(!l_hash_str){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_DUMP_HASH_PARAM_NOT_FOUND, "Command 'results' require the parameter -hash");
            return -DAP_CHAIN_NET_VOTE_DUMP_HASH_PARAM_NOT_FOUND;
        }

        dap_hash_fast_t l_voting_hash = {};
        if (dap_chain_hash_fast_from_str(l_hash_str, &l_voting_hash)) {
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_DUMP_HASH_PARAM_INVALID,
                                   "Can't recognize hash string as a valid HEX or BASE58 format hash");
            return -DAP_CHAIN_NET_VOTE_DUMP_HASH_PARAM_INVALID;
        }
        struct voting *l_voting = s_voting_find(l_net->pub.id, &l_voting_hash);
        if(!l_voting){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_DUMP_CAN_NOT_FIND_VOTE, "Can't find voting with hash %s", l_hash_str);
            return -DAP_CHAIN_NET_VOTE_DUMP_CAN_NOT_FIND_VOTE;
        }

        uint64_t l_options_count = 0;
        l_options_count = dap_list_length(l_voting->params.options);
        if(!l_options_count){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_DUMP_NO_OPTIONS, "No options. May be datum is crashed.");
            return -DAP_CHAIN_NET_VOTE_DUMP_NO_OPTIONS;
        }

        struct voting_results {uint64_t num_of_votes; uint256_t weights;};

        struct voting_results* l_results = DAP_NEW_Z_SIZE(struct voting_results, sizeof(struct voting_results)*l_options_count);
        if(!l_results){
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_VOTE_DUMP_MEMORY_ERR, "Memory allocation error!");
            return -DAP_CHAIN_NET_VOTE_DUMP_MEMORY_ERR;
        }
        dap_list_t* l_list_tmp = l_voting->votes;
        uint256_t l_total_weight = {};
        while(l_list_tmp){
            struct vote *l_vote = l_list_tmp->data;
            l_results[l_vote->answer_idx].num_of_votes++;
            SUM_256_256(l_results[l_vote->answer_idx].weights, l_vote->weight, &l_results[l_vote->answer_idx].weights);
            l_list_tmp = l_list_tmp->next;
            SUM_256_256(l_total_weight, l_vote->weight, &l_total_weight);
        }

        uint64_t l_votes_count = 0;
        l_votes_count = dap_list_length(l_voting->votes);
        json_object* json_vote_out = json_object_new_object();
        json_object_object_add(json_vote_out, "hash of voting", 
                                    json_object_new_string(l_hash_str));
        json_object_object_add(json_vote_out, "Voting dump", json_object_new_string((char *)l_voting->params.question));

        if (l_voting->params.voting_expire) {
            char l_tmp_buf[DAP_TIME_STR_SIZE];
            dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_voting->params.voting_expire);
            json_object_object_add(json_vote_out, "Voting expire", 
                                    json_object_new_string(l_tmp_buf));
            //dap_string_truncate(l_str_out, l_str_out->len - 1);
            json_object_object_add(json_vote_out, "status", 
                                    l_voting->params.voting_expire > dap_time_now() ?
                                    json_object_new_string("active") :
                                    json_object_new_string("expired"));
        }
        if (l_voting->params.votes_max_count){
            char *l_val = dap_strdup_printf(" %"DAP_UINT64_FORMAT_U" (%s)\n", l_voting->params.votes_max_count,
                                     l_voting->params.votes_max_count <= l_votes_count ? "closed" : "active");
            json_object_object_add(json_vote_out, "Votes max count", json_object_new_string(l_val));
            DAP_DELETE(l_val);
        }
        json_object_object_add(json_vote_out, "changing vote status", l_voting->params.vote_changing_allowed ?
                                                                        json_object_new_string("available") : 
                                                                        json_object_new_string("not available"));
        json_object_object_add(json_vote_out, "delegated voting key status", l_voting->params.delegate_key_required ?
                                                                        json_object_new_string("is required") : 
                                                                        json_object_new_string("not required"));
        
        json_object* json_arr_vote_out = json_object_new_array();
        for (uint64_t i = 0; i < dap_list_length(l_voting->params.options); i++){
            json_object* json_vote_obj = json_object_new_object();
            char *l_val = NULL;
            l_val = dap_strdup_printf(" %"DAP_UINT64_FORMAT_U")  ", i);
            json_object_object_add(json_vote_obj, "#", json_object_new_string(l_val));
            DAP_DELETE(l_val);
            dap_list_t* l_option = dap_list_nth(l_voting->params.options, (uint64_t)i);
            struct vote_option* l_vote_option = (struct vote_option*)l_option->data;
            json_object_object_add(json_vote_obj, "voting tx", json_object_new_string((char *)l_vote_option->option));
            float l_percentage = l_votes_count ? ((float)l_results[i].num_of_votes/l_votes_count)*100 : 0;
            uint256_t l_weight_percentage = {};

            DIV_256_COIN(l_results[i].weights, l_total_weight, &l_weight_percentage);
            MULT_256_COIN(l_weight_percentage, dap_chain_balance_coins_scan("100.0"), &l_weight_percentage);
            const char *l_weight_percentage_str = dap_uint256_decimal_to_round_char(l_weight_percentage, 2, true);
            const char *l_w_coins, *l_w_datoshi = dap_uint256_to_char(l_results[i].weights, &l_w_coins);
            l_val = dap_strdup_printf("Votes: %"DAP_UINT64_FORMAT_U" (%.2f%%)\nWeight: %s (%s) %s (%s%%)",
                                     l_results[i].num_of_votes, l_percentage, l_w_coins, l_w_datoshi, l_net->pub.native_ticker, l_weight_percentage_str);
            json_object_object_add(json_vote_obj, "price", json_object_new_string(l_val));
            DAP_DELETE(l_val);
            json_object_array_add(json_arr_vote_out, json_vote_obj);
        }
        json_object_object_add(json_vote_out, "Results", json_arr_vote_out);
        DAP_DELETE(l_results);
        char *l_val = NULL;
        l_val = dap_strdup_printf(" %"DAP_UINT64_FORMAT_U, l_votes_count);
        json_object_object_add(json_vote_out, "Total number of votes", json_object_new_string(l_val));
        DAP_DELETE(l_val);
        const char *l_tw_coins, *l_tw_datoshi = dap_uint256_to_char(l_total_weight, &l_tw_coins);
        l_val = dap_strdup_printf("%s (%s) %s\n\n", l_tw_coins, l_tw_datoshi, l_net->pub.native_ticker);
        json_object_object_add(json_vote_out, "Total weight", json_object_new_string(l_val));
        DAP_DELETE(l_val);
        json_object_array_add(*json_arr_reply, json_vote_out);
    }break;
    default:{

    }break;
    }

    return 0;
}

static int s_tx_check_colored(dap_ledger_t *a_ledger, struct voting *a_voting, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, dap_hash_fast_t *a_pkey_hash)
{
    if (a_tx->header.ts_created < a_voting->params.voting_begin)
        return 0;

    dap_chain_tx_vote_t *l_vote = (dap_chain_tx_vote_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_VOTE, NULL);
    if (l_vote && dap_hash_fast_compare(&l_vote->voting_hash, &a_voting->hash)) {
        for (dap_list_t *it = a_voting->votes; it; it = it->next) {
            struct vote *l_vote = (struct vote *)it->data;
            if (dap_hash_fast_compare(&l_vote->vote_hash, a_tx_hash)) {
                if (a_voting->params.vote_changing_allowed &&
                        !dap_hash_fast_is_blank(a_pkey_hash) &&
                        dap_hash_fast_compare(&l_vote->pkey_hash, a_pkey_hash))
                    return 0;  // it's vote changing, allow it
                return 1;
            }
        }
    }

    dap_list_t *l_ins_list = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_IN, NULL);;
    l_ins_list = dap_list_concat(l_ins_list, dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_IN_COND, NULL));
    if (!l_ins_list)
        return 0;
    for (dap_list_t *it = l_ins_list; it; it = it->next) {
        dap_chain_tx_in_t *l_in_cur = it->data;
        dap_hash_fast_t *l_tx_prev_hash = &l_in_cur->header.tx_prev_hash;
        dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash(a_ledger, l_tx_prev_hash);
        if (!l_tx_prev) {
            log_it(L_ERROR, "Can't find tx %s for vote of voting %s", dap_hash_fast_to_str_static(l_tx_prev_hash), dap_hash_fast_to_str_static(&a_voting->hash));
            return -1;
        }
        dap_chain_tx_out_t *l_prev_out_union = (dap_chain_tx_out_t *)dap_chain_datum_tx_out_get_by_out_idx(l_tx_prev, l_in_cur->header.tx_out_prev_idx);
        if (!l_prev_out_union)
            continue;

        const char* l_tx_token = NULL;
        switch (l_prev_out_union->header.type) {
        case TX_ITEM_TYPE_OUT:
            l_tx_token = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, l_tx_prev_hash);
            break;
        case TX_ITEM_TYPE_OUT_EXT:
            l_tx_token = ((dap_chain_tx_out_ext_t *)l_prev_out_union)->token;
            break;
        case TX_ITEM_TYPE_OUT_COND:
            if (s_cond_out_check_colored(a_ledger->net, &a_voting->hash, l_tx_prev_hash, l_in_cur->header.tx_out_prev_idx)) {
                dap_list_free(l_ins_list);
                return 1;
            }
        default:
            break;
        }

        if (dap_strcmp(l_tx_token, a_ledger->net->pub.native_ticker))
            continue;

        int l_nested_tx_spent = s_tx_check_colored(a_ledger, a_voting, l_tx_prev, l_tx_prev_hash, a_pkey_hash);
        if (l_nested_tx_spent) {
            dap_list_free(l_ins_list);
            return l_nested_tx_spent;
        }
    }
    dap_list_free(l_ins_list);
    return 0;
}

static int s_coin_check_colored(dap_chain_net_t *a_net, dap_hash_fast_t *a_voting_hash, dap_hash_fast_t *a_tx_prev_hash, int a_out_idx, dap_hash_fast_t *a_pkey_hash)
{
    int l_coin_is_spent = 0;
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    assert(l_ledger);

    struct voting *l_voting = s_voting_find(a_net->pub.id, a_voting_hash);
    if (!l_voting) {
        log_it(L_ERROR, "Can't find voting %s", dap_hash_fast_to_str_static(a_voting_hash));
        return -2;
    }
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, a_tx_prev_hash);
    if (!l_tx) {
        log_it(L_ERROR, "Can't find tx %s for vote of voting %s", dap_hash_fast_to_str_static(a_tx_prev_hash), dap_hash_fast_to_str_static(a_voting_hash));
        return -1;
    }

    int l_nested_tx_spent = s_tx_check_colored(a_net->pub.ledger, l_voting, l_tx, a_tx_prev_hash, a_pkey_hash);
    if (l_nested_tx_spent)
        return l_nested_tx_spent;

    if (s_cond_out_check_colored(a_net, a_voting_hash, a_tx_prev_hash, a_out_idx) != 0)
        return 1;

    return l_coin_is_spent;
}

static int s_cond_out_check_colored(dap_chain_net_t *a_net, dap_hash_fast_t *a_voting_hash, dap_hash_fast_t *a_tx_cond_hash, int a_cond_out_idx)
{

    struct voting *l_voting = s_voting_find(a_net->pub.id, a_voting_hash);
    if (!l_voting ) {
        log_it(L_ERROR, "Can't find voting with hash %s in net %s",
            dap_chain_hash_fast_to_str_static(a_voting_hash), a_net->pub.name);
        return -1;
    }
    struct voting_cond_outs *l_tx_outs = NULL;
    HASH_FIND(hh, l_voting->spent_cond_outs, a_tx_cond_hash, sizeof(dap_hash_fast_t), l_tx_outs);

    if (!l_tx_outs || l_tx_outs->out_idx != a_cond_out_idx)
        return 0;

    return 1;
}

int dap_chain_net_srv_voting_create(const char *a_question, dap_list_t *a_options, dap_time_t a_expire_vote,
                              uint64_t a_max_vote, uint256_t a_fee, bool a_delegated_key_required,
                              bool a_vote_changing_allowed, dap_chain_wallet_t *a_wallet,
                              dap_chain_net_t *a_net, const char *a_hash_out_type, char **a_hash_output)
{

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
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                       l_addr_from, l_total_fee, &l_value_transfer);
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
        if(dap_chain_datum_tx_add_out_item(&l_tx, l_addr_from, l_value_back) != 1) {
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

int dap_chain_net_srv_vote_create(dap_cert_t *a_cert, uint256_t a_fee, dap_chain_wallet_t *a_wallet, dap_hash_fast_t *a_voting_hash,
                              uint64_t a_option_idx, dap_chain_net_t *a_net, const char *a_hash_out_type,
                              char **a_hash_tx_out)
{


    struct voting *l_voting = s_voting_find(a_net->pub.id, a_voting_hash);
    if (!l_voting)
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_FIND_VOTE;

    if (l_voting->params.votes_max_count && dap_list_length(l_voting->votes) >= l_voting->params.votes_max_count)
        return DAP_CHAIN_NET_VOTE_VOTING_THIS_VOTING_HAVE_MAX_VALUE_VOTES;

    if (l_voting->params.voting_expire && dap_time_now() > l_voting->params.voting_expire)
        return DAP_CHAIN_NET_VOTE_VOTING_ALREADY_EXPIRED;

    dap_hash_fast_t l_pkey_hash = {0};

    if (l_voting->params.delegate_key_required) {
        if (!a_cert)
            return DAP_CHAIN_NET_VOTE_VOTING_CERT_REQUIRED;
        if (!a_cert->enc_key)
            return DAP_CHAIN_NET_VOTE_VOTING_NO_KEY_FOUND_IN_CERT;
        // Get publivc key hash
        size_t l_pub_key_size = 0;
        uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(a_cert->enc_key, &l_pub_key_size);;
        if (l_pub_key == NULL)
            return DAP_CHAIN_NET_VOTE_VOTING_NO_PUBLIC_KEY_IN_CERT;

        dap_hash_fast(l_pub_key, l_pub_key_size, &l_pkey_hash);
        DAP_DELETE(l_pub_key);
        if (!dap_chain_net_srv_stake_check_pkey_hash(a_net->pub.id, &l_pkey_hash))
            return DAP_CHAIN_NET_VOTE_VOTING_KEY_IS_NOT_DELEGATED;
        for (dap_list_t *it = l_voting->votes; it; it = it->next)
            if (dap_hash_fast_compare(&((struct vote *)it->data)->pkey_hash, &l_pkey_hash) &&
                    !l_voting->params.vote_changing_allowed)
                return DAP_CHAIN_NET_VOTE_VOTING_DOES_NOT_ALLOW_CHANGE_YOUR_VOTE;
    }

    dap_enc_key_t *l_priv_key = NULL;

    l_priv_key = dap_chain_wallet_get_key(a_wallet, 0);

    const dap_chain_addr_t *l_addr_from = (const dap_chain_addr_t *) dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);

    if (!l_addr_from)
        return DAP_CHAIN_NET_VOTE_VOTING_SOURCE_ADDRESS_INVALID;

    const char *l_native_ticker = a_net->pub.native_ticker;
    uint256_t l_net_fee = {}, l_total_fee = {}, l_value_transfer;
    dap_chain_addr_t l_addr_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_addr_fee);
    SUM_256_256(l_net_fee, a_fee, &l_total_fee);

    dap_ledger_t* l_ledger = dap_ledger_by_net_name(a_net->pub.name);
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs(l_ledger, l_native_ticker, l_addr_from, &l_value_transfer);
    if (!l_list_used_out || compare256(l_value_transfer, l_total_fee) <= 0) {
        return DAP_CHAIN_NET_VOTE_VOTING_NOT_ENOUGH_FUNDS_TO_TRANSFER;
    }

    // check outputs UTXOs
    uint256_t l_value_transfer_new = {};
    dap_list_t *it, *tmp;
    DL_FOREACH_SAFE(l_list_used_out, it, tmp) {
        dap_chain_tx_used_out_item_t *l_out = (dap_chain_tx_used_out_item_t *)it->data;
        if (s_coin_check_colored(a_net, a_voting_hash, &l_out->tx_hash_fast, l_out->num_idx_out, &l_pkey_hash) &&
                !l_voting->params.vote_changing_allowed) {
            dap_list_delete_link(l_list_used_out, it);
            continue;
        }
        if (SUM_256_256(l_value_transfer_new, l_out->value, &l_value_transfer_new))
            return DAP_CHAIN_NET_VOTE_VOTING_INTEGER_OVERFLOW;
    }

    if (IS_ZERO_256(l_value_transfer_new) || compare256(l_value_transfer_new, l_total_fee) <= 0){
        return DAP_CHAIN_NET_VOTE_VOTING_UNSPENT_UTX0_FOR_PARTICIPATION_THIS_VOTING;
    }

    l_value_transfer = l_value_transfer_new;

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // Add vote item
    if (a_option_idx > dap_list_length(l_voting->params.options)){
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_INVALID_OPTION_INDEX;
    }
    dap_chain_tx_vote_t* l_vote_item = dap_chain_datum_tx_item_vote_create(a_voting_hash, &a_option_idx);
    if(!l_vote_item){
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_VOTE_ITEM;
    }
    dap_chain_datum_tx_add_item(&l_tx, l_vote_item);
    DAP_DEL_Z(l_vote_item);

    // add stake out conds items
    dap_list_t *l_outs = dap_ledger_get_list_tx_cond_outs(l_ledger, a_net->pub.native_ticker,  l_addr_from,
                                                          DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, NULL);
    dap_list_t *l_temp = l_outs;
    while(l_temp){
        dap_chain_tx_used_out_item_t *l_out_item = (dap_chain_tx_used_out_item_t *)l_temp->data;
        if (dap_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &l_out_item->tx_hash_fast, l_out_item->num_idx_out, NULL) ||
            s_cond_out_check_colored(a_net, a_voting_hash, &l_out_item->tx_hash_fast, l_out_item->num_idx_out ) != 0){
            l_temp = l_temp->next;
            continue;
        }
        dap_chain_tx_tsd_t *l_item = dap_chain_datum_voting_vote_tx_cond_tsd_create(l_out_item->tx_hash_fast, l_out_item->num_idx_out);
        if(!l_item){
            dap_chain_datum_tx_delete(l_tx);

            dap_list_free_full(l_outs, NULL);
            return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_TSD_TX_COND_ITEM;
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
            return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_NET_FEE_OUT;
        }
    }
    // Validator's fee
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) == 1)
            SUM_256_256(l_value_pack, a_fee, &l_value_pack);
        else {
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_NET_FEE_OUT;
        }
    }
    // coin back
    uint256_t l_value_back;
    SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
    if(!IS_ZERO_256(l_value_back)) {
        if(dap_chain_datum_tx_add_out_item(&l_tx, l_addr_from, l_value_back) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_ADD_OUT_WITH_VALUE_BACK;
        }
    }

    // add 'sign' items with wallet sign
    if(dap_chain_datum_tx_add_sign_item(&l_tx, l_priv_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_SIGN_TX;
    }

    // add 'sign' items with delegated key if needed
    if(a_cert){
        if(dap_chain_datum_tx_add_sign_item(&l_tx, a_cert->enc_key) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_SIGN_TX;
        }
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
        *a_hash_tx_out = l_ret;
        return DAP_CHAIN_NET_VOTE_VOTING_OK;
    } else {
        return DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_POOL_IN_MEMPOOL;
    }
}

dap_chain_net_voting_info_t *s_voting_extract_info(struct voting *a_voting)
{
    dap_chain_net_voting_info_t *l_info;
    DAP_NEW_Z_RET_VAL(l_info, dap_chain_net_voting_info_t, NULL, NULL);

    l_info->question.question_size = a_voting->params.question_length;
    l_info->question.question_str = a_voting->params.question;
    l_info->hash = a_voting->hash;
    l_info->is_expired = (l_info->expired = a_voting->params.voting_expire);
    l_info->is_max_count_votes = (l_info->max_count_votes = a_voting->params.votes_max_count);
    l_info->is_changing_allowed = a_voting->params.vote_changing_allowed;
    l_info->is_delegate_key_required = a_voting->params.delegate_key_required;
    l_info->options.count_option = dap_list_length(a_voting->params.options);
    dap_chain_net_voting_info_option_t **l_options = DAP_NEW_Z_COUNT(dap_chain_net_voting_info_option_t*, l_info->options.count_option);
    for (uint64_t i = 0; i < l_info->options.count_option; i++){
        dap_list_t* l_option = dap_list_nth(a_voting->params.options, (uint64_t)i);
        struct vote_option* l_vote_option = (struct vote_option*)l_option->data;
        dap_chain_net_voting_info_option_t *l_option_info;
        DAP_NEW_Z_RET_VAL(l_option_info, dap_chain_net_voting_info_option_t, NULL, NULL);
        l_option_info->option_idx = i;
        l_option_info->description_size = l_vote_option->option_length;
        l_option_info->description = l_vote_option->option;
        l_option_info->votes_count = 0;
        l_option_info->weight = uint256_0;
        l_option_info->hashes_tx_votes = NULL;
        for (dap_list_t *it = a_voting->votes; it; it = it->next) {
            struct vote *l_vote = it->data;
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

dap_list_t *dap_chain_net_voting_list(dap_chain_net_t *a_net)
{
    dap_return_val_if_fail(a_net, NULL);
    struct voting *votings_ht = s_votings_ht_get(a_net->pub.id), *it;
    dap_list_t *ret = NULL;
    for (it = votings_ht; it; it = it->hh.next) {
        dap_chain_net_voting_info_t *l_info = s_voting_extract_info(it);
        if (!l_info)
            continue;
        ret = dap_list_append(ret, l_info);
    }
    return ret;
}

dap_chain_net_voting_info_t *dap_chain_net_voting_extract_info(dap_chain_net_t *a_net, dap_hash_fast_t *a_voting_hash)
{
    dap_return_val_if_fail(a_net && a_voting_hash, NULL);
    struct voting *l_voting = s_voting_find(a_net->pub.id, a_voting_hash);
    return l_voting ? s_voting_extract_info(l_voting) : NULL;
}

void dap_chain_net_voting_info_free(dap_chain_net_voting_info_t *a_info)
{
    for (size_t i = 0; i < a_info->options.count_option; i++)
        DAP_DELETE(a_info->options.options[i]);
    DAP_DEL_MULTY(a_info->options.options, a_info);
}
