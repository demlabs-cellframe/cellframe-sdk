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
#include "dap_chain_datum_service_state.h"
#include "dap_chain_datum_tx_voting.h"
#include "dap_chain_wallet_cache.h"

#define LOG_TAG "dap_chain_net_srv_voting"


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
} DAP_ALIGN_PACKED;

struct voting {
    dap_chain_hash_fast_t hash;
    dap_time_t start_time;
    dap_list_t *votes;
    dap_chain_datum_tx_voting_params_t *params;
    UT_hash_handle hh;
};

struct srv_voting {
    struct voting *ht;
};

static void *s_callback_start(dap_chain_net_id_t UNUSED_ARG a_net_id, dap_config_t UNUSED_ARG *a_config);
static void s_callback_delete(void *a_service_internal);

static int s_voting_ledger_verificator_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_hash, bool a_apply);
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
    dap_ledger_voting_verificator_add(s_voting_ledger_verificator_callback, s_datum_tx_voting_verification_delete_callback, dap_chain_net_srv_voting_get_expiration_time);
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
    dap_chain_datum_tx_voting_params_delete(a_voting->params);

    if (a_voting->votes)
        dap_list_free_full(a_voting->votes, NULL);
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
    if (!l_service_internal) {
        log_it(L_ERROR, "Can't find voting service for net id 0x%016" DAP_UINT64_FORMAT_x, a_net_id.uint64);
        return NULL;
    }
    return l_service_internal->ht;
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
    size_t l_options_count = dap_list_length(l_voting->params->options);
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

dap_time_t dap_chain_net_srv_voting_get_expiration_time(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_voting_hash)
{
    dap_return_val_if_fail(a_ledger && a_voting_hash, 0);
    struct voting *l_voting = s_voting_find(a_ledger->net->pub.id, a_voting_hash);
    if (!l_voting) {
        log_it(L_ERROR, "Can't find voting with hash %s in net %s", dap_hash_fast_to_str_static(a_voting_hash), a_ledger->net->pub.name);
        return 0;
    }
    return l_voting->params->voting_expire;
}


static int s_voting_verificator(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_hash, bool a_apply)
{
    if (!a_apply) {
        bool l_question_present = false, l_options_present = false;
        byte_t *l_item; size_t l_tx_item_size;
        TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx_in) {
            if (*l_item != TX_ITEM_TYPE_TSD)
                continue;
            dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t *)l_item)->tsd;
            switch(l_tsd->type) {
            case VOTING_TSD_TYPE_QUESTION:
                if (!l_tsd->size || !memchr(l_tsd->data, '\0', l_tsd->size || *l_tsd->data == '\0')) {
                    log_it(L_WARNING, "Invalid content for string TSD section QUESTION of voting %s", dap_hash_fast_to_str_static(a_tx_hash));
                    return -DAP_LEDGER_CHECK_PARSE_ERROR;
                }
                l_question_present = true;
                break;
            case VOTING_TSD_TYPE_OPTION:
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

        if (!l_question_present || !l_options_present) {
            log_it(L_WARNING, "Voting with hash %s contain no question or answer options", dap_hash_fast_to_str_static(a_tx_hash));
            return -2;
        }

        return DAP_LEDGER_CHECK_OK;
    }

    struct voting *l_item;
    DAP_NEW_Z_RET_VAL(l_item, struct voting, -DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY, NULL);
    l_item->hash = *a_tx_hash;
    l_item->start_time = a_tx_in->header.ts_created;
    l_item->params = dap_chain_datum_tx_voting_parse_tsd(a_tx_in);
    if (!l_item->params)
        return -DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY;
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
        if (l_vote_tx_item->answer_idx > dap_list_length(l_voting->params->options)) {
            log_it(L_WARNING, "Invalid vote option index %" DAP_UINT64_FORMAT_U " for vote tx %s",
                                                    l_vote_tx_item->answer_idx, dap_chain_hash_fast_to_str_static(a_tx_hash));
            return -6;
        }
        if (l_voting->params->votes_max_count && dap_list_length(l_voting->votes) >= l_voting->params->votes_max_count){
            log_it(L_WARNING, "The required number of votes has been collected for voting %s", dap_chain_hash_fast_to_str_static(&l_voting->hash));
            return -7;
        }
        if (l_voting->params->voting_expire && l_voting->params->voting_expire <= a_tx_in->header.ts_created) {
            log_it(L_WARNING, "The voting %s has been expired", dap_chain_hash_fast_to_str_static(&l_voting->hash));
            return -8;
        }

        if (l_voting->params->delegate_key_required &&
                !dap_chain_net_srv_stake_check_pkey_hash(a_ledger->net->pub.id, &pkey_hash)){
            log_it(L_WARNING, "Voting %s required a delegated key", dap_chain_hash_fast_to_str_static(&l_voting->hash));
            return -10;
        }


    }
    dap_list_t *l_vote_overwrited = NULL;
    for (dap_list_t *it = l_voting->votes; it; it = it->next) {
        if (dap_hash_fast_compare(&((struct vote *)it->data)->pkey_hash, &pkey_hash)) {
            dap_hash_fast_t *l_vote_hash = &((struct vote *)it->data)->vote_hash;
            if (!l_voting->params->vote_changing_allowed) {
                char l_vote_hash_str[DAP_HASH_FAST_STR_SIZE];
                dap_hash_fast_to_str(l_vote_hash, l_vote_hash_str, DAP_HASH_FAST_STR_SIZE);
                log_it(L_WARNING, "The voting %s don't allow change your vote %s",
                       dap_hash_fast_to_str_static(&l_voting->hash), l_vote_hash_str);
                return -11;
            }
            l_vote_overwrited = it;
            break;
        }
    }
    uint256_t l_weight = {};
    byte_t *l_item; size_t l_tx_item_size;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx_in) {
        dap_hash_fast_t l_tx_hash;
        int l_out_idx;
        switch (*l_item) {
        case TX_ITEM_TYPE_IN:       // check inputs
            l_tx_hash = ((dap_chain_tx_in_t *)l_item)->header.tx_prev_hash;
            l_out_idx = ((dap_chain_tx_in_t *)l_item)->header.tx_out_prev_idx;
            break;
        case TX_ITEM_TYPE_TSD: {    // check out conds
            dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t *)l_item)->tsd;
            if (l_tsd->type != VOTING_TSD_TYPE_VOTE_TX_COND)
                continue;
            l_tx_hash = ((dap_chain_tx_voting_tx_cond_t *)l_tsd->data)->tx_hash;
            l_out_idx = ((dap_chain_tx_voting_tx_cond_t *)l_tsd->data)->out_idx;
            break;
        }
        default:
            continue;
        }
        uint256_t l_uncoloured_value = dap_ledger_coin_get_uncoloured_value(a_ledger, &l_vote_tx_item->voting_hash, &l_tx_hash, l_out_idx);
        if (IS_ZERO_256(l_uncoloured_value)) {
            log_it(L_ERROR, "Coin with OUT number %d of tx %s is voted before in voting %s", l_out_idx, dap_chain_hash_fast_to_str_static(&l_tx_hash),
                                                                            dap_chain_hash_fast_to_str_static(&l_vote_tx_item->voting_hash));
            return -13;
        }
        if (SUM_256_256(l_weight, l_uncoloured_value, &l_weight)) {
            log_it(L_WARNING, "Integer overflow while parsing vote tx %s", dap_chain_hash_fast_to_str_static(a_tx_hash));
            return -DAP_LEDGER_CHECK_INTEGER_OVERFLOW;
        }
    }

    if (IS_ZERO_256(l_weight) && !l_vote_overwrited) {
        log_it(L_ERROR, "No uncoloured inputs in vote %s of voting %s", dap_chain_hash_fast_to_str_static(a_tx_hash),
                                                                        dap_chain_hash_fast_to_str_static(&l_vote_tx_item->voting_hash));
        return -14;
    }

    if (a_apply) {
        struct vote *l_vote_item;
        DAP_NEW_Z_RET_VAL(l_vote_item, struct vote, -DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY, NULL);
        l_vote_item->vote_hash = *a_tx_hash;
        l_vote_item->pkey_hash = pkey_hash;
        l_vote_item->answer_idx = l_vote_tx_item->answer_idx;
        l_vote_item->weight = l_weight;

        if (l_vote_overwrited) {
            SUM_256_256(l_vote_item->weight, ((struct vote *)l_vote_overwrited->data)->weight, &l_vote_item->weight);
            // change vote & move it to the end of list
            l_voting->votes = dap_list_remove_link(l_voting->votes, l_vote_overwrited);
            DAP_DELETE(l_vote_overwrited->data);
        }
        l_voting->votes = dap_list_append(l_voting->votes, l_vote_item);
        char l_vote_hash_str[DAP_HASH_FAST_STR_SIZE];
        dap_hash_fast_to_str(a_tx_hash, l_vote_hash_str, DAP_HASH_FAST_STR_SIZE);
        log_it(L_INFO, "Vote %s of voting %s has been %s", l_vote_hash_str, dap_hash_fast_to_str_static(&l_voting->hash),
                                     l_vote_overwrited ? "accepted" : "changed");
    }
    return DAP_LEDGER_CHECK_OK;
}

int s_voting_ledger_verificator_callback(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_hash, bool a_apply)
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
            json_object_object_add(json_obj_vote, "Voting question", json_object_new_string((char *)it->params->question));
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
        l_options_count = dap_list_length(l_voting->params->options);
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
        json_object_object_add(json_vote_out, "Voting dump", json_object_new_string((char *)l_voting->params->question));

        if (l_voting->params->voting_expire) {
            char l_tmp_buf[DAP_TIME_STR_SIZE];
            dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_voting->params->voting_expire);
            json_object_object_add(json_vote_out, "Voting expire", 
                                    json_object_new_string(l_tmp_buf));
            //dap_string_truncate(l_str_out, l_str_out->len - 1);
            json_object_object_add(json_vote_out, "status", 
                                    l_voting->params->voting_expire > dap_time_now() ?
                                    json_object_new_string("active") :
                                    json_object_new_string("expired"));
        }
        if (l_voting->params->votes_max_count){
            char *l_val = dap_strdup_printf(" %"DAP_UINT64_FORMAT_U" (%s)\n", l_voting->params->votes_max_count,
                                     l_voting->params->votes_max_count <= l_votes_count ? "closed" : "active");
            json_object_object_add(json_vote_out, "Votes max count", json_object_new_string(l_val));
            DAP_DELETE(l_val);
        }
        json_object_object_add(json_vote_out, "changing vote status", l_voting->params->vote_changing_allowed ?
                                                                        json_object_new_string("available") : 
                                                                        json_object_new_string("not available"));
        json_object_object_add(json_vote_out, "delegated voting key status", l_voting->params->delegate_key_required ?
                                                                        json_object_new_string("is required") : 
                                                                        json_object_new_string("not required"));
        
        json_object* json_arr_vote_out = json_object_new_array();
        for (uint64_t i = 0; i < dap_list_length(l_voting->params->options); i++){
            json_object* json_vote_obj = json_object_new_object();
            char *l_val = NULL;
            l_val = dap_strdup_printf("%"DAP_UINT64_FORMAT_U")", i);
            json_object_object_add(json_vote_obj, "#", json_object_new_string(l_val));
            DAP_DELETE(l_val);
            dap_list_t* l_option = dap_list_nth(l_voting->params->options, (uint64_t)i);
            json_object_object_add(json_vote_obj, "voting tx", json_object_new_string(l_option->data));
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
        l_val = dap_strdup_printf("%"DAP_UINT64_FORMAT_U, l_votes_count);
        json_object_object_add(json_vote_out, "Total number of votes", json_object_new_string(l_val));
        DAP_DELETE(l_val);
        const char *l_tw_coins, *l_tw_datoshi = dap_uint256_to_char(l_total_weight, &l_tw_coins);
        l_val = dap_strdup_printf("%s (%s) %s", l_tw_coins, l_tw_datoshi, l_net->pub.native_ticker);
        json_object_object_add(json_vote_out, "Total weight", json_object_new_string(l_val));
        DAP_DELETE(l_val);
        json_object_array_add(*json_arr_reply, json_vote_out);
    }break;
    default:{

    }break;
    }

    return 0;
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
    dap_list_t *l_list_used_out = NULL;
    if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_native_ticker, l_addr_from, &l_list_used_out, l_total_fee, &l_value_transfer) == -101)
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
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

    if (l_voting->params->votes_max_count && dap_list_length(l_voting->votes) >= l_voting->params->votes_max_count)
        return DAP_CHAIN_NET_VOTE_VOTING_THIS_VOTING_HAVE_MAX_VALUE_VOTES;

    if (l_voting->params->voting_expire && dap_time_now() > l_voting->params->voting_expire)
        return DAP_CHAIN_NET_VOTE_VOTING_ALREADY_EXPIRED;

    dap_hash_fast_t l_pkey_hash = {0};

    if (l_voting->params->delegate_key_required) {
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
                    !l_voting->params->vote_changing_allowed)
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
        uint256_t l_uncoloured_value = dap_ledger_coin_get_uncoloured_value(a_net->pub.ledger, a_voting_hash,
                                                                            &l_out->tx_hash_fast, l_out->num_idx_out);
        if (IS_ZERO_256(l_uncoloured_value)) {
            dap_list_delete_link(l_list_used_out, it);
            continue;
        }
        if (SUM_256_256(l_value_transfer_new, l_out->value, &l_value_transfer_new))
            return DAP_CHAIN_NET_VOTE_VOTING_INTEGER_OVERFLOW;
    }

    if ((IS_ZERO_256(l_value_transfer_new) || compare256(l_value_transfer_new, l_total_fee) <= 0))
        return DAP_CHAIN_NET_VOTE_VOTING_UNSPENT_UTX0_FOR_PARTICIPATION_THIS_VOTING;

    l_value_transfer = l_value_transfer_new;

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // Add vote item
    if (a_option_idx > dap_list_length(l_voting->params->options)){
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
    int err = 0;
    dap_list_t *l_outs = dap_ledger_get_list_tx_cond_outs(l_ledger, l_addr_from);
    for (dap_list_t *it = l_outs; it; it = it->next) {
        dap_chain_tx_used_out_item_t *l_out_item = (dap_chain_tx_used_out_item_t *)it->data;
        uint256_t l_value = dap_ledger_coin_get_uncoloured_value(l_ledger, a_voting_hash, &l_out_item->tx_hash_fast, l_out_item->num_idx_out);
        if (IS_ZERO_256(l_value))
            continue;
        dap_chain_tx_tsd_t *l_item = dap_chain_datum_voting_vote_tx_cond_tsd_create(l_out_item->tx_hash_fast, l_out_item->num_idx_out);
        if (!l_item) {
            err = DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_TSD_TX_COND_ITEM;
            break;
        }
        if (dap_chain_datum_tx_add_item(&l_tx, l_item) != 1) {
            err = DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_CREATE_TSD_TX_COND_ITEM;
            break;
        }
        DAP_DEL_Z(l_item);
    }
    dap_list_free_full(l_outs, NULL);
    if (err) {
        dap_chain_datum_tx_delete(l_tx);
        return err;
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

    l_info->question.question_size = strlen(a_voting->params->question);
    l_info->question.question_str = a_voting->params->question;
    l_info->hash = a_voting->hash;
    l_info->is_expired = (l_info->expired = a_voting->params->voting_expire);
    l_info->is_max_count_votes = (l_info->max_count_votes = a_voting->params->votes_max_count);
    l_info->is_changing_allowed = a_voting->params->vote_changing_allowed;
    l_info->is_delegate_key_required = a_voting->params->delegate_key_required;
    l_info->options.count_option = dap_list_length(a_voting->params->options);
    dap_chain_net_voting_option_info_t **l_options = DAP_NEW_Z_COUNT(dap_chain_net_voting_option_info_t*, l_info->options.count_option);
    for (uint64_t i = 0; i < l_info->options.count_option; i++){
        dap_list_t* l_option = dap_list_nth(a_voting->params->options, (uint64_t)i);
        struct vote_option* l_vote_option = (struct vote_option*)l_option->data;
        dap_chain_net_voting_option_info_t *l_option_info;
        DAP_NEW_Z_RET_VAL(l_option_info, dap_chain_net_voting_option_info_t, NULL, NULL);
        l_option_info->option_idx = i;
        l_option_info->description_size = strlen(l_option->data);
        l_option_info->description = l_option->data;
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

struct voting_serial {
    uint64_t size;
    dap_hash_fast_t hash;
    dap_time_t voting_start;
    dap_time_t voting_expire;
    uint64_t votes_max_count;
    uint64_t votes_count;
    uint8_t delegate_key_required;
    uint8_t vote_changing_allowed;
    byte_t question_n_options_n_votes[];
} DAP_ALIGN_PACKED;

static size_t s_voting_serial_size_calc(struct voting *a_voting, size_t *a_votes_count)
{
    size_t i = 0, ret = sizeof(struct voting_serial) + sizeof(dap_tsd_t) + strlen(a_voting->params->question);
    for (dap_list_t *it = a_voting->params->options; it; it = it->next, i++)
        ret += strlen(it->data);
    ret += i * sizeof(dap_tsd_t);
    size_t l_votes_count = dap_list_length(a_voting->votes);
    ret += l_votes_count * (sizeof(dap_tsd_t) + sizeof(struct vote));
    if (a_votes_count)
        *a_votes_count = l_votes_count;
    return ret;
}

static int s_voting_dump(dap_chain_datum_t **a_dump_datum, struct voting *a_voting)
{
    size_t l_votes_count = 0;
    size_t l_voting_size = s_voting_serial_size_calc(a_voting, &l_votes_count);
    dap_chain_datum_t *l_dump_datum = DAP_REALLOC(*a_dump_datum, dap_chain_datum_size(*a_dump_datum) + l_voting_size);
    if (!l_dump_datum) {
        DAP_DELETE(*a_dump_datum);
        return -1;
    }
    l_dump_datum->header.data_size += l_voting_size;
    struct voting_serial *cur = (struct voting_serial *)(l_dump_datum->data + l_dump_datum->header.data_size);
    *cur = (struct voting_serial) {
            .size = l_voting_size,
            .hash = a_voting->hash,
            .voting_start = a_voting->start_time,
            .voting_expire = a_voting->params->voting_expire,
            .votes_max_count = a_voting->params->votes_max_count,
            .votes_count = l_votes_count,
            .delegate_key_required = a_voting->params->delegate_key_required,
            .vote_changing_allowed = a_voting->params->vote_changing_allowed
    };
    byte_t *l_tsd = dap_tsd_write(cur->question_n_options_n_votes, VOTING_TSD_TYPE_QUESTION, a_voting->params->question, strlen(a_voting->params->question));
    for (dap_list_t *it = a_voting->params->options; it; it = it->next)
        l_tsd = dap_tsd_write(l_tsd, VOTING_TSD_TYPE_OPTION, it->data, strlen(it->data));
    for (dap_list_t *it = a_voting->votes; it; it = it->next)
        l_tsd = dap_tsd_write(l_tsd, VOTING_TSD_TYPE_VOTE, it->data, sizeof(struct vote));
    assert(l_tsd == l_dump_datum->data + l_dump_datum->header.data_size);
    *a_dump_datum = l_dump_datum;
    return 0;
}

static int s_votings_backup(dap_chain_net_t *a_net)
{
    struct voting *votings_ht = s_votings_ht_get(a_net->pub.id);
    if (!votings_ht) {
        log_it(L_INFO, "No data to backup for voting service for net id 0x%016" DAP_UINT64_FORMAT_x, a_net->pub.id.uint64);
        return 0;
    }
    dap_chain_datum_t *l_hardfork_state_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_SERVICE_STATE, NULL, sizeof(dap_chain_datum_service_state_t));
    if (!l_hardfork_state_datum)
        return -1;
    size_t i = 0;
    for (struct voting *it = votings_ht; it; it = it->hh.next, i++) {
        int ret = s_voting_dump(&l_hardfork_state_datum, it);
        if (ret)
            return ret;
    }
    ((dap_chain_datum_service_state_t *)l_hardfork_state_datum->data)->srv_uid = (dap_chain_srv_uid_t) { .uint64 = DAP_CHAIN_NET_SRV_VOTING_ID };
    ((dap_chain_datum_service_state_t *)l_hardfork_state_datum->data)->states_count = i;
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    char *l_datum_hash = dap_chain_mempool_datum_add(l_hardfork_state_datum, l_chain, "hex");
    log_it(L_INFO, "Datum hash %s with voting service states successfully placed in mempool", l_datum_hash);
    DAP_DELETE(l_datum_hash);
    return 0;
}

static int s_votings_restore(dap_chain_net_id_t a_net_id, dap_chain_datum_service_state_t *a_state, size_t a_data_size)
{
    struct srv_voting *l_service_internal = dap_chain_srv_get_internal(a_net_id, (dap_chain_srv_uid_t) { .uint64 = DAP_CHAIN_NET_SRV_VOTING_ID });
    if (!l_service_internal)
        return -1;
    byte_t *l_cur_ptr = a_state->states + sizeof(dap_chain_datum_service_state_t);
    for (uint32_t i = 0; i < a_state->states_count; i++) {
        struct voting_serial *cur = (struct voting_serial *)l_cur_ptr;
        if (l_cur_ptr + cur->size > (byte_t *)a_state + a_data_size ||
                cur->size <  sizeof(struct voting_serial) + sizeof(dap_tsd_t) * 2)
            return -2;
        unsigned l_hash_value;
        HASH_VALUE(&cur->hash, sizeof(dap_hash_fast_t), l_hash_value);
        struct voting *l_voting = NULL;
        HASH_FIND_BYHASHVALUE(hh, l_service_internal->ht, &cur->hash, sizeof(dap_hash_fast_t), l_hash_value, l_voting);
        if (!l_voting) {
            DAP_NEW_Z_RET_VAL(l_voting, struct voting, -3, NULL);
            *l_voting = (struct voting) {
                    .hash = cur->hash,
                    .start_time = cur->voting_start
            };
            DAP_NEW_Z_RET_VAL(l_voting->params, dap_chain_datum_tx_voting_params_t, -3, l_voting, NULL);
            *l_voting->params = (dap_chain_datum_tx_voting_params_t) {
                    .voting_expire = cur->voting_expire,
                    .votes_max_count = cur->votes_max_count,
                    .delegate_key_required = cur->delegate_key_required,
                    .vote_changing_allowed = cur->vote_changing_allowed
            };
            dap_tsd_t *l_tsd; size_t l_tsd_size;
            dap_tsd_iter(l_tsd, l_tsd_size,
                         cur->question_n_options_n_votes + sizeof(struct voting_serial),
                         a_data_size - sizeof(struct voting_serial)) {
                switch (l_tsd->type) {
                case VOTING_TSD_TYPE_QUESTION:
                    l_voting->params->question = DAP_DUP_SIZE(l_tsd->data, l_tsd->size);
                    if (!l_voting->params->question) {
                        dap_chain_datum_tx_voting_params_delete(l_voting->params);
                        DAP_DELETE(l_voting);
                        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                        return -3;
                    }
                    break;
                case VOTING_TSD_TYPE_OPTION: {
                    char *l_option = DAP_DUP_SIZE(l_tsd->data, l_tsd->size);
                    if (!l_option) {
                        dap_chain_datum_tx_voting_params_delete(l_voting->params);
                        DAP_DELETE(l_voting);
                        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                        return -3;
                    }
                    l_voting->params->options = dap_list_append(l_voting->params->options, l_option);
                    break;
                }
                case VOTING_TSD_TYPE_VOTE: {
                    struct vote *l_vote = DAP_DUP_SIZE(l_tsd->data, l_tsd->size);
                    if (!l_vote) {
                        dap_list_free_full(l_voting->votes, NULL);
                        dap_chain_datum_tx_voting_params_delete(l_voting->params);
                        DAP_DELETE(l_voting);
                        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                        return -3;
                    }
                    l_voting->votes = dap_list_append(l_voting->votes, l_vote);
                    break;
                }
                default:
                    log_it(L_ERROR, "Unexpected TSD type %d in voting service state data", l_tsd->type);
                    return -4;
                }
            }
            HASH_ADD_BYHASHVALUE(hh, l_service_internal->ht, hash, sizeof(dap_hash_fast_t), l_hash_value, l_voting);
        }
        l_cur_ptr = l_cur_ptr + cur->size;
    }
    return 0;
}
